"""Everything one task knows about its investigation, behind two operations.

The agent loop asks `before_call` what to do with the model's call and gives
the runtime's answer to `after_call`. The tool catalog, GraphLedger, the
`still_open` merge, the local knowledge lookup, the wording of local answers
and the trace events of those decisions all live here.
"""

from dataclasses import dataclass
from typing import Any

from loguru import logger

from sibyl_h0und.catalog import FINISH_TOOL, ToolCatalog
from sibyl_h0und.ledger import GraphLedger
from sibyl_h0und.llm import render_json
from sibyl_h0und.outcome import ToolOutcome, decode_json
from sibyl_h0und.trace import TaskTrace
from sibyl_h0und.vocabulary import KNOWLEDGE_TOOL, KNOWLEDGE_TOOL_SPEC, shared

# Observation fields that repeat in every response and are not part of the alert.
NON_ALERT_FIELDS = frozenset({"available_tools", "last_tool_result"})
# Shorter reasoning is a placeholder, not a report: practice runs ended long
# investigations with "" and "Short test" (ADR 0018).
MIN_REPORT_REASONING = 20
# The list a report of each verdict must not leave empty.
REPORT_CITATIONS = {"malicious": "ir_artifacts", "benign": "legitimacy_evidence"}
# Asked once before a benign report reaches the runtime: practice runs called
# attacks benign after a look at the trigger alone (ADR 0020).
BENIGN_CHALLENGE = (
    "A benign verdict overrules the detection that raised this alert, so check it once "
    "before submitting. Answer from the evidence: why did the detection fire? What came "
    "one stage before the trigger on the kill chain (how it started: parent, logon and "
    "its source, delivery) and one stage after (what it led to: children, written or "
    "changed files, persistence, connections and the hosts they reach)? If a stage is "
    "not opened yet (`still_open` lists what is known but unvisited), open it; do not "
    "repeat calls. If the evidence already answers all of this, submit the report "
    "again, malicious or benign as the evidence says."
)


@dataclass(frozen=True)
class LocalAnswer:
    """The call is answered without the runtime.

    Attributes:
        feedback: Tool message content for the model.
    """

    feedback: dict[str, Any]


@dataclass(frozen=True)
class Send:
    """The call goes to the runtime.

    Attributes:
        arguments: Arguments to send, completed and checked against the catalog.
    """

    arguments: dict[str, Any]


@dataclass(frozen=True)
class Reply:
    """What the model gets after a runtime call.

    Attributes:
        feedback: Tool message content for the model.
    """

    feedback: dict[str, Any]


class Investigation:
    """Per-task state and rules that turn tool calls and responses into messages."""

    def __init__(self, observation: dict[str, Any], trace: TaskTrace | None = None) -> None:
        """Build the catalog, ledger and knowledge vocabulary of one task.

        Args:
            observation: Public task observation with a JSON-encoded `available_tools`.
            trace: Task trace that receives the events of local decisions.

        Raises:
            ValueError: If the observation has an invalid tool catalog.
        """
        self.catalog = ToolCatalog.from_observation(observation, local_tools=[KNOWLEDGE_TOOL_SPEC])
        self.trace = trace or TaskTrace(None)
        self.alert = {
            key: decode_json(value)
            for key, value in observation.items()
            if key not in NON_ALERT_FIELDS
        }
        self._ledger = GraphLedger()
        self._ledger.observe_alert(self.alert)
        self._vocabulary = shared()
        self._report_refused = False
        self._benign_challenged = False
        # A search scoped to a relation type lists an entity's relations by its id.
        self._relation_search = self.catalog.relation_search()

    def opening_message(self) -> dict[str, Any]:
        """Return the first user message: the alert and the tool catalog, once."""
        return {
            "role": "user",
            "content": render_json(
                {
                    "instruction": "Investigate this alert and submit the correct response.",
                    "initial_observation": self.alert,
                    "available_tools": self.catalog.specs,
                }
            ),
        }

    def before_call(
        self, tool: str, arguments: dict[str, Any], *, finish_only: bool = False
    ) -> LocalAnswer | Send:
        """Decide whether the model's call reaches the runtime.

        A tool outside the catalog or outside the allowed set, arguments that
        break the tool's schema, a knowledge lookup, an id the runtime never
        returned and a repeated call are answered locally. So are the first
        placeholder report (ADR 0018) and the first benign report outside the
        finish-only mode (ADR 0020).

        Args:
            tool: Tool the model chose.
            arguments: Arguments the model chose, without nulls.
            finish_only: Whether only `finish_investigation` may be called.

        Returns:
            A local answer, or the prepared arguments to send.
        """
        problem = None
        if tool in self.catalog:
            try:
                arguments = self.catalog.prepare(tool, arguments)
            except ValueError as exc:
                problem = str(exc)

        if tool not in self.catalog or (finish_only and tool != FINISH_TOOL):
            allowed = [FINISH_TOOL] if finish_only else self.catalog.names
            logger.warning("Rejected unavailable tool {} locally.", tool)
            self.trace.local_answer("tool_rejected", tool, arguments, None)
            return LocalAnswer(
                {
                    "status": "error",
                    "message": f"Tool {tool!r} cannot be called now. Available tools: {allowed}",
                }
            )
        if problem is not None:
            feedback = {"status": "error", "message": f"Not sent to the runtime: {problem}"}
            logger.warning("Rejected invalid {} arguments locally: {}", tool, problem)
            self.trace.local_answer("tool_invalid", tool, arguments, feedback)
            return LocalAnswer(feedback)
        challenge = (
            tool == FINISH_TOOL
            and not finish_only
            and not self._benign_challenged
            and report_verdict(arguments) == "benign"
        )
        empty = report_problem(arguments) if tool == FINISH_TOOL else None
        if empty is not None and not self._report_refused:
            # Refused once: a second weak report still beats no report at all.
            self._report_refused = True
            message = f"Not sent to the runtime: {empty} Submit the report again."
            if challenge:
                # One refusal, not two in a row with different reasons.
                self._benign_challenged = True
                message = f"{message} {BENIGN_CHALLENGE}"
            feedback = {"status": "error", "message": message}
            logger.warning("Refused an empty report once: {}", empty)
            self.trace.local_answer("report_refused", tool, arguments, feedback)
            return LocalAnswer(feedback)
        if tool == KNOWLEDGE_TOOL and self.catalog.is_local(tool):
            feedback = self._vocabulary.lookup(arguments["query"])
            self.trace.local_answer("tool_knowledge", tool, arguments, feedback)
            return LocalAnswer(feedback)
        decision = self._ledger.check(tool, arguments)
        if decision.feedback is not None:
            logger.warning("Answered {} locally: {}.", tool, decision.reason)
            self.trace.local_answer(f"tool_{decision.reason}", tool, arguments, decision.feedback)
            return LocalAnswer(decision.feedback)
        if challenge:
            # Once: the model may still be right, and at the ceiling it cannot look further.
            self._benign_challenged = True
            feedback: dict[str, Any] = {
                "status": "error",
                "message": f"Not sent to the runtime: {BENIGN_CHALLENGE}",
            }
            if open_items := self._ledger.summary():
                feedback["still_open"] = open_items
            logger.warning("Challenged a benign verdict once before sending it.")
            self.trace.local_answer("benign_challenged", tool, arguments, feedback)
            return LocalAnswer(feedback)
        return Send(arguments)

    def after_call(self, tool: str, arguments: dict[str, Any], outcome: ToolOutcome) -> Reply:
        """Learn from a runtime answer and build the message the model sees.

        The message carries the evidence, then `still_open` for what is known
        but not yet visited. The ledger caches the evidence alone.

        Args:
            tool: Tool that was called.
            arguments: Arguments sent to the runtime, as `before_call` returned them.
            outcome: The runtime's answer to a non-terminal call.

        Returns:
            The tool message content.
        """
        self._ledger.record(tool, arguments, outcome)
        feedback = outcome.evidence()
        if open_items := self._ledger.summary():
            fetched = arguments.get("entity_id")
            opened = open_items.get("entities_with_open_relations", [])
            if self._relation_search and any(item["entity_id"] == fetched for item in opened):
                # Said once per fetched entity, where the model picks how to open them.
                open_items["list_relations_with"] = (
                    f"{self._relation_search} with this entity's full id as `query` returns "
                    "its relations in full with their types; keep those whose source or "
                    "target is this entity. For an entity with many relations, limit "
                    "`scope` to one relation type."
                )
            feedback["still_open"] = open_items
        return Reply(feedback)


def report_problem(arguments: dict[str, Any]) -> str | None:
    """Find a report that says nothing.

    The report is the arguments or an object directly inside them that holds a
    `verdict`. Only fields next to that verdict are read, so a report tool of
    another shape passes untouched.

    Args:
        arguments: Prepared arguments of the report tool.

    Returns:
        What is missing, or `None` for a report that can be sent.
    """
    report = find_report(arguments)
    if report is None:
        return None
    reasoning = report.get("reasoning")
    if isinstance(reasoning, str) and len(reasoning.strip()) < MIN_REPORT_REASONING:
        return (
            "the reasoning is empty or too short: tell the chain you established, "
            "with its stages, techniques and entities, in a few sentences."
        )
    citations = REPORT_CITATIONS.get(str(report.get("verdict")))
    if citations is not None and report.get(citations) == []:
        return f"a {report['verdict']} report must cite entities in `{citations}`."
    return None


def find_report(arguments: dict[str, Any]) -> dict[str, Any] | None:
    """Find the report: the arguments or an object directly inside them with a `verdict`.

    Args:
        arguments: Prepared arguments of the report tool.

    Returns:
        The report object, or `None` for a report tool of another shape.
    """
    candidates = [arguments, *(value for value in arguments.values() if isinstance(value, dict))]
    return next((item for item in candidates if "verdict" in item), None)


def report_verdict(arguments: dict[str, Any]) -> str | None:
    """Return the verdict of a report in lower case, or `None` when it has none.

    Args:
        arguments: Prepared arguments of the report tool.

    Returns:
        The verdict, or `None` when the report has no string verdict.
    """
    verdict = (find_report(arguments) or {}).get("verdict")
    return verdict.strip().lower() if isinstance(verdict, str) else None
