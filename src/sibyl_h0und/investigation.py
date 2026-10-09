"""Everything one task knows about its investigation, behind three operations.

The agent loop asks `before_call` what to do with the model's call and gives
the runtime's answer to `after_call`. When the call needs a side turn of the
LLM first (the benign challenger, ADR 0022), the loop runs it and gives its
reply to `after_review`. The tool catalog, GraphLedger, the `still_open`
merge, the local knowledge lookup, the side turns' requests, the wording of
local answers and the trace events of those decisions all live here.
"""

from dataclasses import dataclass
from typing import Any

from loguru import logger
from pydantic import BaseModel

from sibyl_h0und.catalog import FINISH_TOOL, ToolCatalog
from sibyl_h0und.digest import evidence_digest
from sibyl_h0und.ledger import GraphLedger
from sibyl_h0und.llm import render_json
from sibyl_h0und.models import Challenge, ToolCall
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
CHALLENGER_ROLE = "challenger"
# The challenger argues the opposite of a benign verdict from the evidence
# alone (ADR 0022). Written from general principles: no program, port,
# relation type or scenario of any practice task.
CHALLENGER_PROMPT = """
You are a threat hunter reviewing an investigation before it closes. A detection (a SIEM
rule, an EDR or an antivirus) raised the alert, and the investigation is about to call it
benign. You see the alert, the tools, every piece of evidence the investigation gathered
and `still_open`: what is known but was never opened. You do not see the investigation's
reasoning, and you need not agree with it.

Your job is to argue the opposite verdict.
- Write the strongest attack hypothesis these facts allow: which stages of an intrusion the
  evidence could be, which entities would carry them out, and why the detection would fire.
  Build it only from facts in the evidence; do not invent entities or properties.
- Then give one to three checks that would refute the hypothesis if it is wrong. Each check
  is one call of an available tool, with ids taken from the alert, the evidence or
  `still_open`, and says what result would refute the hypothesis. Prefer what is still
  open: relations not yet visited, entities never fetched. A call already made adds nothing.
- Judge what each entity did, to what and from where, not what it is called. A familiar
  name, a signature, a usual parent or a plausible purpose does not refute an attack.
  An entity with many relations of which few were opened is a place an attack can hide.
- Always argue the attack, even when the evidence looks clean and your case is weak: the
  investigation weighs it and decides. A weak case is still worth making when its checks
  open what nobody has looked at.

Evidence layout: `hosts` groups each host with the entities and relations nearest to it;
`between_hosts` holds relations that join entities of different hosts; `no_host` holds
what no host reaches. `unvisited_relation_ids` on an entity lists its relations never
opened.

Return exactly one JSON object matching the supplied schema, with no prose.
""".strip()
REPORTER_ROLE = "reporter"
# The reporter writes the report the runtime receives, for the verdict the
# investigation reached (ADR 0023). General principles only, like the challenger.
REPORTER_PROMPT = """
You are the incident responder who writes the final report of an investigation. The
investigation has reached its verdict; your job is to make the report right for that
verdict. You see the alert, every piece of evidence the investigation gathered, what is
still unvisited, the investigation's draft report and, if one was raised, a reviewer's
challenge to a benign draft.

Write the report as one call of the report tool:
- Keep the draft's verdict. Do not change it.
- Cite only ids that appear in the alert or the evidence, and only entities that belong to
  the incident. An entity the investigation visited is not part of the incident just
  because it was visited; extra entities are penalized like missing ones.
- Malicious: the response artifacts cover every stage the evidence establishes:
  compromised hosts, accounts used, persistence, dropped or changed files, attacker
  network endpoints. Give each entity one consistent action; use an observed kind for an
  incident entity that needs no action. Keep what the draft got right, drop what the
  evidence does not tie to the incident, and add incident entities the draft missed.
- Benign: the legitimacy evidence cites the entities and relations that explain the
  activity, with the property fields that show it; use only property fields the evidence
  shows for that entity or relation.
- The reasoning tells the chain in a few sentences: stages, techniques and entities; for
  benign, why each suspicious-looking action is explained, including the reviewer's
  challenge if there was one.

Evidence layout: `hosts` groups each host with the entities and relations nearest to it;
`between_hosts` holds relations that join entities of different hosts; `no_host` holds
what no host reaches.

Return exactly one JSON object matching the supplied schema, with no prose.
""".strip()
# What the reporter is told when its report cannot be sent.
REPORT_REPAIR = (
    "This report cannot be sent: {problem} Return the corrected report as one JSON object "
    "matching the schema."
)
# What the head is told with the challenger's case.
CHALLENGE_ANSWER = (
    "A benign verdict overrules the detection that raised this alert, so a reviewer who did "
    "not see your reasoning read the same evidence and argues it is an attack. `challenge` "
    "gives its hypothesis and the checks that would refute it; `still_open` lists what is "
    "known but unvisited. Make the checks you need (a repeated call returns its earlier "
    "result). In `current_state`, answer each check: checked with which call, refuted by "
    "which evidence id, or why it cannot be checked. Then submit the report again, malicious "
    "or benign as the evidence says."
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
class Review:
    """The call waits for a side turn of the LLM; its reply goes to `after_review`.

    Attributes:
        role: Name of the side turn in the trace.
        arguments: The model's call, prepared, that the side turn is about.
        messages: The side turn's whole request.
        response_format: The side turn's schema.
        model: Model that validates the side turn's reply.
        repaired: Whether this turn is the one repair a reporter gets.
    """

    role: str
    arguments: dict[str, Any]
    messages: list[dict[str, Any]]
    response_format: dict[str, Any]
    model: type[BaseModel]
    repaired: bool = False


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
        # The challenger's case the head was given, for the reporter.
        self._challenge_record: dict[str, Any] | None = None
        # Whether the report last sent is the reporter's rewrite of the head's.
        self._rewritten = False
        # Why the last report sent is the head's own, or `None` (ADR 0023).
        self.report_fallback: str | None = None
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
    ) -> LocalAnswer | Send | Review:
        """Decide whether the model's call reaches the runtime.

        A tool outside the catalog or outside the allowed set, arguments that
        break the tool's schema, a knowledge lookup, an id the runtime never
        returned and a repeated call are answered locally. So is the first
        placeholder report (ADR 0018). The first benign report outside the
        finish-only mode goes to the challenger first (ADR 0020, 0022); a
        report that is to be sent goes to the reporter first (ADR 0023).

        Args:
            tool: Tool the model chose.
            arguments: Arguments the model chose, without nulls.
            finish_only: Whether only `finish_investigation` may be called.

        Returns:
            A local answer, the prepared arguments to send, or the side turn
            to run before the call is answered.
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
            feedback = self._vocabulary.lookup(arguments["query"], arguments.get("terms"))
            self.trace.local_answer("tool_knowledge", tool, arguments, feedback)
            return LocalAnswer(feedback)
        if (known := self._ledger_answer(tool, arguments)) is not None:
            return known
        if challenge:
            # Once: the model may still be right, and at the ceiling it cannot look further.
            self._benign_challenged = True
            tools = self.catalog.runtime_tools()
            if not tools:
                return self._challenge(arguments, None, "no runtime tool to check with")
            logger.info("Asking the challenger about a benign verdict.")
            return Review(
                CHALLENGER_ROLE,
                arguments,
                self._challenger_request(tools),
                self.catalog.challenge_format(tools),
                Challenge,
            )
        if tool == FINISH_TOOL and (report_format := self.catalog.report_format()) is not None:
            logger.info("Asking the reporter to write the report.")
            return Review(
                REPORTER_ROLE, arguments, self._reporter_request(arguments), report_format, ToolCall
            )
        return Send(arguments)

    def after_review(
        self, review: Review, reply: BaseModel | None, error: str | None = None
    ) -> LocalAnswer | Send | Review:
        """Answer the call a side turn was about.

        Args:
            review: The side turn `before_call` or a previous `after_review` asked for.
            reply: The side turn's validated reply, or `None` when it failed.
            error: Why the side turn failed, if it did.

        Returns:
            The local answer to the model's call, the report to send, or one
            repair turn of the reporter.
        """
        if review.role == REPORTER_ROLE:
            return self._report(review, reply if isinstance(reply, ToolCall) else None, error)
        challenge = reply if isinstance(reply, Challenge) else None
        return self._challenge(review.arguments, challenge, error)

    def _reporter_request(self, draft: dict[str, Any]) -> list[dict[str, Any]]:
        """Build the reporter's request: the alert, the evidence, the draft and any challenge."""
        request: dict[str, Any] = {
            "alert": self.alert,
            "available_tools": self.catalog.specs_of([FINISH_TOOL]),
            "evidence": evidence_digest(self._ledger),
        }
        if open_items := self._ledger.summary():
            request["still_open"] = open_items
        request["draft_report"] = draft
        if self._challenge_record is not None:
            request["challenge"] = self._challenge_record
        return [
            {"role": "system", "content": REPORTER_PROMPT},
            {"role": "user", "content": render_json(request)},
        ]

    def _ledger_answer(self, tool: str, arguments: dict[str, Any]) -> LocalAnswer | None:
        """Answer a call with an unknown id or a repeated call from GraphLedger, else `None`."""
        decision = self._ledger.check(tool, arguments)
        if decision.feedback is None:
            return None
        logger.warning("Answered {} locally: {}.", tool, decision.reason)
        self.trace.local_answer(f"tool_{decision.reason}", tool, arguments, decision.feedback)
        return LocalAnswer(decision.feedback)

    def _report(
        self, review: Review, reply: ToolCall | None, error: str | None
    ) -> LocalAnswer | Send | Review:
        """Send the reporter's report, ask it once to repair one, or send the draft.

        Args:
            review: The reporter turn.
            reply: The reporter's report call, or `None` when the turn failed.
            error: Why the turn failed, if it did.

        Returns:
            The report to send, the reporter's repair turn, or the ledger's
            answer when the runtime already answered this very report.
        """
        draft = review.arguments
        problem = error
        report = None
        if reply is not None:
            report, problem = self._checked_report(draft, reply)
        if report is not None:
            if (known := self._ledger_answer(FINISH_TOOL, report)) is not None:
                return known
            self.trace.report_written(draft, report, None)
            self._rewritten, self.report_fallback = report != draft, None
            return Send(report)
        if reply is not None and not review.repaired:
            logger.warning("The reporter's report cannot be sent ({}); asking once more.", problem)
            messages = [
                *review.messages,
                {
                    "role": "assistant",
                    "content": render_json({"tool": FINISH_TOOL, **reply.arguments}),
                },
                {"role": "user", "content": REPORT_REPAIR.format(problem=problem)},
            ]
            return Review(
                review.role, draft, messages, review.response_format, review.model, repaired=True
            )
        logger.warning("Sending the investigation's own report: {}", problem)
        self.trace.report_written(draft, None, problem)
        self._rewritten, self.report_fallback = False, problem
        return Send(draft)

    def _checked_report(
        self, draft: dict[str, Any], reply: ToolCall
    ) -> tuple[dict[str, Any] | None, str | None]:
        """Check a reporter's report as any report is checked, and against the draft's verdict.

        A report the runtime already answered passes here; the ledger answers it.

        Returns:
            The prepared report and `None`, or `None` and what is wrong with it.
        """
        if reply.tool != FINISH_TOOL:
            return None, f"the reply must call {FINISH_TOOL}, not {reply.tool!r}."
        try:
            report = self.catalog.prepare(FINISH_TOOL, reply.arguments)
        except ValueError as exc:
            return None, str(exc)
        if report_verdict(report) != report_verdict(draft):
            return None, f"the verdict must stay {report_verdict(draft)!r}."
        if (empty := report_problem(report)) is not None:
            return None, empty
        decision = self._ledger.check(FINISH_TOOL, report)
        if decision.reason == "rejected" and decision.feedback is not None:
            return None, decision.feedback["message"].removeprefix("Not sent to the runtime: ")
        return report, None

    def _challenger_request(self, tools: list[str]) -> list[dict[str, Any]]:
        """Build the challenger's request: the alert, the tools and the evidence, once."""
        evidence: dict[str, Any] = {
            "alert": self.alert,
            "available_tools": self.catalog.specs_of(tools),
            "evidence": evidence_digest(self._ledger),
        }
        if open_items := self._ledger.summary():
            evidence["still_open"] = open_items
        return [
            {"role": "system", "content": CHALLENGER_PROMPT},
            {"role": "user", "content": render_json(evidence)},
        ]

    def _challenge(
        self, arguments: dict[str, Any], challenge: Challenge | None, error: str | None
    ) -> LocalAnswer:
        """Return a benign report to the model with the challenger's case.

        Checks that call a tool outside the catalog, break its schema or name
        an id the runtime never returned are dropped. Without a usable check,
        the model gets the general question of ADR 0020 instead.

        Args:
            arguments: The benign report.
            challenge: The challenger's reply, or `None` when it failed.
            error: Why the challenger failed, if it did.

        Returns:
            The local answer to the report.
        """
        checks = self._usable_checks(challenge) if challenge is not None else []
        fallback = error
        if checks:
            self._challenge_record = {"hypothesis": challenge.hypothesis, "checks": checks}
            feedback: dict[str, Any] = {
                "status": "error",
                "message": f"Not sent to the runtime: {CHALLENGE_ANSWER}",
                "challenge": self._challenge_record,
            }
        else:
            fallback = fallback or "no usable check"
            feedback = {
                "status": "error",
                "message": f"Not sent to the runtime: {BENIGN_CHALLENGE}",
            }
            logger.warning("The challenger gave nothing usable ({}); asking in general.", fallback)
        if open_items := self._ledger.summary():
            feedback["still_open"] = open_items
        logger.warning("Challenged a benign verdict once before sending it.")
        self.trace.local_answer(
            "benign_challenged", FINISH_TOOL, arguments, feedback, fallback=fallback
        )
        return LocalAnswer(feedback)

    def _usable_checks(self, challenge: Challenge) -> list[dict[str, Any]]:
        """Keep the checks the model could make: real tools, valid arguments, known ids, once."""
        tools = self.catalog.runtime_tools()
        checks: list[dict[str, Any]] = []
        for check in challenge.checks:
            tool = check.call.tool
            if tool not in tools:
                continue
            try:
                arguments = self.catalog.prepare(tool, check.call.arguments)
            except ValueError:
                continue
            decision = self._ledger.check(tool, arguments)
            if decision.reason == "rejected":
                continue
            call = {"tool": tool, **arguments}
            if any(item["call"] == call for item in checks):
                continue
            item: dict[str, Any] = {"call": call, "refuted_if": check.refuted_if}
            if decision.reason == "cached":
                item["already_made"] = True
            checks.append(item)
        return checks

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
        if tool == FINISH_TOOL and self._rewritten:
            # The model's history shows its own draft; the answer is about this report.
            feedback["sent_report"] = arguments
            feedback["note"] = "The reporter rewrote your report; this answer is about sent_report."
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
