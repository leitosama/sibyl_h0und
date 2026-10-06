"""Everything one task knows about its investigation, behind two operations.

The agent loop asks `before_call` what to do with the model's call and gives
the runtime's answer to `after_call`. The tool catalog, GraphLedger,
FlagBoard, the `still_open` and `flags` merge, the wording of local answers and
the trace events of those decisions all live here. Replay feeds recorded
outcomes through `after_call`, so it sees what the model would have seen.
"""

from dataclasses import asdict, dataclass
from typing import Any

from loguru import logger

from sibyl_h0und.catalog import FINISH_TOOL, ToolCatalog
from sibyl_h0und.flags import Finding, FlagBoard, flag_lines, rank_flags
from sibyl_h0und.ledger import GraphLedger
from sibyl_h0und.llm import render_json
from sibyl_h0und.outcome import ToolOutcome, decode_json
from sibyl_h0und.rules import DEFAULT_RULES
from sibyl_h0und.trace import TaskTrace

# Observation fields that repeat in every response and are not part of the alert.
NON_ALERT_FIELDS = frozenset({"available_tools", "last_tool_result"})


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
        shown: Findings that reached the model after the per-result limit.
    """

    feedback: dict[str, Any]
    shown: tuple[Finding, ...] = ()


class Investigation:
    """Per-task state and rules that turn tool calls and responses into messages."""

    def __init__(self, observation: dict[str, Any], trace: TaskTrace | None = None) -> None:
        """Build the catalog, ledger and flag board of one task.

        Args:
            observation: Public task observation with a JSON-encoded `available_tools`.
            trace: Task trace that receives the events of local decisions and flags.

        Raises:
            ValueError: If the observation has an invalid tool catalog.
        """
        self.catalog = ToolCatalog.from_observation(observation)
        self.trace = trace or TaskTrace(None)
        self.alert = {
            key: decode_json(value)
            for key, value in observation.items()
            if key not in NON_ALERT_FIELDS
        }
        self._ledger = GraphLedger()
        self._ledger.observe_alert(self.alert)
        self._board = FlagBoard(DEFAULT_RULES)

    @property
    def findings(self) -> list[Finding]:
        """The latest finding of each rule about each node, so far."""
        return list(self._board.findings.values())

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
        break the tool's schema, an id the runtime never returned and a repeated
        call are answered locally.

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
        decision = self._ledger.check(tool, arguments)
        if decision.feedback is not None:
            logger.warning("Answered {} locally: {}.", tool, decision.reason)
            self.trace.local_answer(f"tool_{decision.reason}", tool, arguments, decision.feedback)
            return LocalAnswer(decision.feedback)
        return Send(arguments)

    def after_call(self, tool: str, arguments: dict[str, Any], outcome: ToolOutcome) -> Reply:
        """Learn from a runtime answer and build the message the model sees.

        The message carries the evidence, then `still_open` for what is known
        but not yet visited and `flags` for fresh findings. A failed call is
        not judged. The ledger caches the evidence alone, so a repeated call
        gets no flags twice.

        Args:
            tool: Tool that was called.
            arguments: Arguments sent to the runtime, as `before_call` returned them.
            outcome: The runtime's answer to a non-terminal call.

        Returns:
            The tool message content and the findings that reached the model.
        """
        self._ledger.record(tool, arguments, outcome)
        feedback = outcome.evidence()
        if open_items := self._ledger.summary():
            feedback["still_open"] = open_items
        if outcome.failed:
            return Reply(feedback)
        fresh = self._board.observe(outcome.result)
        if fresh:
            self.trace.flags(tool, [asdict(finding) for finding in fresh])
        groups, omitted = rank_flags(fresh)
        if lines := flag_lines(groups, omitted):
            feedback["flags"] = lines
        return Reply(feedback, tuple(finding for group in groups for finding in group))
