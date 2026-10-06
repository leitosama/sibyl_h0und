"""What the runtime answered to one tool call, decoded once.

The agent decodes a live response and replay decodes a recorded one with the
same code, so both see the same evidence.
"""

import json
from dataclasses import dataclass
from typing import Any


def decode_json(value: Any) -> Any:
    """Parse a JSON-encoded string so the LLM sees it without escaping."""
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


@dataclass(frozen=True)
class ToolOutcome:
    """The runtime's answer to one tool call.

    The step reward is deliberately absent: it never reaches agent logic or the
    model (ADR 0006).

    Attributes:
        status: Tool status reported by the runtime.
        result: Decoded `last_tool_result`.
        error: Error reported by the runtime, if any.
        terminal: Whether the call ended the task.
    """

    status: str
    result: Any
    error: Any = None
    terminal: bool = False

    @classmethod
    def from_wire(
        cls, *, info: dict[str, Any], observation: dict[str, Any], terminal: bool
    ) -> "ToolOutcome":
        """Decode the `info` and `observation` of a runtime tool response."""
        return cls(
            status=info.get("tool_status", "unknown"),
            result=decode_json(observation.get("last_tool_result")),
            error=info.get("error"),
            terminal=terminal,
        )

    @property
    def failed(self) -> bool:
        """Whether the runtime reported an error."""
        return self.error is not None

    def evidence(self) -> dict[str, Any]:
        """Reduce the answer to the new evidence it carries.

        The alert and the tool catalog repeat in every observation and are
        already in the first message.

        Returns:
            Tool status, the complete tool result and the error, if any.
        """
        evidence = {"status": self.status, "result": self.result}
        if self.failed:
            evidence["error"] = self.error
        return evidence
