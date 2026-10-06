"""Safety ceiling on runtime calls that always leaves room for the report.

The runtime ends a task after 100 tool calls, and a task that ends without
`finish_investigation` scores nothing. The ceiling counts runtime calls only:
turns that the catalog check or GraphLedger answer locally do not use it up.
It is a safety net, not an economy budget (ADR 0004, 0015).
"""

from dataclasses import dataclass

# The runtime ends a task after this many tool calls.
RUNTIME_CALL_LIMIT = 100
# Default ceiling, counting the `finish_investigation` call.
DEFAULT_MAX_RUNTIME_CALLS = 95
# Locally answered turns in a row after which the model must finish. This is
# a stall guard, not an economy limit: it spends no runtime calls and fires
# only when the model loops on calls that bring no new evidence (ADR 0009).
MAX_LOCAL_STREAK = 20
# Turns the model gets to produce an accepted report once it must finish.
MAX_FINISH_TURNS = 5


class CallBudgetExhaustedError(RuntimeError):
    """Raised when the model fails to submit a report within the safety limits."""


@dataclass
class CallBudget:
    """Runtime calls of one task and whether only the report remains.

    Attributes:
        max_runtime_calls: Ceiling on runtime calls, `finish_investigation` included.
        runtime_calls: Calls sent to the runtime so far.
        local_streak: Locally answered turns since the last runtime call.
        finish_reason: Why only `finish_investigation` remains, or `None`.
        finish_turns: Turns started since only `finish_investigation` remains.
    """

    max_runtime_calls: int = DEFAULT_MAX_RUNTIME_CALLS
    runtime_calls: int = 0
    local_streak: int = 0
    finish_reason: str | None = None
    finish_turns: int = 0

    def __post_init__(self) -> None:
        """Reject a ceiling that leaves no room for an investigation call or the report."""
        if not 2 <= self.max_runtime_calls < RUNTIME_CALL_LIMIT:
            raise ValueError(
                f"max_runtime_calls must be between 2 and {RUNTIME_CALL_LIMIT - 1}, "
                f"got {self.max_runtime_calls}"
            )

    @property
    def finish_only(self) -> bool:
        """Whether the model may call only `finish_investigation`."""
        return self.finish_reason is not None

    def start_turn(self) -> bool:
        """Account for one model turn and decide which tools it may call.

        Returns:
            Whether the turn may call only `finish_investigation`. Once set,
            this stays for the rest of the task.

        Raises:
            CallBudgetExhaustedError: If the model had its finish turns, or
                the runtime's own limit is used up.
        """
        if self.finish_reason is None:
            if self.runtime_calls >= self.max_runtime_calls - 1:
                self.finish_reason = (
                    f"{self.runtime_calls} runtime calls made, the safety limit is "
                    f"{self.max_runtime_calls}"
                )
            elif self.local_streak >= MAX_LOCAL_STREAK:
                self.finish_reason = (
                    f"{self.local_streak} calls in a row were answered locally without new evidence"
                )
        if self.finish_reason is None:
            return False
        self.finish_turns += 1
        # The runtime accepts its 100th call, so a report may still be sent as that call.
        if self.finish_turns > MAX_FINISH_TURNS or self.runtime_calls >= RUNTIME_CALL_LIMIT:
            raise CallBudgetExhaustedError(
                f"No accepted finish_investigation after {self.runtime_calls} runtime calls "
                f"and {self.finish_turns - 1} finish-only turns ({self.finish_reason})."
            )
        return True

    def record_runtime_call(self) -> None:
        """Count a call that reached the runtime."""
        self.runtime_calls += 1
        self.local_streak = 0

    def record_local_answer(self) -> None:
        """Count a turn answered without the runtime."""
        self.local_streak += 1
