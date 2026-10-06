import pytest

from sibyl_h0und.budget import (
    MAX_FINISH_TURNS,
    MAX_LOCAL_STREAK,
    RUNTIME_CALL_LIMIT,
    CallBudget,
    CallBudgetExhaustedError,
)


def test_ceiling_counts_runtime_calls_not_turns() -> None:
    """Local answers never use up the ceiling, and the last call is left for the report."""
    budget = CallBudget(5)
    for _ in range(3):
        assert budget.start_turn() is False
        budget.record_local_answer()
        assert budget.start_turn() is False
        budget.record_runtime_call()
    assert budget.start_turn() is False
    budget.record_runtime_call()

    assert budget.start_turn() is True
    assert budget.runtime_calls == 4


def test_a_stuck_model_must_finish_and_then_gives_up() -> None:
    """Turns without new evidence end in a report, and a report that never comes ends the task."""
    budget = CallBudget()
    for _ in range(MAX_LOCAL_STREAK):
        assert budget.start_turn() is False
        budget.record_local_answer()

    for _ in range(MAX_FINISH_TURNS):
        assert budget.start_turn() is True
        # A rejected report resets the streak, but the model still has to finish.
        budget.record_runtime_call()
    with pytest.raises(CallBudgetExhaustedError):
        budget.start_turn()


def test_finish_retries_stop_before_the_runtime_limit() -> None:
    """Retried reports never reach the runtime's own call limit."""
    budget = CallBudget(RUNTIME_CALL_LIMIT - 1)
    budget.runtime_calls = RUNTIME_CALL_LIMIT - 2
    assert budget.start_turn() is True
    budget.record_runtime_call()

    with pytest.raises(CallBudgetExhaustedError):
        budget.start_turn()


@pytest.mark.parametrize("ceiling", [1, RUNTIME_CALL_LIMIT])
def test_ceiling_must_leave_room_below_the_runtime_limit(ceiling: int) -> None:
    """A ceiling of 100 lets the runtime end the task before the report."""
    with pytest.raises(ValueError):
        CallBudget(ceiling)
