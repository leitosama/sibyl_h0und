import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

from bluesec1_client import (
    PublicTask,
    RemoteBenchmarkClient,
    RemoteBenchmarkSession,
    TaskResult,
    ToolCallResult,
)
from sibyl_h0und.agent import SimpleSGRAgent
from sibyl_h0und.models import (
    FinishInvestigationArtifact,
    FinishInvestigationRequest,
    GetEntityRequest,
    MaliciousFinishInvestigationSubmission,
    NextStep,
)
from sibyl_h0und.trace import TaskTrace


class FakeStepClient:
    """Deterministic structured steps used by the agent unit test."""

    def __init__(self, steps: list[NextStep]) -> None:
        """Store steps in their expected request order.

        Args:
            steps: Prepared LLM steps.
        """
        self.steps = list(steps)
        self.requests: list[list[dict[str, Any]]] = []

    async def next_step(
        self,
        messages: list[dict[str, Any]],
        *,
        trace: TaskTrace | None = None,
    ) -> NextStep:
        """Record one conversation and return its next prepared step.

        Args:
            messages: Current LLM history.
            trace: Ignored task trace.

        Returns:
            Next prepared structured step.
        """
        self.requests.append([dict(message) for message in messages])
        return self.steps.pop(0)


class FakeSession:
    """In-memory remote session used by the structured agent test."""

    def __init__(self) -> None:
        """Create a task with a JSON-encoded remote tool catalog."""
        self.task = PublicTask(
            task_id="task-1",
            observation={
                "alert_text": {"trigger_entities": []},
                "available_tools": json.dumps(
                    [
                        {"name": "get_entity", "parameters": {"type": "object"}},
                        {"name": "finish_investigation", "parameters": {"type": "object"}},
                    ]
                ),
            },
        )
        self.calls: list[tuple[str, dict[str, Any]]] = []

    @property
    def task_id(self) -> str:
        """Return the public task identifier.

        Returns:
            Task identifier.
        """
        return self.task.task_id

    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> ToolCallResult:
        """Record one call and terminate on the finishing tool.

        Args:
            tool_name: Invoked tool name.
            arguments: Invoked tool arguments.

        Returns:
            Fake server response.
        """
        self.calls.append((tool_name, arguments))
        terminal = tool_name == "finish_investigation"
        task_result = None
        if terminal:
            task_result = TaskResult(
                task_id="task-1",
                completion_reason="terminated",
            )
        return ToolCallResult(
            task_id="task-1",
            tool_name=tool_name,
            reward=1.0,
            terminated=terminal,
            info={
                "tool_status": "ok",
                "tool_result": (
                    [{"entity_id": "process-1", "pid": 42}] if not terminal else "Report accepted"
                ),
            },
            task_result=task_result,
        )

    async def abort_task(self, *, error_message: str | None = None) -> TaskResult:
        """Reject unexpected aborts.

        Args:
            error_message: Agent failure diagnostic.

        Raises:
            AssertionError: Always, because this task must finish normally.
        """
        raise AssertionError(f"Unexpected abort: {error_message}")


class FakeClient:
    """Single-task stand-in for an open RemoteBenchmarkClient."""

    def __init__(self, session: FakeSession) -> None:
        """Store the only session returned before queue exhaustion.

        Args:
            session: Prepared task session.
        """
        self.run = SimpleNamespace(run_id="run-1")
        self.session: FakeSession | None = session

    async def start_task(self) -> RemoteBenchmarkSession | None:
        """Lease the prepared session once.

        Returns:
            Prepared session or `None` after it was leased.
        """
        if self.session is None:
            return None
        session = self.session
        self.session = None
        return cast(RemoteBenchmarkSession, session)


def investigation_steps() -> list[NextStep]:
    """Build one evidence step followed by the terminal verdict."""
    return [
        NextStep(
            current_state="Alert identifies process 42 on host-1.",
            plan_remaining_steps_brief=["Inspect its process ancestry and descendants."],
            task_completed=False,
            function=GetEntityRequest(
                tool="get_entity",
                entity_id="entity-1",
                reasoning="Inspect the alert entity.",
            ),
        ),
        NextStep(
            current_state="The suspicious process is confirmed on host-1.",
            plan_remaining_steps_brief=["Submit the evidence-backed malicious verdict."],
            task_completed=True,
            function=FinishInvestigationRequest(
                tool="finish_investigation",
                submission=MaliciousFinishInvestigationSubmission(
                    verdict="malicious",
                    ir_artifacts=[
                        FinishInvestigationArtifact(
                            entity_id="host-1",
                            kind="host_to_isolate",
                        )
                    ],
                    reasoning="The alert process is part of a suspicious process chain.",
                ),
            ),
        ),
    ]


def read_events(path: Path) -> list[dict[str, Any]]:
    """Parse every line of a JSONL trace."""
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_agent_executes_fresh_structured_task_via_remote_session(tmp_path: Path) -> None:
    """Tool evidence should feed the next step, and the task should leave a trace."""
    llm = FakeStepClient(investigation_steps())
    session = FakeSession()
    agent = SimpleSGRAgent(llm, trace_dir=tmp_path, trace_metadata={"model": "m-1"})

    result = asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))

    assert result.run_id == "run-1"
    assert result.successful_tasks == 1
    assert result.failed_tasks == 0
    assert [name for name, _ in session.calls] == [
        "get_entity",
        "finish_investigation",
    ]
    assert session.calls[0][1] == {
        "entity_id": "entity-1",
        "reasoning": "Inspect the alert entity.",
    }
    assert session.calls[1][1] == {
        "submission": {
            "verdict": "malicious",
            "ir_artifacts": [{"entity_id": "host-1", "kind": "host_to_isolate"}],
            "reasoning": "The alert process is part of a suspicious process chain.",
        }
    }
    assert any(
        message.get("role") == "tool" and "process-1" in str(message.get("content"))
        for message in llm.requests[1]
    )

    (run_dir,) = tmp_path.iterdir()
    events = read_events(run_dir / "001_task-1.trace.jsonl")
    assert [event["kind"] for event in events] == [
        "task_start",
        "step",
        "tool_call",
        "step",
        "tool_call",
        "task_end",
    ]
    assert events[0]["payload"]["run"] == {"model": "m-1"}
    assert "available_tools" in events[0]["payload"]["task"]["observation"]
    assert events[2]["tool"] == "get_entity"
    assert events[2]["payload"]["response"]["info"]["tool_result"][0]["pid"] == 42
    assert events[-1]["completion_reason"] == "terminated"
    assert events[-1]["runtime_calls"] == 2


def test_trace_write_failure_does_not_break_the_run(tmp_path: Path) -> None:
    """An unwritable trace root must not stop an arena run."""
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("", encoding="utf-8")
    agent = SimpleSGRAgent(FakeStepClient(investigation_steps()), trace_dir=blocker)

    result = asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(FakeSession()))))

    assert result.successful_tasks == 1
