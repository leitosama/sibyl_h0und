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
from sibyl_h0und.models import NextStep
from sibyl_h0und.trace import TaskTrace

# A catalog entry with a marker that shows where the catalog reaches the LLM.
TOOL_CATALOG = json.dumps(
    [
        {"name": "get_entity", "description": "CATALOG-MARKER", "parameters": {"type": "object"}},
        {"name": "finish_investigation", "parameters": {"type": "object"}},
    ]
)


class FakeStepClient:
    """Deterministic structured steps used by the agent unit test."""

    def __init__(self, steps: list[NextStep]) -> None:
        """Store steps in their expected request order.

        Args:
            steps: Prepared LLM steps.
        """
        self.steps = list(steps)
        self.requests: list[list[dict[str, Any]]] = []
        self.formats: list[dict[str, Any]] = []

    async def next_step(
        self,
        messages: list[dict[str, Any]],
        *,
        response_format: dict[str, Any],
        trace: TaskTrace | None = None,
    ) -> NextStep:
        """Record one conversation and return its next prepared step.

        Args:
            messages: Current LLM history.
            response_format: Step schema of this turn.
            trace: Ignored task trace.

        Returns:
            Next prepared structured step.
        """
        self.requests.append([dict(message) for message in messages])
        self.formats.append(response_format)
        return self.steps.pop(0)


class FakeSession:
    """In-memory remote session used by the structured agent test."""

    def __init__(self) -> None:
        """Create a task with a JSON-encoded remote tool catalog."""
        self.task = PublicTask(
            task_id="task-1",
            observation={
                "last_tool_result": '""',
                "available_tools": TOOL_CATALOG,
                "alert_text": json.dumps({"trigger_entities": [{"id": "entity-1"}]}),
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
        # The runtime repeats the alert and the catalog in every observation
        # and puts the new evidence only in `last_tool_result`.
        result = self.entity_result(arguments) if not terminal else "Report accepted"
        return ToolCallResult(
            task_id="task-1",
            tool_name=tool_name,
            observation={**self.task.observation, "last_tool_result": json.dumps(result)},
            reward=1.0,
            terminated=terminal,
            info={"tool_status": "ok", "tool_name": tool_name},
            task_result=task_result,
        )

    @staticmethod
    def entity_result(arguments: dict[str, Any]) -> dict[str, Any]:
        """Return the entity a `get_entity` call asked for."""
        return {"id": arguments.get("entity_id"), "pid": 42}

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


def make_step(tool: str, **arguments: Any) -> NextStep:
    """Build a step that calls one tool."""
    return NextStep.model_validate(
        {
            "current_state": "Reading the graph.",
            "plan_remaining_steps_brief": [f"Call {tool}."],
            "task_completed": tool == "finish_investigation",
            "function": {"tool": tool, **arguments},
        }
    )


def get_entity_step(entity_id: str, reasoning: str = "Inspect the entity.") -> NextStep:
    """Build a step that reads one entity."""
    return make_step("get_entity", entity_id=entity_id, reasoning=reasoning)


MALICIOUS_SUBMISSION = {
    "verdict": "malicious",
    "ir_artifacts": [{"entity_id": "entity-1", "kind": "host_to_isolate"}],
    "reasoning": "The alert process is part of a suspicious process chain.",
}


def investigation_steps() -> list[NextStep]:
    """Build one evidence step followed by the terminal verdict."""
    return [
        get_entity_step("entity-1", reasoning="Inspect the alert entity."),
        make_step("finish_investigation", submission=MALICIOUS_SUBMISSION),
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
    assert session.calls[1][1] == {"submission": MALICIOUS_SUBMISSION}
    tool_message = llm.requests[1][-1]
    assert tool_message["role"] == "tool"
    assert json.loads(tool_message["content"]) == {
        "status": "ok",
        "result": {"id": "entity-1", "pid": 42},
    }
    request_text = json.dumps(llm.requests[1])
    assert request_text.count("CATALOG-MARKER") == 1
    assert "entity-1" in str(llm.requests[0][1]["content"])

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
    assert json.loads(events[2]["payload"]["response"]["observation"]["last_tool_result"]) == {
        "id": "entity-1",
        "pid": 42,
    }
    assert events[-1]["completion_reason"] == "terminated"
    assert events[-1]["runtime_calls"] == 2


def test_trace_write_failure_does_not_break_the_run(tmp_path: Path) -> None:
    """An unwritable trace root must not stop an arena run."""
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("", encoding="utf-8")
    agent = SimpleSGRAgent(FakeStepClient(investigation_steps()), trace_dir=blocker)

    result = asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(FakeSession()))))

    assert result.successful_tasks == 1


def benign_finish_step(entity_id: str, field: str) -> NextStep:
    """Build a benign verdict that cites one entity property."""
    return make_step(
        "finish_investigation",
        submission={
            "verdict": "benign",
            "legitimacy_evidence": [
                {"anchor": "entity", "entity_id": entity_id, "property_fields": [field]}
            ],
            "reasoning": "Signed vendor binary.",
        },
    )


def test_ledger_answers_invented_ids_and_repeats_without_the_runtime(tmp_path: Path) -> None:
    """Invented ids, repeated calls and an invalid finish must not cost runtime calls."""
    llm = FakeStepClient(
        [
            get_entity_step("entity-invented"),
            get_entity_step("entity-1"),
            get_entity_step("entity-1", reasoning="Look again."),
            benign_finish_step("entity-invented", "pid"),
            benign_finish_step("entity-1", "digitial_signature"),
            benign_finish_step("entity-1", "pid"),
        ]
    )
    session = FakeSession()
    agent = SimpleSGRAgent(llm, trace_dir=tmp_path)

    result = asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))

    assert result.successful_tasks == 1
    assert [(name, arguments.get("entity_id")) for name, arguments in session.calls] == [
        ("get_entity", "entity-1"),
        ("finish_investigation", None),
    ]
    feedback = [json.loads(request[-1]["content"]) for request in llm.requests[1:]]
    assert feedback[0]["status"] == "error"
    assert "entity-invented" in feedback[0]["message"]
    assert feedback[2]["result"] == {"id": "entity-1", "pid": 42}
    assert "note" in feedback[2]
    assert "entity-invented" in feedback[3]["message"]
    assert "digitial_signature" in feedback[4]["message"]

    (run_dir,) = tmp_path.iterdir()
    events = read_events(run_dir / "001_task-1.trace.jsonl")
    assert [event["kind"] for event in events if event["kind"].startswith("tool_")] == [
        "tool_rejected",
        "tool_call",
        "tool_cached",
        "tool_rejected",
        "tool_rejected",
        "tool_call",
    ]
    assert events[-1]["runtime_calls"] == 2


class DroppedFileSession(FakeSession):
    """Session whose only entity is a script dropped into a public directory."""

    @staticmethod
    def entity_result(arguments: dict[str, Any]) -> dict[str, Any]:
        """Return a high-scoring file entity."""
        return {
            "id": arguments["entity_id"],
            "type": "windows_file",
            "properties": {"path": "C:\\Windows\\System32\\run.ps1"},
        }


def test_flags_reach_the_model_and_the_trace(tmp_path: Path) -> None:
    """A finding reaches the model next to the evidence it explains and is traced.

    What a rule rates and how it words the reason belong to test_flags; here
    only the delivery is checked, so retuning a rule does not break this test.
    """
    llm = FakeStepClient([get_entity_step("entity-1"), investigation_steps()[1]])
    agent = SimpleSGRAgent(llm, trace_dir=tmp_path)

    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(DroppedFileSession()))))

    feedback = json.loads(llm.requests[1][-1]["content"])
    assert feedback["result"]["id"] == "entity-1"
    (line,) = feedback["flags"]
    assert (line["id"], line["type"]) == ("entity-1", "windows_file")
    assert line["why"]
    (run_dir,) = tmp_path.iterdir()
    events = read_events(run_dir / "001_task-1.trace.jsonl")
    (flags_event,) = [event for event in events if event["kind"] == "flags"]
    assert {finding["node_id"] for finding in flags_event["payload"]["findings"]} == {"entity-1"}


def test_agent_reserves_the_last_runtime_call_for_the_report(tmp_path: Path) -> None:
    """At the ceiling the model is told to finish, and other tools no longer reach the runtime."""
    llm = FakeStepClient(
        [
            get_entity_step("entity-invented"),
            get_entity_step("entity-1"),
            get_entity_step("entity-2"),
            investigation_steps()[1],
        ]
    )
    session = FakeSession()
    agent = SimpleSGRAgent(llm, max_runtime_calls=2, trace_dir=tmp_path)

    result = asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))

    assert result.successful_tasks == 1
    # The locally answered first turn did not use up the ceiling of two calls.
    assert [name for name, _ in session.calls] == ["get_entity", "finish_investigation"]
    notice = llm.requests[2][-1]
    assert notice["role"] == "user"
    assert "Only finish_investigation remains" in notice["content"]
    finish_only = llm.formats[2]["json_schema"]["schema"]["properties"]["function"]["anyOf"]
    assert [option["properties"]["tool"]["enum"] for option in finish_only] == [
        ["finish_investigation"]
    ]
    assert "cannot be called now" in json.loads(llm.requests[3][-1]["content"])["message"]
    (run_dir,) = tmp_path.iterdir()
    kinds = [event["kind"] for event in read_events(run_dir / "001_task-1.trace.jsonl")]
    assert kinds.count("finish_only") == 1
