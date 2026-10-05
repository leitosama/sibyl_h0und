import asyncio
import json
from pathlib import Path
from typing import Any, cast

from openai import AsyncOpenAI
from test_agent import FakeClient, FakeSession, FakeStepClient
from test_llm import FakeOpenAI, valid_process_step

from bluesec1_client import RemoteBenchmarkClient
from sibyl_h0und.agent import SimpleSGRAgent
from sibyl_h0und.llm import OpenAIStructuredStepClient
from sibyl_h0und.models import (
    FinishInvestigationArtifact,
    FinishInvestigationRequest,
    MaliciousFinishInvestigationSubmission,
    NextStep,
)
from sibyl_h0und.trace import TaskTrace


def finish_step() -> NextStep:
    """Build one valid terminal step."""
    return NextStep(
        current_state="Confirmed.",
        plan_remaining_steps_brief=["Submit."],
        task_completed=True,
        function=FinishInvestigationRequest(
            tool="finish_investigation",
            submission=MaliciousFinishInvestigationSubmission(
                verdict="malicious",
                ir_artifacts=[
                    FinishInvestigationArtifact(entity_id="host-1", kind="host_to_isolate")
                ],
                reasoning="Suspicious chain.",
            ),
        ),
    )


def read_events(path: Path) -> list[dict[str, Any]]:
    """Parse every JSONL line of a trace file."""
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_agent_writes_one_trace_per_task(tmp_path: Path) -> None:
    """A run should leave a task trace with run settings and raw runtime responses."""
    llm = FakeStepClient([valid_process_step(), finish_step()])
    agent = SimpleSGRAgent(llm, trace_dir=tmp_path, trace_metadata={"model": "m-1"})

    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(FakeSession()))))

    (run_dir,) = tmp_path.iterdir()
    assert run_dir.name.endswith("_run-1")
    events = read_events(run_dir / "001_task-1.trace.jsonl")
    assert [event["kind"] for event in events] == [
        "task_start",
        "step",
        "tool_call",
        "step",
        "tool_call",
        "task_end",
    ]
    assert [event["seq"] for event in events] == list(range(1, 7))
    assert all(event["task_id"] == "task-1" for event in events)
    assert events[0]["payload"]["run"] == {"model": "m-1"}
    assert "available_tools" in events[0]["payload"]["task"]["observation"]

    first_call = events[2]
    assert first_call["step"] == 1
    assert first_call["tool"] == "get_entity"
    assert first_call["status"] == "ok"
    assert first_call["payload"]["arguments"]["entity_id"] == "entity-1"
    assert first_call["payload"]["response"]["info"]["tool_result"][0]["pid"] == 42

    task_end = events[-1]
    assert task_end["completion_reason"] == "terminated"
    assert task_end["agent_steps"] == 2
    assert task_end["runtime_calls"] == 2
    assert task_end["error"] is None


def test_llm_client_traces_every_attempt(tmp_path: Path) -> None:
    """Rejected replies should be traced with their raw content."""
    fake_openai = FakeOpenAI(["not-json", valid_process_step().model_dump_json()])
    client = OpenAIStructuredStepClient(
        base_url="https://llm.example/v1",
        api_key="secret",
        model="test-model",
        timeout_seconds=10.0,
        max_completion_tokens=1000,
        max_retries=3,
        client=cast(AsyncOpenAI, fake_openai),
    )
    path = tmp_path / "task.trace.jsonl"
    trace = TaskTrace(path, run_id="run-1", task_id="task-1")

    asyncio.run(client.next_step([{"role": "system", "content": "Investigate."}], trace=trace))

    first, second = read_events(path)
    assert first["kind"] == second["kind"] == "llm_call"
    assert first["attempt"] == 1
    assert first["tokens"] == 17
    assert first["payload"]["raw_content"] == "not-json"
    assert second["payload"]["messages"][-1]["role"] == "user"
    assert "secret" not in path.read_text(encoding="utf-8")
    assert trace.llm_calls == 2
    assert trace.llm_tokens == 34


def test_trace_write_failure_does_not_break_the_run(tmp_path: Path) -> None:
    """An unwritable trace root should not break the run."""
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("", encoding="utf-8")
    llm = FakeStepClient([valid_process_step(), finish_step()])
    agent = SimpleSGRAgent(llm, trace_dir=blocker)

    result = asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(FakeSession()))))

    assert result.successful_tasks == 1
    assert blocker.read_text(encoding="utf-8") == ""
