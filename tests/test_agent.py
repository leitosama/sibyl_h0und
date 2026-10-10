import asyncio
import json
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from bluesec1_client import (
    PublicTask,
    RemoteBenchmarkClient,
    RemoteBenchmarkSession,
    TaskResult,
    ToolCallResult,
)
from sibyl_h0und.agent import SYSTEM_PROMPT, SimpleSGRAgent
from sibyl_h0und.catalog import FINISH_TOOL
from sibyl_h0und.investigation import Send
from sibyl_h0und.llm import NextStepRequestError
from sibyl_h0und.models import PRACTICE_ARGUMENT_MODELS, Challenge, NextStep, ToolCall
from sibyl_h0und.replay import load_tasks
from sibyl_h0und.side_replay import load_cases, side_turn
from sibyl_h0und.trace import TaskTrace
from sibyl_h0und.vocabulary import KNOWLEDGE_TOOL

# A catalog entry with a marker that shows where the catalog reaches the LLM.
TOOL_CATALOG = json.dumps(
    [
        {"name": "get_entity", "description": "CATALOG-MARKER", "parameters": {"type": "object"}},
        {"name": "finish_investigation", "parameters": {"type": "object"}},
    ]
)


class FakeStepClient:
    """Deterministic structured steps used by the agent unit test."""

    def __init__(
        self,
        steps: list[NextStep],
        challenges: tuple[Challenge, ...] = (),
        reports: tuple[ToolCall, ...] = (),
    ) -> None:
        """Store steps and side-turn replies in their expected request order.

        Args:
            steps: Prepared LLM steps.
            challenges: Prepared challenger replies.
            reports: Prepared reporter replies. With no reply left, a side
                turn fails as a provider would.
        """
        self.steps = list(steps)
        self.challenges = list(challenges)
        self.reports = list(reports)
        self.requests: list[list[dict[str, Any]]] = []
        self.side_requests: dict[str, list[list[dict[str, Any]]]] = {}
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

    async def structured(
        self,
        messages: list[dict[str, Any]],
        *,
        response_format: dict[str, Any],
        model: type[Any],
        role: str,
        trace: TaskTrace | None = None,
    ) -> Any:
        """Record one side-turn request and return the next prepared challenger reply.

        Raises:
            NextStepRequestError: When no reply is prepared.
        """
        self.side_requests.setdefault(role, []).append([dict(message) for message in messages])
        replies = self.challenges if role == "challenger" else self.reports
        if not replies:
            raise NextStepRequestError("No valid reply.")
        return replies.pop(0)


class FakeSession:
    """In-memory remote session used by the structured agent test."""

    def __init__(self, entities: tuple[str, ...] = ("entity-1",)) -> None:
        """Create a task with a JSON-encoded remote tool catalog.

        Args:
            entities: Ids of the entities the alert names.
        """
        self.task = PublicTask(
            task_id="task-1",
            observation={
                "last_tool_result": '""',
                "available_tools": TOOL_CATALOG,
                "alert_text": json.dumps({"trigger_entities": [{"id": item} for item in entities]}),
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
    """The alert stage's evidence reaches the first turn, a repeat is free, and all is traced."""
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
    assert session.calls[0][1]["entity_id"] == "entity-1"
    assert session.calls[1][1] == {"submission": MALICIOUS_SUBMISSION}
    # Before the first turn the model already sees the alert stage's call and its evidence.
    stage_call, stage_answer, stage_summary = llm.requests[0][2:]
    assert stage_summary["role"] == "user"
    assert "Before your first turn" in stage_summary["content"]
    assert stage_call["tool_calls"][0]["function"]["name"] == "get_entity"
    assert stage_answer["role"] == "tool"
    assert stage_answer["tool_call_id"] == stage_call["tool_calls"][0]["id"]
    assert json.loads(stage_answer["content"]) == {
        "status": "ok",
        "result": {"id": "entity-1", "pid": 42},
    }
    # The model's own fetch of the same entity is answered from the ledger.
    repeat = json.loads(llm.requests[1][-1]["content"])
    assert repeat["result"] == {"id": "entity-1", "pid": 42}
    assert "note" in repeat
    request_text = json.dumps(llm.requests[1])
    assert request_text.count("CATALOG-MARKER") == 1
    assert "entity-1" in str(llm.requests[0][1]["content"])

    (run_dir,) = tmp_path.iterdir()
    events = read_events(run_dir / "001_task-1.trace.jsonl")
    assert [event["kind"] for event in events] == [
        "task_start",
        "tool_call",
        "step",
        "tool_cached",
        "step",
        "report_written",
        "tool_call",
        "task_end",
    ]
    assert events[0]["payload"]["run"] == {"model": "m-1"}
    assert "available_tools" in events[0]["payload"]["task"]["observation"]
    assert events[1]["tool"] == "get_entity"
    assert [event["alert_stage"] for event in events if event["kind"] == "tool_call"] == [
        True,
        False,
    ]
    assert json.loads(events[1]["payload"]["response"]["observation"]["last_tool_result"]) == {
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
    """Invented ids, invalid arguments, repeats and an invalid finish cost no runtime calls."""
    llm = FakeStepClient(
        [
            get_entity_step("entity-invented"),
            make_step("get_entity", reasoning="No id given."),
            get_entity_step("entity-1"),
            get_entity_step("entity-1", reasoning="Look again."),
            benign_finish_step("entity-invented", "pid"),
            benign_finish_step("entity-1", "digitial_signature"),
            benign_finish_step("entity-1", "pid"),
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
    assert "entity_id" in feedback[1]["message"]
    assert feedback[3]["result"] == {"id": "entity-1", "pid": 42}
    assert "note" in feedback[3]
    assert "entity-invented" in feedback[4]["message"]
    assert "digitial_signature" in feedback[5]["message"]

    (run_dir,) = tmp_path.iterdir()
    events = read_events(run_dir / "001_task-1.trace.jsonl")
    assert [event["kind"] for event in events if event["kind"].startswith("tool_")] == [
        "tool_call",
        "tool_rejected",
        "tool_invalid",
        "tool_cached",
        "tool_cached",
        "tool_rejected",
        "tool_rejected",
        "tool_call",
    ]
    assert events[-1]["runtime_calls"] == 2


def test_knowledge_lookup_is_answered_locally_and_costs_no_runtime_call(tmp_path: Path) -> None:
    """The model sees the lookup tool, calls it, and gets the vocabulary's answer."""
    llm = FakeStepClient(
        [make_step("lookup_knowledge", query="sdelete.exe"), investigation_steps()[1]]
    )
    session = FakeSession()
    agent = SimpleSGRAgent(llm, trace_dir=tmp_path)

    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))

    assert [name for name, _ in session.calls] == ["get_entity", "finish_investigation"]
    opening = json.loads(llm.requests[0][1]["content"])
    assert "lookup_knowledge" in [tool["name"] for tool in opening["available_tools"]]
    offered = llm.formats[0]["json_schema"]["schema"]["properties"]["function"]["anyOf"]
    assert "lookup_knowledge" in [option["properties"]["tool"]["enum"][0] for option in offered]
    answer = json.loads(llm.requests[1][-1]["content"])
    assert answer["query"] == "sdelete.exe"
    assert answer["matches"]
    (run_dir,) = tmp_path.iterdir()
    kinds = [event["kind"] for event in read_events(run_dir / "001_task-1.trace.jsonl")]
    assert "tool_knowledge" in kinds


def test_agent_reserves_the_last_runtime_call_for_the_report(tmp_path: Path) -> None:
    """The alert stage stops at the ceiling, and then only the report reaches the runtime."""
    llm = FakeStepClient([get_entity_step("entity-2"), investigation_steps()[1]])
    session = FakeSession(entities=("entity-1", "entity-2"))
    agent = SimpleSGRAgent(llm, max_runtime_calls=2, trace_dir=tmp_path)

    result = asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))

    assert result.successful_tasks == 1
    # The stage fetched one of the two alert entities and left the last call for the report.
    assert [(name, arguments.get("entity_id")) for name, arguments in session.calls] == [
        ("get_entity", "entity-1"),
        ("finish_investigation", None),
    ]
    notice = llm.requests[0][-1]
    assert notice["role"] == "user"
    assert "Only finish_investigation remains" in notice["content"]
    finish_only = llm.formats[0]["json_schema"]["schema"]["properties"]["function"]["anyOf"]
    assert [option["properties"]["tool"]["enum"] for option in finish_only] == [
        ["finish_investigation"]
    ]
    assert "cannot be called now" in json.loads(llm.requests[1][-1]["content"])["message"]
    (run_dir,) = tmp_path.iterdir()
    kinds = [event["kind"] for event in read_events(run_dir / "001_task-1.trace.jsonl")]
    assert kinds.count("finish_only") == 1


def test_a_trace_the_agent_wrote_is_the_one_replay_reads(tmp_path: Path) -> None:
    """Replay reads the runtime calls the agent traced, not the local lookups."""
    llm = FakeStepClient([make_step("lookup_knowledge", query="x"), *investigation_steps()])
    agent = SimpleSGRAgent(llm, trace_dir=tmp_path / "traces")
    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(FakeSession()))))

    (task,) = load_tasks(tmp_path / "traces", tmp_path / "cache")

    assert [call["tool"] for call in task["calls"]] == ["get_entity", "finish_investigation"]
    assert task["calls"][0]["result"]["id"] == "entity-1"
    assert task["verdict"] == "malicious"


def test_system_prompt_names_the_knowledge_tool_and_the_report() -> None:
    """The model learns about the local vocabulary and the report from the prompt (ADR 0017)."""
    assert f"`{KNOWLEDGE_TOOL}`" in SYSTEM_PROMPT
    assert f"`{FINISH_TOOL}`" in SYSTEM_PROMPT


def test_system_prompt_leaves_tools_to_the_catalog_and_reward_out() -> None:
    """Runtime tools come from `available_tools` (ADR 0003); reward is offline only (ADR 0006)."""
    # Plain words such as "search" may appear as words; compound tool names may not.
    runtime_tools = {tool for tool in PRACTICE_ARGUMENT_MODELS if "_" in tool} - {FINISH_TOOL}

    assert [tool for tool in runtime_tools if re.search(rf"\b{tool}\b", SYSTEM_PROMPT)] == []
    assert "reward" not in SYSTEM_PROMPT.lower()


CHALLENGE = Challenge.model_validate(
    {
        "hypothesis": "entity-1 is a payload started by a remote session.",
        "checks": [
            {
                "look_for": "Who started entity-1.",
                "confirms_if": "A remote logon started it.",
                "refuted_if": "A local interactive logon started it.",
                "source": {
                    "call": {"tool": "get_entity", "entity_id": "entity-1", "reasoning": "Parent."}
                },
            },
            {
                "look_for": "The process id entity-1 ran under.",
                "confirms_if": "It is the payload's.",
                "refuted_if": "It is the updater's.",
                "source": {"seen": {"evidence_id": "entity-1", "property_fields": ["pid"]}},
            },
        ],
    }
)
# The head's answers to the checks, in the state of the report it submits next.
CHECK_ANSWERS = "1: started by a remote logon -> confirms. 2: pid 42 -> confirms."


def challenged_run(
    tmp_path: Path,
    steps: list[NextStep] | None = None,
    max_runtime_calls: int = 95,
    reports: tuple[ToolCall, ...] = (),
) -> tuple[FakeStepClient, FakeSession]:
    """Run a task; by default its benign report is challenged and then turned malicious."""
    llm = FakeStepClient(
        steps
        or [
            get_entity_step("entity-1"),
            benign_finish_step("entity-1", "pid"),
            make_step("finish_investigation", submission=MALICIOUS_SUBMISSION).model_copy(
                update={"current_state": CHECK_ANSWERS}
            ),
        ],
        # The check that repeats a call is asked once more; the same reply then stands.
        (CHALLENGE, CHALLENGE),
        reports,
    )
    session = FakeSession()
    agent = SimpleSGRAgent(llm, max_runtime_calls=max_runtime_calls, trace_dir=tmp_path / "traces")
    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))
    return llm, session


def test_a_benign_report_is_challenged_from_the_evidence_and_costs_no_runtime_call(
    tmp_path: Path,
) -> None:
    """The challenger reads the evidence, not the report; the head gets its case and its
    next report is sent."""
    llm, session = challenged_run(tmp_path)

    assert [name for name, _ in session.calls] == ["get_entity", "finish_investigation"]
    assert session.calls[1][1] == {"submission": MALICIOUS_SUBMISSION}
    side, _ = llm.side_requests["challenger"]
    assert "Signed vendor binary" not in json.dumps(side)
    assert '"pid": 42' in side[-1]["content"]
    answer = json.loads(llm.requests[2][-1]["content"])
    assert answer["challenge"]["hypothesis"] == CHALLENGE.hypothesis
    assert [check["n"] for check in answer["challenge"]["checks"]] == [1, 2]


def test_the_harness_rebuilds_the_challenger_turn_from_a_trace_the_agent_wrote(
    tmp_path: Path,
) -> None:
    """Cut at the first benign report, a saved task asks the challenger what the live
    agent asked it, and gets the same answer."""
    llm, _ = challenged_run(tmp_path)

    (case,) = load_cases(tmp_path / "traces")
    replay_llm = FakeStepClient([], [CHALLENGE, CHALLENGE])
    answer = asyncio.run(side_turn(case, replay_llm))

    assert replay_llm.side_requests["challenger"] == llm.side_requests["challenger"]
    assert answer.feedback == json.loads(llm.requests[2][-1]["content"])
    assert case.final_verdict == "malicious"
    assert case.split in {"dev", "holdout"}


@pytest.mark.parametrize(
    ("steps", "max_runtime_calls"),
    [
        (
            [
                make_step(
                    "finish_investigation",
                    submission={
                        **benign_finish_step("entity-1", "pid").function.arguments["submission"],
                        "reasoning": "",
                    },
                ),
                benign_finish_step("entity-1", "pid"),
            ],
            95,
        ),
        ([get_entity_step("entity-1"), benign_finish_step("entity-1", "pid")], 2),
    ],
    ids=["after-a-refused-placeholder", "at-the-ceiling"],
)
def test_the_harness_skips_a_benign_report_the_live_agent_never_challenged(
    tmp_path: Path, steps: list[NextStep], max_runtime_calls: int
) -> None:
    """A benign report sent as is, after the one refusal or when only the report remained,
    is no challenger case."""
    llm, session = challenged_run(tmp_path, steps, max_runtime_calls)

    assert "challenger" not in llm.side_requests
    assert session.calls[-1][0] == FINISH_TOOL
    assert list(load_cases(tmp_path / "traces")) == []


def test_the_reporters_report_reaches_the_runtime_after_one_repair(tmp_path: Path) -> None:
    """A report the reporter must repair goes back to it once; the repaired one is sent."""
    invented = {**MALICIOUS_SUBMISSION, "ir_artifacts": [{"entity_id": "x-9", "kind": "other"}]}
    repaired = {**MALICIOUS_SUBMISSION, "reasoning": "entity-1 ran the suspicious chain."}
    llm = FakeStepClient(
        investigation_steps(),
        reports=(
            ToolCall.model_validate({"tool": FINISH_TOOL, "submission": invented}),
            ToolCall.model_validate({"tool": FINISH_TOOL, "submission": repaired}),
        ),
    )
    session = FakeSession()
    agent = SimpleSGRAgent(llm, trace_dir=tmp_path)

    asyncio.run(agent.run(cast(RemoteBenchmarkClient, FakeClient(session))))

    assert session.calls[-1] == (FINISH_TOOL, {"submission": repaired})
    first, second = llm.side_requests["reporter"]
    assert "x-9" in second[-1]["content"]
    assert second[: len(first)] == first


def test_the_harness_replays_the_reporter_turn_as_the_agent_asked_it(tmp_path: Path) -> None:
    """Cut at the report that was sent, a saved task gives the reporter the head's draft,
    not the rewrite the runtime got, and asks what the live agent asked, the challenger's
    recorded case and the head's answers to it included."""
    rewrite = {**MALICIOUS_SUBMISSION, "reasoning": "entity-1 ran the suspicious chain."}
    report = ToolCall.model_validate({"tool": FINISH_TOOL, "submission": rewrite})
    llm, session = challenged_run(tmp_path, reports=(report,))

    (case,) = load_cases(tmp_path / "traces", role="reporter")
    replay_llm = FakeStepClient([], reports=(report,))
    answer = asyncio.run(side_turn(case, replay_llm))

    assert session.calls[-1][1] == {"submission": rewrite}
    assert case.review.arguments == {"submission": MALICIOUS_SUBMISSION}
    (live,) = llm.side_requests["reporter"]
    assert json.loads(live[-1]["content"])["challenge"]["answers"] == CHECK_ANSWERS
    assert replay_llm.side_requests["reporter"] == llm.side_requests["reporter"]
    assert answer == Send({"submission": rewrite})
