import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import httpx
import pytest
from openai import (
    APIConnectionError,
    APIError,
    APITimeoutError,
    AsyncOpenAI,
    AuthenticationError,
    BadRequestError,
)

from sibyl_h0und.llm import (
    OpenAIStructuredStepClient,
    parse_next_step_payload,
)
from sibyl_h0und.models import Challenge, NextStep
from sibyl_h0und.trace import TaskTrace, llm_requests


class FakeCompletions:
    """Queue-backed fake for the OpenAI chat completion endpoint."""

    def __init__(self, contents: list[str | Exception]) -> None:
        """Store response content and request audit state."""
        self.contents = list(contents)
        self.requests: list[dict[str, Any]] = []

    async def create(self, **kwargs: Any) -> Any:
        """Return the next queued assistant message or raise the queued error."""
        self.requests.append({**kwargs, "messages": list(kwargs["messages"])})
        content = self.contents.pop(0)
        if isinstance(content, Exception):
            raise content
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=content,
                        refusal=None,
                    )
                )
            ],
            usage=SimpleNamespace(total_tokens=17),
        )


class FakeOpenAI:
    """Minimal object graph required by `OpenAIStructuredStepClient`."""

    def __init__(self, contents: list[str | Exception]) -> None:
        """Expose fake chat completions."""
        self.completions = FakeCompletions(contents)
        self.chat = SimpleNamespace(completions=self.completions)


def valid_process_step() -> NextStep:
    """Build one valid non-terminal graph navigation step."""
    return NextStep.model_validate(
        {
            "current_state": "The trigger entity needs its relations.",
            "plan_remaining_steps_brief": ["Read the trigger entity."],
            "function": {
                "tool": "get_entity",
                "entity_id": "entity-1",
                "reasoning": "Inspect the alert entity.",
            },
        }
    )


# The schema itself is built and tested in test_catalog; the client only forwards it.
STEP_FORMAT = {"type": "json_schema", "json_schema": {"name": "step", "schema": {}}}


def test_structured_client_repairs_malformed_response(tmp_path: Path) -> None:
    """Malformed provider output should be retried outside the main history and traced."""
    valid = valid_process_step().model_dump_json()
    fake_openai = FakeOpenAI(["not-json", valid, valid])
    client = OpenAIStructuredStepClient(
        base_url="https://llm.example/v1",
        api_key="secret",
        model="test-model",
        timeout_seconds=10.0,
        max_completion_tokens=1000,
        max_retries=3,
        client=cast(AsyncOpenAI, fake_openai),
    )
    original_messages = [{"role": "system", "content": "Investigate."}]
    trace = TaskTrace(tmp_path / "task.trace.jsonl")

    step = asyncio.run(
        client.next_step(original_messages, response_format=STEP_FORMAT, trace=trace)
    )

    assert step.function.tool == "get_entity"
    assert len(fake_openai.completions.requests) == 2
    assert fake_openai.completions.requests[0]["response_format"] == STEP_FORMAT
    first_messages = fake_openai.completions.requests[0]["messages"]
    assert "Never use top-level `action`" in first_messages[0]["content"]
    assert "advertised_tool" in first_messages[0]["content"]
    repaired_messages = fake_openai.completions.requests[1]["messages"]
    assert repaired_messages[-1]["role"] == "user"
    assert original_messages == [{"role": "system", "content": "Investigate."}]
    # The next step drops the repair exchange, so its history diverges from the
    # previous request after the system message.
    next_messages = [
        *original_messages,
        {"role": "assistant", "content": "Read the trigger entity."},
        {"role": "tool", "content": "{}", "tool_call_id": "step_1"},
    ]
    asyncio.run(client.next_step(next_messages, response_format=STEP_FORMAT, trace=trace))

    events = [json.loads(line) for line in trace.path.read_text(encoding="utf-8").splitlines()]
    assert [event["attempt"] for event in events] == [1, 2, 1]
    assert events[0]["payload"]["raw_content"] == "not-json"
    assert llm_requests(events) == [
        request["messages"] for request in fake_openai.completions.requests
    ]
    assert len(events[2]["payload"]["messages"]) == 2
    assert (trace.llm_calls, trace.llm_tokens) == (3, 51)


def test_parser_drops_envelope_keys_the_agent_does_not_read() -> None:
    """A stray `task_completed` from the old contract does not cost a repair (ADR 0009)."""
    payload = json.dumps(
        {
            "current_state": "The trigger entity needs its relations.",
            "plan_remaining_steps_brief": ["Read the trigger entity."],
            "task_completed": True,
            "function": {"tool": "get_entity", "entity_id": "entity-1", "reasoning": "Inspect."},
        }
    )

    step = parse_next_step_payload(payload)

    assert step.function.tool == "get_entity"


def test_parser_keeps_arguments_of_any_tool_without_nulls() -> None:
    """A tool unknown to the code keeps its arguments; nulls of omitted ones are dropped."""
    payload = json.dumps(
        {
            "current_state": "The alert is explained by authorized activity.",
            "plan_remaining_steps_brief": ["Submit the verdict."],
            "function": {
                "tool": "finish_investigation_v2",
                "submission": {
                    "verdict": "benign",
                    "legitimacy_evidence": [
                        {"anchor": "relation", "relation_id": "rel-1", "property_fields": []}
                    ],
                    "confidence": None,
                },
                "page_id": None,
            },
        }
    )

    step = parse_next_step_payload(f"```json\n{payload}\n```")

    assert step.function.tool == "finish_investigation_v2"
    assert step.function.arguments == {
        "submission": {
            "verdict": "benign",
            "legitimacy_evidence": [
                {"anchor": "relation", "relation_id": "rel-1", "property_fields": []}
            ],
        }
    }
    with pytest.raises(ValueError):
        parse_next_step_payload(json.dumps({**json.loads(payload), "function": {"x": 1}}))


REQUEST = httpx.Request("POST", "https://llm.example/v1/chat/completions")


def status_error(error_type: type[APIError], status: int, detail: str) -> APIError:
    """Build the HTTP error the OpenAI client raises for one provider reply."""
    body = {"detail": detail}
    response = httpx.Response(status, json=body, request=REQUEST)
    return error_type(f"Error code: {status} - {body}", response=response, body=body)


PROXY_OUTAGE = status_error(BadRequestError, 400, "Open WebUI: Server Connection Error")
CONTEXT_OVERFLOW = status_error(BadRequestError, 400, "maximum context length exceeded")
BAD_KEY = status_error(AuthenticationError, 401, "invalid api key")
CONNECTION = APIConnectionError(request=REQUEST)
TIMEOUT = APITimeoutError(request=REQUEST)


@pytest.mark.parametrize(
    ("errors", "requests"),
    [
        pytest.param([PROXY_OUTAGE], 2, id="proxy-outage-recovers"),
        pytest.param([CONNECTION] * 3, 4, id="last-retry-recovers"),
        pytest.param([CONNECTION] * 4, 4, id="retries-run-out"),
        pytest.param([TIMEOUT, TIMEOUT], 2, id="timeout-retried-once"),
        pytest.param([CONTEXT_OVERFLOW], 1, id="context-overflow-fails-fast"),
        pytest.param([BAD_KEY], 1, id="bad-key-fails-fast"),
    ],
)
def test_structured_client_retries_only_transient_provider_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, errors: list[APIError], requests: int
) -> None:
    """Transient provider errors are retried a bounded number of times, others surface."""
    fake_openai = FakeOpenAI([*errors, valid_process_step().model_dump_json()])
    real_sleep = asyncio.sleep
    monkeypatch.setattr(asyncio, "sleep", lambda _delay: real_sleep(0))
    client = OpenAIStructuredStepClient(
        base_url="https://llm.example/v1",
        api_key="secret",
        model="test-model",
        timeout_seconds=10.0,
        max_completion_tokens=1000,
        max_retries=3,
        client=cast(AsyncOpenAI, fake_openai),
    )
    trace = TaskTrace(tmp_path / "task.trace.jsonl")
    messages = [{"role": "system", "content": "Investigate."}]

    if requests > len(errors):
        step = asyncio.run(client.next_step(messages, response_format=STEP_FORMAT, trace=trace))
        assert step.function.tool == "get_entity"
    else:
        with pytest.raises(type(errors[requests - 1])):
            asyncio.run(client.next_step(messages, response_format=STEP_FORMAT, trace=trace))
    assert len(fake_openai.completions.requests) == requests
    events = [json.loads(line) for line in trace.path.read_text(encoding="utf-8").splitlines()]
    assert [event["kind"] for event in events].count("llm_error") == min(len(errors), requests)


def test_a_side_turn_sends_only_its_own_request_and_is_traced_by_role(tmp_path: Path) -> None:
    """A challenger turn between two head steps gets no step instructions, repairs against
    its own schema, goes to the challenger's model, and leaves events that name its role
    and model and rebuild every request."""
    step = valid_process_step().model_dump_json()
    reply = json.dumps(
        {
            "hypothesis": "Dropped payload.",
            "checks": [
                {
                    "look_for": "Who wrote it.",
                    "confirms_if": "A remote shell.",
                    "refuted_if": "No writer.",
                    "source": {"call": {"tool": "get_entity"}},
                }
            ],
        }
    )
    fake_openai = FakeOpenAI([step, "not-json", reply, step])
    client = OpenAIStructuredStepClient(
        base_url="https://llm.example/v1",
        api_key="secret",
        model="test-model",
        timeout_seconds=10.0,
        max_completion_tokens=1000,
        max_retries=3,
        role_models={"challenger": "challenger-model"},
        client=cast(AsyncOpenAI, fake_openai),
    )
    trace = TaskTrace(tmp_path / "task.trace.jsonl")
    history = [{"role": "system", "content": "Investigate."}]
    side = [{"role": "system", "content": "Argue."}, {"role": "user", "content": "{}"}]

    asyncio.run(client.next_step(history, response_format=STEP_FORMAT, trace=trace))
    challenge = asyncio.run(
        client.structured(
            side, response_format=STEP_FORMAT, model=Challenge, role="challenger", trace=trace
        )
    )
    history = [*history, {"role": "assistant", "content": "Read."}]
    asyncio.run(client.next_step(history, response_format=STEP_FORMAT, trace=trace))

    assert challenge.hypothesis == "Dropped payload."
    requests = [request["messages"] for request in fake_openai.completions.requests]
    assert requests[1] == side
    assert "schema" in requests[2][-1]["content"]
    events = [json.loads(line) for line in trace.path.read_text(encoding="utf-8").splitlines()]
    assert [event["role"] for event in events] == ["head", "challenger", "challenger", "head"]
    models = ["test-model", "challenger-model", "challenger-model", "test-model"]
    assert [request["model"] for request in fake_openai.completions.requests] == models
    assert [event["model"] for event in events] == models
    assert llm_requests(events) == requests
    # The head's next request stores only what it added, not its whole history again.
    assert events[3]["payload"]["prefix"] == 1
