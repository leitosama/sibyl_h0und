"""JSONL traces of investigation runs, written outside the repository.

One directory per run holds one `<seq>_<task_id>.trace.jsonl` file per task.
Every line is one event with flat top-level fields for viewers and SQL, and
raw request/response data under `payload`. Tracing never breaks a run: a
failed write is logged and skipped.

This module owns the event format. `TaskTrace` writes each event kind through
a typed method, and `read_task` reads the same kinds back, so the agent, the
LLM client and replay never touch the raw shape. Old traces must stay
readable (ADR 0008): add fields, do not rename them.
"""

import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from loguru import logger

from sibyl_h0und.catalog import FINISH_TOOL
from sibyl_h0und.outcome import ToolOutcome


def default_trace_dir() -> Path:
    """Return `$XDG_DATA_HOME/sibyl_h0und/traces` or its `~/.local/share` default."""
    data_home = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(data_home) / "sibyl_h0und" / "traces"


def run_trace_dir(root: Path, run_id: str) -> Path:
    """Return the trace directory of a run, ordered by start time."""
    return root / f"{datetime.now(UTC):%Y%m%dT%H%M%SZ}_{_safe_name(run_id)}"


def task_trace_path(run_dir: Path, seq: int, task_id: str) -> Path:
    """Return the trace file of the `seq`-th task leased in a run."""
    return run_dir / f"{seq:03d}_{_safe_name(task_id)}.trace.jsonl"


def elapsed_ms(started_at: float) -> int:
    """Return whole milliseconds elapsed since a `time.perf_counter()` value."""
    return int((time.perf_counter() - started_at) * 1000)


def _safe_name(value: str) -> str:
    """Make an identifier usable as a file name component."""
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._") or "unknown"


class TaskTrace:
    """Event writer and counters for one task; `path=None` writes nothing."""

    def __init__(self, path: Path | None, *, run_id: str = "", task_id: str = "") -> None:
        """Store the target file and identifiers stamped on every event.

        Args:
            path: Target JSONL file, created with its directory on first write.
            run_id: Runtime run identifier.
            task_id: Runtime task identifier.
        """
        self.path = path
        self.run_id = run_id
        self.task_id = task_id
        self.step = 0
        self.llm_calls = 0
        self.llm_tokens = 0
        self.llm_ms = 0
        self.runtime_calls = 0
        self._seq = 0
        # The last request of each role: a side turn shares no history with the head.
        self._last_llm_request: dict[str, list[dict[str, Any]]] = {}
        self._started_at = time.perf_counter()

    @property
    def wall_ms(self) -> int:
        """Milliseconds since the task trace was created."""
        return elapsed_ms(self._started_at)

    def event(self, kind: str, *, payload: dict[str, Any] | None = None, **fields: Any) -> None:
        """Append one event line.

        Args:
            kind: Event type, for example `llm_call` or `tool_call`.
            payload: Raw data kept under the nested `payload` key.
            **fields: Small flat fields shown next to the common ones.
        """
        if self.path is None:
            return
        self._seq += 1
        record = {
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "run_id": self.run_id,
            "task_id": self.task_id,
            "seq": self._seq,
            "step": self.step,
            "kind": kind,
            **fields,
        }
        if payload is not None:
            record["payload"] = payload
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as file:
                file.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        except OSError as error:
            logger.warning("Skipping trace event {} in {}: {}", kind, self.path, error)

    def next_step(self) -> int:
        """Start the next agent turn and return its number."""
        self.step += 1
        return self.step

    def count_runtime_call(self) -> None:
        """Count a call sent to the runtime, before it can fail."""
        self.runtime_calls += 1

    def count_llm_attempt(self, *, tokens: int, ms: int) -> None:
        """Count one LLM request attempt with its token usage and latency."""
        self.llm_calls += 1
        self.llm_tokens += tokens
        self.llm_ms += ms

    def task_start(
        self, run: dict[str, Any], task: dict[str, Any], step_format: dict[str, Any]
    ) -> None:
        """Write the opening event: run settings, the task and the step schema."""
        self.event("task_start", payload={"run": run, "task": task, "step_format": step_format})

    def finish_only(self, reason: str | None, runtime_calls: int) -> None:
        """Write that only `finish_investigation` may be called from now on."""
        self.event("finish_only", payload={"reason": reason, "runtime_calls": runtime_calls})

    def step_chosen(self, tool: str, step: dict[str, Any]) -> None:
        """Write the model's decoded step."""
        self.event("step", tool=tool, payload={"step": step})

    def local_answer(
        self,
        kind: str,
        tool: str,
        arguments: dict[str, Any],
        feedback: dict[str, Any] | None,
        **fields: Any,
    ) -> None:
        """Write a call answered without the runtime.

        Args:
            kind: `tool_rejected`, `tool_invalid`, `report_refused`, `citations_refused`,
                `benign_challenged`, `tool_cached` or `tool_knowledge` (the lookup
                and its answer).
            tool: Tool the model asked for.
            arguments: Arguments of the call.
            feedback: Answer shown to the model, if it is worth keeping.
            **fields: Small flat fields shown next to the common ones.
        """
        payload: dict[str, Any] = {"arguments": arguments}
        if feedback is not None:
            payload["feedback"] = feedback
        self.event(kind, tool=tool, payload=payload, **fields)

    def report_written(
        self, draft: dict[str, Any], report: dict[str, Any] | None, fallback: str | None
    ) -> None:
        """Write what the reporter made of the head's draft (ADR 0023).

        Args:
            draft: The head's report.
            report: The reporter's report that is sent, or `None` when the draft is.
            fallback: Why the draft is sent, or `None`.
        """
        payload: dict[str, Any] = {"draft": draft}
        if report is not None:
            payload["report"] = report
        self.event("report_written", fallback=fallback, payload=payload)

    def tool_call(
        self,
        tool: str,
        arguments: dict[str, Any],
        response: dict[str, Any],
        duration_ms: int,
        *,
        alert_stage: bool = False,
    ) -> None:
        """Write one runtime call with the full decoded `ToolCallResult` response.

        `alert_stage` marks a call the harness made before the first turn
        (ADR 0027); older traces lack the field.
        """
        self.event(
            "tool_call",
            duration_ms=duration_ms,
            tool=tool,
            alert_stage=alert_stage,
            status=response.get("info", {}).get("tool_status"),
            reward=response.get("reward"),
            terminated=response.get("terminated"),
            truncated=response.get("truncated"),
            payload={"arguments": arguments, "response": response},
        )

    def task_end(self, task_result: dict[str, Any], error: str | None) -> None:
        """Write the closing summary line with the authoritative result and counters."""
        self.event(
            "task_end",
            duration_ms=self.wall_ms,
            completion_reason=task_result.get("completion_reason"),
            total_reward=task_result.get("total_reward"),
            quality_score=task_result.get("quality_score"),
            efficiency_score=task_result.get("efficiency_score"),
            tool_calls=task_result.get("tool_calls"),
            steps_taken=task_result.get("steps_taken"),
            agent_steps=self.step,
            runtime_calls=self.runtime_calls,
            llm_calls=self.llm_calls,
            llm_tokens=self.llm_tokens,
            llm_ms=self.llm_ms,
            error=error,
            payload={"task_result": task_result},
        )

    def llm_call(
        self, messages: list[dict[str, Any]], *, raw_content: str, role: str, **fields: Any
    ) -> None:
        """Append an `llm_call` event that stores only the request's new messages.

        The payload keeps `prefix`, the number of leading messages shared with
        the previous `llm_call` of the same role in this task, and the messages
        after it, so the trace grows linearly with the history even when side
        turns come between head turns. `llm_requests` rebuilds the full requests.

        Args:
            messages: Exact message list sent to the LLM.
            raw_content: Model reply as received.
            role: `head` for the investigation's turns, or the side turn's name.
            **fields: Small flat fields shown next to the common ones.
        """
        if self.path is None:
            return
        previous = self._last_llm_request.get(role, [])
        prefix = 0
        while prefix < min(len(previous), len(messages)) and previous[prefix] == messages[prefix]:
            prefix += 1
        self._last_llm_request[role] = list(messages)
        self.event(
            "llm_call",
            role=role,
            payload={"prefix": prefix, "messages": messages[prefix:], "raw_content": raw_content},
            **fields,
        )


def llm_requests(events: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Rebuild the full message list of every `llm_call` event of one task.

    A prefix counts from the previous request of the same role; an event
    without a role, from older traces, is the head's.

    Args:
        events: Events of one task trace in file order.

    Returns:
        One full request per `llm_call` event, in order.
    """
    requests: list[list[dict[str, Any]]] = []
    current: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        if event.get("kind") != "llm_call":
            continue
        payload = event["payload"]
        role = event.get("role", "head")
        current[role] = current.get(role, [])[: payload.get("prefix", 0)] + payload["messages"]
        requests.append(current[role])
    return requests


@dataclass(frozen=True)
class RecordedCall:
    """One runtime call read back from a trace."""

    tool: str
    arguments: dict[str, Any]
    outcome: ToolOutcome


@dataclass(frozen=True)
class RecordedDraft:
    """A report the model submitted, whether or not it reached the runtime.

    Attributes:
        calls_before: How many runtime calls came before it.
        arguments: Arguments of the report call as the head wrote them, before
            any reporter rewrite.
        finish_only: Whether only the report could be called by then.
        feedback: The local answer the model got instead of a runtime call,
            if the report was answered locally.
        state: The model's `current_state` of the step that submitted it.
    """

    calls_before: int
    arguments: dict[str, Any]
    finish_only: bool = False
    feedback: dict[str, Any] | None = None
    state: str | None = None


# Local answers to a report: the report never reached the runtime.
REPORT_ANSWERS = ("report_refused", "citations_refused", "benign_challenged")


@dataclass
class RecordedTask:
    """What a trace says about one task.

    Attributes:
        run_id: Runtime run id; practice runs repeat task ids across runs.
        task_id: Runtime task id.
        observation: The task's observation as the agent received it, or `None`
            when the trace has no `task_start`.
        calls: Runtime calls in order.
        drafts: Every report the model submitted, answered locally or sent.
        quality: Final quality score, `None` when the task never ended.
        reward: Final total reward, `None` when the task never ended.
    """

    run_id: str | None = None
    task_id: str | None = None
    observation: dict[str, Any] | None = None
    calls: list[RecordedCall] = field(default_factory=list)
    drafts: list[RecordedDraft] = field(default_factory=list)
    quality: float | None = None
    reward: float | None = None

    @property
    def submission(self) -> dict[str, Any] | None:
        """Arguments of the last `finish_investigation` call, without its wrapper."""
        for call in reversed(self.calls):
            if call.tool == FINISH_TOOL:
                return call.arguments.get("submission", call.arguments)
        return None


def read_task(path: Path) -> RecordedTask:
    """Read the events a replay needs from one task trace.

    Args:
        path: JSONL trace of one task.

    Returns:
        Identifiers, the task observation, every runtime call decoded as the
        agent decodes a live response, and the final scores.
    """
    task = RecordedTask()
    kinds = (
        "task_start",
        "tool_call",
        "task_end",
        "finish_only",
        "report_written",
        "step",
        *REPORT_ANSWERS,
    )
    finish_only = False
    # The state of the step that chose the next report.
    state: str | None = None
    # The head's report behind the next sent report, when the reporter rewrote it.
    head_draft: dict[str, Any] | None = None
    with path.open(encoding="utf-8") as lines:
        for line in lines:
            if not any(f'"kind": "{kind}"' in line for kind in kinds):
                continue
            event = json.loads(line)
            kind = event.get("kind")
            if kind not in kinds:
                continue
            task.run_id, task.task_id = event.get("run_id"), event.get("task_id")
            payload = event.get("payload") or {}
            arguments = payload.get("arguments") or {}
            if kind in REPORT_ANSWERS or (kind == "tool_call" and event.get("tool") == FINISH_TOOL):
                draft = head_draft if kind == "tool_call" and head_draft is not None else arguments
                task.drafts.append(
                    RecordedDraft(
                        len(task.calls), draft, finish_only, payload.get("feedback"), state
                    )
                )
                head_draft, state = None, None
            if kind == "step":
                step = payload.get("step") or {}
                state = step.get("current_state") if event.get("tool") == FINISH_TOOL else None
            elif kind == "report_written":
                head_draft = payload.get("draft") if "report" in payload else None
            elif kind == "finish_only":
                finish_only = True
            elif kind == "task_start":
                task.observation = (payload.get("task") or {}).get("observation")
            elif kind == "task_end":
                task.quality = event.get("quality_score")
                task.reward = event.get("total_reward")
            else:
                response = payload.get("response") or {}
                outcome = ToolOutcome.from_wire(
                    info=response.get("info") or {},
                    observation=response.get("observation") or {},
                    terminal=response.get("task_result") is not None,
                )
                task.calls.append(RecordedCall(event.get("tool", ""), arguments, outcome))
    return task
