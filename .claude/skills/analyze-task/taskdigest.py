"""Compact digest of one task trace, shared by the run monitor and the task analysis.

A trace is megabytes (full tool responses and prompts). The digest keeps what
a reviewer needs to decide whether the task deserves a deep read: the alert,
the verdict, the numbers, and the reasons behind challenges, refusals and
errors. Nothing here is used by the agent; it is offline trace analysis only.
"""

import contextlib
import json
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from sibyl_h0und.catalog import FINISH_TOOL
from sibyl_h0und.investigation import find_report
from sibyl_h0und.replay import DEFAULT_WRONG_BELOW

NOT_SHOWN = 160


def clip(value: Any, limit: int = NOT_SHOWN) -> str:
    """Return `value` as one line of at most `limit` characters."""
    text = " ".join(str(value).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def read_events(path: Path) -> Iterator[dict[str, Any]]:
    """Yield the events of a trace file, skipping a partly written last line."""
    with path.open("rb") as fh:
        for raw in fh:
            if raw.endswith(b"\n"):
                yield json.loads(raw)


def citations(report: dict[str, Any]) -> Counter:
    """Count every cited id with its action kind and property fields."""
    found: Counter = Counter()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            key = node.get("entity_id") or node.get("relation_id")
            if isinstance(key, str):
                fields = tuple(sorted(node.get("property_fields") or []))
                found[(key, node.get("kind"), fields)] += 1
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(report)
    return found


def reporter_change(payload: dict[str, Any], fallback: str | None) -> str:
    """Describe how the sent report differs from the head's draft."""
    if payload.get("report") is None:
        return "failed" if fallback else "none"
    draft = find_report(payload.get("draft") or {}) or {}
    sent = find_report(payload["report"]) or {}
    if draft == sent:
        return "kept"
    old, new = citations(draft), citations(sent)
    old_ids = Counter(key for key, _, _ in old.elements())
    new_ids = Counter(key for key, _, _ in new.elements())
    added, removed = sum((new_ids - old_ids).values()), sum((old_ids - new_ids).values())
    changed = sum((new - old).values()) - added
    if not (added or removed or changed):
        return "text"
    return f"+{added}/-{removed}ids,{changed}changed"


def alert_summary(observation: dict[str, Any]) -> str:
    """Return the alert description from the task observation, clipped."""
    text = observation.get("alert_text")
    if isinstance(text, str):
        with contextlib.suppress(ValueError, AttributeError):
            text = json.loads(text).get("alert_description", text)
    return clip(text or "", 300)


class Task:
    """Everything the digest reports about one task, fed event by event."""

    def __init__(self, number: int, task_id: str):
        self.number, self.id = number, task_id[:8]
        self.verdict = "?"
        self.alert = ""
        self.model = ""
        self.challenged = self.rejected = self.refused = self.tool_errors = 0
        self.llm_errors = 0
        self.reporter = "none"
        self.fallback: str | None = None
        self.ended = False
        self.report_ids = 0
        self.tools: Counter = Counter()
        self.errors: list[str] = []
        self.hypotheses: list[str] = []
        self.checks: list[str] = []
        self.refusals: list[str] = []
        self.last_state = ""
        self.finish_seq: int | None = None

    def feed(self, event: dict[str, Any]) -> dict[str, Any] | None:
        """Take one event; return it when it ends the task."""
        kind, payload = event["kind"], event.get("payload") or {}
        if kind == "task_start":
            task = payload.get("task") or {}
            self.alert = alert_summary(task.get("observation") or {})
            self.model = (payload.get("run") or {}).get("model") or ""
        elif kind == "step":
            state = (payload.get("step") or {}).get("current_state")
            if state:
                self.last_state = clip(state, 400)
        elif kind == "tool_call":
            self.tools[event.get("tool")] += 1
            if event.get("tool") == FINISH_TOOL:
                report = find_report(payload.get("arguments") or {}) or {}
                self.verdict = report.get("verdict", self.verdict)
                self.report_ids = sum(citations(report).values())
                self.finish_seq = event.get("seq")
            if event.get("status") != "ok":
                self.tool_errors += 1
                self.errors.append(
                    f"seq={event.get('seq')} {event.get('tool')}: "
                    f"{clip(event.get('error') or event.get('status'), 120)}"
                )
        elif kind == "llm_error":
            self.llm_errors += 1
        elif kind == "tool_rejected":
            self.rejected += 1
        elif kind == "report_refused":
            self.refused += 1
        elif kind == "answers_refused":
            for item in event.get("review") or []:
                why = clip(item.get("why"), 140)
                self.refusals.append(f"{item.get('n')}:{item.get('outcome')} {why}")
        elif kind == "benign_challenged":
            self.challenged += 1
            challenge = (payload.get("feedback") or {}).get("challenge") or {}
            self.hypotheses.append(clip(challenge.get("hypothesis", ""), 260))
            for check in challenge.get("checks") or []:
                self.checks.append(f"{check.get('n')}: {clip(check.get('look_for'), 140)}")
        elif kind == "report_written":
            self.fallback = event.get("fallback")
            self.reporter = reporter_change(payload, self.fallback)
        elif kind == "task_end":
            self.ended = True
            return event
        return None


def scores_hidden(end: dict[str, Any]) -> bool:
    """Tell whether the runtime withheld the scores.

    A wrong verdict always has a negative `total_reward`, so zero Q, E and
    reward together mean the fields were not filled, not a zero score.
    """
    return not any(end.get(k) for k in ("quality_score", "efficiency_score", "total_reward"))


def flags(task: Task, end: dict[str, Any]) -> list[str]:
    """Name the reasons a finished task deserves a look; empty when it is routine."""
    found = []
    if task.verdict == "benign":
        found.append("benign")
    if task.challenged:
        found.append("challenged")
    if task.refused or task.rejected:
        found.append("refused")
    if task.fallback or task.reporter == "failed":
        found.append("fallback")
    if task.tool_errors:
        found.append("tool_errors")
    if task.llm_errors:
        found.append("llm_errors")
    if end.get("completion_reason") != "terminated" or end.get("error"):
        found.append("not_terminated")
    if not scores_hidden(end) and (end.get("quality_score") or 0.0) < DEFAULT_WRONG_BELOW:
        found.append("low_q")
    return found


def render(task: Task, end: dict[str, Any] | None) -> str:
    """Return the multi-line digest of a task for a reviewer."""
    lines = [f"[{task.number:03d} {task.id}] model={task.model} verdict={task.verdict}"]
    lines.append(f"alert: {task.alert}")
    if end:
        lines.append(
            f"end={end.get('completion_reason')} error={end.get('error')} "
            f"calls={end.get('runtime_calls')} llm={end.get('llm_calls')} "
            f"tokens={end.get('llm_tokens')} duration_s={(end.get('duration_ms') or 0) / 1000:.0f} "
            f"flags={','.join(flags(task, end)) or '-'}"
        )
        if scores_hidden(end):
            lines.append("scores: hidden by the runtime")
        else:
            q, e = end.get("quality_score") or 0.0, end.get("efficiency_score") or 0.0
            lines.append(f"scores: Q={q:.2f} E={e:.2f} reward={end.get('total_reward')}")
    lines.append(f"tools: {dict(task.tools.most_common())}")
    lines.append(
        f"report: cited={task.report_ids} reporter={task.reporter} fallback={task.fallback} "
        f"finish_seq={task.finish_seq}"
    )
    for label, items in (
        ("challenge hypothesis", task.hypotheses),
        ("challenge checks", task.checks),
        ("answers refused", task.refusals),
        ("errors", task.errors),
    ):
        if items:
            lines.append(f"{label}:")
            lines.extend(f"  - {item}" for item in items[:8])
    if task.last_state:
        lines.append(f"last current_state: {task.last_state}")
    return "\n".join(lines)


def build(path: Path) -> tuple[Task, dict[str, Any] | None]:
    """Replay one trace file into a Task and its `task_end` event, if any."""
    number = int(path.name.split("_", 1)[0])
    task: Task | None = None
    end = None
    for event in read_events(path):
        task = task or Task(number, event["task_id"])
        end = task.feed(event) or end
    if task is None:
        raise SystemExit(f"{path}: no events")
    return task, end


def find_trace(run_dir: Path, number: int) -> Path:
    """Return the trace file of task `number` in a run directory."""
    found = sorted(run_dir.glob(f"{number:03d}_*.trace.jsonl"))
    if not found:
        raise SystemExit(f"no trace for task {number:03d} in {run_dir}")
    return found[0]
