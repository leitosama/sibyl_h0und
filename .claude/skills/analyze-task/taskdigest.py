"""Compact digest of one task trace, shared by the run monitor and the task analysis.

A trace is megabytes (full tool responses and prompts). The digest keeps what
a reviewer needs to decide whether the task deserves a deep read: the alert,
the verdict, the numbers, and the reasons behind challenges, refusals and
errors. Nothing here is used by the agent; it is offline trace analysis only.
"""

import contextlib
import json
import math
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from sibyl_h0und.catalog import FINISH_TOOL
from sibyl_h0und.investigation import find_report
from sibyl_h0und.replay import DEFAULT_WRONG_BELOW

NOT_SHOWN = 160
GRADED, PRACTICE = "graded", "practice"
GRADED_AGENT = "h0und1"  # the competition token profile, `.env.h0und1` (ADR 0002)
TRIAGE_LOG = "analysis.log"


def mode_of_agent(agent_name: str) -> str:
    """Return `graded` for the competition agent name, `practice` for any other."""
    return GRADED if agent_name == GRADED_AGENT else PRACTICE


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

    def __init__(self, number: int, task_id: str, mode: str | None = None):
        self.number, self.id = number, task_id[:8]
        self.agent = ""
        self.mode = mode or PRACTICE
        self.mode_fixed = mode is not None
        self.mode_mismatch = False
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
        self.label = ""
        self.ceiling: int | None = None
        self.roles: dict[str, list[int]] = {}  # role -> [calls, tokens, ms]
        self.head_tokens: list[int] = []
        self.llm_slow: list[tuple[int, int, str]] = []  # (ms, seq, role)
        self.tool_slow: list[tuple[int, int, str]] = []  # (ms, seq, tool)
        self.tool_ms = 0
        self.calls: list[tuple[int, str, str]] = []  # (seq, tool, arguments key)
        self.cached: Counter = Counter()
        self.knowledge: list[str] = []
        self.opened: set[str] = set()
        self.cited: set[str] = set()
        self.pages = 0
        self.attempts: list[tuple[int, str, str | None]] = []  # (seq, outcome, verdict)

    def _attempt(self, event: dict[str, Any], outcome: str) -> None:
        """Record one try to finish: its outcome and the verdict it carried."""
        arguments = (event.get("payload") or {}).get("arguments") or {}
        verdict = (find_report(arguments) or {}).get("verdict")
        self.attempts.append((event.get("seq") or 0, outcome, verdict))

    def feed(self, event: dict[str, Any]) -> dict[str, Any] | None:
        """Take one event; return it when it ends the task."""
        kind, payload = event["kind"], event.get("payload") or {}
        if kind == "task_start":
            task = payload.get("task") or {}
            self.alert = alert_summary(task.get("observation") or {})
            run = payload.get("run") or {}
            self.model = run.get("model") or ""
            self.label = run.get("run_label") or ""
            self.agent = run.get("agent_name") or ""
            detected = mode_of_agent(self.agent)
            if self.mode_fixed:
                self.mode_mismatch = detected != self.mode
            else:
                self.mode = detected
            self.ceiling = run.get("agent_max_runtime_calls")
        elif kind == "llm_call":
            role = event.get("role") or "?"
            tokens, ms = event.get("tokens") or 0, event.get("duration_ms") or 0
            row = self.roles.setdefault(role, [0, 0, 0])
            row[0], row[1], row[2] = row[0] + 1, row[1] + tokens, row[2] + ms
            self.llm_slow.append((ms, event.get("seq") or 0, role))
            if role == "head":
                self.head_tokens.append(tokens)
        elif kind == "tool_cached":
            self.cached[event.get("tool")] += 1
        elif kind == "tool_knowledge":
            query = (payload.get("arguments") or {}).get("query")
            self.knowledge.append(clip(query, 100))
        elif kind == "step":
            state = (payload.get("step") or {}).get("current_state")
            if state:
                self.last_state = clip(state, 400)
        elif kind == "tool_call":
            tool, arguments = event.get("tool"), payload.get("arguments") or {}
            self.tools[tool] += 1
            ms = event.get("duration_ms") or 0
            self.tool_ms += ms
            self.tool_slow.append((ms, event.get("seq") or 0, str(tool)))
            same = json.dumps(
                {k: v for k, v in arguments.items() if k != "reasoning"}, sort_keys=True
            )
            self.calls.append((event.get("seq") or 0, str(tool), same))
            for key in ("entity_id", "relation_id"):
                if isinstance(arguments.get(key), str):
                    self.opened.add(arguments[key])
            if tool == "search" and (arguments.get("page_id") or 1) > 1:
                self.pages += 1
            if tool == FINISH_TOOL:
                report = find_report(arguments) or {}
                self.verdict = report.get("verdict", self.verdict)
                self.report_ids = sum(citations(report).values())
                self.cited = {key for key, _, _ in citations(report)}
                self.finish_seq = event.get("seq")
                self._attempt(event, "sent")
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
            self._attempt(event, "rejected")
        elif kind == "report_refused":
            self.refused += 1
            self._attempt(event, "report_refused")
        elif kind == "citations_refused":
            self._attempt(event, "citations_refused")
        elif kind == "answers_refused":
            self._attempt(event, "answers_refused")
            for item in event.get("review") or []:
                why = clip(item.get("why"), 140)
                self.refusals.append(f"{item.get('n')}:{item.get('outcome')} {why}")
        elif kind == "benign_challenged":
            self.challenged += 1
            self._attempt(event, "challenged")
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


def hidden(task: Task, end: dict[str, Any]) -> bool:
    """Tell whether scores must not be shown: always in graded mode, else when unfilled."""
    return task.mode == GRADED or scores_hidden(end)


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
    if not hidden(task, end) and (end.get("quality_score") or 0.0) < DEFAULT_WRONG_BELOW:
        found.append("low_q")
    return found


REWORK_CALLS = 5
REPEAT_CALLS = 3
CEILING_SHARE = 0.9
BIG_CONTEXT = 50_000


def metrics(task: Task, end: dict[str, Any] | None) -> dict[str, Any]:
    """Return the structural numbers of a task: cost, repeats, rework and coverage.

    They come from the trace alone, so they stay available when the runtime
    hides the scores.
    """
    end = end or {}
    calls = end.get("runtime_calls") or len(task.calls)
    first_finish = min((seq for seq, _, _ in task.attempts), default=None)
    after = [c for c in task.calls if first_finish is not None and c[0] > first_finish]
    after = [c for c in after if c[1] != FINISH_TOOL]
    same = Counter(key for _, tool, key in task.calls if tool != FINISH_TOOL)
    streak, best, previous = 0, ("", 0), None
    for _, tool, _ in task.calls:
        streak = streak + 1 if tool == previous else 1
        previous = tool
        if streak > best[1]:
            best = (tool, streak)
    verdicts = [v for _, _, v in task.attempts if v]
    head = task.head_tokens
    big = next((i + 1 for i, t in enumerate(head) if t >= BIG_CONTEXT), None)
    return {
        "calls": calls,
        "ceiling": task.ceiling,
        "ceiling_share": calls / task.ceiling if task.ceiling else None,
        "tokens": end.get("llm_tokens") or sum(r[1] for r in task.roles.values()),
        "tokens_by_role": {k: v[1] for k, v in task.roles.items()},
        "ms_by_role": {k: v[2] for k, v in task.roles.items()},
        "llm_ms": sum(r[2] for r in task.roles.values()),
        "tool_ms": task.tool_ms,
        "duration_s": (end.get("duration_ms") or 0) / 1000,
        "head_first": head[0] if head else 0,
        "head_last": head[-1] if head else 0,
        "head_big_at_call": big,
        "tools": dict(task.tools),
        "cached": sum(task.cached.values()),
        "cached_by_tool": dict(task.cached),
        "same_args": sum(n - 1 for n in same.values() if n > 1),
        "streak_tool": best[0],
        "streak": best[1],
        "pages": task.pages,
        "opened": len(task.opened),
        "cited": len(task.cited),
        "knowledge": len(task.knowledge),
        "attempts": len(task.attempts),
        "calls_after_first_finish": len(after),
        "verdicts": verdicts,
        "flip": len(set(verdicts)) > 1,
    }


def structure_flags(m: dict[str, Any]) -> list[str]:
    """Flag structural waste; only counts of trace events, never knowledge content."""
    found = []
    if m["calls_after_first_finish"] >= REWORK_CALLS:
        found.append("rework")
    if m["cached"] + m["same_args"] >= REPEAT_CALLS:
        found.append("repeat")
    if (m["ceiling_share"] or 0) >= CEILING_SHARE:
        found.append("near_ceiling")
    return found


def percentile(values: list[float], share: float = 0.9) -> float | None:
    """Return the `share` quantile of `values` (nearest rank), None when empty."""
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(share * len(ordered)) - 1)]


def economy_lines(task: Task, m: dict[str, Any]) -> list[str]:
    """Return the cost and waste section of the digest."""
    total_tokens = sum(m["tokens_by_role"].values()) or 1
    total_ms = (m["llm_ms"] + m["tool_ms"]) or 1
    by_role = m["tokens_by_role"]
    roles = ", ".join(
        f"{role} {by_role[role] / 1000:.0f}k ({by_role[role] * 100 // total_tokens}%)"
        f"/{m['ms_by_role'][role] / 1000:.0f}s"
        for role in sorted(by_role, key=lambda r: -by_role[r])
    )
    lines = [f"tokens by role: {roles}"]
    big = m["head_big_at_call"]
    lines.append(
        f"head context: {m['head_first'] / 1000:.0f}k -> {m['head_last'] / 1000:.0f}k tokens/call"
        + (f", over {BIG_CONTEXT // 1000}k from head call {big}" if big else "")
    )
    lines.append(
        f"time: llm {m['llm_ms'] / 1000:.0f}s ({m['llm_ms'] * 100 // total_ms}%), "
        f"runtime {m['tool_ms'] / 1000:.0f}s"
    )
    if m["ceiling"]:
        share = m["calls"] * 100 // m["ceiling"]
        lines.append(f"ceiling: {m['calls']}/{m['ceiling']} runtime calls ({share}%)")
    slow_llm = ", ".join(
        f"seq {s} {r} {ms / 1000:.1f}s" for ms, s, r in sorted(task.llm_slow)[-3:][::-1]
    )
    slow_tool = ", ".join(
        f"seq {s} {t} {ms / 1000:.1f}s" for ms, s, t in sorted(task.tool_slow)[-3:][::-1]
    )
    lines.append(f"slowest llm: {slow_llm}")
    lines.append(f"slowest runtime: {slow_tool}")
    lines.append(
        f"repeats: cached={m['cached']} {m['cached_by_tool'] or ''} same_args={m['same_args']} "
        f"longest_streak={m['streak_tool']} x{m['streak']} search_pages>1={m['pages']}"
    )
    lines.append(
        f"coverage: opened={m['opened']} cited={m['cited']} lookups={m['knowledge']}"
        + (f" ({'; '.join(task.knowledge[:3])})" if task.knowledge else "")
    )
    if task.attempts:
        chain = " -> ".join(f"{o}@{s}" + (f"[{v}]" if v else "") for s, o, v in task.attempts)
        lines.append(
            f"finish attempts: {chain}; calls after the first: {m['calls_after_first_finish']}"
            + ("; verdict flipped" if m["flip"] else "")
        )
    return lines


def render(task: Task, end: dict[str, Any] | None) -> str:
    """Return the multi-line digest of a task for a reviewer."""
    lines = [
        f"[{task.number:03d} {task.id}] mode={task.mode} agent={task.agent} "
        f"model={task.model} verdict={task.verdict}"
    ]
    lines.append(f"alert: {task.alert}")
    if end:
        lines.append(
            f"end={end.get('completion_reason')} error={end.get('error')} "
            f"calls={end.get('runtime_calls')} llm={end.get('llm_calls')} "
            f"tokens={end.get('llm_tokens')} duration_s={(end.get('duration_ms') or 0) / 1000:.0f} "
            f"flags={','.join(flags(task, end) + structure_flags(metrics(task, end))) or '-'}"
        )
        if task.mode == GRADED:
            lines.append("scores: not used in graded mode")
        elif scores_hidden(end):
            lines.append("scores: hidden by the runtime")
        else:
            q, e = end.get("quality_score") or 0.0, end.get("efficiency_score") or 0.0
            lines.append(f"scores: Q={q:.2f} E={e:.2f} reward={end.get('total_reward')}")
    lines.append(f"tools: {dict(task.tools.most_common())}")
    lines.extend(economy_lines(task, metrics(task, end)))
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


def load_rows(run_dir: Path) -> list[dict[str, Any]]:
    """Read the per-task rows the watcher wrote to `monitor.jsonl`."""
    path = run_dir / "monitor.jsonl"
    if not path.exists():
        raise SystemExit(f"{path} is missing: run watch_run.py on this run first")
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def summarize(rows: list[dict[str, Any]]) -> dict[str, str]:
    """Return the run-level table as label -> text, from the watcher's rows."""

    def stat(key: str, scale: float = 1.0) -> str:
        values = [r[key] / scale for r in rows if r.get(key) is not None]
        if not values:
            return "n/a"
        return f"{sum(values) / len(values):.1f} (p90 {percentile(values):.1f})"

    flag_count = Counter(f for r in rows for f in r["flags"])
    verdicts = Counter(r["verdict"] for r in rows)
    first = rows[0] if rows else {}
    repeats = sum(r["cached"] + r["same_args"] for r in rows) / max(len(rows), 1)
    return {
        "run": f"{first.get('label')} / {first.get('model')}",
        "mode": ", ".join(sorted({r.get("mode", PRACTICE) for r in rows})) or "n/a",
        "tasks": str(len(rows)),
        "verdicts": ", ".join(f"{k} {v}" for k, v in verdicts.most_common()),
        "calls": stat("calls"),
        "ktokens": stat("tokens", 1000),
        "head ctx last, k": stat("head_last", 1000),
        "duration, s": stat("duration_s"),
        "repeats/task": f"{repeats:.1f}",
        "calls after 1st finish": stat("calls_after_first_finish"),
        "opened": stat("opened"),
        "cited": stat("cited"),
        "verdict flips": str(sum(bool(r["flip"]) for r in rows)),
        "flags": ", ".join(f"{k} {v}" for k, v in flag_count.most_common()) or "-",
    }


def append_triage(run_dir: Path, task: Task, text: str) -> str:
    """Append one triage line to `analysis.log` and return it.

    `text` must start with DEEP or SKIP so that the candidate list stays exact.
    """
    verdict = text.strip().split(maxsplit=1)[0].upper() if text.strip() else ""
    if verdict not in ("DEEP", "SKIP"):
        raise SystemExit("triage must start with DEEP or SKIP")
    line = f"[{task.number:03d} {task.id}] {task.mode} {clip(text, 220)}"
    with (run_dir / TRIAGE_LOG).open("a") as log:
        log.write(line + "\n")
    return line


def deep_candidates(run_dir: Path) -> list[str]:
    """Return the task numbers triaged DEEP and not yet superseded by a SKIP."""
    path = run_dir / TRIAGE_LOG
    state: dict[str, bool] = {}
    for line in path.read_text().splitlines() if path.exists() else []:
        parts = line.split()
        if len(parts) >= 4 and parts[0].startswith("["):
            state[parts[0].lstrip("[")] = parts[3].upper() == "DEEP"
    return [number for number, deep in state.items() if deep]


def build(path: Path, mode: str | None = None) -> tuple[Task, dict[str, Any] | None]:
    """Replay one trace file into a Task and its `task_end` event, if any."""
    number = int(path.name.split("_", 1)[0])
    task: Task | None = None
    end = None
    for event in read_events(path):
        task = task or Task(number, event["task_id"], mode)
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
