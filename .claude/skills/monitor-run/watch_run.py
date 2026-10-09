"""Stream a run's trace directory as one compact block per finished task.

Usage: uv run python watch_run.py [RUN_DIR] [--seen N]

Without RUN_DIR the script waits for the first run directory created after it
started, so start it together with `h0und`. Tasks numbered N or below are read
for the running totals but not printed, and neither is anything already in the
traces when the watch starts, so a re-armed watch repeats nothing. The script
exits when the traces go quiet and no `h0und` process runs.
"""

import json
import shutil
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

from sibyl_h0und.catalog import FINISH_TOOL
from sibyl_h0und.investigation import find_report
from sibyl_h0und.replay import DEFAULT_TRACES, DEFAULT_WRONG_BELOW

STALL_SECONDS = 300
TOTALS_EVERY = 5
POLL_SECONDS = 2


def wait_for_new_run(root: Path, started: float) -> Path:
    """Return the first run directory under `root` created after `started`."""
    while True:
        fresh = [p for p in root.glob("*/") if p.stat().st_mtime >= started]
        if fresh:
            return min(fresh, key=lambda p: p.stat().st_mtime)
        time.sleep(POLL_SECONDS)


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


class Task:
    """Counters of one task, fed event by event."""

    def __init__(self, number: int, task_id: str):
        self.number, self.id = number, task_id[:8]
        self.verdict = "?"
        self.challenged = self.rejected = self.refused = self.tool_errors = 0
        self.answers_refused = 0
        self.llm_errors = 0
        self.reporter = "none"
        self.fallback: str | None = None
        self.ended = False

    def feed(self, event: dict[str, Any]) -> dict[str, Any] | None:
        """Take one event; return it when it ends the task."""
        kind, payload = event["kind"], event.get("payload") or {}
        if kind == "tool_call":
            if event.get("tool") == FINISH_TOOL:
                report = find_report(payload.get("arguments") or {}) or {}
                self.verdict = report.get("verdict", self.verdict)
            if event.get("status") != "ok":
                self.tool_errors += 1
        elif kind == "llm_error":
            self.llm_errors += 1
        elif kind == "tool_rejected":
            self.rejected += 1
        elif kind == "report_refused":
            self.refused += 1
        elif kind == "benign_challenged":
            self.challenged += 1
        elif kind == "answers_refused":
            self.answers_refused += 1
        elif kind == "report_written":
            self.fallback = event.get("fallback")
            self.reporter = reporter_change(payload, self.fallback)
        elif kind == "task_end":
            self.ended = True
            return event
        return None


def task_line(task: Task, end: dict[str, Any]) -> tuple[str, dict[str, float]]:
    """Format one finished task and return its numbers for the totals."""
    q, e = end.get("quality_score") or 0.0, end.get("efficiency_score") or 0.0
    row = {
        "Q": q,
        "E": e,
        "score": q * (0.6 + 0.4 * e),
        "reward": end.get("total_reward") or 0.0,
        "calls": end.get("runtime_calls") or 0,
        "llm": end.get("llm_calls") or 0,
        "llm_s": (end.get("llm_ms") or 0) / 1000,
    }
    numbers = (
        f"Q={q:.2f} E={e:.2f} score={row['score']:.2f} reward={row['reward']:.0f} "
        f"calls={row['calls']} llm={row['llm']} llm_s={row['llm_s']:.0f} "
        f"challenged={task.challenged} answers_refused={task.answers_refused} "
        f"reporter={task.reporter} fallback={task.fallback} "
        f"rejected={task.rejected} refused={task.refused} tool_errors={task.tool_errors} "
        f"llm_errors={task.llm_errors} end={end.get('completion_reason')} "
        f"error={end.get('error')}"
    )
    correct = "correct" if q >= DEFAULT_WRONG_BELOW else "incorrect"
    return f"[{task.number:03d} {task.id}] {numbers}\nResult={task.verdict} {correct}", row


def totals_line(rows: list[dict[str, float]], last: int) -> str:
    """Format the means of the last few finished tasks."""
    n = len(rows)
    mean = {k: sum(r[k] for r in rows) / n for k in rows[0]}
    wrong = sum(r["Q"] < DEFAULT_WRONG_BELOW for r in rows)
    return (
        f"=== Tasks {last - n + 1:03d}-{last:03d}: mean Q={mean['Q']:.2f} E={mean['E']:.2f} "
        f"score={mean['score']:.2f} reward={mean['reward']:.0f} calls={mean['calls']:.1f} "
        f"llm={mean['llm']:.1f} llm_s={mean['llm_s']:.0f} incorrect={wrong}/{n}"
    )


def agent_running() -> bool:
    """Tell whether an `h0und` process runs; assume it does when pgrep is missing."""
    if shutil.which("pgrep") is None:
        return True
    found = subprocess.run(["pgrep", "-f", "bin/h0und"], capture_output=True, check=False)
    return found.returncode == 0


def complete_lines(path: Path, offset: int) -> tuple[list[bytes], int]:
    """Read whole lines from `offset`; a partly written last line waits for the next poll."""
    with path.open("rb") as fh:
        fh.seek(offset)
        chunk = fh.read()
    end = chunk.rfind(b"\n") + 1
    return chunk[:end].splitlines(), offset + end


def main() -> None:
    """Watch a run and print each finished task."""
    args = sys.argv[1:]
    seen = 0
    if "--seen" in args:
        i = args.index("--seen")
        seen = int(args[i + 1])
        del args[i : i + 2]
    started = time.time()
    if args:
        run_dir = Path(args[0])
    else:
        print(f"Waiting for a new run under {DEFAULT_TRACES}", flush=True)
        run_dir = wait_for_new_run(DEFAULT_TRACES, started)
    print(f"Watching {run_dir}", flush=True)

    offsets: dict[Path, int] = {}
    tasks: dict[Path, Task] = {}
    rows: list[dict[str, float]] = []
    last_event, stalled, catching_up = time.time(), False, True
    while True:
        for path in sorted(run_dir.glob("*.trace.jsonl")):
            if path in tasks and tasks[path].ended:
                continue
            number = int(path.name.split("_", 1)[0])
            lines, offsets[path] = complete_lines(path, offsets.get(path, 0))
            for line in lines:
                last_event, stalled = time.time(), False
                event = json.loads(line)
                if path not in tasks:
                    tasks[path] = Task(number, event["task_id"])
                task = tasks[path]
                live = number > seen and not catching_up
                if event["kind"] == "task_start" and live:
                    print(f"[{number:03d} {task.id}] START", flush=True)
                end = task.feed(event)
                if end is None:
                    continue
                text, row = task_line(task, end)
                rows.append(row)
                if number > seen:
                    print(text, flush=True)
                    if len(rows) % TOTALS_EVERY == 0:
                        print(totals_line(rows[-TOTALS_EVERY:], number), flush=True)
        catching_up = False
        if not stalled and time.time() - last_event > STALL_SECONDS:
            stalled = True
            if not agent_running():
                print(f"RUN ENDED: {len(rows)} tasks, no h0und process", flush=True)
                return
            minutes = STALL_SECONDS // 60
            print(f"STALL: no trace events for {minutes} min, h0und still runs", flush=True)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
