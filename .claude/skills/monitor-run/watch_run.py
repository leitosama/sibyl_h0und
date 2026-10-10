"""Stream a run's trace directory: anomalies and totals only, every task in a log.

Usage: uv run python watch_run.py [RUN_DIR] [--seen N] [--verbose] [--total N]
       [--mode graded|practice]

Standard output is one line per event, each starting with a fixed keyword or
glyph (`MODE`, `⚠`/`✖`, `Σ`, `DASHBOARD`, `STALL`, `RUN ENDED`); `--total` is
the task count the `Σ` line and the ETA count to (default 40).

The mode comes from the run's `agent_name` (`h0und1` is graded, the competition
token; anything else is practice) unless `--mode` is given. In graded mode the
scores are never shown and the watch is strictly read-only: it never starts or
changes a run, and the run's metadata stays as `.env.h0und1` sets it.

Without RUN_DIR the script waits for the first run directory created after it
started, so start it together with `h0und`. Every finished task is appended to
`monitor.log` in the run directory. Standard output, which wakes the model,
carries a task only when it has flags (a benign verdict, a challenge, a refusal,
an error, a low Q), plus a totals line every few tasks; `--verbose` prints all.
Tasks numbered N or below are read for the totals but not printed, and neither
is a task already in `monitor.log`, so a re-armed watch repeats nothing. The
script exits when the traces go quiet and no `h0und` process runs.
"""

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "analyze-task"))

from taskdigest import (  # noqa: E402
    GRADED,
    PRACTICE,
    Task,
    clip,
    deep_candidates,
    event_line,
    flags,
    metrics,
    percentile,
    structure_flags,
    totals_event_line,
)
from taskdigest import hidden as scores_not_shown  # noqa: E402

from sibyl_h0und.replay import DEFAULT_TRACES, DEFAULT_WRONG_BELOW  # noqa: E402

STALL_SECONDS = 300
TOTALS_EVERY = 5
DASHBOARD_EVERY = 10
POLL_SECONDS = 2
LOG_NAME = "monitor.log"
JSONL_NAME = "monitor.jsonl"
MIN_HISTORY = 5  # finished tasks before a p90 flag means anything


def wait_for_new_run(root: Path, started: float) -> Path:
    """Return the first run directory under `root` created after `started`."""
    while True:
        fresh = [p for p in root.glob("*/") if p.stat().st_mtime >= started]
        if fresh:
            return min(fresh, key=lambda p: p.stat().st_mtime)
        time.sleep(POLL_SECONDS)


def task_line(task: Task, end: dict[str, Any]) -> str:
    """Format one finished task for `monitor.log`, with scores only when they may be shown."""
    hidden = scores_not_shown(task, end)
    q = None if hidden else end.get("quality_score") or 0.0
    e = None if hidden else end.get("efficiency_score") or 0.0
    row = {
        "Q": q,
        "E": e,
        "score": None if q is None or e is None else q * (0.6 + 0.4 * e),
        "reward": None if hidden else end.get("total_reward") or 0.0,
        "calls": end.get("runtime_calls") or 0,
        "llm": end.get("llm_calls") or 0,
        "llm_s": (end.get("llm_ms") or 0) / 1000,
        "ktok": (end.get("llm_tokens") or 0) / 1000,
    }

    def fmt(key: str, spec: str) -> str:
        return "n/a" if row[key] is None else format(row[key], spec)

    numbers = (
        f"Q={fmt('Q', '.2f')} E={fmt('E', '.2f')} score={fmt('score', '.2f')} "
        f"reward={fmt('reward', '.0f')} calls={row['calls']} llm={row['llm']} "
        f"llm_s={row['llm_s']:.0f} ktok={row['ktok']:.0f} "
        f"challenged={task.challenged} reporter={task.reporter} fallback={task.fallback} "
        f"rejected={task.rejected} refused={task.refused} tool_errors={task.tool_errors} "
        f"llm_errors={task.llm_errors} end={end.get('completion_reason')} "
        f"error={end.get('error')}"
    )
    # Without scores `correct`/`incorrect` would be a guess from nothing.
    if q is None:
        result = f"Result={task.verdict} (scores not shown, {task.mode})"
    else:
        result = f"Result={task.verdict} {'correct' if q >= DEFAULT_WRONG_BELOW else 'incorrect'}"
    return f"[{task.number:03d} {task.id}] {numbers}\n{result}"


def why_lines(task: Task) -> str:
    """Return the reasons behind the flags, a few short lines for `monitor.log`."""
    lines = [f"alert: {task.alert}"]
    if task.hypotheses:
        lines.append(f"challenge: {task.hypotheses[0]}")
    if task.refusals:
        lines.append(f"refused: {task.refusals[0]}")
    if task.errors:
        lines.append(f"error: {task.errors[0]}")
    return "\n".join(lines)


def why_line(task: Task) -> str:
    """Return the single most telling reason behind the flags, clipped to one line."""
    for label, items in (
        ("challenge", task.hypotheses),
        ("refused", task.refusals),
        ("error", task.errors),
    ):
        if items:
            return f"{label}: {clip(items[0], 110)}"
    return f"alert: {clip(task.alert, 110)}"


def mode_banner(task: Task) -> str:
    """Name the mode once, with what it forbids; flag a `--mode` the traces contradict."""
    head = f"{task.mode} · {task.agent} · {task.label} · {task.model}"
    if task.mode_mismatch:
        return f"MODE MISMATCH --mode {task.mode} but the traces say agent={task.agent} · {head}"
    if task.mode == GRADED:
        return f"MODE {head} · read-only, metadata stays as .env.h0und1 sets it"
    return f"MODE {head}"


def relative_flags(m: dict[str, Any], earlier: list[dict[str, Any]]) -> list[str]:
    """Flag a task whose time or tokens exceed the p90 of the tasks before it."""
    if len(earlier) < MIN_HISTORY:
        return []
    found = []
    for flag, key in (("slow", "duration_s"), ("heavy", "tokens")):
        limit = percentile([e[key] for e in earlier])
        if limit is not None and m[key] > limit:
            found.append(flag)
    return found


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
    """Watch a run and print each flagged task."""
    args = sys.argv[1:]
    seen = 0
    if "--seen" in args:
        i = args.index("--seen")
        seen = int(args[i + 1])
        del args[i : i + 2]
    verbose = "--verbose" in args
    args = [a for a in args if a != "--verbose"]
    mode = None
    if "--mode" in args:
        i = args.index("--mode")
        mode = args[i + 1]
        if mode not in (GRADED, PRACTICE):
            raise SystemExit("--mode must be graded or practice")
        del args[i : i + 2]
    total = None
    if "--total" in args:
        i = args.index("--total")
        total = int(args[i + 1])
        del args[i : i + 2]
    started = time.time()
    if args:
        run_dir = Path(args[0])
    else:
        print(f"Waiting for a new run under {DEFAULT_TRACES}", flush=True)
        run_dir = wait_for_new_run(DEFAULT_TRACES, started)
    print(f"Watching {run_dir} (full log: {run_dir / LOG_NAME})", flush=True)

    offsets: dict[Path, int] = {}
    tasks: dict[Path, Task] = {}
    history: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    jsonl_path = run_dir / JSONL_NAME
    if jsonl_path.exists():
        records = [json.loads(x) for x in jsonl_path.read_text().splitlines() if x.strip()]
    log_path = run_dir / LOG_NAME
    logged = {
        line.split("]")[0] + "]"
        for line in (log_path.read_text().splitlines() if log_path.exists() else [])
        if line.startswith("[")
    }
    last_event, stalled, announced = time.time(), False, False
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
                    tasks[path] = Task(number, event["task_id"], mode)
                task = tasks[path]
                end = task.feed(event)
                if event["kind"] == "task_start" and not announced:
                    announced = True
                    print(mode_banner(task), flush=True)
                if end is None:
                    continue
                text = task_line(task, end)
                m = metrics(task, end)
                earlier, history = history, [*history, m]
                key = f"[{task.number:03d} {task.id}]"
                if number <= seen or key in logged:
                    continue
                found = flags(task, end) + structure_flags(m) + relative_flags(m, earlier)
                block = f"{text}\nflags={','.join(found) or '-'}"
                if found:
                    block += f"\n{why_lines(task)}"
                with log_path.open("a") as log:
                    log.write(block + "\n")
                record = {
                    "number": task.number,
                    "id": task.id,
                    "verdict": task.verdict,
                    "flags": found,
                    "model": task.model,
                    "label": task.label,
                    "mode": task.mode,
                    "agent": task.agent,
                    "scores_hidden": scores_not_shown(task, end),
                    **m,
                }
                with (run_dir / JSONL_NAME).open("a") as jsonl:
                    jsonl.write(json.dumps(record, ensure_ascii=False) + "\n")
                records.append(record)
                if found or verbose:
                    print(f"{event_line(record)}\n  {why_line(task)}", flush=True)
                if len(records) % TOTALS_EVERY == 0:
                    deep = deep_candidates(run_dir)
                    print(totals_event_line(records, deep, total), flush=True)
                    if len(records) % DASHBOARD_EVERY == 0:
                        print(f"DASHBOARD {run_dir}", flush=True)
        if not stalled and time.time() - last_event > STALL_SECONDS:
            stalled = True
            if not agent_running():
                print(f"RUN ENDED {len(records)} tasks, no h0und process", flush=True)
                print(totals_event_line(records, deep_candidates(run_dir), total), flush=True)
                print(f"DASHBOARD {run_dir}", flush=True)
                return
            minutes = STALL_SECONDS // 60
            print(f"STALL {minutes}m without trace events, h0und still runs", flush=True)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
