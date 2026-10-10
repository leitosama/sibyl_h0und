"""Stream a run's trace directory: anomalies and totals only, every task in a log.

Usage: uv run python watch_run.py [RUN_DIR] [--seen N] [--verbose]

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

from taskdigest import Task, flags, scores_hidden  # noqa: E402

from sibyl_h0und.replay import DEFAULT_TRACES, DEFAULT_WRONG_BELOW  # noqa: E402

STALL_SECONDS = 300
TOTALS_EVERY = 5
POLL_SECONDS = 2
LOG_NAME = "monitor.log"


def wait_for_new_run(root: Path, started: float) -> Path:
    """Return the first run directory under `root` created after `started`."""
    while True:
        fresh = [p for p in root.glob("*/") if p.stat().st_mtime >= started]
        if fresh:
            return min(fresh, key=lambda p: p.stat().st_mtime)
        time.sleep(POLL_SECONDS)


def task_line(task: Task, end: dict[str, Any]) -> tuple[str, dict[str, float | None]]:
    """Format one finished task and return its numbers for the totals."""
    hidden = scores_hidden(end)
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
        result = f"Result={task.verdict} (scores hidden)"
    else:
        result = f"Result={task.verdict} {'correct' if q >= DEFAULT_WRONG_BELOW else 'incorrect'}"
    return f"[{task.number:03d} {task.id}] {numbers}\n{result}", row


def why_lines(task: Task) -> str:
    """Return the reasons behind the flags, a few short lines for the reviewer."""
    lines = [f"alert: {task.alert}"]
    if task.hypotheses:
        lines.append(f"challenge: {task.hypotheses[0]}")
    if task.refusals:
        lines.append(f"refused: {task.refusals[0]}")
    if task.errors:
        lines.append(f"error: {task.errors[0]}")
    return "\n".join(lines)


def totals_line(rows: list[dict[str, float | None]], last: int) -> str:
    """Format the means of the last few finished tasks; hidden scores print as n/a."""

    def mean(key: str) -> float | None:
        known = [r[key] for r in rows if r[key] is not None]
        return sum(known) / len(known) if known else None

    def fmt(key: str, spec: str) -> str:
        value = mean(key)
        return "n/a" if value is None else format(value, spec)

    n = len(rows)
    scored = [r for r in rows if r["Q"] is not None]
    wrong = sum(r["Q"] < DEFAULT_WRONG_BELOW for r in scored)
    incorrect = f"{wrong}/{len(scored)}" if scored else "n/a"
    return (
        f"=== Tasks {last - n + 1:03d}-{last:03d}: mean Q={fmt('Q', '.2f')} E={fmt('E', '.2f')} "
        f"score={fmt('score', '.2f')} reward={fmt('reward', '.0f')} calls={fmt('calls', '.1f')} "
        f"llm={fmt('llm', '.1f')} llm_s={fmt('llm_s', '.0f')} ktok={fmt('ktok', '.0f')} "
        f"incorrect={incorrect}"
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
    """Watch a run and print each flagged task."""
    args = sys.argv[1:]
    seen = 0
    if "--seen" in args:
        i = args.index("--seen")
        seen = int(args[i + 1])
        del args[i : i + 2]
    verbose = "--verbose" in args
    args = [a for a in args if a != "--verbose"]
    started = time.time()
    if args:
        run_dir = Path(args[0])
    else:
        print(f"Waiting for a new run under {DEFAULT_TRACES}", flush=True)
        run_dir = wait_for_new_run(DEFAULT_TRACES, started)
    print(f"Watching {run_dir} (full log: {run_dir / LOG_NAME})", flush=True)

    offsets: dict[Path, int] = {}
    tasks: dict[Path, Task] = {}
    rows: list[dict[str, float | None]] = []
    log_path = run_dir / LOG_NAME
    logged = {
        line.split("]")[0] + "]"
        for line in (log_path.read_text().splitlines() if log_path.exists() else [])
        if line.startswith("[")
    }
    last_event, stalled = time.time(), False
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
                end = task.feed(event)
                if end is None:
                    continue
                text, row = task_line(task, end)
                rows.append(row)
                key = f"[{task.number:03d} {task.id}]"
                if number <= seen or key in logged:
                    continue
                found = flags(task, end)
                block = f"{text}\nflags={','.join(found) or '-'}"
                if found:
                    block += f"\n{why_lines(task)}"
                with log_path.open("a") as log:
                    log.write(block + "\n")
                if found or verbose:
                    print(block, flush=True)
                if len(rows) % TOTALS_EVERY == 0:
                    print(totals_line(rows[-TOTALS_EVERY:], number), flush=True)
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
