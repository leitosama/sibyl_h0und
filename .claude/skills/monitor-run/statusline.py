"""Claude Code status line for the active runs: a line per run, no model tokens, fast.

Configure in `.claude/settings.local.json`:

    {"statusLine": {"type": "command",
                    "command": "python3 .claude/skills/monitor-run/statusline.py",
                    "refreshInterval": 5}}

Runs are the newest directories under `$TRACE_DIR` (default
`~/.local/share/sibyl_h0und/traces`) that have a live `h0und` process or a trace
written in the last 15 minutes; `$MONITOR_RUN_DIR` pins one run. Finished tasks
come from `monitor.jsonl` (written by `watch_run.py`); the running task is read
from the tail of its trace. It prints nothing when there is no run, never raises.
"""

import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "analyze-task"))

from runview import (  # noqa: E402
    deep_candidates,
    eta,
    expected_total,
    match_runs,
    progress,
    read_rows,
    run_tag,
    run_totals,
    run_ts,
    short_count,
    symbol,
)

QUIET_SECONDS = 300
ACTIVE_SECONDS = 900
TAIL_BYTES = 400_000
MAX_RUNS = 3
MAX_ACTIVE, MAX_STARTS = 2, 5
RED, YELLOW, GREEN, GREY, RESET = "\033[31m", "\033[33m", "\033[32m", "\033[90m", "\033[0m"


def traces_root() -> Path:
    """Return the traces directory."""
    return Path(os.environ.get("TRACE_DIR", "~/.local/share/sibyl_h0und/traces")).expanduser()


def run_dirs(root: Path) -> list[Path]:
    """Return the run directories under `root`, newest first."""
    runs = [p for p in root.glob("*/") if p.is_dir() and run_ts(p.name) is not None]
    return sorted(runs, key=lambda p: run_ts(p.name) or 0.0, reverse=True)


def last_write(directory: Path) -> float:
    """Return the newest trace mtime in a run directory, 0 when it has none."""
    return max((p.stat().st_mtime for p in directory.glob("*.trace.jsonl")), default=0.0)


def running_task(directory: Path, done: set[int]) -> dict | None:
    """Return calls, head context, age and quiet time of the task being written, or None."""
    for path in reversed(sorted(directory.glob("*.trace.jsonl"))):
        number = int(path.name.split("_", 1)[0])
        if number in done:
            continue
        data = path.read_bytes()
        context = re.findall(rb'"role": "head"[^\n]*?"tokens": (\d+)', data[-TAIL_BYTES:])
        first = re.search(rb'"ts": "([^"]+)"', data[:400])
        started = datetime.fromisoformat(first.group(1).decode()).timestamp() if first else None
        now = time.time()
        return {
            "number": number,
            "calls": data.count(b'"kind": "tool_call"'),
            "context": int(context[-1]) if context else 0,
            "age": now - started if started else 0.0,
            "quiet": now - path.stat().st_mtime,
        }
    return None


def run_lines(directory: Path, pid: int | None) -> list[str]:
    """Return the status lines of one run: the totals line and, when running, the task."""
    rows = read_rows(directory)
    first = rows[0] if rows else {}
    mode = first.get("mode") or "practice"
    tag = first.get("tag") or run_tag(directory.name, mode)
    t = run_totals(rows, expected_total(mode, first.get("total")))
    color = RED if mode == "graded" else GREY
    deep = deep_candidates(directory)
    live = running_task(directory, {r["number"] for r in rows})
    head = (
        f"{color}{tag}{RESET} {first.get('agent', '')} {progress(t)} · "
        f"{GREEN}✔{t['ok']}{RESET} {YELLOW}⚠{t['warn']}{RESET} {RED}✖{t['fail']}{RESET} · "
        f"⌀{t['calls']:.0f} calls · {short_count(t['tokens'])} tok · ETA {eta(t)}"
    )
    parts = [head]
    if live and pid is not None:
        quiet = live["quiet"] > QUIET_SECONDS
        state = (
            f"{YELLOW}quiet {live['quiet'] / 60:.0f}m{RESET}"
            if quiet
            else f"{live['age'] / 60:.0f}m"
        )
        parts.append(
            f"#{live['number']:03d} {live['calls']}c ctx {short_count(live['context'])} {state}"
        )
    elif pid is None:
        parts.append(f"{GREY}ended{RESET}")
    if deep:
        parts.append(f"{YELLOW}DEEP {','.join(deep)}{RESET}")
    flagged = [f"{symbol(r)}{r['number']:03d}" for r in rows if r.get("flags")][-3:]
    if flagged:
        parts.append(" ".join(flagged))
    return [" · ".join(parts)]


def render(root: Path) -> str:
    """Return the status text for the active runs under `root`."""
    pinned = os.environ.get("MONITOR_RUN_DIR")
    recent = [Path(pinned)] if pinned else run_dirs(root)[:12]
    bound = match_runs(recent)
    now = time.time()
    active = [
        d for d in recent if bound.get(d) is not None or now - last_write(d) < ACTIVE_SECONDS
    ][:MAX_RUNS]
    lines = []
    for directory in active:
        lines.extend(run_lines(directory, bound.get(directory)))
    starts = sum(1 for d in run_dirs(root) if (run_ts(d.name) or 0) >= now - 1800)
    alive = sum(1 for d in active if bound.get(d) is not None)
    over = alive > MAX_ACTIVE or starts > MAX_STARTS
    tail = f"starts 30m {starts}/{MAX_STARTS} · active {alive}/{MAX_ACTIVE}"
    lines.append(f"{RED if over else GREY}{tail}{RESET}")
    return "\n".join(lines)


def main() -> None:
    """Print the status line; stay silent on any problem."""
    try:
        root = traces_root()
        if root.is_dir():
            print(render(root))
    except Exception:  # a status line must never break the session
        return


if __name__ == "__main__":
    main()
