"""Claude Code status line for a run: two lines, no model tokens, fast.

Configure in `.claude/settings.local.json`:

    {"statusLine": {"type": "command",
                    "command": "python3 .claude/skills/monitor-run/statusline.py",
                    "refreshInterval": 5}}

The run is the newest directory under `$TRACE_DIR` (default
`~/.local/share/sibyl_h0und/traces`), or `$MONITOR_RUN_DIR`. Finished tasks come
from `monitor.jsonl` (written by `watch_run.py`); the running task is read from
the tail of its trace. It prints nothing when there is no run, never raises.
"""

import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "analyze-task"))

from runview import (  # noqa: E402
    COMPETITION_TASKS,
    deep_candidates,
    read_rows,
    run_totals,
    short_count,
    symbol,
)

QUIET_SECONDS = 300
TAIL_BYTES = 400_000
RED, YELLOW, GREEN, GREY, RESET = "\033[31m", "\033[33m", "\033[32m", "\033[90m", "\033[0m"


def run_dir() -> Path | None:
    """Return the run directory to show, or None."""
    chosen = os.environ.get("MONITOR_RUN_DIR")
    if chosen:
        return Path(chosen)
    root = Path(os.environ.get("TRACE_DIR", "~/.local/share/sibyl_h0und/traces")).expanduser()
    runs = [p for p in root.glob("*/") if p.is_dir()]
    return max(runs, key=lambda p: p.stat().st_mtime) if runs else None


def running_task(directory: Path, done: set[int]) -> dict | None:
    """Return calls, head context, age and quiet time of the task being written, or None."""
    files = sorted(directory.glob("*.trace.jsonl"))
    for path in reversed(files):
        number = int(path.name.split("_", 1)[0])
        if number in done:
            continue
        data = path.read_bytes()
        calls = data.count(b'"kind": "tool_call"')
        tail = data[-TAIL_BYTES:]
        context = re.findall(rb'"role": "head"[^\n]*?"tokens": (\d+)', tail)
        first = re.search(rb'"ts": "([^"]+)"', data[:400])
        started = datetime.fromisoformat(first.group(1).decode()).timestamp() if first else None
        now = time.time()
        return {
            "number": number,
            "calls": calls,
            "context": int(context[-1]) if context else 0,
            "age": now - started if started else 0.0,
            "quiet": now - path.stat().st_mtime,
        }
    return None


def render(directory: Path) -> str:
    """Return the status text for a run directory."""
    rows = read_rows(directory)
    first = rows[0] if rows else {}
    mode = first.get("mode") or "run"
    color = RED if mode == "graded" else GREY
    total = COMPETITION_TASKS if mode == "graded" else max(len(rows), COMPETITION_TASKS)
    t = run_totals(rows, total)
    deep = deep_candidates(directory)
    head = (
        f"{color}{mode}{RESET} {first.get('agent', '')} · {t['done']}/{t['total']} · "
        f"{GREEN}✔{t['ok']}{RESET} {YELLOW}⚠{t['warn']}{RESET} {RED}✖{t['fail']}{RESET} · "
        f"⌀{t['calls']:.0f} calls · {short_count(t['tokens'])} tok · ETA {t['eta_min']:.0f}m"
        + (f" · {YELLOW}DEEP {', '.join(deep)}{RESET}" if deep else "")
    )
    lines = [head]
    live = running_task(directory, {r["number"] for r in rows})
    flagged = [r for r in rows if r.get("flags")][-3:]
    parts = []
    if live:
        quiet = live["quiet"] > QUIET_SECONDS
        state = (
            f"{YELLOW}quiet {live['quiet'] / 60:.0f}m{RESET}"
            if quiet
            else f"{live['age'] / 60:.0f}m"
        )
        parts.append(
            f"#{live['number']:03d} now: {live['calls']} calls · ctx {short_count(live['context'])}"
            f" · {state}"
        )
    for row in flagged:
        parts.append(f"{symbol(row)}{row['number']:03d} {','.join(row['flags'][:2])}")
    if parts:
        lines.append(" · ".join(parts))
    return "\n".join(lines)


def main() -> None:
    """Print the status line; stay silent on any problem."""
    try:
        if not sys.stdin.isatty():
            json.load(sys.stdin)
    except ValueError:
        pass
    try:
        directory = run_dir()
        if directory is not None and directory.is_dir():
            print(render(directory))
    except Exception:  # a status line must never break the session
        return


if __name__ == "__main__":
    main()
