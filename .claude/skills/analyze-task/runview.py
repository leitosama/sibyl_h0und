"""Light helpers that turn finished-task rows into one-line views of a run.

No project imports on purpose: the status line calls this on every refresh and
must start fast. Rows are the dicts the watcher writes to `monitor.jsonl`.
"""

import json
import os
import re
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Queue sizes by mode: graded is 40 by the competition rules, the practice arena has 30.
TASKS_BY_MODE = {"graded": 40, "practice": 30}
TRIAGE_LOG = "analysis.log"
JSONL_NAME = "monitor.jsonl"
START_WINDOW = (-600.0, 10.0)  # process start relative to the run directory's timestamp


def expected_total(mode: str | None, override: int | None = None) -> int | None:
    """Return the queue size to count to: an override, the mode's size, or None."""
    return override or TASKS_BY_MODE.get(mode or "")


def run_ts(name: str) -> float | None:
    """Return the UTC epoch in a run directory name like `20261010T101949Z_<uuid>`."""
    found = re.match(r"(\d{8}T\d{6})Z_", name)
    if not found:
        return None
    parsed = datetime.strptime(found.group(1), "%Y%m%dT%H%M%S")
    return parsed.replace(tzinfo=UTC).timestamp()


def run_tag(name: str, mode: str | None) -> str:
    """Return a short stable label such as `G1019` (graded) or `P1023` (practice)."""
    found = re.match(r"\d{8}T(\d{4})\d{2}Z_", name)
    letter = "G" if mode == "graded" else "P"
    return f"{letter}{found.group(1) if found else name[:4]}"


def symbol(row: dict[str, Any]) -> str:
    """Return the state glyph of a finished task row: ok, flagged, or failed."""
    found = row.get("flags") or []
    if {"not_terminated", "tool_errors", "llm_errors"} & set(found):
        return "✖"
    return "⚠" if found else "✔"


def short_count(value: float) -> str:
    """Return a token or call count as 678k / 1.2M."""
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}M"
    if value >= 1000:
        return f"{value / 1000:.0f}k"
    return f"{value:.0f}"


def event_line(row: dict[str, Any], note: str = "", tag: str = "") -> str:
    """One line for a finished task: glyph, run tag, number, verdict, flags, calls, tokens."""
    found = ",".join(row.get("flags") or []) or "-"
    gates = [g for g in row.get("gates") or [] if g != "sent"]
    chain = "→".join(dict.fromkeys(gates))
    tag = tag or row.get("tag") or ""
    parts = [
        f"{symbol(row)} {tag + ' ' if tag else ''}#{row['number']:03d}",
        row.get("verdict", "?"),
        found + (f" [{chain}]" if chain else ""),
        f"{row.get('calls', 0)} calls",
        f"{short_count(row.get('tokens', 0))} tok",
    ]
    if note:
        parts.append(note)
    return " · ".join(parts)


def run_totals(rows: list[dict[str, Any]], total: int | None = None) -> dict[str, Any]:
    """Return the counters of the totals line, the status line and the dashboard.

    `total` None means the queue size is unknown: `total` and `eta_min` stay None.
    """
    n = len(rows)
    glyphs = Counter(symbol(r) for r in rows)
    durations = [r.get("duration_s") or 0 for r in rows]
    mean_duration = sum(durations) / n if n else 0.0
    return {
        "done": n,
        "total": total,
        "ok": glyphs["✔"],
        "warn": glyphs["⚠"],
        "fail": glyphs["✖"],
        "calls": sum(r.get("calls") or 0 for r in rows) / n if n else 0.0,
        "tokens": sum(r.get("tokens") or 0 for r in rows),
        "eta_min": None if total is None else mean_duration * max(total - n, 0) / 60,
    }


def progress(t: dict[str, Any]) -> str:
    """Return `done/total` with `?` when the queue size is unknown."""
    return f"{t['done']}/{t['total'] if t['total'] is not None else '?'}"


def eta(t: dict[str, Any]) -> str:
    """Return the ETA in minutes, or `?`."""
    return "?" if t["eta_min"] is None else f"{t['eta_min']:.0f}m"


def triage_answers(run_dir: Path) -> dict[str, str]:
    """Return `analysis.log` as {task number: latest answer text}, `DEEP ...` or `SKIP ...`."""
    path = run_dir / TRIAGE_LOG
    answers: dict[str, str] = {}
    for line in path.read_text().splitlines() if path.exists() else []:
        parts = line.split(maxsplit=4)
        if len(parts) >= 4 and parts[0].startswith("["):
            tail = line.split("] ", 1)[1].split(maxsplit=1)
            answers[parts[0].lstrip("[")] = tail[1] if len(tail) > 1 else ""
    return answers


def deep_candidates(run_dir: Path) -> list[str]:
    """Return the task numbers triaged DEEP and not yet superseded by a SKIP."""
    found = []
    for number, text in triage_answers(run_dir).items():
        first = text.split(maxsplit=1)[0].upper() if text.split() else ""
        if first == "DEEP":
            found.append(number)
    return found


def totals_event_line(
    rows: list[dict[str, Any]], deep: list[str], total: int | None = None, tag: str = ""
) -> str:
    """One line for the run so far: progress, glyph counts, cost, ETA, deep candidates."""
    t = run_totals(rows, total)
    shown = ", ".join(deep[:6]) + (f" +{len(deep) - 6}" if len(deep) > 6 else "")
    return (
        f"Σ {tag + ' ' if tag else ''}{progress(t)} · ✔{t['ok']} ⚠{t['warn']} ✖{t['fail']} · "
        f"⌀{t['calls']:.0f} calls · {short_count(t['tokens'])} tok · ETA {eta(t)} · "
        f"DEEP {len(deep)}: {shown or '-'}"
    )


def read_rows(run_dir: Path) -> list[dict[str, Any]]:
    """Read `monitor.jsonl`, skipping a partly written last line; empty when missing."""
    path = run_dir / JSONL_NAME
    if not path.exists():
        return []
    rows = []
    for line in path.read_text().splitlines():
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    return rows


def h0und_processes() -> list[tuple[int, float]]:
    """Return (pid, start epoch) of every running `h0und` agent process, via /proc.

    The agent is the interpreter running `.../bin/h0und`; `uv run ... h0und`
    (the launcher) has no such argument and is not counted.
    """
    proc = Path("/proc")
    try:
        boot = next(
            float(line.split()[1])
            for line in (proc / "stat").read_text().splitlines()
            if line.startswith("btime")
        )
        ticks = os.sysconf("SC_CLK_TCK")
    except (OSError, StopIteration, ValueError):
        return []
    found = []
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            argv = (entry / "cmdline").read_bytes().split(b"\0")
            if not any(a.endswith(b"/bin/h0und") for a in argv[:3]):
                continue
            stat = (entry / "stat").read_text()
            start_ticks = float(stat.rsplit(")", 1)[1].split()[19])
        except (OSError, ValueError, IndexError):
            continue
        found.append((int(entry.name), boot + start_ticks / ticks))
    return found


def match_runs(dirs: list[Path]) -> dict[Path, int | None]:
    """Bind each run directory to the `h0und` process that created it, or None.

    A run directory is created at `CreateRun`, shortly after its process starts,
    so the newest directory takes the latest process that started before it,
    then the next newest takes the next process, and so on. Two runs started in
    the same second may swap, which only matters for the end-of-run signal.
    """
    free = sorted(h0und_processes(), key=lambda p: p[1], reverse=True)
    bound: dict[Path, int | None] = {}
    stamped = [(run_ts(d.name), d) for d in dirs]
    for ts, directory in sorted(stamped, key=lambda x: x[0] or 0.0, reverse=True):
        bound[directory] = None
        if ts is None:
            continue
        for item in free:
            pid, started = item
            if ts + START_WINDOW[0] <= started <= ts + START_WINDOW[1]:
                bound[directory] = pid
                free.remove(item)
                break
    return bound
