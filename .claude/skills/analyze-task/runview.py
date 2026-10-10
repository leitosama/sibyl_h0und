"""Light helpers that turn finished-task rows into one-line views of a run.

No project imports on purpose: the status line calls this on every refresh and
must start fast. Rows are the dicts the watcher writes to `monitor.jsonl`.
"""

import json
from collections import Counter
from pathlib import Path
from typing import Any

COMPETITION_TASKS = 40
TRIAGE_LOG = "analysis.log"
JSONL_NAME = "monitor.jsonl"


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


def event_line(row: dict[str, Any], note: str = "") -> str:
    """One line for a finished task: glyph, number, verdict, flags, calls, tokens."""
    found = ",".join(row.get("flags") or []) or "-"
    gates = [g for g in row.get("gates") or [] if g != "sent"]
    chain = "→".join(dict.fromkeys(gates))
    parts = [
        f"{symbol(row)} #{row['number']:03d}",
        row.get("verdict", "?"),
        found + (f" [{chain}]" if chain else ""),
        f"{row.get('calls', 0)} calls",
        f"{short_count(row.get('tokens', 0))} tok",
    ]
    if note:
        parts.append(note)
    return " · ".join(parts)


def run_totals(rows: list[dict[str, Any]], total: int | None = None) -> dict[str, Any]:
    """Return the counters of the totals line, the status line and the dashboard."""
    n = len(rows)
    total = total or COMPETITION_TASKS
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
        "eta_min": mean_duration * max(total - n, 0) / 60,
    }


def deep_candidates(run_dir: Path) -> list[str]:
    """Return the task numbers triaged DEEP and not yet superseded by a SKIP."""
    path = run_dir / TRIAGE_LOG
    state: dict[str, bool] = {}
    for line in path.read_text().splitlines() if path.exists() else []:
        parts = line.split()
        if len(parts) >= 4 and parts[0].startswith("["):
            state[parts[0].lstrip("[")] = parts[3].upper() == "DEEP"
    return [number for number, deep in state.items() if deep]


def totals_event_line(rows: list[dict[str, Any]], deep: list[str], total: int | None = None) -> str:
    """One line for the run so far: progress, glyph counts, cost, ETA, deep candidates."""
    t = run_totals(rows, total)
    return (
        f"Σ {t['done']}/{t['total']} · ✔{t['ok']} ⚠{t['warn']} ✖{t['fail']} · "
        f"⌀{t['calls']:.0f} calls · {short_count(t['tokens'])} tok · ETA {t['eta_min']:.0f}m · "
        f"DEEP: {', '.join(deep) if deep else '-'}"
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
