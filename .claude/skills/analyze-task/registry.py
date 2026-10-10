"""Registry of runs worth analysing later, one JSON line per run, kept outside the repo.

The file sits next to the traces directory (`final_runs.jsonl`, or the path in
`$FINAL_REGISTRY`). It holds only ids, counts, flags and triage verdicts, never
alert text or runtime answers, so it can be read and quoted freely. Traces stay
where they are (ADR 0008); `KEEP` in a run directory marks it as not to delete.
"""

import json
import os
import time
from pathlib import Path
from typing import Any

from runview import run_tag, run_ts, triage_answers

NAME = "final_runs.jsonl"


def traces_root() -> Path:
    """Return the traces directory the watcher and the agent use."""
    return Path(os.environ.get("TRACE_DIR", "~/.local/share/sibyl_h0und/traces")).expanduser()


def registry_path() -> Path:
    """Return the registry file: `$FINAL_REGISTRY`, else beside the traces directory."""
    chosen = os.environ.get("FINAL_REGISTRY")
    return Path(chosen).expanduser() if chosen else traces_root().parent / NAME


def load(path: Path | None = None) -> dict[str, dict[str, Any]]:
    """Read the registry as {run_id: entry}; a missing file or a bad line is skipped."""
    path = path or registry_path()
    entries: dict[str, dict[str, Any]] = {}
    if path.exists():
        for line in path.read_text().splitlines():
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            entries[entry["run_id"]] = entry
    return entries


def build_entry(
    run_dir: Path,
    info: dict[str, Any],
    run_id: str,
    mode: str,
    rows: list[dict[str, Any]],
    state: str,
    total: int | None,
) -> dict[str, Any]:
    """Return the registry entry of a run from its watcher rows."""
    answers = triage_answers(run_dir)
    started = run_ts(run_dir.name)
    tasks = []
    for row in rows:
        number = f"{row['number']:03d}"
        tasks.append(
            {
                "number": row["number"],
                "task_id": row.get("task_id") or row.get("id"),
                "trace": row.get("trace"),
                "verdict": row.get("verdict"),
                "flags": row.get("flags") or [],
                "calls": row.get("calls"),
                "tokens": row.get("tokens"),
                "triage": answers.get(number, "")[:4] or None,
            }
        )
    return {
        "run_id": run_id,
        "dir": run_dir.name,
        "path": str(run_dir),
        "tag": run_tag(run_dir.name, mode),
        "mode": mode,
        "agent_name": info.get("agent_name"),
        "run_label": info.get("run_label"),
        "model": info.get("model"),
        "role_models": info.get("role_models"),
        "arena": info.get("arena"),
        "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started)) if started else None,
        "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "state": state,
        "tasks_total": total,
        "tasks_done": len(rows),
        "tasks": tasks,
    }


def upsert(entry: dict[str, Any], path: Path | None = None) -> None:
    """Write `entry` into the registry, replacing the line with the same `run_id`."""
    path = path or registry_path()
    entries = load(path)
    entries[entry["run_id"]] = entry
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text("".join(json.dumps(e, ensure_ascii=False) + "\n" for e in entries.values()))
    os.replace(tmp, path)


def mark_keep(run_dir: Path) -> None:
    """Drop a `KEEP` note in the run directory so nobody cleans it up by mistake."""
    note = run_dir / "KEEP"
    if not note.exists():
        note.write_text(
            "Final run kept for analysis: do not delete or overwrite.\n"
            f"Registry: {registry_path()}\n"
        )


def table(entries: dict[str, dict[str, Any]]) -> str:
    """Return the registry as a text table, newest run last."""
    rows = sorted(entries.values(), key=lambda e: e.get("started") or "")
    if not rows:
        return "registry is empty"
    lines = [f"{'tag':<6} {'mode':<9} {'state':<8} {'done':<7} {'model':<26} run_id"]
    for e in rows:
        total = e.get("tasks_total")
        done = f"{e.get('tasks_done', 0)}/{total if total is not None else '?'}"
        deep = sum(1 for t in e.get("tasks", []) if t.get("triage") == "DEEP")
        lines.append(
            f"{e.get('tag', '?'):<6} {e.get('mode', '?'):<9} {e.get('state', '?'):<8} {done:<7} "
            f"{str(e.get('model'))[:26]:<26} {e['run_id']}" + (f"  DEEP {deep}" if deep else "")
        )
    return "\n".join(lines)


def expand(entry: dict[str, Any]) -> str:
    """Return one run as a task list with a ready digest command per task."""
    head = (
        f"{entry.get('tag')} {entry.get('mode')} {entry.get('agent_name')} "
        f"{entry.get('run_label')} {entry.get('model')} {entry.get('state')}\n"
        f"dir: {entry.get('path')}\nrun_id: {entry['run_id']}"
    )
    lines = [head]
    for t in entry.get("tasks", []):
        lines.append(
            f"#{t['number']:03d} {t.get('verdict')} {','.join(t.get('flags') or []) or '-'} "
            f"{t.get('calls')} calls {t.get('tokens')} tok triage={t.get('triage')} "
            f"task_id={t.get('task_id')}"
        )
    lines.append(
        "digest: uv run python .claude/skills/analyze-task/digest_task.py "
        f"{entry.get('path')} <NUMBER>"
    )
    return "\n".join(lines)
