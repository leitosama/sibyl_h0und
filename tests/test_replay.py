import json
from pathlib import Path
from typing import Any

from sibyl_h0und.replay import diff, load_tasks, replay, rule_table, snapshot

SHELL_PROCESS = {
    "id": "proc-1",
    "type": "windows_process",
    "properties": {
        "image_path": "C:\\Windows\\System32\\cmd.exe",
        "parent_image": "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
    },
}


def write_trace(root: Path, run: str, verdict: str, quality: float, result: dict[str, Any]) -> None:
    """Write the trace of one task `t1`: a graph read and a verdict."""
    events = [
        {
            "run_id": run,
            "task_id": "t1",
            "kind": "tool_call",
            "tool": "get_entity",
            "payload": {
                "arguments": {},
                "response": {"observation": {"last_tool_result": json.dumps(result)}, "info": {}},
            },
        },
        {
            "run_id": run,
            "task_id": "t1",
            "kind": "tool_call",
            "tool": "finish_investigation",
            "payload": {"arguments": {"submission": {"verdict": verdict}}, "response": {}},
        },
        {"run_id": run, "task_id": "t1", "kind": "task_end", "quality_score": quality},
    ]
    run_dir = root / run
    run_dir.mkdir(parents=True)
    lines = (json.dumps(event) for event in events)
    (run_dir / "001_t1.trace.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_replay_separates_runs_that_repeat_a_task_id(tmp_path: Path) -> None:
    """Practice runs reuse task ids, so each run is judged and counted on its own."""
    write_trace(tmp_path / "traces", "run-a", "benign", 0.0, SHELL_PROCESS)
    write_trace(tmp_path / "traces", "run-b", "benign", 0.9, {"id": "x", "type": "host"})

    tasks = load_tasks(tmp_path / "traces", tmp_path / "cache")
    findings = replay(tasks)

    assert [(task["run_id"], task["verdict"]) for task in tasks] == [
        ("run-a", "benign"),
        ("run-b", "benign"),
    ]
    assert rule_table(tasks, findings, wrong_below=0.2) == [
        {"rule": "web_server_spawns_shell", "wrong_tasks": "1/1", "other_tasks": "0/1", "nodes": 1}
    ]
    assert load_tasks(tmp_path / "traces", tmp_path / "cache") == tasks


def test_diff_lists_findings_gained_and_lost_per_task() -> None:
    """A rule change shows up as a per-task difference between two snapshots."""
    old = snapshot({"r:t1": [], "r:t2": []})
    new = {"r:t1": ["rule|n1|high"], "r:t2": []}

    assert diff(old, new) == {"r:t1": {"gained": ["rule|n1|high"], "lost": []}}
