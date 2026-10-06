import json
from pathlib import Path
from typing import Any

from sibyl_h0und.replay import diff, hits, is_wrong, load_tasks, source_table, terms
from sibyl_h0und.trace import TaskTrace, task_trace_path
from sibyl_h0und.vocabulary import shared

RENAMED_SDELETE = {
    "id": "proc-1",
    "type": "windows_process",
    "properties": {
        "image_path": "C:\\Users\\Public\\runtime.exe",
        "original_filename": "sdelete.exe",
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


def test_replay_separates_runs_that_repeat_a_task_id_and_counts_each_source(
    tmp_path: Path,
) -> None:
    """Practice runs reuse task ids, so each run is counted on its own, wrong and other."""
    write_trace(tmp_path / "traces", "run-a", "benign", 0.0, RENAMED_SDELETE)
    write_trace(tmp_path / "traces", "run-b", "benign", 0.9, {"id": "x", "type": "host"})

    tasks = load_tasks(tmp_path / "traces", tmp_path / "cache")
    found = hits(tasks, shared())
    rows = {row["source"]: row for row in source_table(tasks, found, wrong_below=0.2)}

    assert [(task["run_id"], is_wrong(task, 0.2)) for task in tasks] == [
        ("run-a", True),
        ("run-b", False),
    ]
    assert terms(tasks[0]) == {"C:\\Users\\Public\\runtime.exe", "sdelete.exe"}
    assert rows["attack"]["wrong_tasks"] == "1/1"
    assert rows["attack"]["other_tasks"] == "0/1"
    assert load_tasks(tmp_path / "traces", tmp_path / "cache") == tasks


def test_diff_lists_entries_gained_and_lost_per_task() -> None:
    """A new pack or source shows up as a per-task difference between two snapshots."""
    old = {"r:t1": [], "r:t2": ["attack|a"]}
    new = {"r:t1": ["lolrmm|b"], "r:t2": ["attack|a"]}

    assert diff(old, new) == {"r:t1": {"gained": ["lolrmm|b"], "lost": []}}


def test_cache_of_another_trace_directory_is_not_reused(tmp_path: Path) -> None:
    """A different or empty trace directory must not answer with the old tasks."""
    write_trace(tmp_path / "traces", "run-a", "benign", 0.0, RENAMED_SDELETE)
    assert len(load_tasks(tmp_path / "traces", tmp_path / "cache")) == 1

    (tmp_path / "empty").mkdir()

    assert load_tasks(tmp_path / "empty", tmp_path / "cache") == []
