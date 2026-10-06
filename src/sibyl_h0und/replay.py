"""Offline replay of saved task traces through the flag rules.

No model and no runtime are involved: a trace already holds every tool
response. The first pass extracts, per task, the ordered tool results, the
submitted verdict and the scores into a small cache next to the traces. Later
passes read only the cache, so a changed rule is judged against all tasks in
about a second.

A replay judges the nodes the recorded agent happened to visit. It shows what
a flag could have told the model, not what the model would then have done.
"""

import argparse
import json
from collections import defaultdict
from collections.abc import Iterable
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any

from sibyl_h0und.flags import HIGH, LOW, MEDIUM, Finding, FlagBoard
from sibyl_h0und.rules import DEFAULT_RULES

DEFAULT_ROOT = Path("~/.local/share/sibyl_h0und").expanduser()
TRACE_GLOB = "*/*.trace.jsonl"
# Bump the number when the cached fields change, so an old cache is ignored.
CACHE_NAME = "tasks-v2.jsonl"
# Quality below this marks a task as probably wrong. The runtime does not say
# whether a verdict was right, so this is a heuristic to be tuned by the reader.
DEFAULT_WRONG_BELOW = 0.2
LEVEL_ORDER = {LOW: 0, MEDIUM: 1, HIGH: 2}

Task = dict[str, Any]
Findings = dict[str, list[Finding]]


def task_key(task: Task) -> str:
    """Identify a task within all runs: practice runs repeat the same task ids."""
    return f"{task['run_id']}:{task['task_id']}"


def read_task(path: Path) -> Task:
    """Extract what a replay needs from one task trace.

    Args:
        path: JSONL trace of one task.

    Returns:
        Run and task ids, the submission and its verdict, quality and reward (`None`
        when the task never ended) and the decoded result of every successful
        runtime call, in order.
    """
    task: Task = {
        "run_id": None,
        "task_id": None,
        "verdict": None,
        "submission": None,
        "quality": None,
        "reward": None,
        "results": [],
    }
    with path.open(encoding="utf-8") as lines:
        for line in lines:
            if "tool_call" not in line and "task_end" not in line:
                continue
            event = json.loads(line)
            task["run_id"], task["task_id"] = event.get("run_id"), event.get("task_id")
            if event["kind"] == "task_end":
                task["quality"] = event.get("quality_score")
                task["reward"] = event.get("total_reward")
            elif event["kind"] == "tool_call":
                _read_call(event, task)
    return task


def _read_call(event: dict[str, Any], task: Task) -> None:
    """Add one runtime call to the task, as a verdict or as a result."""
    payload = event.get("payload", {})
    if event.get("tool") == "finish_investigation":
        arguments = payload.get("arguments", {})
        submission = arguments.get("submission", arguments)
        task["submission"] = submission
        task["verdict"] = submission.get("verdict")
        return
    response = payload.get("response", {})
    if response.get("info", {}).get("error") is not None:
        return
    raw = response.get("observation", {}).get("last_tool_result")
    try:
        task["results"].append(json.loads(raw) if isinstance(raw, str) else raw)
    except json.JSONDecodeError:
        task["results"].append(raw)


def load_tasks(trace_dir: Path, cache_dir: Path, *, rebuild: bool = False) -> list[Task]:
    """Return every task, extracting from the traces only when the cache is stale.

    Args:
        trace_dir: Directory of run directories with task traces.
        cache_dir: Directory for the extracted cache.
        rebuild: Ignore an existing cache.

    Returns:
        Tasks ordered by trace path.
    """
    paths = sorted(trace_dir.glob(TRACE_GLOB))
    cache = cache_dir / CACHE_NAME
    newest = max((path.stat().st_mtime for path in paths), default=0.0)
    if not rebuild and cache.exists() and cache.stat().st_mtime >= newest:
        with cache.open(encoding="utf-8") as lines:
            return [json.loads(line) for line in lines]
    with ProcessPoolExecutor() as pool:
        tasks = [task for task in pool.map(read_task, paths, chunksize=4) if task["task_id"]]
    cache_dir.mkdir(parents=True, exist_ok=True)
    with cache.open("w", encoding="utf-8") as out:
        for task in tasks:
            out.write(json.dumps(task, ensure_ascii=False) + "\n")
    return tasks


def replay(tasks: Iterable[Task]) -> Findings:
    """Run the default rules over every task, as the agent would have.

    Args:
        tasks: Extracted tasks.

    Returns:
        Latest finding of each rule about each node, by `task_key`.
    """
    findings: Findings = {}
    for task in tasks:
        board = FlagBoard(DEFAULT_RULES)
        for result in task["results"]:
            board.observe(result)
        findings[task_key(task)] = list(board.findings.values())
    return findings


def is_wrong(task: Task, wrong_below: float) -> bool | None:
    """Tell whether a task probably got a wrong verdict, or `None` when unknown."""
    if task["quality"] is None:
        return None
    return task["quality"] < wrong_below


def rule_table(tasks: list[Task], findings: Findings, wrong_below: float) -> list[dict[str, Any]]:
    """Count, per rule, the tasks where it reached medium or high.

    Args:
        tasks: Extracted tasks.
        findings: Result of `replay`.
        wrong_below: Quality under which a task counts as wrong.

    Returns:
        One row per rule with the number of wrong and other tasks it fired on
        and the number of nodes it fired on.
    """
    totals = {"wrong": 0, "other": 0}
    fired: dict[str, dict[str, set[str]]] = defaultdict(lambda: {"wrong": set(), "other": set()})
    nodes: dict[str, int] = defaultdict(int)
    for task in tasks:
        wrong = is_wrong(task, wrong_below)
        if wrong is None:
            continue
        group = "wrong" if wrong else "other"
        totals[group] += 1
        for finding in findings[task_key(task)]:
            if finding.level != LOW:
                fired[finding.rule][group].add(task_key(task))
                nodes[finding.rule] += 1
    return [
        {
            "rule": rule,
            "wrong_tasks": f"{len(groups['wrong'])}/{totals['wrong']}",
            "other_tasks": f"{len(groups['other'])}/{totals['other']}",
            "nodes": nodes[rule],
        }
        for rule, groups in sorted(fired.items())
    ]


def snapshot(findings: Findings) -> dict[str, list[str]]:
    """Reduce findings to comparable strings, by `task_key`."""
    return {
        key: sorted(f"{item.rule}|{item.node_id}|{item.level}" for item in items)
        for key, items in findings.items()
    }


def diff(old: dict[str, list[str]], new: dict[str, list[str]]) -> dict[str, dict[str, list[str]]]:
    """List findings gained and lost per task between two snapshots."""
    changes: dict[str, dict[str, list[str]]] = {}
    for key in sorted(old.keys() | new.keys()):
        before, after = set(old.get(key, [])), set(new.get(key, []))
        if before != after:
            changes[key] = {"gained": sorted(after - before), "lost": sorted(before - after)}
    return changes


def task_rows(tasks: list[Task], findings: Findings, wrong_below: float) -> list[str]:
    """Format one line per task, lowest quality first."""
    rows = []
    for task in sorted(tasks, key=lambda item: (item["quality"] is None, item["quality"] or 0)):
        items = findings[task_key(task)]
        top = max((item.level for item in items), key=LEVEL_ORDER.__getitem__, default="-")
        counts = {level: sum(item.level == level for item in items) for level in (MEDIUM, HIGH)}
        quality = "n/a" if task["quality"] is None else f"{task['quality']:.2f}"
        mark = "WRONG?" if is_wrong(task, wrong_below) else ""
        rows.append(
            f"{(task['run_id'] or '')[:8]} {(task['task_id'] or '')[:8]} "
            f"{task['verdict'] or '-':9} q={quality:5} top={top:6} "
            f"med={counts[MEDIUM]:<3} high={counts[HIGH]:<3} {mark}"
        )
    return rows


def main(argv: list[str] | None = None) -> None:
    """Replay saved traces and print per-task and per-rule results."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--traces", type=Path, default=DEFAULT_ROOT / "traces")
    parser.add_argument("--cache", type=Path, default=DEFAULT_ROOT / "replay")
    parser.add_argument("--run", default="", help="Only runs whose id contains this text.")
    parser.add_argument("--rebuild", action="store_true", help="Re-extract the traces.")
    parser.add_argument("--wrong-below", type=float, default=DEFAULT_WRONG_BELOW)
    parser.add_argument("--details", action="store_true", help="List findings of wrong tasks.")
    parser.add_argument("--save", metavar="NAME", help="Save this replay as a baseline.")
    parser.add_argument("--compare", metavar="NAME", help="Show changes against a baseline.")
    args = parser.parse_args(argv)

    tasks = [
        task
        for task in load_tasks(args.traces, args.cache, rebuild=args.rebuild)
        if args.run in (task["run_id"] or "")
    ]
    findings = replay(tasks)

    print("\n".join(task_rows(tasks, findings, args.wrong_below)))
    print(f"\nRules at medium or high (wrong = quality < {args.wrong_below}):")
    for row in rule_table(tasks, findings, args.wrong_below):
        print(
            f"  {row['rule']:28} wrong {row['wrong_tasks']:>6}  "
            f"other {row['other_tasks']:>7}  nodes {row['nodes']}"
        )
    if args.details:
        for task in tasks:
            if is_wrong(task, args.wrong_below):
                print(f"\n{task_key(task)} {task['verdict']} q={task['quality']:.2f}")
                for item in findings[task_key(task)]:
                    if item.level != LOW:
                        print(f"  {item.level:6} {item.rule} {item.node_id}: {item.reason}")

    baselines = args.cache / "baselines"
    current = snapshot(findings)
    if args.compare:
        old = json.loads((baselines / f"{args.compare}.json").read_text(encoding="utf-8"))
        changes = diff(old, current)
        print(f"\nChanges against {args.compare}: {len(changes)} tasks")
        for key, change in changes.items():
            gained, lost = len(change["gained"]), len(change["lost"])
            print(f"  {key[:17]} +{gained} -{lost}")
            for entry in change["gained"]:
                print(f"    + {entry}")
            for entry in change["lost"]:
                print(f"    - {entry}")
    if args.save:
        baselines.mkdir(parents=True, exist_ok=True)
        (baselines / f"{args.save}.json").write_text(json.dumps(current), encoding="utf-8")
        print(f"\nSaved baseline {args.save}.")
