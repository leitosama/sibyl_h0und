"""Offline replay of saved task traces through the flag rules.

No model and no runtime are involved: a trace already holds every tool
response. The first pass extracts, per task, the ordered tool results, the
submitted verdict and the scores into a small cache next to the traces. Later
passes read only the cache, so a changed rule is judged against all tasks in
about a second.

A replay judges the nodes the recorded agent happened to visit. It shows what
a flag could have told the model, not what the model would then have done.

Every rule names its knowledge source, and the tables and `--compare` break
results down by source, so a new source shows what it adds before it is merged.
"""

import argparse
import json
from collections import defaultdict
from collections.abc import Callable, Iterable
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any

from sibyl_h0und.flags import HIGH, LEVEL_ORDER, LOW, MEDIUM, Finding, FlagBoard, rank_flags
from sibyl_h0und.rules import DEFAULT_RULES

DEFAULT_ROOT = Path("~/.local/share/sibyl_h0und").expanduser()
TRACE_GLOB = "*/*.trace.jsonl"
# Bump the number when the cached fields change, so an old cache is ignored.
CACHE_NAME = "tasks-v2.jsonl"
# Quality below this marks a task as probably wrong. The runtime does not say
# whether a verdict was right, so this is a heuristic to be tuned by the reader.
DEFAULT_WRONG_BELOW = 0.2

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


def replay(tasks: Iterable[Task]) -> tuple[Findings, Findings]:
    """Run the default rules over every task, as the agent would have.

    Args:
        tasks: Extracted tasks.

    Returns:
        By `task_key`: the latest finding of each rule about each node, and the
        findings the model would have seen after the per-result flag limit.
    """
    findings: Findings = {}
    shown: Findings = {}
    for task in tasks:
        board = FlagBoard(DEFAULT_RULES)
        seen: list[Finding] = []
        for result in task["results"]:
            groups, _ = rank_flags(board.observe(result))
            seen.extend(finding for group in groups for finding in group)
        findings[task_key(task)] = list(board.findings.values())
        shown[task_key(task)] = seen
    return findings, shown


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
    sources = {finding.rule: finding.source for items in findings.values() for finding in items}
    return [
        {"rule": rule, "source": sources[rule], **counts}
        for rule, counts in _fired(tasks, findings, wrong_below, lambda item: item.rule).items()
    ]


def source_table(
    tasks: list[Task], findings: Findings, shown: Findings, wrong_below: float
) -> list[dict[str, Any]]:
    """Count, per knowledge source, the tasks and nodes it reached medium or high on.

    Args:
        tasks: Extracted tasks.
        findings: First result of `replay`.
        shown: Second result of `replay`.
        wrong_below: Quality under which a task counts as wrong.

    Returns:
        One row per source, as in `rule_table`, plus the number of its findings
        that would have reached the model after the flag limit.
    """
    seen: dict[str, int] = defaultdict(int)
    for task in tasks:
        for finding in shown[task_key(task)]:
            seen[finding.source] += 1
    return [
        {"source": source, **counts, "shown": seen[source]}
        for source, counts in _fired(tasks, findings, wrong_below, lambda item: item.source).items()
    ]


def _fired(
    tasks: list[Task], findings: Findings, wrong_below: float, group_by: Callable[[Finding], str]
) -> dict[str, dict[str, Any]]:
    """Count wrong and other tasks, and nodes, with a medium or high finding per group."""
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
                fired[group_by(finding)][group].add(task_key(task))
                nodes[group_by(finding)] += 1
    return {
        name: {
            "wrong_tasks": f"{len(groups['wrong'])}/{totals['wrong']}",
            "other_tasks": f"{len(groups['other'])}/{totals['other']}",
            "nodes": nodes[name],
        }
        for name, groups in sorted(fired.items())
    }


def snapshot(findings: Findings) -> dict[str, Any]:
    """Reduce findings to a baseline: comparable strings by `task_key` and rule sources."""
    return {
        "sources": {item.rule: item.source for items in findings.values() for item in items},
        "tasks": {
            key: sorted(f"{item.rule}|{item.node_id}|{item.level}" for item in items)
            for key, items in findings.items()
        },
    }


def read_baseline(data: dict[str, Any]) -> dict[str, Any]:
    """Accept a saved baseline, including the older form without rule sources."""
    if "tasks" in data and "sources" in data:
        return data
    return {"sources": {}, "tasks": data}


def source_changes(
    changes: dict[str, dict[str, list[str]]], sources: dict[str, str]
) -> dict[str, dict[str, int]]:
    """Count findings gained and lost per source.

    Args:
        changes: Result of `diff`.
        sources: Source of each rule, from both baselines; a rule missing from
            both counts under `?`.
    """
    counts: dict[str, dict[str, int]] = defaultdict(lambda: {"gained": 0, "lost": 0})
    for change in changes.values():
        for kind in ("gained", "lost"):
            for entry in change[kind]:
                counts[sources.get(entry.split("|", 1)[0], "?")][kind] += 1
    return dict(sorted(counts.items()))


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
    findings, shown = replay(tasks)

    print("\n".join(task_rows(tasks, findings, args.wrong_below)))
    print(f"\nRules at medium or high (wrong = quality < {args.wrong_below}):")
    for row in rule_table(tasks, findings, args.wrong_below):
        print(
            f"  {row['rule']:28} {row['source']:10} wrong {row['wrong_tasks']:>6}  "
            f"other {row['other_tasks']:>7}  nodes {row['nodes']}"
        )
    print("\nSources at medium or high (shown = flags left after the per-result limit):")
    for row in source_table(tasks, findings, shown, args.wrong_below):
        print(
            f"  {row['source']:28} wrong {row['wrong_tasks']:>6}  "
            f"other {row['other_tasks']:>7}  nodes {row['nodes']:<5} shown {row['shown']}"
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
        path = baselines / f"{args.compare}.json"
        old = read_baseline(json.loads(path.read_text(encoding="utf-8")))
        changes = diff(old["tasks"], current["tasks"])
        print(f"\nChanges against {args.compare}: {len(changes)} tasks")
        sources = {**old["sources"], **current["sources"]}
        for source, counts in source_changes(changes, sources).items():
            print(f"  source {source:21} +{counts['gained']} -{counts['lost']}")
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
