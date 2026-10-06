"""Offline coverage of the knowledge vocabulary over saved task traces.

No model and no runtime are involved: a trace already holds every tool
response. The first pass extracts, per task, the ordered tool results, the
submitted verdict and the scores into a small cache next to the traces. Later
passes read only the cache.

The replay asks the vocabulary about the terms the recorded agent saw: image
names, original file names, parent images and host names. It shows which
sources have something to say about the entities of wrong and other tasks. It
does not say what the model would have done with the answer; that is visible
only in a `practice` run (ADR 0017).
"""

import argparse
import json
import os
from collections import defaultdict
from collections.abc import Iterator
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict
from pathlib import Path
from typing import Any

from sibyl_h0und.catalog import FINISH_TOOL
from sibyl_h0und.trace import default_trace_dir
from sibyl_h0und.trace import read_task as read_task_events
from sibyl_h0und.vocabulary import Vocabulary

# Where traces are read from, as the agent writes them: `$TRACE_DIR`, else the default.
DEFAULT_TRACES = Path(os.environ.get("TRACE_DIR") or default_trace_dir()).expanduser()
# The cache stays in the data root whatever `$TRACE_DIR` is; it records which traces built it.
DEFAULT_ROOT = default_trace_dir().parent
TRACE_GLOB = "*/*.trace.jsonl"
# Bump the number when the cached fields change, so an old cache is ignored.
CACHE_NAME = "tasks-v3.jsonl"
# Quality below this marks a task as probably wrong. The runtime does not say
# whether a verdict was right, so this is a heuristic to be tuned by the reader.
DEFAULT_WRONG_BELOW = 0.2

Task = dict[str, Any]
# Node properties whose value is a term worth asking the vocabulary about.
TERM_PROPERTIES = ("image_path", "original_filename", "parent_image", "fqdn")


def task_key(task: Task) -> str:
    """Identify a task within all runs: practice runs repeat the same task ids."""
    return f"{task['run_id']}:{task['task_id']}"


def read_task(path: Path) -> Task:
    """Extract what a replay needs from one task trace.

    Args:
        path: JSONL trace of one task.

    Returns:
        Run and task ids, the task observation, every runtime call with its
        decoded outcome, the submission and its verdict, and quality and
        reward (`None` when the task never ended).
    """
    recorded = read_task_events(path)
    submission = recorded.submission
    return {
        "run_id": recorded.run_id,
        "task_id": recorded.task_id,
        "observation": recorded.observation,
        "calls": [
            {"tool": call.tool, "arguments": call.arguments, **asdict(call.outcome)}
            for call in recorded.calls
        ],
        "verdict": submission.get("verdict") if submission else None,
        "submission": submission,
        "quality": recorded.quality,
        "reward": recorded.reward,
    }


def task_results(task: Task) -> Iterator[Any]:
    """Yield the decoded result of every successful runtime call that is not the report."""
    for call in task["calls"]:
        if call["tool"] != FINISH_TOOL and call["error"] is None:
            yield call["result"]


def load_tasks(trace_dir: Path, cache_dir: Path, *, rebuild: bool = False) -> list[Task]:
    """Return every task, extracting from the traces only when the cache is stale.

    The cache belongs to one trace directory and one set of trace files: it is
    ignored when either differs from the one that built it.

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
    source = {"trace_dir": str(trace_dir.resolve()), "files": len(paths)}
    if not rebuild and cache.exists() and cache.stat().st_mtime >= newest:
        with cache.open(encoding="utf-8") as lines:
            if json.loads(next(lines, "{}")) == source:
                return [json.loads(line) for line in lines]
    with ProcessPoolExecutor() as pool:
        tasks = [task for task in pool.map(read_task, paths, chunksize=4) if task["task_id"]]
    cache_dir.mkdir(parents=True, exist_ok=True)
    with cache.open("w", encoding="utf-8") as out:
        out.write(json.dumps(source) + "\n")
        for task in tasks:
            out.write(json.dumps(task, ensure_ascii=False) + "\n")
    return tasks


def nodes(value: Any) -> Iterator[dict[str, Any]]:
    """Yield every JSON object with a string `id` and `type` in a JSON value."""
    if isinstance(value, dict):
        if isinstance(value.get("id"), str) and isinstance(value.get("type"), str):
            yield value
        for child in value.values():
            yield from nodes(child)
    elif isinstance(value, list):
        for child in value:
            yield from nodes(child)


def terms(task: Task) -> set[str]:
    """Return the terms of a task that a model could ask the vocabulary about."""
    found = set()
    for result in task_results(task):
        for node in nodes(result):
            properties = node.get("properties")
            for name in TERM_PROPERTIES if isinstance(properties, dict) else ():
                if isinstance(value := properties.get(name), str) and value:
                    found.add(value)
    return found


def is_wrong(task: Task, wrong_below: float) -> bool | None:
    """Tell whether a task probably got a wrong verdict, or `None` when unknown."""
    if task["quality"] is None:
        return None
    return task["quality"] < wrong_below


def hits(tasks: list[Task], vocabulary: Vocabulary) -> dict[str, set[str]]:
    """Map each task to the `source|term` pairs the vocabulary has an entry for."""
    answers: dict[str, set[str]] = {}
    found: dict[str, set[str]] = {}
    for task in tasks:
        pairs = set()
        for term in terms(task):
            if term not in answers:
                answers[term] = {m["source"] for m in vocabulary.lookup(term)["matches"]}
            pairs |= {f"{source}|{term}" for source in answers[term]}
        found[task_key(task)] = pairs
    return found


def source_table(
    tasks: list[Task], found: dict[str, set[str]], wrong_below: float
) -> list[dict[str, Any]]:
    """Count, per source, the wrong and other tasks with an entry for something they saw.

    Returns:
        One row per source with the tasks it has an entry in, wrong and other,
        and the number of distinct terms it knows.
    """
    totals = {"wrong": 0, "other": 0}
    tasks_by_source: dict[str, dict[str, set[str]]] = defaultdict(
        lambda: {"wrong": set(), "other": set()}
    )
    known: dict[str, set[str]] = defaultdict(set)
    for task in tasks:
        wrong = is_wrong(task, wrong_below)
        if wrong is None:
            continue
        group = "wrong" if wrong else "other"
        totals[group] += 1
        for pair in found[task_key(task)]:
            source, term = pair.split("|", 1)
            tasks_by_source[source][group].add(task_key(task))
            known[source].add(term)
    return [
        {
            "source": source,
            "wrong_tasks": f"{len(groups['wrong'])}/{totals['wrong']}",
            "other_tasks": f"{len(groups['other'])}/{totals['other']}",
            "terms": len(known[source]),
        }
        for source, groups in sorted(tasks_by_source.items())
    ]


def diff(old: dict[str, list[str]], new: dict[str, list[str]]) -> dict[str, dict[str, list[str]]]:
    """List entries gained and lost per task between two snapshots."""
    changes: dict[str, dict[str, list[str]]] = {}
    for key in sorted(old.keys() | new.keys()):
        before, after = set(old.get(key, [])), set(new.get(key, []))
        if before != after:
            changes[key] = {"gained": sorted(after - before), "lost": sorted(before - after)}
    return changes


def main(argv: list[str] | None = None) -> None:
    """Print which sources know the entities of the saved traces."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--traces", type=Path, default=DEFAULT_TRACES)
    parser.add_argument("--cache", type=Path, default=DEFAULT_ROOT / "replay")
    parser.add_argument("--run", default="", help="Only runs whose id contains this text.")
    parser.add_argument("--rebuild", action="store_true", help="Re-extract the traces.")
    parser.add_argument("--wrong-below", type=float, default=DEFAULT_WRONG_BELOW)
    parser.add_argument("--details", action="store_true", help="List hits of wrong tasks.")
    parser.add_argument("--save", metavar="NAME", help="Save these hits as a baseline.")
    parser.add_argument("--compare", metavar="NAME", help="Show changes against a baseline.")
    args = parser.parse_args(argv)

    tasks = [
        task
        for task in load_tasks(args.traces, args.cache, rebuild=args.rebuild)
        if args.run in (task["run_id"] or "")
    ]
    found = hits(tasks, Vocabulary())

    print(f"Sources with an entry for something a task saw (wrong = quality < {args.wrong_below}):")
    for row in source_table(tasks, found, args.wrong_below):
        print(
            f"  {row['source']:12} wrong {row['wrong_tasks']:>6}  "
            f"other {row['other_tasks']:>7}  terms {row['terms']}"
        )
    if args.details:
        for task in tasks:
            if is_wrong(task, args.wrong_below):
                print(f"\n{task_key(task)} {task['verdict']} q={task['quality']:.2f}")
                for pair in sorted(found[task_key(task)]):
                    print(f"  {pair}")

    baselines = args.cache / "knowledge-baselines"
    current = {key: sorted(pairs) for key, pairs in found.items()}
    if args.compare:
        path = baselines / f"{args.compare}.json"
        changes = diff(json.loads(path.read_text(encoding="utf-8")), current)
        print(f"\nChanges against {args.compare}: {len(changes)} tasks")
        for key, change in changes.items():
            print(f"  {key[:17]} +{len(change['gained'])} -{len(change['lost'])}")
            for entry in change["gained"]:
                print(f"    + {entry}")
            for entry in change["lost"]:
                print(f"    - {entry}")
    if args.save:
        baselines.mkdir(parents=True, exist_ok=True)
        (baselines / f"{args.save}.json").write_text(json.dumps(current), encoding="utf-8")
        print(f"\nSaved baseline {args.save}.")
