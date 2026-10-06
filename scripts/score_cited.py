"""Score the objects a task's final submission cites with Nextron ratings.

An experiment on saved traces, not part of the agent. For each cited entity or
relation it rates location, form and, through the relation that created or
ran it, the account of the actor, all on the sheet's full 0-2 scale. It then
counts the cited objects that reach a score of 3 per verdict and per task
outcome. The question it answers: would Nextron scoring of the model's own
suspects have contradicted a wrong verdict?

Usage: uv run python scripts/score_cited.py [--wrong-below 0.2]
"""

import argparse
from collections import Counter
from collections.abc import Iterator
from typing import Any

from sibyl_h0und.nextron import form_rating, location_rating, user_rating
from sibyl_h0und.replay import (
    DEFAULT_ROOT,
    DEFAULT_TRACES,
    DEFAULT_WRONG_BELOW,
    Task,
    is_wrong,
    load_tasks,
    task_key,
    task_results,
)

HIGH_SCORE = 3
# Relations that say an actor created a file or started a process.
ACTOR_RELATIONS = frozenset(
    {"wrote_file", "created_file", "modified_file", "overwrite_in_place", "dropped_file"}
    | {"win_process_create", "runs_process"}
)

Node = dict[str, Any]


def index_task(task: Task) -> tuple[dict[str, Node], dict[str, Node]]:
    """Collect every entity and relation of a task's results by id."""
    entities: dict[str, Node] = {}
    relations: dict[str, Node] = {}

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            node_id, node_type = node.get("id"), node.get("type")
            if isinstance(node_id, str) and isinstance(node_type, str):
                if "source_id" in node:
                    relations[node_id] = node
                elif isinstance(node.get("properties"), dict):
                    entities[node_id] = node
            for child in node.values():
                walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)

    for result in task_results(task):
        walk(result)
    return entities, relations


def cited_ids(submission: dict[str, Any]) -> Iterator[str]:
    """Yield the ids a submission cites as artifacts or as legitimacy evidence."""
    for artifact in submission.get("ir_artifacts") or []:
        yield artifact.get("entity_id")
    for evidence in submission.get("legitimacy_evidence") or []:
        yield evidence.get("entity_id") or evidence.get("relation_id")


def rate_object(
    object_id: str, entities: dict[str, Node], relations: dict[str, Node]
) -> dict[str, int] | None:
    """Rate where, what and who for a cited object, or `None` if it was never fetched."""
    actor = target = None
    if object_id in relations:
        relation = relations[object_id]
        actor, target = entities.get(relation["source_id"]), entities.get(relation["target_id"])
    elif object_id in entities:
        target = entities[object_id]
        for relation in relations.values():
            if relation["target_id"] == object_id and relation["type"] in ACTOR_RELATIONS:
                actor = entities.get(relation["source_id"])
                break
    if target is None:
        return None
    properties = target["properties"]
    ratings: dict[str, int | None] = {}
    if target["type"] == "windows_process":
        ratings["where"] = location_rating(properties.get("image_path"), executed=True)
        ratings["who"] = user_rating(properties)
    elif "path" in properties:
        ratings["where"] = location_rating(properties["path"], executed=False)
        ratings["what"] = form_rating(properties["path"])
        if actor is not None and actor["type"] == "windows_process":
            ratings["who"] = user_rating(actor["properties"])
    return {name: value for name, value in ratings.items() if value is not None}


def main() -> None:
    """Print, per verdict and outcome, how many cited objects score high."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--wrong-below", type=float, default=DEFAULT_WRONG_BELOW)
    args = parser.parse_args()

    # (verdict, wrong) -> cited, rated, high objects and tasks with a high object.
    totals: dict[tuple[str, bool], Counter[str]] = {}
    for task in load_tasks(DEFAULT_TRACES, DEFAULT_ROOT / "replay"):
        wrong = is_wrong(task, args.wrong_below)
        if wrong is None or task["submission"] is None:
            continue
        entities, relations = index_task(task)
        count = totals.setdefault((task["verdict"], wrong), Counter())
        count["tasks"] += 1
        high_in_task = False
        for object_id in cited_ids(task["submission"]):
            count["cited"] += 1
            ratings = rate_object(object_id, entities, relations)
            if not ratings:
                continue
            count["rated"] += 1
            if sum(ratings.values()) >= HIGH_SCORE:
                count["high"] += 1
                high_in_task = True
                if wrong:
                    print(f"{task_key(task)[:17]} {task['verdict']} {object_id[:8]} {ratings}")
        count["tasks_with_high"] += high_in_task

    print(f"\nWrong = quality < {args.wrong_below}; high = score >= {HIGH_SCORE}")
    for (verdict, wrong), count in sorted(totals.items()):
        outcome = "wrong" if wrong else "other"
        print(
            f"{verdict:9} {outcome:5} cited={count['cited']:3} rated={count['rated']:3} "
            f"high={count['high']:3} tasks_with_high={count['tasks_with_high']}/{count['tasks']}"
        )


if __name__ == "__main__":
    main()
