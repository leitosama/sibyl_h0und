"""The alert stage at its owner boundary: `Investigation.alert_stage_call` and `after_call`."""

import json
from typing import Any

import pytest

from sibyl_h0und.catalog import FINISH_TOOL
from sibyl_h0und.investigation import Investigation, LocalAnswer
from sibyl_h0und.outcome import ToolOutcome

# Tools named unlike the practice ones: the stage finds them by their arguments.
FETCH = {
    "name": "fetch_node",
    "parameters": {
        "type": "object",
        "properties": {"entity_id": {"type": "string"}, "reasoning": {"type": "string"}},
        "required": ["entity_id", "reasoning"],
    },
}
FIND = {
    "name": "find",
    "parameters": {
        "$defs": {
            "RelationSearchScope": {
                "type": "object",
                "properties": {"kind": {"const": "relation"}, "type": {"type": "string"}},
            },
            "Window": {
                "type": "object",
                "properties": {"from": {"type": "string"}, "to": {"type": "string"}},
            },
        },
        "type": "object",
        "properties": {
            "query": {"type": "string"},
            "page_id": {"type": "integer", "default": 1},
            "scope": {"anyOf": [{"$ref": "#/$defs/RelationSearchScope"}, {"type": "null"}]},
            "time_window": {"anyOf": [{"$ref": "#/$defs/Window"}, {"type": "null"}]},
        },
        "required": ["query"],
    },
}
REPORT = {"name": FINISH_TOOL, "parameters": {"type": "object"}}
# A host up since boot and the process that triggered the alert on it.
HOST = {"id": "host-1", "type": "host", "timestamps": ["2024-06-12T07:34:32+00:00"]}
PROCESS = {
    "id": "proc-1",
    "type": "windows_process",
    "timestamps": ["2024-06-12T10:05:58+00:00", "2024-06-12T10:05:59+00:00"],
}
HOSTS = {
    "id": "rel-hosts",
    "type": "hosts",
    "source_id": "host-1",
    "target_id": "proc-1",
    "timestamp": None,
    "properties": None,
}


def relation(relation_id: str, source: str, target: str) -> dict[str, Any]:
    """A whole relation, as a fetch by id or a search returns it."""
    return {
        "id": relation_id,
        "type": "win_process_create",
        "source_id": source,
        "target_id": target,
        "timestamp": "2024-06-12T10:05:59+00:00",
        "properties": None,
    }


def fetched(entity: dict[str, Any], *relation_ids: str) -> dict[str, Any]:
    """The fetch answer for an entity: the entity with its relation ids."""
    incoming = [item for item in relation_ids if item == "rel-hosts"]
    outgoing = [item for item in relation_ids if item != "rel-hosts"]
    return {**entity, "relation_ids": {"incoming": incoming, "outgoing": outgoing}}


def page(next_page: int | None, *results: dict[str, Any]) -> dict[str, Any]:
    """One search page."""
    return {"current_page_id": 1, "next_page_id": next_page, "results": list(results)}


def run_stage(
    investigation: Investigation, answers: dict[str, list[Any]]
) -> list[tuple[str, dict[str, Any]]]:
    """Make every call of the stage against canned answers, in order per tool.

    Returns:
        Each call the stage made, without its `reasoning`.
    """
    calls = []
    while (call := investigation.alert_stage_call()) is not None:
        calls.append(
            (call.tool, {key: value for key, value in call.arguments.items() if key != "reasoning"})
        )
        result = answers[call.tool].pop(0)
        investigation.after_call(call.tool, call.arguments, ToolOutcome("ok", result))
    return calls


def task(*specs: dict[str, Any], alert: dict[str, Any] | None = None) -> Investigation:
    """An investigation of an alert on `proc-1` running on `host-1`."""
    alert = alert or {"trigger_entities": [HOST, PROCESS], "trigger_relations": [HOSTS]}
    return Investigation(
        {
            "available_tools": json.dumps([*specs, REPORT]),
            "last_tool_result": '""',
            "alert_text": json.dumps(alert),
        }
    )


def test_each_alert_entity_is_fetched_and_its_relations_fit_one_search_page() -> None:
    """A page that holds the whole search is all; an entity with nothing open gets no search."""
    child = relation("rel-child", "proc-1", "proc-2")
    investigation = task(FETCH, FIND)

    calls = run_stage(
        investigation,
        {
            "fetch_node": [fetched(HOST, "rel-hosts"), fetched(PROCESS, "rel-hosts", "rel-child")],
            "find": [page(None, PROCESS, child)],
        },
    )

    # The host's only relation came with the alert, so only the process is searched.
    assert calls == [
        ("fetch_node", {"entity_id": "host-1"}),
        ("fetch_node", {"entity_id": "proc-1"}),
        ("find", {"query": "proc-1", "page_id": 1}),
    ]
    # The model's repeat of a stage call does not reach the runtime.
    repeat = investigation.before_call("find", {"query": "proc-1"})
    assert isinstance(repeat, LocalAnswer)
    assert repeat.feedback["result"]["results"][1] == child


def test_a_busy_entity_gets_every_page_of_the_search_within_the_alert_window() -> None:
    """More than a page: the search restarts within the window and runs to its last page."""
    investigation = task(FETCH, FIND, alert={"trigger_entities": [HOST, PROCESS]})
    open_ids = [f"rel-{number}" for number in range(3)]

    calls = run_stage(
        investigation,
        {
            "fetch_node": [fetched(HOST, *open_ids), fetched(PROCESS)],
            "find": [
                page(2, relation("rel-0", "host-1", "proc-1")),
                page(2, relation("rel-1", "host-1", "proc-1")),
                page(None),
            ],
        },
    )

    # The window runs from the process's start, not the host's boot, one hour each side.
    window = {"from": "2024-06-12T09:05:58Z", "to": "2024-06-12T11:05:59Z"}
    assert calls == [
        ("fetch_node", {"entity_id": "host-1"}),
        ("find", {"query": "host-1", "page_id": 1}),
        ("find", {"query": "host-1", "time_window": window, "page_id": 1}),
        ("find", {"query": "host-1", "time_window": window, "page_id": 2}),
        ("fetch_node", {"entity_id": "proc-1"}),
    ]


@pytest.mark.parametrize(
    ("specs", "alert", "expected"),
    [
        # No search in the catalog: the entities are only fetched.
        ((FETCH,), None, [("fetch_node", {"entity_id": "host-1"})]),
        # No fetch in the catalog: nothing is known to be opened, so the search runs.
        ((FIND,), None, [("find", {"query": "host-1", "page_id": 1})]),
        # No timestamp in the alert: no window, so a busy entity gets only the first page.
        (
            (FIND,),
            {"trigger_entities": [{"id": "host-1"}]},
            [("find", {"query": "host-1", "page_id": 1})],
        ),
    ],
)
def test_a_missing_tool_or_window_skips_that_part_of_the_stage(
    specs: tuple[dict[str, Any], ...], alert: dict[str, Any] | None, expected: list[Any]
) -> None:
    """The stage uses only what the catalog and the alert give (ADR 0003)."""
    alert = alert or {"trigger_entities": [{"id": "host-1"}]}
    investigation = task(*specs, alert=alert)

    calls = run_stage(
        investigation,
        {"fetch_node": [fetched(HOST)], "find": [page(2, relation("rel-0", "host-1", "x"))]},
    )

    assert calls == expected


def test_a_search_whose_next_page_does_not_move_forward_ends_the_stage() -> None:
    """A runtime that names the same page again cannot loop the stage forever (ADR 0009)."""
    investigation = task(FIND, alert={"trigger_entities": [HOST]})

    calls = run_stage(investigation, {"find": [page(2), page(1), page(1)]})

    assert [arguments.get("time_window") is not None for _, arguments in calls] == [False, True]


def test_without_stage_tools_the_model_starts_at_once() -> None:
    """A catalog with only the report makes no call before the first turn."""
    assert task().alert_stage_call() is None
