import json
from pathlib import Path
from typing import Any

import pytest

from sibyl_h0und.catalog import FINISH_TOOL
from sibyl_h0und.investigation import Investigation, LocalAnswer, Send
from sibyl_h0und.outcome import ToolOutcome
from sibyl_h0und.trace import TaskTrace

CATALOG = [
    {
        "name": "get_entity",
        "parameters": {
            "type": "object",
            "properties": {"entity_id": {"type": "string"}, "reasoning": {"type": "string"}},
            "required": ["entity_id", "reasoning"],
        },
    },
    {"name": FINISH_TOOL, "parameters": {"type": "object"}},
]
DROPPED_FILE = {
    "id": "file-1",
    "type": "windows_file",
    "properties": {"path": "C:\\Windows\\System32\\run.ps1"},
}


REPORT = {
    "verdict": "malicious",
    "ir_artifacts": [{"entity_id": "file-1", "kind": "host_to_isolate"}],
    "reasoning": "Script dropped into System32.",
}


def observation(specs: list[dict[str, Any]] = CATALOG) -> dict[str, Any]:
    """Build a task observation whose alert names `file-1`."""
    return {
        "available_tools": json.dumps(specs),
        "last_tool_result": '""',
        "alert_text": json.dumps({"trigger_entities": [{"id": "file-1"}]}),
    }


def get_entity(entity_id: str = "file-1") -> dict[str, Any]:
    """Arguments of a valid `get_entity` call."""
    return {"entity_id": entity_id, "reasoning": "Inspect."}


def test_tool_outside_the_catalog_is_answered_locally() -> None:
    """A tool the task did not advertise never reaches the runtime."""
    answer = Investigation(observation()).before_call("delete_everything", {})

    assert isinstance(answer, LocalAnswer)
    assert answer.feedback["status"] == "error"
    assert "get_entity" in answer.feedback["message"]


def test_only_the_report_is_allowed_when_finish_only() -> None:
    """At the safety ceiling an advertised tool is still refused, and the report goes through."""
    investigation = Investigation(observation())

    refused = investigation.before_call("get_entity", get_entity(), finish_only=True)
    allowed = investigation.before_call(FINISH_TOOL, {"submission": REPORT}, finish_only=True)

    assert isinstance(refused, LocalAnswer)
    assert FINISH_TOOL in refused.feedback["message"]
    assert allowed == Send({"submission": REPORT})


def test_a_catalog_without_the_report_tool_is_refused() -> None:
    """A task that cannot be finished is not started."""
    with pytest.raises(ValueError, match=FINISH_TOOL):
        Investigation(observation(CATALOG[:1]))


def test_invalid_arguments_and_invented_ids_are_answered_locally() -> None:
    """Both cost no runtime call, and the model is told what is wrong."""
    investigation = Investigation(observation())

    invalid = investigation.before_call("get_entity", {"reasoning": "No id."})
    invented = investigation.before_call("get_entity", get_entity("file-404"))

    assert isinstance(invalid, LocalAnswer)
    assert "Not sent to the runtime" in invalid.feedback["message"]
    assert isinstance(invented, LocalAnswer)
    assert "file-404" in invented.feedback["message"]


def test_evidence_comes_with_open_ids_and_a_repeat_gets_only_the_evidence() -> None:
    """still_open is delivered once; the cached reply repeats the evidence."""
    investigation = Investigation(observation())
    sent = investigation.before_call("get_entity", get_entity())
    assert isinstance(sent, Send)

    reply = investigation.after_call("get_entity", sent.arguments, ToolOutcome("ok", DROPPED_FILE))
    repeat = investigation.before_call("get_entity", get_entity())

    assert reply.feedback["result"] == DROPPED_FILE
    assert isinstance(repeat, LocalAnswer)
    assert repeat.feedback["result"] == DROPPED_FILE
    assert "still_open" not in repeat.feedback
    assert "note" in repeat.feedback


SCOPED_SEARCH = {
    "name": "find",
    "parameters": {
        "$defs": {
            "RelationSearchScope": {
                "type": "object",
                "properties": {"kind": {"const": "relation"}, "type": {"type": "string"}},
            }
        },
        "type": "object",
        "properties": {
            "query": {"type": "string"},
            "scope": {"anyOf": [{"$ref": "#/$defs/RelationSearchScope"}, {"type": "null"}]},
        },
        "required": ["query"],
    },
}
PROCESS = {**DROPPED_FILE, "relation_ids": {"incoming": [], "outgoing": ["rel-1", "rel-2"]}}


def fetch_process(investigation: Investigation) -> dict[str, Any]:
    """Fetch the alert entity, which has two open relations, and return `still_open`."""
    sent = investigation.before_call("get_entity", get_entity())
    assert isinstance(sent, Send)
    reply = investigation.after_call("get_entity", sent.arguments, ToolOutcome("ok", PROCESS))
    return reply.feedback["still_open"]


def test_a_fetched_entity_with_open_relations_points_to_the_catalogs_relation_search() -> None:
    """The advice names the task's own search, once, on the reply that fetched the entity."""
    investigation = Investigation(observation([*CATALOG, SCOPED_SEARCH]))

    still_open = fetch_process(investigation)
    later = investigation.after_call(
        "find", {"query": "run.ps1"}, ToolOutcome("ok", {"results": []})
    )

    assert still_open["list_relations_with"].startswith("find with this entity's full id")
    assert "list_relations_with" not in later.feedback["still_open"]


def test_no_relation_search_advice_without_such_a_tool() -> None:
    """A task without a relation-scoped search is never told to use one."""
    still_open = fetch_process(Investigation(observation()))

    assert still_open["entities_with_open_relations"]
    assert "list_relations_with" not in still_open


def test_a_runtime_error_teaches_nothing() -> None:
    """An error response is not learned from, even if it echoes a node."""
    investigation = Investigation(observation())

    reply = investigation.after_call(
        "get_entity", get_entity("file-9"), ToolOutcome("error", DROPPED_FILE, "boom")
    )

    assert reply.feedback["error"] == "boom"
    assert isinstance(investigation.before_call("get_entity", get_entity("file-9")), LocalAnswer)


def test_the_knowledge_tool_is_offered_and_answered_locally_whatever_the_ledger_knows() -> None:
    """A lookup needs no known id, can repeat, and is answered by the vocabulary."""
    investigation = Investigation(observation())

    first = investigation.before_call("lookup_knowledge", {"query": "T1036.003"})
    again = investigation.before_call("lookup_knowledge", {"query": "T1036.003"})

    assert "lookup_knowledge" in [spec["name"] for spec in investigation.catalog.specs]
    assert isinstance(first, LocalAnswer)
    assert first.feedback["matches"][0]["id"] == "T1036.003"
    assert again == first


def test_a_knowledge_lookup_without_a_query_is_refused_locally_not_crashed() -> None:
    """The model's malformed lookup gets an error message instead of breaking the task."""
    answer = Investigation(observation()).before_call("lookup_knowledge", {})

    assert isinstance(answer, LocalAnswer)
    assert "Not sent to the runtime" in answer.feedback["message"]


def test_a_runtime_tool_of_the_same_name_wins_over_the_local_one() -> None:
    """The runtime's catalog is authoritative (ADR 0003): its tool is sent to the runtime."""
    runtime_tool = {
        "name": "lookup_knowledge",
        "parameters": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    }
    investigation = Investigation(observation([*CATALOG, runtime_tool]))

    decision = investigation.before_call("lookup_knowledge", {"query": "x"})

    assert isinstance(decision, Send)


def test_local_decisions_are_traced(tmp_path: Path) -> None:
    """Rejections and cache hits leave the events the trace format promises."""
    path = tmp_path / "t.trace.jsonl"
    investigation = Investigation(observation(), TaskTrace(path, task_id="t"))
    investigation.before_call("delete_everything", {})
    investigation.before_call("get_entity", {"reasoning": "No id."})
    sent = investigation.before_call("get_entity", get_entity())
    assert isinstance(sent, Send)
    investigation.after_call("get_entity", sent.arguments, ToolOutcome("ok", DROPPED_FILE))
    investigation.before_call("get_entity", get_entity())

    investigation.before_call("lookup_knowledge", {"query": "x"})

    kinds = [json.loads(line)["kind"] for line in path.read_text().splitlines()]

    assert kinds == ["tool_rejected", "tool_invalid", "tool_cached", "tool_knowledge"]
