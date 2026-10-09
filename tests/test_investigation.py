import json
from pathlib import Path
from typing import Any

import pytest

from sibyl_h0und.catalog import FINISH_TOOL
from sibyl_h0und.investigation import Investigation, LocalAnswer, Review, Send
from sibyl_h0und.models import Challenge
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


@pytest.mark.parametrize(
    ("report", "missing"),
    [
        ({**REPORT, "reasoning": ""}, "reasoning"),
        ({**REPORT, "reasoning": "Short test"}, "reasoning"),
        ({**REPORT, "ir_artifacts": []}, "ir_artifacts"),
        (
            {"verdict": "benign", "legitimacy_evidence": [], "reasoning": REPORT["reasoning"]},
            "legitimacy_evidence",
        ),
    ],
)
def test_a_report_that_says_nothing_is_refused_once(report: dict[str, Any], missing: str) -> None:
    """The model gets one chance to redo a placeholder; the second report is sent as is."""
    investigation = Investigation(observation())

    refused = investigation.before_call(FINISH_TOOL, {"submission": report})
    again = investigation.before_call(FINISH_TOOL, {"submission": report}, finish_only=True)

    assert isinstance(refused, LocalAnswer)
    assert missing in refused.feedback["message"]
    assert again == Send({"submission": report})


BENIGN_REPORT = {
    "verdict": "benign",
    "legitimacy_evidence": [
        {"anchor": "entity", "entity_id": "file-1", "property_fields": ["path"]}
    ],
    "reasoning": "Signed vendor binary run by the updater.",
}


def challenge(*calls: dict[str, Any]) -> Challenge:
    """Build a challenger reply whose checks make these calls."""
    return Challenge.model_validate(
        {
            "hypothesis": "The script in System32 is a dropped payload.",
            "checks": [{"refuted_if": "No writer.", "call": call} for call in calls],
        }
    )


def fetched_file_investigation(path: Path | None = None) -> Investigation:
    """An investigation that fetched the alert's file once."""
    investigation = Investigation(observation(), TaskTrace(path, task_id="t"))
    sent = investigation.before_call("get_entity", get_entity())
    assert isinstance(sent, Send)
    investigation.after_call("get_entity", sent.arguments, ToolOutcome("ok", DROPPED_FILE))
    return investigation


def test_the_first_benign_report_goes_to_the_challenger_without_the_heads_reasoning() -> None:
    """The challenger reads the alert and the evidence, may call only runtime tools, and
    never sees the report it argues against."""
    review = fetched_file_investigation().before_call(FINISH_TOOL, {"submission": BENIGN_REPORT})

    assert isinstance(review, Review)
    request = json.loads(review.messages[-1]["content"])
    assert request["evidence"]["no_host"]["entities"] == [DROPPED_FILE]
    assert BENIGN_REPORT["reasoning"] not in json.dumps(review.messages)
    schema = json.dumps(review.response_format)
    assert '"get_entity"' in schema
    assert FINISH_TOOL not in schema


def test_the_challengers_usable_checks_reach_the_model_and_the_next_report_is_sent() -> None:
    """A check with an invented id is dropped, a repeated one is marked as made, and the
    model's next report goes to the runtime as is."""
    investigation = fetched_file_investigation()
    review = investigation.before_call(FINISH_TOOL, {"submission": BENIGN_REPORT})
    assert isinstance(review, Review)

    reply = challenge(
        {"tool": "get_entity", "entity_id": "file-404", "reasoning": "Invented."},
        {"tool": "get_entity", "entity_id": "file-1", "reasoning": "Again."},
    )
    answer = investigation.after_review(review, reply)
    again = investigation.before_call(FINISH_TOOL, {"submission": BENIGN_REPORT})

    assert answer.feedback["challenge"] == {
        "hypothesis": reply.hypothesis,
        "checks": [
            {
                "call": {"tool": "get_entity", "entity_id": "file-1", "reasoning": "Again."},
                "refuted_if": "No writer.",
                "already_made": True,
            }
        ],
    }
    assert again == Send({"submission": BENIGN_REPORT})


@pytest.mark.parametrize(
    ("reply", "error"),
    [
        (None, "NextStepRequestError: invalid JSON"),
        (challenge({"tool": "get_entity", "entity_id": "file-404", "reasoning": "x"}), None),
    ],
    ids=["challenger-failed", "no-usable-check"],
)
def test_without_a_usable_challenge_the_model_gets_the_general_question(
    tmp_path: Path, reply: Challenge | None, error: str | None
) -> None:
    """The run never depends on the challenger: the general question replaces it, and the
    trace says why."""
    path = tmp_path / "t.trace.jsonl"
    investigation = fetched_file_investigation(path)
    review = investigation.before_call(FINISH_TOOL, {"submission": BENIGN_REPORT})
    assert isinstance(review, Review)

    answer = investigation.after_review(review, reply, error)

    assert "one stage before" in answer.feedback["message"]
    assert "challenge" not in answer.feedback
    event = json.loads(path.read_text().splitlines()[-1])
    assert event["kind"] == "benign_challenged"
    assert event["fallback"] == (error or "no usable check")


def test_a_placeholder_benign_report_is_refused_and_challenged_in_one_answer() -> None:
    """The model gets one refusal with both reasons, not two refusals in a row."""
    investigation = Investigation(observation())

    refused = investigation.before_call(
        FINISH_TOOL, {"submission": {**BENIGN_REPORT, "reasoning": ""}}
    )
    fixed = investigation.before_call(FINISH_TOOL, {"submission": BENIGN_REPORT})

    assert isinstance(refused, LocalAnswer)
    assert "reasoning" in refused.feedback["message"]
    assert "one stage before" in refused.feedback["message"]
    assert fixed == Send({"submission": BENIGN_REPORT})


@pytest.mark.parametrize(
    ("report", "finish_only"),
    [(REPORT, False), (BENIGN_REPORT, True)],
    ids=["malicious", "benign-at-the-ceiling"],
)
def test_no_challenge_for_malicious_or_when_only_the_report_remains(
    report: dict[str, Any], finish_only: bool
) -> None:
    """A malicious report is not questioned, and at the ceiling there is nothing left to open."""
    investigation = Investigation(observation())

    decision = investigation.before_call(
        FINISH_TOOL, {"submission": report}, finish_only=finish_only
    )

    assert decision == Send({"submission": report})


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


def test_a_knowledge_lookup_answers_every_term_the_model_lists() -> None:
    """The catalog accepts `terms` and the vocabulary answers each of them."""
    answer = Investigation(observation()).before_call(
        "lookup_knowledge", {"query": "vssadmin.exe", "terms": ["T1490"]}
    )

    assert isinstance(answer, LocalAnswer)
    assert {match["term"] for match in answer.feedback["matches"]} == {"vssadmin.exe", "T1490"}


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

    assert kinds == [
        "tool_rejected",
        "tool_invalid",
        "tool_cached",
        "tool_knowledge",
    ]
