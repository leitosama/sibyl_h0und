import pytest

from sibyl_h0und.ledger import GraphLedger
from sibyl_h0und.outcome import ToolOutcome

ALERT = {
    "alert": {
        "trigger_entities": [{"id": "proc-1", "type": "windows_process"}],
        "trigger_relations": ["rel-1"],
    }
}
ENTITY = {
    "id": "proc-1",
    "properties": {"image": "C:/a.exe", "digital_signature": "Vendor"},
    "relation_ids": {"incoming": ["rel-1"], "outgoing": ["rel-2", "rel-3"]},
}


def fetched_ledger() -> GraphLedger:
    """Build a ledger that has seen the alert and fetched its trigger process."""
    ledger = GraphLedger()
    ledger.observe_alert(ALERT)
    arguments = {"entity_id": "proc-1", "reasoning": "Inspect."}
    ledger.record("get_entity", arguments, ToolOutcome("ok", ENTITY, None))
    return ledger


def test_unknown_id_is_rejected_with_the_open_ids() -> None:
    """An id the runtime never returned must not reach it."""
    ledger = fetched_ledger()

    decision = ledger.check("get_relation", {"relation_id": "rel-9", "reasoning": "Guess."})

    assert decision.reason == "rejected"
    assert decision.feedback is not None
    assert "rel-9" in decision.feedback["message"]
    assert "rel-2" in decision.feedback["message"]
    assert ledger.check("get_relation", {"relation_id": "rel-2", "reasoning": "x"}).feedback is None


def test_ids_from_relations_and_alert_are_known() -> None:
    """Endpoints of a fetched relation become known entities."""
    ledger = fetched_ledger()
    relation = {"id": "rel-2", "source_id": "proc-1", "target_id": "file-7"}
    ledger.record(
        "get_relation",
        {"relation_id": "rel-2", "reasoning": "x"},
        ToolOutcome("ok", relation, None),
    )

    assert ledger.unvisited_entities() == ["file-7"]
    assert ledger.unvisited_relations() == ["rel-1", "rel-3"]
    assert ledger.summary()["entities_with_open_relations"] == [
        {
            "entity_id": "proc-1",
            "incoming": "1 relations, 0 visited",
            "outgoing": "2 relations, 1 visited",
        }
    ]


def test_relations_returned_in_full_by_a_search_count_as_visited() -> None:
    """A relation a search returned whole needs no fetch; one without properties does."""
    ledger = fetched_ledger()
    found = {
        "results": [
            {
                "kind": "relation",
                "id": "rel-2",
                "type": "win_process_create",
                "source_id": "proc-1",
                "target_id": "proc-8",
                "properties": {"cmdline": "x.exe"},
            },
            {
                "kind": "relation",
                "id": "rel-3",
                "type": "wrote_file",
                "source_id": "proc-1",
                "target_id": "file-4",
            },
            {"kind": "entity", "id": "proc-8", "type": "windows_process"},
        ]
    }
    ledger.record(
        "search",
        {"query": "proc-1", "reasoning": "x"},
        ToolOutcome("ok", found, None),
    )

    assert ledger.unvisited_relations() == ["rel-1", "rel-3"]
    assert ledger.unvisited_entities() == ["file-4", "proc-8"]
    cited = {"anchor": "relation", "relation_id": "rel-2", "property_fields": ["cmdline"]}
    assert ledger.check("finish_investigation", {"legitimacy_evidence": [cited]}).feedback is None
    typo = {**cited, "property_fields": ["typo"]}
    decision = ledger.check("finish_investigation", {"legitimacy_evidence": [typo]})
    assert decision.feedback is not None
    assert "'typo'" in decision.feedback["message"]


def test_failed_response_does_not_make_the_requested_id_known() -> None:
    """An error that echoes an invented id must not legitimize it."""
    ledger = GraphLedger()
    error = {"relation_id": "rel-9", "message": "Unknown relation_id 'rel-9'"}
    ledger.record(
        "get_relation",
        {"relation_id": "rel-9", "reasoning": "x"},
        ToolOutcome("error", error, error),
    )

    assert not ledger.is_known("rel-9")


def test_duplicate_call_is_served_from_the_cache() -> None:
    """The same call with other reasoning repeats an earlier one."""
    ledger = fetched_ledger()

    decision = ledger.check("get_entity", {"entity_id": "proc-1", "reasoning": "Again."})

    assert decision.reason == "cached"
    assert decision.feedback is not None
    assert decision.feedback["result"] == ENTITY
    search = {"query": "evil.exe", "reasoning": "Find it."}
    ledger.record("search", search, ToolOutcome("ok", []))
    padded = {"query": " evil.exe ", "reasoning": "Find it again."}
    assert ledger.check("search", padded).reason == "cached"


def test_finish_citing_unknown_id_or_property_is_rejected() -> None:
    """The verdict may cite only returned ids and their real properties."""
    ledger = fetched_ledger()

    def finish(entity_id: str, field: str) -> dict[str, object]:
        evidence = {"anchor": "entity", "entity_id": entity_id, "property_fields": [field]}
        return {"submission": {"verdict": "benign", "legitimacy_evidence": [evidence]}}

    unknown_id = ledger.check("finish_investigation", finish("proc-404", "image"))
    typo = ledger.check("finish_investigation", finish("proc-1", "digitial_signature"))

    assert unknown_id.reason == "rejected"
    assert typo.reason == "rejected"
    assert typo.feedback is not None
    assert "digital_signature" in typo.feedback["message"]
    for field in ("digital_signature", "properties.image"):
        assert ledger.check("finish_investigation", finish("proc-1", field)).feedback is None
    # Properties of an entity never fetched cannot be checked, so they pass.
    assert ledger.check("finish_investigation", finish("rel-3", "anything")).feedback is None


def test_plain_fields_of_trigger_entities_are_not_ids() -> None:
    """Only id keys of an alert entity become ids, not its other fields."""
    ledger = GraphLedger()
    ledger.observe_alert(
        {"trigger_entities": [{"entity_id": "proc-1", "type": "windows_process", "tags": ["x"]}]}
    )

    assert ledger.unvisited_entities() == ["proc-1"]


def test_response_without_the_object_records_no_properties() -> None:
    """A call that takes an entity id but returns something else must not limit its fields."""
    ledger = fetched_ledger()
    other = {"entity_id": "proc-1", "score": 3}
    ledger.record(
        "score_entity",
        {"entity_id": "proc-9-unseen", "reasoning": "x"},
        ToolOutcome("ok", other, None),
    )

    assert "proc-9-unseen" not in ledger.properties


def test_alert_prose_names_ids_only_as_whole_words() -> None:
    """A fragment of an id in the alert text is not a known id."""
    ledger = GraphLedger()
    ledger.observe_alert({"alert_text": "Process proc-12 wrote C:/tmp/a.exe. Then proc-77."})

    assert ledger.is_known("proc-12")
    assert ledger.is_known("proc-77")
    assert ledger.is_known("C:/tmp/a.exe")
    assert not ledger.is_known("proc-1")
    assert not ledger.is_known("1")
    assert not ledger.is_known("proc")


BUSY = {
    "id": "proc-1",
    "relation_ids": {
        "incoming": ["in-1", "in-2"],
        "outgoing": [f"out-{index}" for index in range(25)],
    },
}


def connection(relation_id: str) -> dict[str, object]:
    """An outgoing relation of the dominant type, whole, as a search returns it."""
    return {
        "id": relation_id,
        "type": "connected_to",
        "source_id": "proc-1",
        "target_id": f"conn-{relation_id}",
        "properties": {},
    }


def busy_ledger(incoming_types: tuple[str, ...] = ()) -> GraphLedger:
    """Build a ledger that fetched a busy process and saw a first search page of 10.

    Args:
        incoming_types: Types of the incoming relations to open, in order.
    """
    ledger = GraphLedger()
    ledger.observe_alert(ALERT)
    ledger.record("get_entity", {"entity_id": "proc-1"}, ToolOutcome("ok", BUSY))
    first = {"results": [connection(f"out-{index}") for index in range(10)], "next_page_id": 2}
    ledger.record("search", {"query": "proc-1", "page_id": 1}, ToolOutcome("ok", first))
    for relation_id, relation_type in zip(("in-1", "in-2"), incoming_types, strict=False):
        relation = {
            "id": relation_id,
            "type": relation_type,
            "source_id": "x",
            "target_id": "proc-1",
        }
        ledger.record("get_relation", {"relation_id": relation_id}, ToolOutcome("ok", relation))
    return ledger


def count_page(
    ledger: GraphLedger,
    results: list[dict[str, object]],
    next_page_id: int | None = None,
    **extra: object,
) -> dict[str, object]:
    """Record page 3 of the search by the process id scoped to `connected_to`."""
    arguments = {
        "query": "proc-1",
        "scope": {"kind": "relation", "type": "connected_to"},
        "page_id": 3,
        **extra,
    }
    found = {"results": results, "current_page_id": 3, "next_page_id": next_page_id}
    ledger.record("search", arguments, ToolOutcome("ok", found))
    return ledger.summary()["entities_with_open_relations"][0]


@pytest.mark.parametrize(
    ("on_last_page", "expected"),
    [
        pytest.param(6, "25 outgoing; 0 outgoing relations are of other types", id="all-of-type"),
        pytest.param(3, "22 outgoing; 3 outgoing relations are of other types", id="others"),
    ],
)
def test_the_last_page_of_a_type_counts_the_outgoing_relations_of_other_types(
    on_last_page: int, expected: str
) -> None:
    """Page 3 of 10 makes 20 + n of the type; an incoming one of that type is not outgoing."""
    ledger = busy_ledger(("parent_of", "connected_to"))

    entry = count_page(ledger, [connection(f"x-{index}") for index in range(on_last_page)])

    assert entry["outgoing_by_type"] == {"connected_to": expected}


def test_a_busy_entity_is_told_the_counting_page_until_a_type_is_counted() -> None:
    """25 outgoing relations at 10 per page: page 3 counts one type."""
    ledger = busy_ledger(("parent_of", "parent_of"))
    before = ledger.summary()["entities_with_open_relations"][0]

    after = count_page(ledger, [connection(f"x-{index}") for index in range(5)])

    assert before["count_page"].startswith("page 3 ")
    assert "count_page" not in after


def test_a_count_is_not_split_by_direction_while_an_incoming_type_is_unknown() -> None:
    """An unopened incoming relation may be of the counted type."""
    entry = count_page(busy_ledger(), [connection(f"x-{index}") for index in range(6)])

    assert "open its incoming relations" in entry["outgoing_by_type"]["connected_to"]


def test_an_empty_page_past_the_end_bounds_the_count() -> None:
    """Nothing on page 3 means at most 20 of the type, so at least 5 other outgoing ones."""
    entry = count_page(busy_ledger(("parent_of", "parent_of")), [])

    assert entry["outgoing_by_type"] == {
        "connected_to": "at most 20 name this entity; at least 5 outgoing relations are of other "
        "types; request page 2 next"
    }


def test_an_empty_first_page_says_the_type_is_absent() -> None:
    """A type with no relation at all is not mistaken for a split with no other types."""
    entry = count_page(busy_ledger(), [], page_id=1)

    assert entry["outgoing_by_type"] == {"connected_to": "no relations of this type"}


def test_a_page_with_a_next_one_asks_for_it() -> None:
    """Incoming relations of the type can push it past the advised page."""
    page = [connection(f"x-{index}") for index in range(10)]

    entry = count_page(busy_ledger(("parent_of", "parent_of")), page, next_page_id=4)

    assert entry["outgoing_by_type"]["connected_to"].startswith("more than 30")


def test_an_exact_count_is_kept_over_a_later_bound() -> None:
    """Probing an empty page after the last one must not blur the exact count."""
    ledger = busy_ledger(("parent_of", "parent_of"))
    count_page(ledger, [connection(f"x-{index}") for index in range(5)])

    entry = count_page(ledger, [], page_id=4)

    assert entry["outgoing_by_type"] == {
        "connected_to": "25 outgoing; 0 outgoing relations are of other types"
    }


def test_a_count_larger_than_the_entity_is_flagged_not_split() -> None:
    """A total above the entity's relations cannot give a negative number of others."""
    entry = count_page(
        busy_ledger(("parent_of", "parent_of")), [connection(f"x-{index}") for index in range(8)]
    )

    assert "says nothing" in entry["outgoing_by_type"]["connected_to"]


@pytest.mark.parametrize(
    "extra",
    [
        pytest.param({"time_window": {"from": "2024-06-12T11:00:00Z"}}, id="time-window"),
        pytest.param({"query": "conn-x-1"}, id="not-a-fetched-entity"),
        pytest.param({"scope": {"kind": "entity", "type": "windows_process"}}, id="entity-scope"),
    ],
)
def test_a_search_not_comparable_with_the_relation_ids_counts_nothing(
    extra: dict[str, object],
) -> None:
    """Only an unwindowed search by the entity's id, scoped to a relation type, counts."""
    entry = count_page(busy_ledger(("parent_of", "parent_of")), [connection("x-1")], **extra)

    assert "outgoing_by_type" not in entry


def test_a_page_with_a_hit_that_does_not_name_the_entity_counts_nothing() -> None:
    """A substring match on another relation would inflate the count."""
    stray = {**connection("x-2"), "source_id": "proc-10"}

    entry = count_page(busy_ledger(("parent_of", "parent_of")), [connection("x-1"), stray])

    assert "outgoing_by_type" not in entry
