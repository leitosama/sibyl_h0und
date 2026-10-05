from sibyl_h0und.ledger import GraphLedger

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
    ledger.record("get_entity", arguments, ENTITY, {"status": "ok", "result": ENTITY}, failed=False)
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
        relation,
        {"status": "ok", "result": relation},
        failed=False,
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


def test_failed_response_does_not_make_the_requested_id_known() -> None:
    """An error that echoes an invented id must not legitimize it."""
    ledger = GraphLedger()
    error = {"relation_id": "rel-9", "message": "Unknown relation_id 'rel-9'"}
    ledger.record(
        "get_relation",
        {"relation_id": "rel-9", "reasoning": "x"},
        error,
        {"status": "error", "result": error},
        failed=True,
    )

    assert not ledger.is_known("rel-9")


def test_duplicate_call_is_served_from_the_cache() -> None:
    """The same call with other reasoning repeats an earlier one."""
    ledger = fetched_ledger()

    decision = ledger.check("get_entity", {"entity_id": "proc-1", "reasoning": "Again."})

    assert decision.reason == "cached"
    assert decision.feedback is not None
    assert decision.feedback["result"] == ENTITY


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
        other,
        {"status": "ok", "result": other},
        failed=False,
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
