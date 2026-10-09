from typing import Any

from sibyl_h0und.digest import evidence_digest
from sibyl_h0und.ledger import GraphLedger
from sibyl_h0und.outcome import ToolOutcome


def relation(relation_id: str, kind: str, source: str, target: str) -> dict[str, Any]:
    """A relation as a search returns it in full."""
    return {
        "kind": "relation",
        "id": relation_id,
        "type": kind,
        "source_id": source,
        "target_id": target,
        "properties": {"ts": "2026-10-01T10:00:00Z"},
    }


def two_hosts_ledger(host_type: str = "host") -> GraphLedger:
    """A process on host A connects to a process on host B; one user stands apart."""
    ledger = GraphLedger()
    ledger.observe_alert(
        {
            "trigger_entities": [
                {"id": "proc-1", "type": "windows_process"},
                {"id": "host-a", "type": host_type},
            ]
        }
    )
    process = {
        "id": "proc-1",
        "type": "windows_process",
        "properties": {"image": "a.exe"},
        "relation_ids": {"incoming": ["run-a"], "outgoing": ["conn", "rel-x"]},
    }
    ledger.record("get_entity", {"entity_id": "proc-1"}, ToolOutcome("ok", process))
    found = {
        "results": [
            relation("run-a", "runs_process", "host-a", "proc-1"),
            relation("conn", "connected_to", "proc-1", "proc-9"),
            relation("run-b", "runs_process", "host-b", "proc-9"),
            # A shorter mention of the fetched process must not replace what the fetch gave.
            {"kind": "entity", "id": "proc-1", "properties": {"image": "A~1.EXE"}},
            {"kind": "entity", "id": "proc-9", "type": "windows_process"},
            {"kind": "entity", "id": "host-b", "type": host_type},
            {"kind": "entity", "id": "user-7", "type": "windows_user"},
        ]
    }
    ledger.record("search", {"query": "proc-1"}, ToolOutcome("ok", found))
    return ledger


def ids(items: list[dict[str, Any]]) -> list[str]:
    """Ids of a list of objects, in order."""
    return [item["id"] for item in items]


def test_evidence_is_grouped_by_host_with_cross_host_relations_apart() -> None:
    """Each object appears once under its nearest host; a relation joining two hosts is
    shown between them, and what no host reaches is kept."""
    digest = evidence_digest(two_hosts_ledger())

    host_a, host_b = digest["hosts"]
    assert (host_a["host"]["id"], ids(host_a["entities"]), ids(host_a["relations"])) == (
        "host-a",
        ["proc-1"],
        ["run-a"],
    )
    assert (host_b["host"]["id"], ids(host_b["entities"]), ids(host_b["relations"])) == (
        "host-b",
        ["proc-9"],
        ["run-b"],
    )
    assert ids(digest["between_hosts"]) == ["conn"]
    assert digest["no_host"] == {
        "entities": [{"kind": "entity", "id": "user-7", "type": "windows_user"}]
    }
    (process,) = host_a["entities"]
    assert process["properties"] == {"image": "a.exe"}
    assert "relation_ids" not in process
    assert process["unvisited_relation_ids"] == {"outgoing": ["rel-x"]}


def test_without_host_entities_the_evidence_keeps_the_walk_from_the_alert() -> None:
    """If hosts are named differently, nothing is lost: one group, starting at the trigger."""
    digest = evidence_digest(two_hosts_ledger(host_type="server"))

    assert set(digest) == {"no_host"}
    assert ids(digest["no_host"]["entities"]) == ["proc-1", "host-a", "proc-9", "host-b", "user-7"]
    assert ids(digest["no_host"]["relations"]) == ["run-a", "conn", "run-b"]
