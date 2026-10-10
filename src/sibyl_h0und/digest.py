"""The evidence of one task as one compact view, built from GraphLedger.

A side turn (the benign challenger) reads this view instead of the head's
history. It keeps every object the runtime returned and all of its
properties, once, so no id or property is lost (ADR 0007); it only drops
repeats and response wrappers. Code groups and orders the objects; it never
picks which properties matter (ADR 0017).
"""

from collections import deque
from collections.abc import Collection
from typing import Any

from sibyl_h0und.ledger import GraphLedger, listing

# Entity type of a host in the evidence graph. If the graph names hosts
# differently, nothing is grouped by host and the view keeps the walk order.
HOST_TYPE = "host"
ENDPOINT_KEYS = ("source_id", "target_id")


def evidence_digest(ledger: GraphLedger, only: Collection[str] | None = None) -> dict[str, Any]:
    """Group the evidence by host, each group in walk order from the alert.

    Objects are walked breadth-first over the relations, starting from the
    first object seen (the alert's). Each entity belongs to the nearest host
    entity; a relation belongs to the host of its endpoints, or to
    `between_hosts` when they belong to different hosts. What no host
    reaches is kept under `no_host`.

    Args:
        ledger: The task's ledger.
        only: Ids of the objects to show, such as those new since an earlier
            view; all when `None`. Grouping still uses the whole graph, and a
            host that is not shown itself is named by its id.

    Returns:
        `hosts`, `between_hosts` and `no_host`, each present only when non-empty.
    """
    relations = {key: value for key, value in ledger.objects.items() if key in ledger.relations}
    entities = {key: value for key, value in ledger.objects.items() if key not in relations}
    neighbours: dict[str, list[str]] = {key: [] for key in entities}
    for relation in relations.values():
        source, target = (relation.get(key) for key in ENDPOINT_KEYS)
        if source in neighbours and target in neighbours:
            neighbours[source].append(target)
            neighbours[target].append(source)

    order = _walk(list(entities), neighbours)
    hosts = [key for key in order if entities[key].get("type") == HOST_TYPE]
    host_set = set(hosts)
    owner = _nearest(hosts, neighbours)
    rank = {key: index for index, key in enumerate(order)}

    groups: dict[str | None, dict[str, list[dict[str, Any]]]] = {
        host: {"entities": [], "relations": []} for host in [*hosts, None]
    }
    shown = set(ledger.objects if only is None else only)
    for key in order:
        if key not in host_set and key in shown:
            groups[owner.get(key)]["entities"].append(_entity_view(ledger, entities[key]))
    between: list[dict[str, Any]] = []
    ranked = sorted(
        (value for key, value in relations.items() if key in shown),
        key=lambda item: min(rank.get(item.get(key), len(rank)) for key in ENDPOINT_KEYS),
    )
    for relation in ranked:
        ends = [relation.get(key) for key in ENDPOINT_KEYS]
        owners = {owner[end] for end in ends if end in owner}
        if len(owners) > 1:
            between.append(relation)
        else:
            groups[next(iter(owners), None)]["relations"].append(relation)

    digest: dict[str, Any] = {}
    if listed := [
        {
            "host": _entity_view(ledger, entities[host]) if host in shown else {"id": host},
            **groups[host],
        }
        for host in hosts
        if host in shown or any(groups[host].values())
    ]:
        digest["hosts"] = listed
    if between:
        digest["between_hosts"] = between
    if any(groups[None].values()):
        digest["no_host"] = {key: value for key, value in groups[None].items() if value}
    return digest


def _walk(start: list[str], neighbours: dict[str, list[str]]) -> list[str]:
    """Visit every entity breadth-first, starting a new walk at each one not yet reached."""
    seen: set[str] = set()
    order: list[str] = []
    for root in start:
        if root in seen:
            continue
        seen.add(root)
        queue = deque([root])
        while queue:
            key = queue.popleft()
            order.append(key)
            for neighbour in neighbours[key]:
                if neighbour not in seen:
                    seen.add(neighbour)
                    queue.append(neighbour)
    return order


def _nearest(hosts: list[str], neighbours: dict[str, list[str]]) -> dict[str, str]:
    """Map each entity a host reaches to the nearest host; a walk stops at another host."""
    owner = {host: host for host in hosts}
    queue = deque(hosts)
    while queue:
        key = queue.popleft()
        for neighbour in neighbours[key]:
            if neighbour not in owner:
                owner[neighbour] = owner[key]
                queue.append(neighbour)
    return owner


def _entity_view(ledger: GraphLedger, entity: dict[str, Any]) -> dict[str, Any]:
    """Show an entity without its relation id lists, naming only the unvisited ones."""
    view = {key: value for key, value in entity.items() if key != "relation_ids"}
    unvisited = {
        direction: listing([item for item in ids if item not in ledger.visited_relations])
        for direction, ids in ledger.entity_relations.get(entity["id"], {}).items()
    }
    if unvisited := {key: value for key, value in unvisited.items() if value}:
        view["unvisited_relation_ids"] = unvisited
    return view
