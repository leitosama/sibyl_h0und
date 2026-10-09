"""Per-task record of what the runtime has returned, consulted before every call.

The ledger never knows tool names. It reads ids from response shapes and
checks arguments by their keys, so a tool that is new on the competition day
is handled the same way as the practice tools.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Any

from sibyl_h0und.outcome import ToolOutcome

# Keys whose string value names an entity or a relation.
ENTITY_ID_KEYS = frozenset({"entity_id", "source_id", "target_id"})
RELATION_ID_KEYS = frozenset({"relation_id"})
# Keys whose list holds entities or relations, as dicts with `id` or as bare ids.
ENTITY_LIST_KEYS = frozenset({"trigger_entities", "entities", "entity_ids"})
RELATION_LIST_KEYS = frozenset({"trigger_relations", "relations", "relation_ids"})
# Keys whose string value names an entity, of this type, that a response may
# mention without returning the entity itself, like the host of a process.
ENTITY_REFERENCE_KEYS = {"host_id": "host"}
# Arguments that never change what a call returns.
IGNORED_ARGUMENTS = frozenset({"reasoning"})
# Characters that end an id inside the alert's prose.
ID_BOUNDARY = r"\s\"'`,;()\[\]{}<>"
# Shorter values are too likely to occur in prose by chance.
MIN_PROSE_ID_LENGTH = 4
# How many ids an error message or a summary lists before it only counts them.
MAX_LISTED_IDS = 30
# Marks a property field an object does not hold.
_MISSING = object()


@dataclass(frozen=True)
class LedgerDecision:
    """What to do with a call before it reaches the runtime.

    Attributes:
        feedback: Local answer for the model, or `None` to send the call.
        reason: `rejected` or `cached` when the call is answered locally.
    """

    feedback: dict[str, Any] | None = None
    reason: str | None = None


@dataclass
class GraphLedger:
    """Ids the runtime returned, ids already visited and a cache of responses."""

    entities: set[str] = field(default_factory=set)
    relations: set[str] = field(default_factory=set)
    visited_entities: set[str] = field(default_factory=set)
    visited_relations: set[str] = field(default_factory=set)
    # Every string value the runtime returned: an id that appears anywhere is real.
    seen_values: set[str] = field(default_factory=set)
    # Entity ids named by reference, such as a process's `host_id`, with the
    # type the key implies. A report may cite them, but they are not listed as
    # unvisited.
    entity_references: dict[str, str] = field(default_factory=dict)
    # Free text of the alert, where ids may appear inside prose.
    alert_text: list[str] = field(default_factory=list)
    # Property keys of every entity or relation fetched by its id.
    properties: dict[str, set[str]] = field(default_factory=dict)
    # Incoming and outgoing relation ids of every fetched entity.
    entity_relations: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    cache: dict[str, dict[str, Any]] = field(default_factory=dict)
    # Results on a search page that has a next one, learned from the first such page.
    page_size: int | None = None
    # Per fetched entity and relation type: how many relations of that type name
    # the entity, read from a page of a search by its id scoped to the type, and
    # whether the number is `exact`, `at_most` (an empty page past the end) or
    # `more_than` (a page that has a next one).
    relation_counts: dict[str, dict[str, tuple[int, str]]] = field(default_factory=dict)
    # Every entity or relation object the runtime returned, merged by id, in
    # the order first seen: the alert's objects come first.
    objects: dict[str, dict[str, Any]] = field(default_factory=dict)

    def observe_alert(self, alert: dict[str, Any]) -> None:
        """Record the ids named by the task observation.

        Args:
            alert: Decoded observation fields without the tool catalog.
        """
        self.alert_text.extend(value for value in alert.values() if isinstance(value, str))
        self._collect(alert)

    def check(self, tool_name: str, arguments: dict[str, Any]) -> LedgerDecision:
        """Decide whether a call must reach the runtime.

        Args:
            tool_name: Advertised tool name.
            arguments: Arguments the model chose.

        Returns:
            A local answer for a call with an unknown id or a repeated call,
            otherwise an empty decision.
        """
        problems = self._argument_problems(arguments)
        if problems:
            return LedgerDecision(
                feedback={
                    "status": "error",
                    "message": "Not sent to the runtime: " + " ".join(problems),
                },
                reason="rejected",
            )
        cached = self.cache.get(self._cache_key(tool_name, arguments))
        if cached is not None:
            return LedgerDecision(
                feedback={
                    **cached,
                    "note": "Identical call already made; this is its earlier result.",
                },
                reason="cached",
            )
        return LedgerDecision()

    def record(self, tool_name: str, arguments: dict[str, Any], outcome: ToolOutcome) -> None:
        """Learn from one runtime response and cache its evidence.

        A failed response may echo the requested id, so it never makes an id
        known. A cache hit returns the evidence only: flags and open relations
        were delivered once with the first answer.

        Args:
            tool_name: Called tool name.
            arguments: Arguments sent to the runtime.
            outcome: The runtime's answer.
        """
        self.cache[self._cache_key(tool_name, arguments)] = outcome.evidence()
        if outcome.failed:
            return
        result = outcome.result
        entity_id = arguments.get("entity_id")
        relation_id = arguments.get("relation_id")
        if isinstance(entity_id, str):
            self.visited_entities.add(entity_id)
            self.entities.add(entity_id)
            self._record_fetched(entity_id, result)
            relation_lists = _find_key(result, "relation_ids")
            if isinstance(relation_lists, dict):
                self.entity_relations[entity_id] = {
                    direction: [item for item in ids if isinstance(item, str)]
                    for direction, ids in relation_lists.items()
                    if isinstance(ids, list)
                }
        if isinstance(relation_id, str):
            self.visited_relations.add(relation_id)
            self.relations.add(relation_id)
            self._record_fetched(relation_id, result)
        self._record_page(arguments, result)
        self._collect(result)

    def summary(self) -> dict[str, Any]:
        """Describe what is known but not yet visited.

        Returns:
            Open relations of each fetched entity and the unvisited entities,
            or an empty dict when nothing is open.
        """
        open_entities = []
        for entity_id, directions in self.entity_relations.items():
            counts = {}
            for direction, ids in directions.items():
                visited = sum(item in self.visited_relations for item in ids)
                if visited < len(ids):
                    counts[direction] = f"{len(ids)} relations, {visited} visited"
            if counts:
                open_entities.append(
                    {"entity_id": entity_id, **counts, **self._relation_shape(entity_id)}
                )
        summary: dict[str, Any] = {}
        if open_entities:
            summary["entities_with_open_relations"] = open_entities
        unvisited = self.unvisited_entities()
        if unvisited:
            summary["unvisited_entities"] = listing(unvisited)
        return summary

    def _relation_shape(self, entity_id: str) -> dict[str, Any]:
        """Say how many outgoing relations are of each counted type.

        A count of one type covers incoming relations of that type too, so the
        incoming relations whose type is known are subtracted from it.
        """
        directions = self.entity_relations[entity_id]
        incoming = directions.get("incoming", [])
        outgoing = len(directions.get("outgoing", []))
        by_type: dict[str, str] = {}
        for relation_type, (count, bound) in self.relation_counts.get(entity_id, {}).items():
            if bound == "more_than":
                by_type[relation_type] = (
                    f"more than {count} name this entity; request the next page to finish the count"
                )
                continue
            if bound == "at_most":
                others = outgoing - count
                by_type[relation_type] = f"at most {count} name this entity" + (
                    f"; at least {others} outgoing relations are of other types"
                    if others > 0
                    else ""
                )
                continue
            if count == 0:
                by_type[relation_type] = "no relations of this type"
                continue
            types = [self.objects.get(item, {}).get("type") for item in incoming]
            if None in types:
                by_type[relation_type] = (
                    f"{count} relations name this entity, incoming included; open its "
                    "incoming relations to tell how many are outgoing"
                )
                continue
            out = count - types.count(relation_type)
            if not 0 <= out <= outgoing:
                by_type[relation_type] = (
                    f"{count} found, more than this entity has: the search also matched "
                    "other relations, so this count says nothing"
                )
                continue
            by_type[relation_type] = (
                f"{out} outgoing; {outgoing - out} outgoing relations are of other types"
            )
        return {"outgoing_by_type": by_type} if by_type else {}

    def _record_page(self, arguments: dict[str, Any], result: Any) -> None:
        """Learn the page size and count relation types from one search page.

        A page is the answer to a call with `query` and `page_id` that holds
        `results` and `next_page_id`. Only a search by a fetched entity's full
        id, scoped to a relation type, without a time window, counts, and only
        when every hit on the page names the entity: its total is then
        comparable with the entity's relation ids. An exact count is never
        replaced by a bound.
        """
        query = arguments.get("query")
        page = arguments.get("page_id")
        if (
            not isinstance(result, dict)
            or "next_page_id" not in result
            or not isinstance(result.get("results"), list)
            or not isinstance(query, str)
            or not isinstance(page, int)
        ):
            return
        items = result["results"]
        has_next = result["next_page_id"] is not None
        if has_next and self.page_size is None and items:
            self.page_size = len(items)
        entity_id = query.strip()
        scope = arguments.get("scope")
        if (
            entity_id not in self.entity_relations
            or not isinstance(scope, dict)
            or scope.get("kind") != "relation"
            or not isinstance(scope.get("type"), str)
            or arguments.get("time_window")
            or (page > 1 and self.page_size is None)
        ):
            return
        if any(
            not isinstance(item, dict)
            or entity_id not in (item.get("source_id"), item.get("target_id"))
            for item in items
        ):
            return
        before = (page - 1) * (self.page_size or 0)
        if has_next:
            count = (before + len(items), "more_than")
        elif items or page == 1:
            count = (before + len(items), "exact")
        else:
            count = (before, "at_most")
        counts = self.relation_counts.setdefault(entity_id, {})
        known = counts.get(scope["type"])
        if known is None or known[1] != "exact":
            counts[scope["type"]] = count

    def unvisited_entities(self) -> list[str]:
        """Return known entity ids that were never fetched."""
        return sorted(self.entities - self.visited_entities)

    def unvisited_relations(self) -> list[str]:
        """Return known relation ids that were never fetched."""
        return sorted(self.relations - self.visited_relations)

    def is_known(self, value: str) -> bool:
        """Tell whether the runtime has returned this id.

        Args:
            value: Id chosen by the model.

        Returns:
            Whether the id appeared in the alert or in a runtime response.
        """
        return bool(value) and (
            value in self.entities
            or value in self.relations
            or value in self.seen_values
            or self._in_alert_text(value)
        )

    def is_entity(self, value: str) -> bool:
        """Tell whether the runtime returned this id as an entity, not only as a property value.

        Args:
            value: Id chosen by the model.

        Returns:
            Whether the id is an entity of a response or names one by reference.
        """
        return value in self.entities or value in self.entity_references

    def entity_type(self, entity_id: str) -> str | None:
        """Return the `type` of a known entity, or `None` when unknown."""
        if entity_id in self.entities:
            entity_type = self.objects.get(entity_id, {}).get("type")
            if isinstance(entity_type, str):
                return entity_type
        return self.entity_references.get(entity_id)

    def entities_of_type(self, entity_type: str) -> list[str]:
        """Return the known entity ids of one type, sorted."""
        known = self.entities | self.entity_references.keys()
        return sorted(item for item in known if self.entity_type(item) == entity_type)

    def property_values(self, object_id: str, fields: list[str]) -> dict[str, Any]:
        """Read property fields of an entity or relation the runtime returned.

        A field is a dotted path from the object or from its `properties`,
        or else a bare key at any depth, as a report cites it. A field that
        holds `null` is a fact too; the object's `id` and a whole nested object
        are not.

        Args:
            object_id: Id of the object.
            fields: Property fields to read.

        Returns:
            The value of each field the object holds, by field; fields it does
            not hold are left out.
        """
        found: dict[str, Any] = {}
        node = self.objects.get(object_id)
        if node is None:
            return found
        for name in fields:
            if name == "id":
                continue
            for path in (name, f"properties.{name}"):
                value: Any = node
                for part in path.split("."):
                    value = value.get(part, _MISSING) if isinstance(value, dict) else _MISSING
                if value is not _MISSING:
                    break
            else:
                value = _find_key(node, name)
                if value is None:
                    continue
            if not isinstance(value, dict):
                found[name] = value
        return found

    def _in_alert_text(self, value: str) -> bool:
        """Tell whether the alert's prose names this id as a whole word."""
        if len(value) < MIN_PROSE_ID_LENGTH:
            return False
        pattern = re.compile(
            rf"(?<![^{ID_BOUNDARY}]){re.escape(value)}(?=[{ID_BOUNDARY}]|\.?(?:\s|$))"
        )
        return any(pattern.search(text) for text in self.alert_text)

    def _argument_problems(self, arguments: Any) -> list[str]:
        """Find unknown ids and unknown property fields anywhere in the arguments."""
        problems: list[str] = []
        if isinstance(arguments, list):
            for item in arguments:
                problems.extend(self._argument_problems(item))
            return problems
        if not isinstance(arguments, dict):
            return problems

        cited: str | None = None
        for key, valid in (
            ("entity_id", self.unvisited_entities),
            ("relation_id", self.unvisited_relations),
        ):
            value = arguments.get(key)
            if not isinstance(value, str):
                continue
            if self.is_known(value):
                cited = cited or value
                continue
            problems.append(
                f"{key} {value!r} was never returned by the runtime. "
                f"Known unvisited {key}s: {listing(valid())}."
            )
        fields = arguments.get("property_fields")
        if cited is not None and isinstance(fields, list) and cited in self.properties:
            known_fields = self.properties[cited]
            unknown = [
                item for item in fields if isinstance(item, str) and item not in known_fields
            ]
            if unknown:
                problems.append(
                    f"{cited!r} has no property {', '.join(map(repr, unknown))}. "
                    f"Its properties: {sorted(known_fields)}."
                )
        for value in arguments.values():
            if isinstance(value, dict | list):
                problems.extend(self._argument_problems(value))
        return problems

    def _record_fetched(self, object_id: str, result: Any) -> None:
        """Store an object fetched by its id and the keys of its properties.

        Only a response that carries the object itself, a dict whose `id` is
        the requested id, describes its properties. Any other response says
        nothing about them, and the finish check then skips this object.
        """
        described = _find_object(result, object_id)
        if described is not None:
            _collect_keys(described, "", self.properties.setdefault(object_id, set()))
            self.objects[object_id] = _merge(self.objects.get(object_id, {}), described)

    def _collect(self, node: Any, kind: str | None = None) -> None:
        """Walk a response and record every id it names.

        Args:
            node: Decoded JSON value.
            kind: `entity` or `relation` when the enclosing key tells the kind.
        """
        if isinstance(node, str):
            self.seen_values.add(node)
            if kind is not None:
                self._add(node, kind)
            return
        if isinstance(node, list):
            for item in node:
                self._collect(item, kind)
            return
        if not isinstance(node, dict):
            return

        object_id = node.get("id")
        if isinstance(object_id, str):
            object_kind = kind or _object_kind(node)
            if object_kind is not None:
                self._add(object_id, object_kind)
                # A mention inside a response only fills gaps of what is known.
                self.objects[object_id] = _merge(node, self.objects.get(object_id, {}))
            if object_kind == "relation" and _is_full_relation(node):
                # A search returns the same relation object as a fetch by id.
                self.visited_relations.add(object_id)
                _collect_keys(node, "", self.properties.setdefault(object_id, set()))
        for key, value in node.items():
            if key in ENTITY_REFERENCE_KEYS and isinstance(value, str):
                self.entity_references[value] = ENTITY_REFERENCE_KEYS[key]
            if key in ENTITY_ID_KEYS or key in ENTITY_LIST_KEYS:
                self._collect(value, "entity")
            elif key in RELATION_ID_KEYS or key in RELATION_LIST_KEYS:
                self._collect(value, "relation")
            elif kind is not None and _is_id_container(node):
                # A container such as `{"incoming": [...], "outgoing": [...]}`.
                self._collect(value, kind)
            else:
                self._collect(value)

    def _add(self, value: str, kind: str) -> None:
        """Record one id of a known kind."""
        (self.entities if kind == "entity" else self.relations).add(value)

    @staticmethod
    def _cache_key(tool_name: str, arguments: dict[str, Any]) -> str:
        """Build the identity of a call without arguments that do not change it."""
        relevant = {key: value for key, value in arguments.items() if key not in IGNORED_ARGUMENTS}
        return json.dumps(
            [tool_name, _strip_strings(relevant)], sort_keys=True, ensure_ascii=False, default=str
        )


def _merge(base: dict[str, Any], winner: dict[str, Any]) -> dict[str, Any]:
    """Merge two views of one object: nested dicts merge, other values come from `winner`.

    A fetch by id is the full view and wins over what is known; a mention
    inside a response (a search hit, an endpoint) only fills gaps.
    """
    merged = dict(base)
    for key, value in winner.items():
        old = merged.get(key)
        merged[key] = (
            _merge(old, value) if isinstance(old, dict) and isinstance(value, dict) else value
        )
    return merged


def _strip_strings(value: Any) -> Any:
    """Drop surrounding whitespace from every string, which never changes a lookup."""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        return {key: _strip_strings(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_strip_strings(item) for item in value]
    return value


def _object_kind(node: dict[str, Any]) -> str | None:
    """Guess whether a dict with an `id` describes an entity or a relation."""
    for key in ("kind", "anchor", "object"):
        if node.get(key) in {"entity", "relation"}:
            return str(node[key])
    if "source_id" in node or "target_id" in node:
        return "relation"
    if "relation_ids" in node:
        return "entity"
    return None


def _is_full_relation(node: dict[str, Any]) -> bool:
    """Tell whether a dict is a whole relation: type, both endpoints and its properties."""
    return "properties" in node and all(
        isinstance(node.get(key), str) for key in ("type", "source_id", "target_id")
    )


def _is_id_container(node: dict[str, Any]) -> bool:
    """Tell whether a dict only groups id lists, like `incoming` and `outgoing`."""
    return "id" not in node and all(isinstance(value, list) for value in node.values())


def _find_object(node: Any, object_id: str) -> dict[str, Any] | None:
    """Return the first dict whose `id` is `object_id` anywhere in a JSON value."""
    if isinstance(node, dict):
        if node.get("id") == object_id:
            return node
        children = list(node.values())
    elif isinstance(node, list):
        children = node
    else:
        return None
    for child in children:
        found = _find_object(child, object_id)
        if found is not None:
            return found
    return None


def _find_key(node: Any, key: str) -> Any:
    """Return the first value stored under `key` anywhere in a JSON value."""
    if isinstance(node, dict):
        if key in node:
            return node[key]
        children = list(node.values())
    elif isinstance(node, list):
        children = node
    else:
        return None
    for child in children:
        found = _find_key(child, key)
        if found is not None:
            return found
    return None


def _collect_keys(node: Any, prefix: str, keys: set[str]) -> None:
    """Add every dict key of a JSON value, bare and as a dotted path."""
    if isinstance(node, list):
        for item in node:
            _collect_keys(item, prefix, keys)
        return
    if not isinstance(node, dict):
        return
    for key, value in node.items():
        path = f"{prefix}{key}"
        keys.add(key)
        keys.add(path)
        _collect_keys(value, f"{path}.", keys)


def listing(ids: list[str]) -> list[str] | str:
    """Show a short id list in full and a long one as a prefix and a count."""
    if len(ids) <= MAX_LISTED_IDS:
        return ids
    return f"{', '.join(ids[:MAX_LISTED_IDS])} and {len(ids) - MAX_LISTED_IDS} more"
