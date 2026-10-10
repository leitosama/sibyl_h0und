"""The alert stage: the harness opens the alert's entities and their relations (ADR 0027).

Before the model's first turn, every entity the alert names is fetched once,
and its relations, incoming and outgoing, are listed by a search on its id.
When one page holds the whole search, that page is all. Once every alert
entity has been fetched and searched, each entity with more than a page gets
every page of the search within the alert window. The window, not a count,
bounds the work (ADR 0004).

Tools are found in the task's catalog by their arguments, never by name
(ADR 0003). A call the ledger already knows is never made again, and every id
comes from the alert or a runtime answer (ADR 0005). Which entity is
suspicious is not decided here: every alert entity is opened the same way
(ADR 0017).
"""

from collections.abc import Generator, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from loguru import logger

from sibyl_h0und.catalog import ToolCatalog
from sibyl_h0und.ledger import ENTITY_LIST_KEYS, RELATION_LIST_KEYS, GraphLedger
from sibyl_h0und.outcome import ToolOutcome

# How far the alert window reaches before the alert's activity starts and
# after it ends. On practice traces, 98.7% of the entities a correct
# malicious report cited, hosts and accounts aside, lie within an hour of it.
ALERT_WINDOW_MARGIN = timedelta(hours=1)
# The reason given with each call, for tools whose schema asks for one.
STAGE_REASONING = (
    "Opened by the harness before the first turn: the alert's entities and their relations."
)

Plan = Generator["StageCall", ToolOutcome | None, Any]


@dataclass(frozen=True)
class StageCall:
    """One runtime call of the alert stage.

    Attributes:
        tool: Catalog tool to call.
        arguments: Arguments to send, prepared and checked against the catalog.
    """

    tool: str
    arguments: dict[str, Any]


class AlertStage:
    """The calls that open the alert's entities and their relations, one at a time."""

    def __init__(self, catalog: ToolCatalog, alert: dict[str, Any], ledger: GraphLedger) -> None:
        """Find the tools of the stage and the alert window.

        Args:
            catalog: The task's tool catalog.
            alert: Decoded observation fields without the tool catalog.
            ledger: The task's ledger, which already observed the alert.
        """
        self._catalog = catalog
        self._ledger = ledger
        self._fetch = entity_fetch_tool(catalog)
        self._search = catalog.relation_search()
        properties = _properties(catalog, self._search)
        self._paged = "page_id" in properties
        self._window = alert_window(alert) if "time_window" in properties else None
        self._entities = alert_entity_ids(alert)
        self._calls = self._plan()

    def next_call(self, outcome: ToolOutcome | None = None) -> StageCall | None:
        """Return the next call of the stage, given the answer to the previous one.

        Args:
            outcome: The runtime's answer to the call this method returned
                last, or `None` for the first call.

        Returns:
            The next call, or `None` when the stage is over.
        """
        try:
            # A fresh generator takes `None` as its first send, and an
            # exhausted one stops again on every send.
            return self._calls.send(outcome)
        except StopIteration:
            return None

    def _plan(self) -> Plan:
        """Yield each call of the stage and receive its answer.

        Every alert entity is fetched and searched first, so a busy entity
        cannot spend the calls the next one needs; the window pages come last.
        """
        busy = []
        for entity_id in self._entities:
            if self._fetch is not None and entity_id not in self._ledger.visited_entities:
                yield from self._call(self._fetch, {"entity_id": entity_id})
            if self._search is None or not self._has_open_relations(entity_id):
                continue
            first_page = yield from self._call(self._search, {"query": entity_id})
            if _next_page(first_page) is not None:
                busy.append(entity_id)
        if self._search is None or not self._paged or self._window is None:
            if busy:
                logger.warning("No alert window to page {} busy alert entities in.", len(busy))
            return
        window = {"from": self._window[0].isoformat(), "to": self._window[1].isoformat()}
        for entity_id in busy:
            yield from self._pages(self._search, {"query": entity_id, "time_window": window})

    def _pages(self, tool: str, arguments: dict[str, Any]) -> Plan:
        """Yield every page of one search, until none is left or nothing is open.

        Pages must move forward: a next page that does not would repeat a
        page, so the search ends there.
        """
        page_id = 1
        while self._has_open_relations(arguments["query"]):
            result = yield from self._call(tool, {**arguments, "page_id": page_id})
            following = _next_page(result)
            if not isinstance(following, int) or following <= page_id:
                return
            page_id = following

    def _call(self, tool: str, arguments: dict[str, Any]) -> Plan:
        """Make one call unless the ledger knows it, and return its result.

        A call the catalog rejects or the ledger refuses is skipped with a
        warning; a call the ledger already answered returns that answer
        without a runtime call.

        Returns:
            The decoded result, or `None` for a skipped or failed call.
        """
        if "reasoning" in _properties(self._catalog, tool):
            arguments = {**arguments, "reasoning": STAGE_REASONING}
        try:
            prepared = self._catalog.prepare(tool, arguments)
        except ValueError as exc:
            logger.warning("The alert stage skipped a {} call: {}", tool, exc)
            return None
        decision = self._ledger.check(tool, prepared)
        if decision.reason == "cached" and decision.feedback is not None:
            return decision.feedback.get("result")
        if decision.feedback is not None:
            logger.warning("The alert stage skipped a {} call: {}", tool, decision.reason)
            return None
        outcome = yield StageCall(tool, prepared)
        if outcome is None or outcome.failed:
            return None
        return outcome.result

    def _has_open_relations(self, entity_id: str) -> bool:
        """Tell whether the entity may still have a relation nobody opened.

        Without a fetched list of its relations nothing is known to be
        opened, so the entity counts as open.
        """
        directions = self._ledger.entity_relations.get(entity_id)
        if directions is None:
            return True
        return any(
            relation_id not in self._ledger.visited_relations
            for ids in directions.values()
            for relation_id in ids
        )


def entity_fetch_tool(catalog: ToolCatalog) -> str | None:
    """Name the runtime tool that fetches one entity by its `entity_id`.

    A candidate takes `entity_id` and requires nothing else but `reasoning`.
    One whose description names relations, as a fetch that lists them does,
    wins over the rest.

    Returns:
        The best candidate, first in catalog order, or `None`.
    """
    candidates = []
    for name in catalog.runtime_tools():
        schema = catalog.schema(name)
        if schema is None or "entity_id" not in (schema.get("properties") or {}):
            continue
        if set(schema.get("required") or []) <= {"entity_id", "reasoning"}:
            candidates.append(name)
    for name in candidates:
        spec = next(iter(catalog.specs_of([name])), {})
        if "relation" in str(spec.get("description", "")).lower():
            return name
    return candidates[0] if candidates else None


def alert_entity_ids(alert: dict[str, Any]) -> list[str]:
    """Return the ids of the entities the alert lists, in its order, once each."""
    ids: list[str] = []
    for item in _alert_items(alert, ENTITY_LIST_KEYS):
        entity_id = item.get("id") if isinstance(item, dict) else item
        if isinstance(entity_id, str) and entity_id and entity_id not in ids:
            ids.append(entity_id)
    return ids


def alert_window(
    alert: dict[str, Any], margin: timedelta = ALERT_WINDOW_MARGIN
) -> tuple[datetime, datetime] | None:
    """Return the alert's time window: its activity and a margin on both sides.

    The activity starts when its last entity appears: at the latest of the
    earliest timestamps of the alert's entities. A long-lived entity, such as
    a host up since boot, would otherwise stretch it over its whole life. A
    relation of the alert is part of the activity, so the activity starts no
    later than the earliest of them. It ends at the alert's latest timestamp.

    Args:
        alert: Decoded observation fields without the tool catalog.
        margin: How far the window reaches past the activity on each side.

    Returns:
        The window's bounds in UTC, or `None` when the alert has no usable timestamp.
    """
    entities = _stamps_of(alert, ENTITY_LIST_KEYS)
    relations = [stamp for stamps in _stamps_of(alert, RELATION_LIST_KEYS) for stamp in stamps]
    every = [*(stamp for stamps in entities for stamp in stamps), *relations]
    if not every:
        return None
    starts = [max(min(stamps) for stamps in entities)] if entities else []
    if relations:
        starts.append(min(relations))
    try:
        return min(starts) - margin, max(every) + margin
    except OverflowError:
        return None


def _properties(catalog: ToolCatalog, tool: str | None) -> dict[str, Any]:
    """Return the argument properties of a catalog tool, empty when unknown."""
    schema = catalog.schema(tool) if tool is not None else None
    return (schema or {}).get("properties") or {}


def _alert_items(node: Any, keys: frozenset[str]) -> Iterator[Any]:
    """Yield the items of every list stored under one of `keys` anywhere in the alert."""
    if isinstance(node, dict):
        for name, value in node.items():
            if name in keys and isinstance(value, list):
                yield from value
            else:
                yield from _alert_items(value, keys)
    elif isinstance(node, list):
        for item in node:
            yield from _alert_items(item, keys)


def _stamps_of(alert: dict[str, Any], keys: frozenset[str]) -> list[list[datetime]]:
    """Return the timestamps of each alert object listed under `keys` that has any."""
    return [stamps for item in _alert_items(alert, keys) if (stamps := _timestamps(item))]


def _timestamps(item: Any) -> list[datetime]:
    """Read the `timestamps` and `timestamp` of an alert object, in UTC.

    A value without a timezone is read as UTC; one that cannot be read is skipped.
    """
    if not isinstance(item, dict):
        return []
    values = item.get("timestamps")
    values = [*values] if isinstance(values, list) else []
    values.append(item.get("timestamp"))
    stamps = []
    for value in values:
        if not isinstance(value, str):
            continue
        try:
            stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
            stamps.append(
                stamp.replace(tzinfo=UTC) if stamp.tzinfo is None else stamp.astimezone(UTC)
            )
        except (ValueError, OverflowError):
            continue
    return stamps


def _next_page(result: Any) -> Any:
    """Return the `next_page_id` of a search result, or `None` on its last page."""
    return result.get("next_page_id") if isinstance(result, dict) else None
