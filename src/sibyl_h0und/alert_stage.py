"""The alert stage: the harness opens the alert's entities and their relations (ADR 0027).

Before the model's first turn, every entity the alert names is fetched once,
and its relations, incoming and outgoing, are listed by a search on its id.
When one page holds the whole search, that page is all; an entity with more
than a page gets every page of the search within the alert window instead.
The window, not a count, bounds the work (ADR 0004).

Tools are found in the task's catalog by the shape of their arguments, never
by name (ADR 0003). A call the ledger already knows is never made again, and
every id comes from the alert or a runtime answer (ADR 0005). Which entity is
suspicious is not decided here: every alert entity is opened the same way
(ADR 0017).
"""

from collections.abc import Generator, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sibyl_h0und.catalog import ToolCatalog
from sibyl_h0und.ledger import GraphLedger
from sibyl_h0und.outcome import ToolOutcome

# How far the alert window reaches before the alert's activity starts and
# after it ends. On practice traces, 98.7% of the entities a correct
# malicious report cited, hosts and accounts aside, lie within an hour of it.
ALERT_WINDOW_MARGIN = timedelta(hours=1)
# The reason given with each call, for tools whose schema asks for one.
STAGE_REASONING = (
    "Opened by the harness before the first turn: the alert's entities and their relations."
)
# Keys of the alert that list its entities and relations.
ALERT_ENTITY_KEY = "trigger_entities"
ALERT_RELATION_KEY = "trigger_relations"


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
        schema = self._catalog.schema(self._search) if self._search else None
        properties = (schema or {}).get("properties") or {}
        self._paged = "page_id" in properties
        self._window = alert_window(alert) if "time_window" in properties else None
        self._entities = alert_entity_ids(alert)
        self._calls = self._plan()
        self._done = False

    def next_call(self, outcome: ToolOutcome | None = None) -> StageCall | None:
        """Return the next call of the stage, given the answer to the previous one.

        Args:
            outcome: The runtime's answer to the call this method returned
                last, or `None` for the first call.

        Returns:
            The next call, or `None` when the stage is over.
        """
        if self._done:
            return None
        try:
            # A fresh generator takes `None` as its first send.
            return self._calls.send(outcome)
        except StopIteration:
            self._done = True
            return None

    def _plan(self) -> Generator[StageCall, ToolOutcome | None, None]:
        """Yield each call of the stage and receive its answer."""
        for entity_id in self._entities:
            if self._fetch is not None and entity_id not in self._ledger.visited_entities:
                yield from self._call(self._fetch, {"entity_id": entity_id})
            if self._search is None or not self._has_open_relations(entity_id):
                continue
            page = yield from self._call(self._search, {"query": entity_id})
            if _next_page(page) is None or not self._paged or self._window is None:
                continue
            window = {"from": self._window[0].isoformat(), "to": self._window[1].isoformat()}
            arguments = {"query": entity_id, "time_window": window}
            yield from self._pages(self._search, arguments, entity_id)

    def _pages(
        self, tool: str, arguments: dict[str, Any], entity_id: str
    ) -> Generator[StageCall, ToolOutcome | None, None]:
        """Yield every page of one search, until none is left or nothing is open.

        Pages must move forward: a next page that does not would repeat a
        page, so the search ends there.
        """
        page_id = 1
        while self._has_open_relations(entity_id):
            result = yield from self._call(tool, {**arguments, "page_id": page_id})
            following = _next_page(result)
            if not isinstance(following, int) or following <= page_id:
                return
            page_id = following

    def _call(
        self, tool: str, arguments: dict[str, Any]
    ) -> Generator[StageCall, ToolOutcome | None, Any]:
        """Make one call unless the ledger knows it, and return its result.

        A call the catalog rejects or the ledger refuses is skipped; a call
        the ledger already answered returns that answer without a runtime call.

        Returns:
            The decoded result, or `None` for a skipped or failed call.
        """
        if self._reasoned(tool):
            arguments = {**arguments, "reasoning": STAGE_REASONING}
        try:
            prepared = self._catalog.prepare(tool, arguments)
        except ValueError:
            return None
        decision = self._ledger.check(tool, prepared)
        if decision.reason == "cached" and decision.feedback is not None:
            return decision.feedback.get("result")
        if decision.feedback is not None:
            return None
        outcome = yield StageCall(tool, prepared)
        if outcome is None or outcome.failed:
            return None
        return outcome.result

    def _reasoned(self, tool: str) -> bool:
        """Tell whether the tool's schema takes a `reasoning` argument."""
        schema = self._catalog.schema(tool)
        return "reasoning" in ((schema or {}).get("properties") or {})

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

    Returns:
        The first runtime tool, in catalog order, that takes `entity_id` and
        requires nothing else but `reasoning`, or `None`.
    """
    for name in catalog.runtime_tools():
        schema = catalog.schema(name)
        if schema is None or "entity_id" not in (schema.get("properties") or {}):
            continue
        if set(schema.get("required") or []) <= {"entity_id", "reasoning"}:
            return name
    return None


def alert_entity_ids(alert: dict[str, Any]) -> list[str]:
    """Return the ids of the entities the alert names, in its order, once each."""
    ids: list[str] = []
    for item in _alert_items(alert, ALERT_ENTITY_KEY):
        entity_id = item.get("id") if isinstance(item, dict) else item
        if isinstance(entity_id, str) and entity_id and entity_id not in ids:
            ids.append(entity_id)
    return ids


def alert_window(
    alert: dict[str, Any], margin: timedelta = ALERT_WINDOW_MARGIN
) -> tuple[datetime, datetime] | None:
    """Return the alert's time window: its activity and a margin on both sides.

    The activity starts when its last participant appears: at the latest of
    the earliest timestamps of the alert's entities and relations. A
    long-lived participant, such as a host up since boot, would otherwise
    stretch it over its whole life. The activity ends at the alert's latest
    timestamp.

    Args:
        alert: Decoded observation fields without the tool catalog.
        margin: How far the window reaches past the activity on each side.

    Returns:
        The window's bounds in UTC, or `None` when the alert has no timestamp.
    """
    firsts: list[datetime] = []
    latest: datetime | None = None
    for key in (ALERT_ENTITY_KEY, ALERT_RELATION_KEY):
        for item in _alert_items(alert, key):
            stamps = _timestamps(item)
            if stamps:
                firsts.append(min(stamps))
                latest = max([*stamps, *([latest] if latest else [])])
    if not firsts or latest is None:
        return None
    return max(firsts) - margin, latest + margin


def _alert_items(node: Any, key: str) -> Iterator[Any]:
    """Yield the items of every list stored under `key` anywhere in the alert."""
    if isinstance(node, dict):
        for name, value in node.items():
            if name == key and isinstance(value, list):
                yield from value
            else:
                yield from _alert_items(value, key)
    elif isinstance(node, list):
        for item in node:
            yield from _alert_items(item, key)


def _timestamps(item: Any) -> list[datetime]:
    """Read the `timestamps` and `timestamp` of an alert object, skipping naive values."""
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
        except ValueError:
            continue
        if stamp.tzinfo is not None:
            stamps.append(stamp.astimezone(UTC))
    return stamps


def _next_page(result: Any) -> Any:
    """Return the `next_page_id` of a search result, or `None` on its last page."""
    return result.get("next_page_id") if isinstance(result, dict) else None
