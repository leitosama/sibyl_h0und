"""Deterministic findings computed from the entities and relations the runtime returned.

A rule reads the properties of one node, and the nodes around it that the
board has seen, and returns a `Finding` or nothing. The same graph always
gives the same finding: rules use static tables and no clock, network or
model. The board runs the rules over tool results and keeps track of what the
model has already been told.

Three kinds of rule exist:

- `LevelRule` names a pattern and gives it a fixed level.
- `ScoreRule` rates several attributes of a node on the ordinal scale
  0 (less relevant), 1 (relevant), 2 (highly relevant), sums the rated ones
  and maps the sum to a level by thresholds. An attribute the node has no data
  for is unrated and does not count.
- `LookupRule` finds a node's key in a knowledge pack and judges the entry.

Every rule names its source, so a replay can tell what each source adds.
"""

from collections import defaultdict
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

LOW = "low"
MEDIUM = "medium"
HIGH = "high"
LEVEL_ORDER = {LOW: 0, MEDIUM: 1, HIGH: 2}
# Ordinal scale of one attribute rating.
MAX_RATING = 2
# Most flagged nodes shown to the model after one tool result.
FLAG_LIMIT = 5

Properties = Mapping[str, Any]


@dataclass(frozen=True)
class Finding:
    """One rule's conclusion about one entity or relation.

    Attributes:
        node_id: Id of the entity or relation.
        node_type: Its type as the runtime names it.
        rule: Name of the rule that produced the finding.
        level: `low`, `medium` or `high`.
        reason: Short explanation the model can read.
        score: Sum of the rated attributes, for score rules.
        ratings: Rating of each rated attribute, for score rules.
        source: Knowledge source of the rule, such as `nextron` or `lolbas`.
    """

    node_id: str
    node_type: str
    rule: str
    level: str
    reason: str
    score: int | None = None
    ratings: dict[str, int] = field(default_factory=dict)
    source: str = "builtin"

    def as_feedback(self) -> dict[str, Any]:
        """Return the compact form shown to the model."""
        return {"id": self.node_id, "type": self.node_type, "level": self.level, "why": self.reason}


@dataclass
class Node:
    """An entity or relation the board has seen.

    Attributes:
        id: Node id.
        type: Node type as the runtime names it.
        properties: Properties merged over every response that carried the node.
        source_id: Source entity of a relation, `None` for an entity.
        target_id: Target entity of a relation, `None` for an entity.
    """

    id: str
    type: str
    properties: dict[str, Any] = field(default_factory=dict)
    source_id: str | None = None
    target_id: str | None = None

    @property
    def is_relation(self) -> bool:
        """Tell whether the node is a relation."""
        return self.source_id is not None or self.target_id is not None


class NodeContext:
    """Entities and relations of one task, so a rule can read a node's neighbors.

    The context holds only what the runtime already returned: asking it costs
    no tool call, and a neighbor the agent never fetched is simply absent.
    """

    def __init__(self) -> None:
        """Create an empty context."""
        self.nodes: dict[str, Node] = {}
        self._incoming: dict[str, list[str]] = defaultdict(list)
        self._outgoing: dict[str, list[str]] = defaultdict(list)

    def add(self, raw: Mapping[str, Any]) -> Node | None:
        """Record an entity or relation from a tool result.

        Args:
            raw: A JSON object with string `id` and `type`.

        Returns:
            The recorded node with properties merged, or `None` when the object
            is not a node.
        """
        node_id, node_type = raw.get("id"), raw.get("type")
        if not isinstance(node_id, str) or not isinstance(node_type, str):
            return None
        node = self.nodes.setdefault(node_id, Node(node_id, node_type))
        if isinstance(properties := raw.get("properties"), dict):
            node.properties.update(properties)
        for key, index in (("source_id", self._outgoing), ("target_id", self._incoming)):
            endpoint = raw.get(key)
            if isinstance(endpoint, str) and getattr(node, key) is None:
                setattr(node, key, endpoint)
                index[endpoint].append(node_id)
        return node

    def get(self, node_id: str | None) -> Node | None:
        """Return a seen node, or `None`."""
        return None if node_id is None else self.nodes.get(node_id)

    def relations(
        self, node_id: str, *, direction: str, types: Iterable[str] | None = None
    ) -> list[Node]:
        """Return the seen relations of an entity.

        Args:
            node_id: Entity id.
            direction: `in` for relations that target the entity, `out` for
                relations it is the source of.
            types: Keep only these relation types.
        """
        index = self._incoming if direction == "in" else self._outgoing
        wanted = None if types is None else frozenset(types)
        found = (self.nodes[relation_id] for relation_id in index.get(node_id, ()))
        return [relation for relation in found if wanted is None or relation.type in wanted]

    def neighbors(
        self, node_id: str, *, direction: str, types: Iterable[str] | None = None
    ) -> list[Node]:
        """Return seen entities at the other end of an entity's relations.

        `neighbors(file_id, direction="in", types={"wrote_file"})` gives the
        processes that wrote a file, `direction="in", types={"parent_of"}` on
        a process gives its parent.
        """
        key = "source_id" if direction == "in" else "target_id"
        found = (
            self.get(getattr(relation, key))
            for relation in self.relations(node_id, direction=direction, types=types)
        )
        return [node for node in found if node is not None]

    def endpoints(self, relation_id: str) -> tuple[Node | None, Node | None]:
        """Return the seen source and target entities of a relation."""
        relation = self.get(relation_id)
        if relation is None:
            return None, None
        return self.get(relation.source_id), self.get(relation.target_id)


class Rule(Protocol):
    """Anything that can judge one node."""

    name: str
    source: str

    def evaluate(
        self, node_id: str, node_type: str, properties: Properties, context: NodeContext
    ) -> Finding | None:
        """Judge a node, or return `None` when the rule has nothing to say."""
        ...


class Lookup(Protocol):
    """A knowledge pack, as `LookupRule` uses it."""

    name: str

    def lookup(self, value: Any) -> Any | None:
        """Return the entry for a raw value, or `None`."""
        ...


@dataclass(frozen=True)
class Attribute:
    """One rated aspect of a node.

    Attributes:
        name: Attribute name shown in the reason, such as `location`.
        rate: Returns 0, 1 or 2, or `None` when the node lacks the data.
    """

    name: str
    rate: Callable[[Properties], int | None]


@dataclass(frozen=True)
class LevelRule:
    """A pattern with a fixed level.

    Attributes:
        name: Rule name.
        node_types: Node types the rule applies to.
        level: Level of the finding when the pattern matches.
        match: Returns the reason when the pattern matches, otherwise `None`.
        source: Knowledge source of the pattern.
    """

    name: str
    node_types: frozenset[str]
    level: str
    match: Callable[[Properties], str | None]
    source: str = "builtin"

    def evaluate(
        self, node_id: str, node_type: str, properties: Properties, context: NodeContext
    ) -> Finding | None:
        """Return a finding when the pattern matches the node."""
        if node_type not in self.node_types or (reason := self.match(properties)) is None:
            return None
        return Finding(node_id, node_type, self.name, self.level, reason, source=self.source)


@dataclass(frozen=True)
class ScoreRule:
    """Ordinal ratings of several attributes, summed and mapped to a level.

    Attributes:
        name: Rule name.
        node_types: Node types the rule applies to.
        attributes: Rated aspects of the node.
        medium_at: Smallest sum that is `medium`.
        high_at: Smallest sum that is `high`.
        source: Knowledge source of the ratings.
    """

    name: str
    node_types: frozenset[str]
    attributes: tuple[Attribute, ...]
    medium_at: int
    high_at: int
    source: str = "builtin"

    def evaluate(
        self, node_id: str, node_type: str, properties: Properties, context: NodeContext
    ) -> Finding | None:
        """Return a finding when at least one attribute can be rated."""
        if node_type not in self.node_types:
            return None
        ratings = {
            attribute.name: rating
            for attribute in self.attributes
            if (rating := attribute.rate(properties)) is not None
        }
        if not ratings:
            return None
        score = sum(ratings.values())
        level = HIGH if score >= self.high_at else MEDIUM if score >= self.medium_at else LOW
        parts = " ".join(f"{name}={rating}" for name, rating in ratings.items())
        reason = f"{parts} (score {score} of {MAX_RATING * len(ratings)})"
        return Finding(
            node_id, node_type, self.name, level, reason, score, ratings, source=self.source
        )


@dataclass(frozen=True)
class LookupRule:
    """A knowledge pack lookup and a judgement of the entry it finds.

    Attributes:
        name: Rule name.
        node_types: Node types the rule applies to.
        pack: Pack to look the key up in; its name is the rule's source.
        key: Returns the raw value to look up, such as an image path.
        judge: Given the entry, the node's properties and the context, returns
            the level and reason, or `None` when the entry does not matter here.
    """

    name: str
    node_types: frozenset[str]
    pack: Lookup
    key: Callable[[Properties], Any]
    judge: Callable[[Any, Properties, NodeContext], tuple[str, str] | None]

    @property
    def source(self) -> str:
        """Name of the pack."""
        return self.pack.name

    def evaluate(
        self, node_id: str, node_type: str, properties: Properties, context: NodeContext
    ) -> Finding | None:
        """Return a finding when the node's key is in the pack and the entry matters."""
        if node_type not in self.node_types:
            return None
        entry = self.pack.lookup(self.key(properties))
        if entry is None or (verdict := self.judge(entry, properties, context)) is None:
            return None
        level, reason = verdict
        return Finding(node_id, node_type, self.name, level, reason, source=self.source)


class FlagBoard:
    """Runs the rules over tool results and remembers what each node scored."""

    def __init__(self, rules: Iterable[Rule]) -> None:
        """Create a board for one task.

        Args:
            rules: Rules applied to every node of every result.
        """
        self.rules = tuple(rules)
        self.findings: dict[tuple[str, str], Finding] = {}
        self.context = NodeContext()

    def observe(self, result: Any) -> list[Finding]:
        """Judge every node in a tool result and the entities its relations join.

        A relation can arrive after the entities it joins, so its endpoints are
        judged again: a rule that reads a neighbor may now have one.

        Args:
            result: Decoded `last_tool_result`.

        Returns:
            Findings that are new or differ from an earlier finding of the same
            rule about the same node, which happens when a later response
            carries more properties or more neighbors.
        """
        targets: dict[str, Node] = {}
        for raw in _nodes(result):
            node = self.context.add(raw)
            if node is None:
                continue
            if isinstance(raw.get("properties"), dict):
                targets.setdefault(node.id, node)
            for endpoint in (node.source_id, node.target_id):
                if (neighbor := self.context.get(endpoint)) is not None and neighbor.properties:
                    targets.setdefault(neighbor.id, neighbor)
        fresh: list[Finding] = []
        for node in targets.values():
            for rule in self.rules:
                finding = rule.evaluate(node.id, node.type, node.properties, self.context)
                if finding is None or self.findings.get((node.id, rule.name)) == finding:
                    continue
                self.findings[(node.id, rule.name)] = finding
                fresh.append(finding)
        return fresh


def rank_flags(
    findings: Iterable[Finding], limit: int = FLAG_LIMIT
) -> tuple[list[list[Finding]], int]:
    """Choose what the model sees of one tool result's findings.

    Findings below `medium` are dropped. The rest are grouped per node, so
    several rules about one node make one line, and the nodes are ordered by
    their highest level, keeping the order of the result among equals.

    Args:
        findings: Fresh findings of one tool result.
        limit: Most nodes to show.

    Returns:
        The shown groups, each the findings about one node, and the number of
        flagged nodes left out.
    """
    groups: dict[str, list[Finding]] = {}
    for finding in findings:
        if finding.level != LOW:
            groups.setdefault(finding.node_id, []).append(finding)
    ranked = sorted(
        groups.values(), key=lambda group: -max(LEVEL_ORDER[item.level] for item in group)
    )
    return ranked[:limit], max(len(ranked) - limit, 0)


def flag_feedback(findings: Iterable[Finding], limit: int = FLAG_LIMIT) -> list[dict[str, Any]]:
    """Return the `flags` the model sees after one tool result.

    Each line is one node at the highest level any rule gave it. When several
    rules spoke, the reason names each rule. A final line counts the flagged
    nodes that did not fit the limit.
    """
    shown, omitted = rank_flags(findings, limit)
    lines = []
    for group in shown:
        top = max(group, key=lambda item: LEVEL_ORDER[item.level])
        line = top.as_feedback()
        if len(group) > 1:
            line["why"] = "; ".join(f"{item.rule}: {item.reason}" for item in group)
        lines.append(line)
    if omitted:
        lines.append({"omitted": omitted, "why": "more flagged nodes, ranked lower, not shown"})
    return lines


def _nodes(node: Any) -> Iterator[dict[str, Any]]:
    """Yield every JSON object with a string `id` and `type` in a JSON value."""
    if isinstance(node, dict):
        if isinstance(node.get("id"), str) and isinstance(node.get("type"), str):
            yield node
        for child in node.values():
            yield from _nodes(child)
    elif isinstance(node, list):
        for child in node:
            yield from _nodes(child)
