"""Deterministic findings computed from the entities and relations the runtime returned.

A rule reads the properties of one node and returns a `Finding` or nothing.
The same node always gives the same finding: rules use static tables and no
clock, network or model. The board runs the rules over tool results and keeps
track of what the model has already been told.

Two kinds of rule exist:

- `LevelRule` names a pattern and gives it a fixed level.
- `ScoreRule` rates several attributes of a node on the ordinal scale
  0 (less relevant), 1 (relevant), 2 (highly relevant), sums the rated ones
  and maps the sum to a level by thresholds. An attribute the node has no data
  for is unrated and does not count.
"""

from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

LOW = "low"
MEDIUM = "medium"
HIGH = "high"
# Ordinal scale of one attribute rating.
MAX_RATING = 2

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
    """

    node_id: str
    node_type: str
    rule: str
    level: str
    reason: str
    score: int | None = None
    ratings: dict[str, int] = field(default_factory=dict)

    def as_feedback(self) -> dict[str, Any]:
        """Return the compact form shown to the model."""
        return {"id": self.node_id, "type": self.node_type, "level": self.level, "why": self.reason}


class Rule(Protocol):
    """Anything that can judge one node."""

    name: str

    def evaluate(self, node_id: str, node_type: str, properties: Properties) -> Finding | None:
        """Judge a node, or return `None` when the rule has nothing to say."""
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
    """

    name: str
    node_types: frozenset[str]
    level: str
    match: Callable[[Properties], str | None]

    def evaluate(self, node_id: str, node_type: str, properties: Properties) -> Finding | None:
        """Return a finding when the pattern matches the node."""
        if node_type not in self.node_types or (reason := self.match(properties)) is None:
            return None
        return Finding(node_id, node_type, self.name, self.level, reason)


@dataclass(frozen=True)
class ScoreRule:
    """Ordinal ratings of several attributes, summed and mapped to a level.

    Attributes:
        name: Rule name.
        node_types: Node types the rule applies to.
        attributes: Rated aspects of the node.
        medium_at: Smallest sum that is `medium`.
        high_at: Smallest sum that is `high`.
    """

    name: str
    node_types: frozenset[str]
    attributes: tuple[Attribute, ...]
    medium_at: int
    high_at: int

    def evaluate(self, node_id: str, node_type: str, properties: Properties) -> Finding | None:
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
        return Finding(node_id, node_type, self.name, level, reason, score, ratings)


class FlagBoard:
    """Runs the rules over tool results and remembers what each node scored."""

    def __init__(self, rules: Iterable[Rule]) -> None:
        """Create a board for one task.

        Args:
            rules: Rules applied to every node of every result.
        """
        self.rules = tuple(rules)
        self.findings: dict[tuple[str, str], Finding] = {}

    def observe(self, result: Any) -> list[Finding]:
        """Judge every node in a tool result.

        Args:
            result: Decoded `last_tool_result`.

        Returns:
            Findings that are new or differ from an earlier finding of the same
            rule about the same node, which happens when a later response
            carries more properties.
        """
        fresh: list[Finding] = []
        for node_id, node_type, properties in _nodes(result):
            for rule in self.rules:
                finding = rule.evaluate(node_id, node_type, properties)
                if finding is None or self.findings.get((node_id, rule.name)) == finding:
                    continue
                self.findings[(node_id, rule.name)] = finding
                fresh.append(finding)
        return fresh


def _nodes(node: Any) -> Iterator[tuple[str, str, Properties]]:
    """Yield id, type and properties of every entity or relation in a JSON value."""
    if isinstance(node, dict):
        node_id, node_type, properties = (node.get(key) for key in ("id", "type", "properties"))
        if isinstance(node_id, str) and isinstance(node_type, str) and isinstance(properties, dict):
            yield node_id, node_type, properties
        for child in node.values():
            yield from _nodes(child)
    elif isinstance(node, list):
        for child in node:
            yield from _nodes(child)
