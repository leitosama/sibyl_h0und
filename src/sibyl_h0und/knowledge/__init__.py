"""Knowledge packs: generated JSON snapshots of external sources.

A build script in `scripts/` fetches an upstream source, reduces it to the
entries the rules need and writes `<name>.json` here. The agent and CI only
read the snapshots and never reach the network. Attribution of every source
is kept in `NOTICE`.

A pack file holds:

- `name`: pack name, also the source name shown in replay tables;
- `source`, `url`, `version`, `retrieved`, `licence`: provenance;
- `key`: normalizer of the entry keys, one of `normalize.KEY_NORMALIZERS`;
- `entries`: map from a normalized key to the entry;
- `documents` (optional): entries that have no key but are found by words.
"""

import json
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any

from sibyl_h0und.normalize import KEY_NORMALIZERS

PACK_DIR = Path(__file__).parent
# Largest pack file, in bytes. A pack is read into memory at start-up, so a
# source that does not fit is reduced further by its build script.
SIZE_BUDGET = 512 * 1024
PROVENANCE_FIELDS = ("source", "url", "version", "retrieved", "licence")


class PackError(ValueError):
    """A pack file is missing, too large or malformed."""


@dataclass(frozen=True)
class Pack:
    """One loaded knowledge pack.

    Attributes:
        name: Pack name.
        source: Upstream source name.
        url: Where the build script fetched the source.
        version: Upstream version or a digest of the fetched data.
        retrieved: Retrieval date, `YYYY-MM-DD`.
        licence: SPDX id of the upstream licence.
        key: Name of the key normalizer.
        entries: Entries by normalized key.
        documents: Entries without a key, which a word search finds.
    """

    name: str
    source: str
    url: str
    version: str
    retrieved: str
    licence: str
    key: str
    entries: dict[str, Any]
    documents: list[Any] = field(default_factory=list)

    def normalize(self, value: Any) -> str | None:
        """Reduce a raw value to this pack's key form."""
        return KEY_NORMALIZERS[self.key](value)

    def lookup(self, value: Any) -> Any | None:
        """Return the entry for a raw value, or `None` when the pack has none."""
        key = self.normalize(value)
        return None if key is None else self.entries.get(key)


def parse_pack(data: Any) -> Pack:
    """Validate decoded pack JSON and build a `Pack`.

    Raises:
        PackError: When a field is missing or has the wrong type.
    """
    if not isinstance(data, dict):
        raise PackError("A pack is a JSON object.")
    for name in ("name", "key", *PROVENANCE_FIELDS):
        if not isinstance(data.get(name), str) or not data[name]:
            raise PackError(f"Pack field {name!r} must be a non-empty string.")
    if data["key"] not in KEY_NORMALIZERS:
        raise PackError(f"Unknown key normalizer {data['key']!r}.")
    if not isinstance(data.get("entries"), dict):
        raise PackError("Pack field 'entries' must be an object.")
    documents = data.get("documents", [])
    if not isinstance(documents, list):
        raise PackError("Pack field 'documents' must be a list.")
    required = {name: data[name] for name in Pack.__dataclass_fields__ if name != "documents"}
    return Pack(**required, documents=documents)


def read_pack(path: Path, *, budget: int = SIZE_BUDGET) -> Pack:
    """Read and validate one pack file.

    Raises:
        PackError: When the file is over budget or malformed.
    """
    size = path.stat().st_size
    if size > budget:
        raise PackError(f"{path.name} is {size} bytes, over the {budget}-byte budget.")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise PackError(f"{path.name} is not valid JSON: {error}") from error
    return parse_pack(data)


@cache
def load_pack(name: str) -> Pack:
    """Return a pack shipped with the agent, read once per process."""
    path = PACK_DIR / f"{name}.json"
    if not path.is_file():
        raise PackError(f"No knowledge pack {name!r} in {PACK_DIR}.")
    return read_pack(path)


def pack_names() -> list[str]:
    """Return the names of the packs shipped with the agent."""
    return sorted(path.stem for path in PACK_DIR.glob("*.json"))
