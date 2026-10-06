"""Build the LOLBAS knowledge pack from the project's published API.

Usage: uv run python scripts/build_lolbas_pack.py [--input lolbas.json]

Without `--input` the script downloads the API file. It keeps, for every
binary, the LOLBAS categories of its documented commands and their MITRE ids,
and writes `src/sibyl_h0und/knowledge/lolbas.json`. Only the snapshot is
committed: the agent and CI never reach the network.
"""

import argparse
import datetime
import hashlib
import json
import urllib.request
from pathlib import Path

from sibyl_h0und.knowledge import PACK_DIR, SIZE_BUDGET, parse_pack
from sibyl_h0und.normalize import program_name

URL = "https://lolbas-project.github.io/api/lolbas.json"


def build(raw: bytes, retrieved: str) -> dict:
    """Reduce the LOLBAS API file to a pack.

    Args:
        raw: Downloaded API file.
        retrieved: Retrieval date, `YYYY-MM-DD`.

    Returns:
        Pack JSON keyed by normalized program name.
    """
    entries: dict[str, dict[str, list[str]]] = {}
    for item in json.loads(raw):
        name = program_name(item.get("Name"))
        if name is None:
            continue
        entry = entries.setdefault(name, {"categories": [], "mitre": []})
        for command in item.get("Commands") or []:
            pairs = (("categories", command.get("Category")), ("mitre", command.get("MitreID")))
            for field, value in pairs:
                if isinstance(value, str) and value and value not in entry[field]:
                    entry[field].append(value)
    for entry in entries.values():
        entry["categories"].sort()
        entry["mitre"].sort()
    return {
        "name": "lolbas",
        "source": "LOLBAS Project",
        "url": URL,
        "version": "sha256:" + hashlib.sha256(raw).hexdigest()[:16],
        "retrieved": retrieved,
        "licence": "GPL-3.0-only",
        "key": "program",
        "entries": dict(sorted(entries.items())),
    }


def main() -> None:
    """Fetch or read the API file and write the pack."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--input", type=Path, help="Use a downloaded API file.")
    parser.add_argument("--output", type=Path, default=PACK_DIR / "lolbas.json")
    args = parser.parse_args()

    if args.input:
        raw = args.input.read_bytes()
    else:
        with urllib.request.urlopen(URL, timeout=60) as response:
            raw = response.read()
    pack = build(raw, datetime.date.today().isoformat())
    parse_pack(pack)
    text = json.dumps(pack, ensure_ascii=False, separators=(",", ":")) + "\n"
    if len(text.encode("utf-8")) > SIZE_BUDGET:
        raise SystemExit(f"The pack is over the {SIZE_BUDGET}-byte budget.")
    args.output.write_text(text, encoding="utf-8")
    print(f"Wrote {len(pack['entries'])} entries to {args.output}.")


if __name__ == "__main__":
    main()
