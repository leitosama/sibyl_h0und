"""Build the GTFOBins knowledge pack from the project's published API.

Usage: uv run python scripts/build_gtfobins_pack.py [--input api.json]

GTFOBins lists Unix executables that can be abused. The script keeps, for each
executable, the abuse functions with one example command line each and the
contexts they work in (`sudo`, `suid`, …), and the description and MITRE ids
of each function as `documents`. It writes
`src/sibyl_h0und/knowledge/gtfobins.json`. Only the snapshot is committed: the
agent and CI never reach the network.
"""

import argparse
import datetime
import hashlib
import json
import urllib.request
from pathlib import Path

from sibyl_h0und.knowledge import PACK_DIR, SIZE_BUDGET, parse_pack
from sibyl_h0und.normalize import unix_program

URL = "https://gtfobins.org/api.json"
EXAMPLE_LENGTH = 200


def build(raw: bytes, retrieved: str) -> dict:
    """Reduce the GTFOBins API file to a pack keyed by executable name.

    Args:
        raw: Downloaded API file.
        retrieved: Retrieval date, `YYYY-MM-DD`.
    """
    data = json.loads(raw)
    entries: dict[str, dict] = {}
    for name, executable in data["executables"].items():
        if (key := unix_program(name)) is None:
            continue
        examples: dict[str, str] = {}
        contexts: set[str] = set()
        for function, variants in (executable.get("functions") or {}).items():
            for variant in variants:
                if function not in examples and isinstance(variant.get("code"), str):
                    examples[function] = variant["code"].strip()[:EXAMPLE_LENGTH]
                contexts.update(variant.get("contexts") or {})
        entries[key] = {"functions": dict(sorted(examples.items())), "contexts": sorted(contexts)}
    documents = [
        {
            "id": function,
            "label": item.get("label"),
            "description": item.get("description"),
            "mitre": item.get("mitre", []),
        }
        for function, item in sorted(data["functions"].items())
    ]
    return {
        "name": "gtfobins",
        "source": "GTFOBins",
        "url": URL,
        "version": "sha256:" + hashlib.sha256(raw).hexdigest()[:16],
        "retrieved": retrieved,
        "licence": "GPL-3.0-only",
        "key": "unix_program",
        "entries": dict(sorted(entries.items())),
        "documents": documents,
    }


def main() -> None:
    """Fetch or read the API file and write the pack."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--input", type=Path, help="Use a downloaded API file.")
    parser.add_argument("--output", type=Path, default=PACK_DIR / "gtfobins.json")
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
