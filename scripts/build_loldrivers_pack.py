"""Build the LOLDrivers knowledge pack from the project's published API.

Usage: uv run python scripts/build_loldrivers_pack.py [--input drivers.json]

LOLDrivers lists Windows drivers that attackers load to run code in the kernel
or to disable security tools: vulnerable drivers that are signed and malicious
ones. The script writes one snapshot, `loldrivers.json`, keyed by driver file
name (`.sys`) and by SHA-256, each key naming the drivers that have that name or
sample. A driver keeps its id, category, ATT&CK id, use, the opening of its
description and its page. SHA-1 and MD5 are left out to keep the snapshot under
the size budget; a file node carries the SHA-256 too. Only the snapshot is
committed: the agent and CI never reach the network.
"""

import argparse
import datetime
import hashlib
import json
import urllib.request
from pathlib import Path

from sibyl_h0und.knowledge import PACK_DIR, SIZE_BUDGET, parse_pack
from sibyl_h0und.normalize import file_key

URL = "https://www.loldrivers.io/api/drivers.json"
SITE = "https://www.loldrivers.io/drivers"
SUMMARY_LENGTH = 200


def _summary(driver: dict) -> tuple[str | None, str]:
    """Return the use and the shortened description of a driver's first command."""
    commands = driver.get("Commands")
    # The API gives one command as an object and several as a list.
    command = (commands[0] if isinstance(commands, list) and commands else commands) or {}
    if not isinstance(command, dict):
        command = {}
    text = " ".join(str(command.get("Description") or "").split())
    if len(text) > SUMMARY_LENGTH:
        text = text[:SUMMARY_LENGTH].rstrip() + "…"
    return command.get("Usecase") or None, text


def build(drivers: list[dict], version_source: bytes, retrieved: str) -> dict:
    """Reduce the API list to a pack keyed by driver file name and SHA-256.

    Args:
        drivers: Decoded `drivers.json`.
        version_source: Bytes the version digest is computed from.
        retrieved: Retrieval date, `YYYY-MM-DD`.
    """
    documents = []
    entries: dict[str, set[int]] = {}
    for driver in drivers:
        if not driver.get("Id"):
            continue
        index = len(documents)
        use, summary = _summary(driver)
        documents.append(
            {
                "id": driver["Id"],
                "category": driver.get("Category"),
                "mitre": driver.get("MitreID"),
                "use": use,
                "summary": summary,
                "url": f"{SITE}/{driver['Id']}/",
            }
        )
        names = list(driver.get("Tags") or [])
        samples = [
            item for item in driver.get("KnownVulnerableSamples") or [] if isinstance(item, dict)
        ]
        for sample in samples:
            names += [sample.get("Filename"), sample.get("OriginalFilename")]
        keys = [file_key(name) for name in names if isinstance(name, str)]
        keys += [file_key(sample.get("SHA256")) for sample in samples]
        for key in keys:
            # Product names and bare words in the tags are not file names.
            if key and (key.endswith(".sys") or (len(key) == 64 and key.isalnum())):
                entries.setdefault(key, set()).add(index)
    return {
        "name": "loldrivers",
        "source": "LOLDrivers",
        "url": "https://github.com/magicsword-io/LOLDrivers",
        "version": "sha256:" + hashlib.sha256(version_source).hexdigest()[:16],
        "retrieved": retrieved,
        "licence": "Apache-2.0",
        "key": "file",
        "entries": {key: sorted(found) for key, found in sorted(entries.items())},
        "documents": documents,
    }


def main() -> None:
    """Fetch or read the API list and write the pack."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--input", type=Path, help="Use a downloaded drivers.json.")
    parser.add_argument("--output", type=Path, default=PACK_DIR / "loldrivers.json")
    args = parser.parse_args()

    if args.input:
        raw = args.input.read_bytes()
    else:
        with urllib.request.urlopen(URL, timeout=120) as response:
            raw = response.read()
    pack = build(json.loads(raw), raw, datetime.date.today().isoformat())
    parse_pack(pack)
    out = json.dumps(pack, ensure_ascii=False, separators=(",", ":")) + "\n"
    if len(out.encode("utf-8")) > SIZE_BUDGET:
        raise SystemExit(f"The pack is over the {SIZE_BUDGET}-byte budget.")
    args.output.write_text(out, encoding="utf-8")
    print(f"Wrote {len(pack['entries'])} keys, {len(pack['documents'])} drivers.")


if __name__ == "__main__":
    main()
