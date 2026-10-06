"""Build the ATT&CK knowledge packs from MITRE's STIX bundle.

Usage: uv run python scripts/build_attack_pack.py [--input enterprise-attack.json]

Without `--input` the script downloads the Enterprise ATT&CK bundle and writes
three snapshots to `src/sibyl_h0und/knowledge/`:

- `attack_techniques.json`: technique id to name, tactics, platforms and the
  opening of the description;
- `attack_software.json`: software id (`S0195`) to name, type, the opening of
  the description and the technique ids it uses;
- `attack_software_names.json`: program-like names and aliases to software id.

Only the snapshots are committed: the agent and CI never reach the network.
"""

import argparse
import datetime
import hashlib
import json
import re
import urllib.request
from pathlib import Path

from sibyl_h0und.knowledge import PACK_DIR, SIZE_BUDGET, parse_pack
from sibyl_h0und.normalize import program_name

URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
SOFTWARE_TYPES = ("tool", "malware")
# A name that can be a file name: no spaces, no path or option characters.
PROGRAM_LIKE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$")
SUMMARY_LENGTH = 420
_CITATION = re.compile(r"\(Citation:[^)]*\)")
_LINK = re.compile(r"\[([^\]]+)\]\([^)]+\)")
_TAG = re.compile(r"</?code>")


def _active(item: dict) -> bool:
    """Tell whether a STIX object is neither revoked nor deprecated."""
    return not item.get("revoked") and not item.get("x_mitre_deprecated")


def _attack_id(item: dict) -> str | None:
    """Return the ATT&CK id (`S0195`, `T1070.004`) of a STIX object."""
    for reference in item.get("external_references", []):
        if reference.get("source_name") == "mitre-attack" and reference.get("external_id"):
            return reference["external_id"]
    return None


def summary(text: str | None) -> str:
    """Return the opening of a description without citations, links and markup.

    The text is cut at a sentence end before `SUMMARY_LENGTH` when there is one.
    """
    text = _TAG.sub("", _LINK.sub(r"\1", _CITATION.sub("", text or "")))
    text = " ".join(text.split("\n")[0].split())
    if len(text) <= SUMMARY_LENGTH:
        return text
    cut = text[:SUMMARY_LENGTH]
    end = cut.rfind(". ")
    return cut[: end + 1] if end > SUMMARY_LENGTH // 2 else cut.rstrip() + "…"


def _pack(name: str, key: str, entries: dict, raw: bytes, retrieved: str) -> dict:
    return {
        "name": name,
        "source": "MITRE ATT&CK Enterprise",
        "url": URL,
        "version": "sha256:" + hashlib.sha256(raw).hexdigest()[:16],
        "retrieved": retrieved,
        "licence": "MITRE-ATT&CK-terms-of-use",
        "key": key,
        "entries": dict(sorted(entries.items())),
    }


def build(raw: bytes, retrieved: str) -> list[dict]:
    """Reduce the STIX bundle to the technique, software and software-name packs.

    Args:
        raw: Downloaded STIX bundle.
        retrieved: Retrieval date, `YYYY-MM-DD`.

    Returns:
        The three packs. A name shared by several software entries keeps the
        entry with the lowest software id.
    """
    objects = [item for item in json.loads(raw)["objects"] if _active(item)]
    technique_ids = {
        item["id"]: _attack_id(item) for item in objects if item["type"] == "attack-pattern"
    }
    used: dict[str, set[str]] = {}
    for item in objects:
        technique = technique_ids.get(item.get("target_ref"))
        if item["type"] == "relationship" and item.get("relationship_type") == "uses" and technique:
            used.setdefault(item["source_ref"], set()).add(technique)

    techniques = {
        technique_ids[item["id"]]: {
            "name": item["name"],
            "tactics": [phase["phase_name"] for phase in item.get("kill_chain_phases", [])],
            "platforms": item.get("x_mitre_platforms", []),
            "summary": summary(item.get("description")),
        }
        for item in objects
        if item["type"] == "attack-pattern" and technique_ids[item["id"]]
    }
    software: dict[str, dict] = {}
    names: dict[str, dict] = {}
    ordered = sorted(
        (
            (software_id, item)
            for item in objects
            if item["type"] in SOFTWARE_TYPES and (software_id := _attack_id(item))
        ),
        key=lambda pair: pair[0],
    )
    for software_id, item in ordered:
        software[software_id] = {
            "name": item["name"],
            "type": item["type"],
            "summary": summary(item.get("description")),
            "techniques": sorted(used.get(item["id"], ())),
        }
        for alias in {item["name"], *item.get("x_mitre_aliases", [])}:
            if PROGRAM_LIKE.match(alias) and (key := program_name(alias)) is not None:
                names.setdefault(key, {"id": software_id})
    return [
        _pack("attack_techniques", "attack_id", techniques, raw, retrieved),
        _pack("attack_software", "attack_id", software, raw, retrieved),
        _pack("attack_software_names", "program", names, raw, retrieved),
    ]


def main() -> None:
    """Fetch or read the bundle and write the packs."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--input", type=Path, help="Use a downloaded STIX bundle.")
    parser.add_argument("--output-dir", type=Path, default=PACK_DIR)
    args = parser.parse_args()

    if args.input:
        raw = args.input.read_bytes()
    else:
        with urllib.request.urlopen(URL, timeout=300) as response:
            raw = response.read()
    for pack in build(raw, datetime.date.today().isoformat()):
        parse_pack(pack)
        text = json.dumps(pack, ensure_ascii=False, separators=(",", ":")) + "\n"
        if len(text.encode("utf-8")) > SIZE_BUDGET:
            raise SystemExit(f"Pack {pack['name']} is over the {SIZE_BUDGET}-byte budget.")
        path = args.output_dir / f"{pack['name']}.json"
        path.write_text(text, encoding="utf-8")
        print(f"Wrote {len(pack['entries'])} entries to {path}.")


if __name__ == "__main__":
    main()
