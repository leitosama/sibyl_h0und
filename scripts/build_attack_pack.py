"""Build the ATT&CK knowledge packs from MITRE's STIX bundle.

Usage: uv run python scripts/build_attack_pack.py [--input enterprise-attack.json]

Without `--input` the script downloads the Enterprise ATT&CK bundle and writes
three snapshots to `src/sibyl_h0und/knowledge/`:

- `attack_techniques.json`: technique id to name, tactics, platforms, the
  opening of the description and, when ATT&CK has a detection strategy for it,
  the names of the data components its analytics read, by platform;
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
DETECTION_TYPES = ("x-mitre-detection-strategy", "x-mitre-analytic", "x-mitre-data-component")
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


def _data_components(strategy: dict | None, detection: dict[str, dict]) -> set[tuple[str, str]]:
    """Name the data components a detection strategy's analytics read, by platform.

    Args:
        strategy: The source of a `detects` relationship; only an active
            detection strategy has analytics.
        detection: Active detection strategies, analytics and data components by id.

    Returns:
        `(platform, data component name)` pairs, one per platform of the analytic.
    """
    if strategy is None or strategy["type"] != "x-mitre-detection-strategy":
        return set()
    found = set()
    for ref in strategy.get("x_mitre_analytic_refs", []):
        if (analytic := detection.get(ref)) is None:
            continue
        for source in analytic.get("x_mitre_log_source_references", []):
            if (component := detection.get(source.get("x_mitre_data_component_ref"))) is None:
                continue
            platforms = analytic.get("x_mitre_platforms", [])
            found |= {(platform, component["name"]) for platform in platforms}
    return found


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
    detection = {item["id"]: item for item in objects if item["type"] in DETECTION_TYPES}
    used: dict[str, set[str]] = {}
    detected_by: dict[str, dict[str, set[str]]] = {}
    for item in objects:
        technique = technique_ids.get(item.get("target_ref"))
        if item["type"] != "relationship" or not technique:
            continue
        if item.get("relationship_type") == "uses":
            used.setdefault(item["source_ref"], set()).add(technique)
        elif item.get("relationship_type") == "detects":
            pairs = _data_components(detection.get(item["source_ref"]), detection)
            for platform, name in pairs:
                detected_by.setdefault(technique, {}).setdefault(platform, set()).add(name)

    techniques = {}
    for item in objects:
        if item["type"] != "attack-pattern" or not (technique := technique_ids[item["id"]]):
            continue
        techniques[technique] = {
            "name": item["name"],
            "tactics": [phase["phase_name"] for phase in item.get("kill_chain_phases", [])],
            "platforms": item.get("x_mitre_platforms", []),
            "summary": summary(item.get("description")),
        }
        if components := detected_by.get(technique):
            techniques[technique]["data_components"] = {
                platform: sorted(names) for platform, names in sorted(components.items())
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
