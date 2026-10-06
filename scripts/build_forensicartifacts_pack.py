"""Build the Windows autostart knowledge pack from ForensicArtifacts.

Usage: uv run python scripts/build_forensicartifacts_pack.py [--input windows.yaml]

ForensicArtifacts is a community knowledge base of forensic artifacts in YAML.
The script keeps the registry keys and values of the artifacts that its
`WindowsPersistenceRegistryKeys` group lists (Run keys, Winlogon, AppInit_DLLs,
image file execution options, LSA packages and the like) and of
`WindowsServices`, keyed by the normalized key path (`normalize.registry_path`).
For every key it records the artifact name, the opening of its description, the
value name when the artifact names one, and the source URLs. Keys with a
wildcard inside the path are left out. The sources say
where persistence lives, not which data in it is bad. Only the snapshot is
committed: the agent and CI never reach the network.
"""

import argparse
import datetime
import hashlib
import json
import urllib.request
from pathlib import Path

import yaml

from sibyl_h0und.knowledge import PACK_DIR, SIZE_BUDGET, parse_pack
from sibyl_h0und.normalize import registry_path

REPOSITORY = "ForensicArtifacts/artifacts"
URL = f"https://github.com/{REPOSITORY}"
RAW = f"https://raw.githubusercontent.com/{REPOSITORY}/main/artifacts/data/windows.yaml"
ROOT_GROUP = "WindowsPersistenceRegistryKeys"
EXTRA_ARTIFACTS = ("WindowsServices",)
SUMMARY_LENGTH = 300


def artifacts_in(documents: list[dict], roots: list[str]) -> set[str]:
    """Return the names of the artifacts the roots list, groups expanded."""
    by_name = {doc["name"]: doc for doc in documents}
    found: set[str] = set()
    pending = list(roots)
    while pending:
        name = pending.pop()
        if name in found or name not in by_name:
            continue
        found.add(name)
        for source in by_name[name].get("sources", []):
            if source["type"] == "ARTIFACT_GROUP":
                pending += source["attributes"]["names"]
    return found


def build(text: str, retrieved: str) -> dict:
    """Reduce `windows.yaml` to a pack keyed by normalized registry key path.

    Args:
        text: Content of `windows.yaml`.
        retrieved: Retrieval date, `YYYY-MM-DD`.
    """
    documents = [doc for doc in yaml.safe_load_all(text) if isinstance(doc, dict) and "name" in doc]
    wanted = artifacts_in(documents, [ROOT_GROUP, *EXTRA_ARTIFACTS])
    entries: dict[str, list[dict]] = {}
    for doc in documents:
        if doc["name"] not in wanted:
            continue
        summary = " ".join(str(doc.get("doc", "")).split())
        if len(summary) > SUMMARY_LENGTH:
            summary = summary[:SUMMARY_LENGTH].rstrip() + "…"
        pairs: list[tuple[str, str | None]] = []
        for source in doc.get("sources", []):
            attributes = source.get("attributes", {})
            if source["type"] == "REGISTRY_KEY":
                pairs += [(key, None) for key in attributes["keys"]]
            elif source["type"] == "REGISTRY_VALUE":
                pairs += [(pair["key"], pair["value"]) for pair in attributes["key_value_pairs"]]
        for key, value in pairs:
            # A wildcard inside a path (`Classes\*\shell`) matches no concrete key.
            if (normalized := registry_path(key)) is None or "*" in normalized:
                continue
            entry = {"artifact": doc["name"], "summary": summary}
            if value:
                entry["value"] = value
            if doc.get("urls"):
                entry["urls"] = list(doc["urls"])
            if entry not in (bucket := entries.setdefault(normalized, [])):
                bucket.append(entry)
    return {
        "name": "forensicartifacts_autostart",
        "source": "ForensicArtifacts",
        "url": URL,
        "version": "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:16],
        "retrieved": retrieved,
        "licence": "Apache-2.0",
        "key": "registry",
        "entries": dict(sorted(entries.items())),
    }


def main() -> None:
    """Fetch or read `windows.yaml` and write the pack."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--input", type=Path, help="Use a downloaded windows.yaml.")
    parser.add_argument(
        "--output", type=Path, default=PACK_DIR / "forensicartifacts_autostart.json"
    )
    args = parser.parse_args()

    if args.input:
        text = args.input.read_text(encoding="utf-8")
    else:
        with urllib.request.urlopen(RAW, timeout=60) as response:
            text = response.read().decode("utf-8")
    pack = build(text, datetime.date.today().isoformat())
    parse_pack(pack)
    out = json.dumps(pack, ensure_ascii=False, separators=(",", ":")) + "\n"
    if len(out.encode("utf-8")) > SIZE_BUDGET:
        raise SystemExit(f"The pack is over the {SIZE_BUDGET}-byte budget.")
    args.output.write_text(out, encoding="utf-8")
    print(f"Wrote {len(pack['entries'])} registry keys.")


if __name__ == "__main__":
    main()
