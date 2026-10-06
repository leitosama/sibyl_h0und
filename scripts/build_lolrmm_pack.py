"""Build the LOLRMM knowledge packs from the project's published API.

Usage: uv run python scripts/build_lolrmm_pack.py [--input rmm_tools.json]

LOLRMM lists remote monitoring and management tools that attackers reuse. The
script writes two snapshots to `src/sibyl_h0und/knowledge/`: `lolrmm.json`
(executable names from PE metadata and install paths) and `lolrmm_domains.json`
(domains the tools contact, wildcard prefix removed). Only the snapshots are
committed: the agent and CI never reach the network.
"""

import argparse
import datetime
import hashlib
import json
import urllib.request
from pathlib import Path

from sibyl_h0und.knowledge import PACK_DIR, SIZE_BUDGET, parse_pack
from sibyl_h0und.normalize import domain, program_name

URL = "https://lolrmm.io/api/rmm_tools.json"
# Names LOLRMM lists that are too generic to say "RMM": Windows components,
# placeholders and bare words that unrelated programs use.
GENERIC_NAMES = frozenset(
    {
        "<random>.exe",
        "agent.exe",
        "connect.exe",
        "dd.exe",
        "dwm.exe",
        "installer.exe",
        "mstsc.exe",
        "setup.exe",
        "kitty.exe",
        "level.exe",
        "era.exe",
        "goto.exe",
        "svchost.exe",
    }
)


def _dicts(value: object) -> list[dict]:
    """Return the objects of a JSON list, or nothing for another shape."""
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _executables(item: dict) -> set[str]:
    """Collect the Windows executable names a LOLRMM entry gives for its tool."""
    names: list[object] = []
    details = item.get("Details") or {}
    for metadata in _dicts(details.get("PEMetadata")):
        names += [metadata.get("Filename"), metadata.get("OriginalFileName")]
    for path in details.get("InstallationPaths") or []:
        names.append(path.replace("/", "\\").rsplit("\\", 1)[-1] if isinstance(path, str) else None)
    found = set()
    for name in names:
        if not isinstance(name, str) or "*" in name or not name.lower().endswith(".exe"):
            continue
        if (key := program_name(name)) is not None and key not in GENERIC_NAMES:
            found.add(key)
    return found


def _domains(item: dict) -> set[str]:
    """Collect the domains a LOLRMM entry gives for its tool, `*.` prefix removed."""
    found = set()
    for network in _dicts((item.get("Artifacts") or {}).get("Network")):
        for value in network.get("Domains") or []:
            if isinstance(value, str) and (key := domain(value.removeprefix("*."))) is not None:
                found.add(key)
    return found


def _pack(name: str, key: str, entries: dict[str, dict], raw: bytes, retrieved: str) -> dict:
    return {
        "name": name,
        "source": "LOLRMM",
        "url": URL,
        "version": "sha256:" + hashlib.sha256(raw).hexdigest()[:16],
        "retrieved": retrieved,
        "licence": "Apache-2.0",
        "key": key,
        "entries": dict(sorted(entries.items())),
    }


def build(raw: bytes, retrieved: str) -> tuple[dict, dict]:
    """Reduce the LOLRMM API file to the program pack and the domain pack.

    A name or domain shared by several tools keeps the first tool in file order.
    """
    programs: dict[str, dict] = {}
    domains: dict[str, dict] = {}
    for item in json.loads(raw):
        tool = item.get("Name")
        if not isinstance(tool, str) or not tool:
            continue
        for key in sorted(_executables(item)):
            programs.setdefault(key, {"tool": tool})
        for key in sorted(_domains(item)):
            domains.setdefault(key, {"tool": tool})
    return (
        _pack("lolrmm", "program", programs, raw, retrieved),
        _pack("lolrmm_domains", "domain", domains, raw, retrieved),
    )


def main() -> None:
    """Fetch or read the API file and write both packs."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--input", type=Path, help="Use a downloaded API file.")
    parser.add_argument("--output-dir", type=Path, default=PACK_DIR)
    args = parser.parse_args()

    if args.input:
        raw = args.input.read_bytes()
    else:
        with urllib.request.urlopen(URL, timeout=120) as response:
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
