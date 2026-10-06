"""Build the HijackLibs knowledge pack from the project's entries.

Usage: uv run python scripts/build_hijacklibs_pack.py [--input-dir yml/]

HijackLibs records DLL hijacking opportunities: for a DLL name, where the
legitimate copy lives and which executables load it from where they can be
tricked. Without `--input-dir` the script downloads the entries from the
project repository. The snapshot keys entries by DLL name; for each it keeps
the vendor, the expected locations, the CVE, the vulnerable executables (path,
type and the elevation flags, the first `EXECUTABLE_LIMIT` of them) and the
entry's page. Only the snapshot is committed: the agent and CI never reach the
network.
"""

import argparse
import datetime
import hashlib
import json
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

from sibyl_h0und.knowledge import PACK_DIR, SIZE_BUDGET, parse_pack
from sibyl_h0und.normalize import program_name

REPOSITORY = "wietze/HijackLibs"
URL = f"https://github.com/{REPOSITORY}"
RAW = f"https://raw.githubusercontent.com/{REPOSITORY}/main"
TREE = f"https://api.github.com/repos/{REPOSITORY}/git/trees/main?recursive=1"
SITE = "https://hijacklibs.net/entries"
EXECUTABLE_LIMIT = 10


def parse_entry(text: str, path: str) -> tuple[str, dict] | None:
    """Parse one entry file.

    Args:
        text: YAML of the entry.
        path: Its path in the repository, such as `yml/microsoft/built-in/version.yml`.

    Returns:
        The DLL key and the entry, or `None` when the file has no DLL name.
    """
    data = yaml.safe_load(text)
    if not isinstance(data, dict) or not (key := program_name(data.get("Name"), exe=False)):
        return None
    executables = [
        {
            "path": item.get("Path"),
            "type": item.get("Type"),
            **{flag: True for flag in ("AutoElevate", "PrivilegeEscalation") if item.get(flag)},
        }
        for item in data.get("VulnerableExecutables") or []
        if isinstance(item, dict)
    ]
    page = path.removeprefix("yml/").removesuffix(".yml")
    entry = {
        "vendor": data.get("Vendor"),
        "expected_locations": data.get("ExpectedLocations") or [],
        "vulnerable_executables": executables[:EXECUTABLE_LIMIT],
        "vulnerable_executables_total": len(executables),
        "url": f"{SITE}/{page}.html",
    }
    if data.get("CVE"):
        entry["cve"] = data["CVE"]
    return key, entry


def build(files: dict[str, str], retrieved: str) -> dict:
    """Reduce entry files to a pack keyed by DLL name.

    Args:
        files: Entry text by repository path.
        retrieved: Retrieval date, `YYYY-MM-DD`.
    """
    entries: dict[str, list[dict]] = {}
    for path, text in sorted(files.items()):
        if (parsed := parse_entry(text, path)) is not None:
            entries.setdefault(parsed[0], []).append(parsed[1])
    digest = hashlib.sha256("".join(files[path] for path in sorted(files)).encode("utf-8"))
    return {
        "name": "hijacklibs",
        "source": "HijackLibs",
        "url": URL,
        "version": "sha256:" + digest.hexdigest()[:16],
        "retrieved": retrieved,
        "licence": "GPL-3.0",
        "key": "program",
        "entries": dict(sorted(entries.items())),
    }


def _download(url: str) -> str:
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read().decode("utf-8")


def main() -> None:
    """Fetch or read the entries and write the pack."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--input-dir", type=Path, help="Use a checkout's yml/ directory.")
    parser.add_argument("--output", type=Path, default=PACK_DIR / "hijacklibs.json")
    args = parser.parse_args()

    if args.input_dir:
        files = {
            f"yml/{path.relative_to(args.input_dir).as_posix()}": path.read_text(encoding="utf-8")
            for path in sorted(args.input_dir.rglob("*.yml"))
        }
    else:
        listing = json.loads(_download(TREE))
        if listing.get("truncated"):
            raise SystemExit("GitHub truncated the file listing; use --input-dir with a checkout.")
        tree = listing["tree"]
        paths = sorted(
            item["path"]
            for item in tree
            if item["path"].startswith("yml/") and item["path"].endswith(".yml")
        )
        with ThreadPoolExecutor(8) as pool:
            texts = pool.map(lambda path: _download(f"{RAW}/{path}"), paths)
            files = dict(zip(paths, texts, strict=True))
    pack = build(files, datetime.date.today().isoformat())
    parse_pack(pack)
    out = json.dumps(pack, ensure_ascii=False, separators=(",", ":")) + "\n"
    if len(out.encode("utf-8")) > SIZE_BUDGET:
        raise SystemExit(f"The pack is over the {SIZE_BUDGET}-byte budget.")
    args.output.write_text(out, encoding="utf-8")
    print(f"Wrote {len(pack['entries'])} DLL names from {len(files)} entries.")


if __name__ == "__main__":
    main()
