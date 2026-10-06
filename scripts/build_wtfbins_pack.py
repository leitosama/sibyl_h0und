"""Build the WTFBins knowledge pack from the project's published entries.

Usage: uv run python scripts/build_wtfbins_pack.py [--input-dir content/]

WTFBins catalogues benign programs that behave like malware. Without
`--input-dir` the script downloads the entries from the project repository.
It keeps, for every entry, its title, tags, the opening of the text and its
URL, and keys the entries by the first executable name in the title. The text of
the entries is retrieved by words (`vocabulary.py`), so entries without an
executable in the title are still found. Only the snapshot is committed: the
agent and CI never reach the network.
"""

import argparse
import datetime
import hashlib
import json
import re
import tomllib
import urllib.request
from pathlib import Path

from sibyl_h0und.knowledge import PACK_DIR, SIZE_BUDGET, parse_pack
from sibyl_h0und.normalize import program_name

REPOSITORY = "mttaggart/wtfbins"
URL = f"https://github.com/{REPOSITORY}"
RAW = f"https://raw.githubusercontent.com/{REPOSITORY}/main/content"
TREE = f"https://api.github.com/repos/{REPOSITORY}/git/trees/main?recursive=1"
SITE = "https://wtfbins.wtf"
SUMMARY_LENGTH = 500
_EXECUTABLE = re.compile(r"[\w.-]+\.exe", re.IGNORECASE)
_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_LINK = re.compile(r"!?\[([^\]]*)\]\([^)]*\)")


def parse_entry(text: str) -> dict | None:
    """Parse one entry: TOML front matter between `+++` lines, then the text.

    Returns:
        The entry, or `None` when it has no id or title.
    """
    parts = text.split("+++", 2)
    if len(parts) != 3:
        return None
    meta = tomllib.loads(parts[1])
    if not isinstance(meta.get("id"), int) or not meta.get("title"):
        return None
    body = _LINK.sub(r"\1", _COMMENT.sub("", parts[2]))
    body = " ".join(body.split())
    if len(body) > SUMMARY_LENGTH:
        body = body[:SUMMARY_LENGTH].rstrip() + "…"
    return {
        "id": meta["id"],
        "title": meta["title"],
        "tags": list((meta.get("taxonomies") or {}).get("tags", [])),
        "summary": body,
        "url": f"{SITE}/{meta['id']}/",
    }


def build(entries: list[str], version_source: bytes, retrieved: str) -> dict:
    """Reduce the entry texts to a pack keyed by the first executable in each title.

    Args:
        entries: Raw text of each entry file.
        version_source: Bytes the version digest is computed from.
        retrieved: Retrieval date, `YYYY-MM-DD`.
    """
    keyed: dict[str, list[dict]] = {}
    documents = list(filter(None, (parse_entry(text) for text in entries)))
    for doc in documents:
        # Only the first executable names the program the entry is about; a later
        # one ("… triggers SYSTEM cmd.exe") is what it did.
        if (found := _EXECUTABLE.search(doc["title"])) and (key := program_name(found.group(0))):
            keyed.setdefault(key, []).append(doc)
    return {
        "name": "wtfbins",
        "source": "WTFBins",
        "url": URL,
        "version": "sha256:" + hashlib.sha256(version_source).hexdigest()[:16],
        "retrieved": retrieved,
        "licence": "MIT",
        "key": "program",
        "entries": dict(sorted(keyed.items())),
        "documents": sorted(documents, key=lambda doc: doc["id"]),
    }


def _download(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read()


def main() -> None:
    """Fetch or read the entries and write the pack."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--input-dir", type=Path, help="Use downloaded entry files.")
    parser.add_argument("--output", type=Path, default=PACK_DIR / "wtfbins.json")
    args = parser.parse_args()

    if args.input_dir:
        raws = [path.read_bytes() for path in sorted(args.input_dir.glob("*.md"))]
    else:
        tree = json.loads(_download(TREE))["tree"]
        names = sorted(
            item["path"].removeprefix("content/")
            for item in tree
            if re.fullmatch(r"content/\d+\.md", item["path"])
        )
        raws = [_download(f"{RAW}/{name}") for name in names]
    pack = build(
        [raw.decode("utf-8") for raw in raws], b"".join(raws), datetime.date.today().isoformat()
    )
    parse_pack(pack)
    text = json.dumps(pack, ensure_ascii=False, separators=(",", ":")) + "\n"
    if len(text.encode("utf-8")) > SIZE_BUDGET:
        raise SystemExit(f"The pack is over the {SIZE_BUDGET}-byte budget.")
    args.output.write_text(text, encoding="utf-8")
    print(f"Wrote {len(pack['entries'])} program keys, {len(pack['documents'])} entries.")


if __name__ == "__main__":
    main()
