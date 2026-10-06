"""Build the GTFOArgs knowledge pack from the project's published text.

Usage: uv run python scripts/build_gtfoargs_pack.py [--input llms-full.txt]

GTFOArgs lists Unix programs whose arguments can be abused through argument
injection. The script reads the project's single-file text edition and keeps,
for each program, its abuse functions, one example argument line per function
and the page URL. It writes `src/sibyl_h0und/knowledge/gtfoargs.json`. Only the
snapshot is committed: the agent and CI never reach the network.
"""

import argparse
import datetime
import hashlib
import json
import re
import urllib.request
from pathlib import Path

from sibyl_h0und.knowledge import PACK_DIR, SIZE_BUDGET, parse_pack
from sibyl_h0und.normalize import unix_program

URL = "https://gtfoargs.github.io/llms-full.txt"
EXAMPLE_LENGTH = 200
_CODE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)


def parse_section(section: str) -> tuple[str, dict] | None:
    """Parse one `## name` section: its URL, its functions and an example each.

    Returns:
        The program name and its entry, or `None` for a section that is not a program.
    """
    head, _, body = section.partition("\n")
    url = re.search(r"^URL: (\S+)", body, re.MULTILINE)
    functions = re.search(r"^Functions: (.+)$", body, re.MULTILINE)
    if not head.strip() or url is None or functions is None:
        return None
    examples: dict[str, str] = {}
    for block in re.split(r"^### ", body, flags=re.MULTILINE)[1:]:
        title, _, text = block.partition("\n")
        function = title.strip().lower().replace(" ", "-")
        if (code := _CODE.search(text)) is not None:
            examples[function] = code.group(1).strip()[:EXAMPLE_LENGTH]
    return head.strip(), {
        "functions": [name.strip() for name in functions.group(1).split(",")],
        "examples": examples,
        "url": url.group(1),
    }


def build(raw: bytes, retrieved: str) -> dict:
    """Reduce the project's text edition to a pack keyed by program name.

    Args:
        raw: Downloaded text.
        retrieved: Retrieval date, `YYYY-MM-DD`.
    """
    entries: dict[str, dict] = {}
    for section in raw.decode("utf-8").split("\n## ")[1:]:
        parsed = parse_section(section)
        if parsed is not None and (key := unix_program(parsed[0])) is not None:
            entries[key] = parsed[1]
    return {
        "name": "gtfoargs",
        "source": "GTFOArgs",
        "url": URL,
        "version": "sha256:" + hashlib.sha256(raw).hexdigest()[:16],
        "retrieved": retrieved,
        "licence": "GPL-3.0-only",
        "key": "unix_program",
        "entries": dict(sorted(entries.items())),
    }


def main() -> None:
    """Fetch or read the text and write the pack."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--input", type=Path, help="Use a downloaded text file.")
    parser.add_argument("--output", type=Path, default=PACK_DIR / "gtfoargs.json")
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
