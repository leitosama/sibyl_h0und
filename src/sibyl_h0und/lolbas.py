"""Rules over the LOLBAS knowledge pack: Windows binaries that attackers live off.

The pack lists, for each binary, the categories of its documented abuse
(Execute, Download, AWL Bypass, …). Being a LOLBin alone is common and benign,
so a plain match stays `low` and reaches only the trace. A binary that LOLBAS
documents as a downloader or uploader with a URL on its command line is
`medium`.
"""

from typing import Any

from sibyl_h0und.flags import LOW, MEDIUM, LookupRule, NodeContext, Properties
from sibyl_h0und.knowledge import load_pack
from sibyl_h0und.nextron import PROCESS_TYPES
from sibyl_h0und.normalize import command_line

TRANSFER_CATEGORIES = frozenset({"Download", "Upload"})
# Property names the runtime may use for a process command line.
COMMAND_LINE_KEYS = ("command_line", "commandline", "cmdline")


def process_command_line(properties: Properties) -> str | None:
    """Return the command line of a process, whichever key carries it."""
    for key in COMMAND_LINE_KEYS:
        if isinstance(value := properties.get(key), str) and value:
            return value
    return None


def _judge(entry: Any, properties: Properties, context: NodeContext) -> tuple[str, str]:
    """Rate a LOLBin by what LOLBAS documents and what its command line shows."""
    categories = entry.get("categories", [])
    parsed = command_line(process_command_line(properties))
    if parsed is not None and parsed.urls and TRANSFER_CATEGORIES.intersection(categories):
        return MEDIUM, f"LOLBAS transfer binary with URL {parsed.urls[0]}"
    return LOW, "LOLBAS: " + ", ".join(categories)


LOLBAS_PROCESS = LookupRule(
    name="lolbas_process",
    node_types=PROCESS_TYPES,
    pack=load_pack("lolbas"),
    key=lambda properties: properties.get("image_path"),
    judge=_judge,
)

LOLBAS_RULES = (LOLBAS_PROCESS,)
