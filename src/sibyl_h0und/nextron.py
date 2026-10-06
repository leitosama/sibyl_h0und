"""Attribute ratings from the Nextron Antivirus Event Analysis Cheat Sheet.

Source: Florian Roth (@cyb3rops), Nextron Systems, "Antivirus Event Analysis
Cheat Sheet" v1.12. The sheet rates the attributes of an antivirus alert as
less relevant, relevant or highly relevant. The lookup tables below restate the
Location, User Context and Form / Type rows in our own words. The sheet gives
no way to combine the rows, so summing them is our choice.

The sheet describes a file that an antivirus flagged. Where we rate a running
process:

- a Windows system directory is the normal home of its image, so it rates 0
  there instead of 2;
- every rating moves one step down (relevant becomes less relevant, highly
  relevant becomes relevant), because replaying the practice traces showed that
  full-scale ratings fire on far more benign processes than wrong ones.
"""

import re
from dataclasses import dataclass
from typing import Any

from sibyl_h0und.flags import Attribute, Properties, ScoreRule

FILE_TYPES = frozenset({"windows_file", "archive_file", "powershell_script"})
PROCESS_TYPES = frozenset({"windows_process"})

# Accounts the sheet lists as administrative or service: SYSTEM, local service,
# network service, per-service SIDs and IIS application pool identities.
SERVICE_SID = re.compile(r"^S-1-5-(18|19|20|80-.+|82-.+)$", re.IGNORECASE)
ADMIN_RID = re.compile(r"-500$")
ADMIN_INTEGRITY = frozenset({"high", "system"})

HIGHLY_RELEVANT_EXTENSIONS = frozenset(
    {
        ".asp", ".aspx", ".bat", ".chm", ".hta", ".jsp", ".jspx", ".jar", ".lnk", ".php",
        ".ps1", ".scf", ".txt", ".vbs", ".war", ".wsf", ".wsh", ".xml", ".cs", ".jpg",
        ".jpeg", ".gif", ".png", ".cab", ".iso", ".jnlp", ".img", ".diagcab", ".appx",
        ".dmg", ".one",
    }
)  # fmt: skip
UNCOMMON_ARCHIVE_EXTENSIONS = frozenset({".rar", ".7z"})
COMMON_ARCHIVE_EXTENSIONS = frozenset({".zip"})


@dataclass(frozen=True)
class _Place:
    """A directory pattern and how relevant a file found there is."""

    pattern: re.Pattern[str]
    rating: int
    # A running image is expected in Windows system directories.
    system_directory: bool = False


def _place(pattern: str, rating: int, *, system_directory: bool = False) -> _Place:
    return _Place(re.compile(pattern, re.IGNORECASE), rating, system_directory)


# Paths are lower-cased with backslashes. The first match wins, so a specific
# directory goes before the directory that contains it.
_PLACES = (
    _place(r"^\\\\(tsclient|client)\\", 2),
    _place(r"^\\\\[^\\]+\\[^\\]+\$(\\|$)", 2),
    _place(r"\\frontend\\httpproxy\\owa\\auth\\", 2),
    _place(r"\\inetpub\\wwwroot\\aspnet_client\\", 2),
    _place(r"^c:\\windows\\temp\\", 1),
    _place(r"\\appdata\\(local|roaming)\\temp\\", 1),
    _place(r"^c:\\temp\\", 1),
    _place(r"^c:\\programdata\\", 1),
    _place(r"^c:\\users\\(public|all users)\\", 1),
    _place(r"\$recycle\.bin\\", 1),
    _place(r"^c:\\windows\\", 2, system_directory=True),
    _place(r"^c:\\perflogs\\", 2),
    _place(r"^c:\\[^\\]+$", 2),
    _place(r"temporary internet files", 0),
)


def _windows_path(value: Any) -> str | None:
    """Normalize a Windows path, or return `None` for anything else."""
    if not isinstance(value, str):
        return None
    path = value.strip().replace("/", "\\").lower()
    if re.match(r"^([a-z]:\\|\\\\)", path):
        return path
    return None


def location_rating(value: Any, *, executed: bool) -> int | None:
    """Rate the directory of a file or of a running image.

    Args:
        value: Path from the entity's properties.
        executed: Whether the path is the image of a running process.

    Returns:
        0, 1 or 2, or `None` when the value is not a Windows path.
    """
    path = _windows_path(value)
    if path is None:
        return None
    for place in _PLACES:
        if place.pattern.search(path):
            return 0 if executed and place.system_directory else place.rating
    return 0


def form_rating(value: Any) -> int | None:
    """Rate the file extension of a path, or return `None` if the sheet is silent."""
    if not isinstance(value, str):
        return None
    name = value.replace("/", "\\").rsplit("\\", 1)[-1].lower()
    extension = "." + name.rsplit(".", 1)[-1] if "." in name else ""
    if extension in HIGHLY_RELEVANT_EXTENSIONS:
        return 2
    if extension in UNCOMMON_ARCHIVE_EXTENSIONS:
        return 1
    if extension in COMMON_ARCHIVE_EXTENSIONS:
        return 0
    return None


def user_rating(properties: Properties) -> int | None:
    """Rate the account a process runs as: administrative or service is 2, standard is 1."""
    sid, user = properties.get("user_sid"), properties.get("user")
    integrity = properties.get("integrity_level")
    if not any(isinstance(value, str) and value for value in (sid, user, integrity)):
        return None
    if isinstance(sid, str) and (SERVICE_SID.match(sid) or ADMIN_RID.search(sid)):
        return 2
    if properties.get("is_elevated") is True:
        return 2
    if isinstance(integrity, str) and integrity.lower() in ADMIN_INTEGRITY:
        return 2
    return 1


NEXTRON_FILE = ScoreRule(
    name="nextron_file",
    node_types=FILE_TYPES,
    attributes=(
        Attribute("location", lambda p: location_rating(p.get("path"), executed=False)),
        Attribute("form", lambda p: form_rating(p.get("path"))),
    ),
    medium_at=3,
    high_at=4,
)


def lowered(rating: int | None) -> int | None:
    """Move a rating one step down the scale, keeping an unrated attribute unrated."""
    return None if rating is None else max(rating - 1, 0)


NEXTRON_PROCESS = ScoreRule(
    name="nextron_process",
    node_types=PROCESS_TYPES,
    attributes=(
        Attribute(
            "location", lambda p: lowered(location_rating(p.get("image_path"), executed=True))
        ),
        Attribute("user", lambda p: lowered(user_rating(p))),
    ),
    # Lowered ratings sum to 2 at most. A single top rating, an administrative
    # or service account, is too common to flag: on the practice traces it
    # fired on most benign tasks as often as on wrong ones.
    medium_at=2,
    high_at=2,
)

NEXTRON_RULES = (NEXTRON_FILE, NEXTRON_PROCESS)
