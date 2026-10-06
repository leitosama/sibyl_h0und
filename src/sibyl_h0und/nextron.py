"""Rows of the Nextron Antivirus Event Analysis Cheat Sheet, as vocabulary.

Source: Florian Roth (@cyb3rops), Nextron Systems, "Antivirus Event Analysis
Cheat Sheet" v1.12. The sheet rates the attributes of an antivirus alert as
less relevant, relevant or highly relevant. The tables below restate the
Location, User Context and Form / Type rows in our own words.

The functions return a row of the sheet for one value and nothing else: no
sum of rows, no threshold and no adjustment for processes. The sheet was
written for files that an antivirus flagged, and each row says so (ADR 0017).
"""

import re
from typing import Any

from sibyl_h0und.normalize import program_name, windows_path

RATINGS = {0: "less relevant", 1: "relevant", 2: "highly relevant"}
SCOPE = "The sheet rates files an antivirus flagged; it does not rate running processes."

# Accounts the sheet lists as administrative or service: SYSTEM, local service,
# network service, per-service SIDs and IIS application pool identities.
SERVICE_SID = re.compile(r"^S-1-5-(18|19|20|80-.+|82-.+)$", re.IGNORECASE)
ADMIN_RID = re.compile(r"-500$")

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

# Paths are lower-cased with backslashes. The first match wins, so a specific
# directory goes before the directory that contains it.
_PLACES = (
    (r"^\\\\(tsclient|client)\\", 2, "remote drive share of a terminal session"),
    (r"^\\\\[^\\]+\\[^\\]+\$(\\|$)", 2, "hidden administrative share"),
    (r"\\frontend\\httpproxy\\owa\\auth\\", 2, "Exchange OWA auth directory"),
    (r"\\inetpub\\wwwroot\\aspnet_client\\", 2, "IIS aspnet_client directory"),
    (r"^c:\\windows\\temp\\", 1, "Windows temp directory"),
    (r"\\appdata\\(local|roaming)\\temp\\", 1, "user temp directory"),
    (r"^c:\\temp\\", 1, "temp directory"),
    (r"^c:\\programdata\\", 1, "ProgramData"),
    (r"^c:\\users\\(public|all users)\\", 1, "Public or All Users profile"),
    (r"\$recycle\.bin\\", 1, "recycle bin"),
    (r"^c:\\windows\\", 2, "Windows directory"),
    (r"^c:\\perflogs\\", 2, "PerfLogs"),
    (r"^c:\\[^\\]+$", 2, "root of the system drive"),
    (r"temporary internet files", 0, "browser cache"),
)
_PLACE_PATTERNS = tuple((re.compile(pattern), rating, label) for pattern, rating, label in _PLACES)


def _absolute_path(value: Any) -> str | None:
    """Normalize an absolute Windows path, or return `None` for anything else."""
    path = windows_path(value)
    return path if path is not None and re.match(r"^([a-z]:\\|\\\\)", path) else None


def location_row(value: Any) -> dict[str, Any] | None:
    """Return the Location row of an absolute path, or `None` for a non-path.

    A path in no listed directory is `less relevant`, as the sheet has it.
    """
    if (path := _absolute_path(value)) is None:
        return None
    for pattern, rating, label in _PLACE_PATTERNS:
        if pattern.search(path):
            return {"rating": RATINGS[rating], "directory": label, "note": SCOPE}
    return {"rating": RATINGS[0], "directory": "not a listed directory", "note": SCOPE}


def extension_row(value: Any) -> dict[str, Any] | None:
    """Return the Form / Type row of a file name or path, or `None` if the sheet is silent."""
    name = program_name(value, exe=False)
    if name is None:
        return None
    extension = "." + name.rsplit(".", 1)[-1] if "." in name else ""
    if extension in HIGHLY_RELEVANT_EXTENSIONS:
        rating = 2
    elif extension in UNCOMMON_ARCHIVE_EXTENSIONS:
        rating = 1
    elif extension in COMMON_ARCHIVE_EXTENSIONS:
        rating = 0
    else:
        return None
    return {"rating": RATINGS[rating], "extension": extension, "note": SCOPE}


def user_row(sid: str) -> dict[str, Any]:
    """Return the User Context row of an account SID."""
    administrative = bool(SERVICE_SID.match(sid) or ADMIN_RID.search(sid))
    return {
        "rating": RATINGS[2 if administrative else 1],
        "account": "administrative or service" if administrative else "standard user",
        "note": SCOPE,
    }
