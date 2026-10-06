"""Normalization shared by the vocabulary and the knowledge pack builders.

The vocabulary and the pack builders reduce raw values to the same keys, so a
lookup made at runtime finds the entry the build script stored. Every function accepts
any value and returns `None` (or an empty result) when the value cannot be
normalized, so callers need no type checks of their own.
"""

import base64
import binascii
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

URL_PATTERN = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>|^]+", re.IGNORECASE)
POWERSHELL_IMAGES = frozenset({"powershell.exe", "pwsh.exe", "powershell_ise.exe"})
# Option prefixes on Windows command lines. A slash also starts Unix paths, so
# only a short token such as `/c` or `/s:value` counts as a slash option.
_SLASH_OPTION = re.compile(r"^/[a-z?][\w-]{0,30}(?:[:=].*)?$", re.IGNORECASE)
_ATTACK_ID = re.compile(r"^(?:T\d{4}(?:\.\d{3})?|S\d{4})$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")


def windows_path(value: Any) -> str | None:
    """Lower-case a Windows path with backslashes, or return `None` for a non-path.

    Surrounding quotes, the `\\\\?\\` prefix and repeated separators are removed.
    A UNC path keeps its leading double backslash.
    """
    if not isinstance(value, str) or not (path := value.strip().strip('"').strip()):
        return None
    path = path.replace("/", "\\").lower()
    if path.startswith("\\\\?\\"):
        path = path[4:]
    unc = path.startswith("\\\\")
    path = re.sub(r"\\{2,}", r"\\", path)
    return "\\" + path if unc else path


def program_name(
    value: Any, *, aliases: Mapping[str, str] | None = None, exe: bool = True
) -> str | None:
    """Return the lower-cased file name of a program path.

    Args:
        value: Image path, file name or first token of a command line.
        aliases: Map from a normalized name to the name to use instead.
        exe: Add `.exe` to a name that has no extension, as Windows does
            when it runs `cmd` or `rundll32`.

    Returns:
        A name such as `certutil.exe`, or `None` when the value is empty.
    """
    path = windows_path(value)
    if path is None or not (name := path.rsplit("\\", 1)[-1].strip()):
        return None
    if exe and "." not in name:
        name += ".exe"
    return (aliases or {}).get(name, name)


def remove_carets(text: str) -> str:
    """Drop the `cmd.exe` escape character outside double quotes: `p^o^wer` is `power`."""
    out: list[str] = []
    quoted = escaped = False
    for char in text:
        if escaped:
            out.append(char)
            escaped = False
        elif char == '"':
            quoted = not quoted
            out.append(char)
        elif char == "^" and not quoted:
            escaped = True
        else:
            out.append(char)
    return "".join(out)


def split_command_line(text: str) -> list[str]:
    """Split a Windows command line into tokens, removing double quotes.

    Whitespace separates tokens outside double quotes. A quote toggles quoting
    and is dropped, so `"C:\\Program Files\\a.exe" -x` gives two tokens.
    """
    tokens: list[str] = []
    current: list[str] = []
    quoted = started = False
    for char in remove_carets(text):
        if char == '"':
            quoted = not quoted
            started = True
        elif char.isspace() and not quoted:
            if started:
                tokens.append("".join(current))
                current, started = [], False
        else:
            current.append(char)
            started = True
    if started:
        tokens.append("".join(current))
    return tokens


def _option(token: str) -> tuple[str, str | None] | None:
    """Return the lower-cased name and inline value of an option token, or `None`."""
    if token.startswith("--") and len(token) > 2:
        body = token[2:]
    elif token.startswith("-") and len(token) > 1 or _SLASH_OPTION.match(token):
        body = token[1:]
    else:
        return None
    name, separator, inline = re.match(r"([^:=]*)([:=]?)(.*)", body, re.DOTALL).groups()
    return name.lower(), inline if separator else None


def decode_powershell(value: str) -> str | None:
    """Decode a PowerShell `-EncodedCommand` value: base64 of UTF-16LE text."""
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
        text = raw.decode("utf-16-le")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    return text if text.isprintable() or "\n" in text else None


def _is_encoded_command(option: str) -> bool:
    """Tell whether a PowerShell option name abbreviates `-EncodedCommand`."""
    return option in {"ec", "e"} or (len(option) >= 2 and "encodedcommand".startswith(option))


@dataclass(frozen=True)
class CommandLine:
    """A parsed command line.

    Attributes:
        text: Command line with carets removed.
        program: Normalized name of the program, see `program_name`.
        arguments: Tokens after the program, quotes removed.
        options: Lower-cased option name without its `-`, `--` or `/` prefix,
            mapped to its value: the part after `:` or `=`, or else the next
            token when that is not an option, or `None`.
        decoded: Script of a PowerShell `-EncodedCommand`, when one decodes.
    """

    text: str
    program: str | None
    arguments: tuple[str, ...]
    options: dict[str, str | None] = field(default_factory=dict)
    decoded: str | None = None

    @property
    def urls(self) -> list[str]:
        """URLs in the arguments, a quoted one whole, and in the decoded script."""
        found = [
            url
            for argument in self.arguments
            for url in ([argument] if URL_PATTERN.match(argument) else urls(argument))
        ]
        return found + urls(self.decoded)


def command_line(value: Any) -> CommandLine | None:
    """Parse a Windows command line, or return `None` for an empty value."""
    if not isinstance(value, str) or not (tokens := split_command_line(value)):
        return None
    program = program_name(tokens[0])
    arguments = tuple(tokens[1:])
    options: dict[str, str | None] = {}
    for index, token in enumerate(arguments):
        if (option := _option(token)) is None:
            continue
        name, inline = option
        following = arguments[index + 1] if index + 1 < len(arguments) else None
        if inline is None and following is not None and _option(following) is None:
            inline = following
        options.setdefault(name, inline)
    decoded = None
    if program in POWERSHELL_IMAGES:
        for name, option_value in options.items():
            if _is_encoded_command(name) and option_value:
                decoded = decode_powershell(option_value)
                break
    return CommandLine(remove_carets(value).strip(), program, arguments, options, decoded)


def urls(text: Any) -> list[str]:
    """Return the URLs found in a text."""
    return URL_PATTERN.findall(text) if isinstance(text, str) else []


def domain(value: Any) -> str | None:
    """Return the lower-cased host name of a domain, URL or e-mail address.

    The scheme, credentials, port, path and trailing dot are dropped. An IP
    address or a single label is not a domain and gives `None`.
    """
    if not isinstance(value, str) or not (text := value.strip().lower()):
        return None
    if "://" in text:
        text = urlsplit(text).hostname or ""
    else:
        text = text.rsplit("@", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    text = text.rstrip(".")
    if re.fullmatch(r"[\d.]+", text) or not _DOMAIN.match(text):
        return None
    return text


def unix_program(value: Any) -> str | None:
    """Return the lower-cased base name of a Unix program, without a `.exe` suffix.

    `/usr/bin/Curl` and `curl.exe` both give `curl`. Unlike `program_name`, no
    extension is added, because Unix programs have none.
    """
    if not isinstance(value, str) or not (path := value.strip().strip('"').strip()):
        return None
    name = path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].strip().lower()
    return (name.removesuffix(".exe") or None) if name else None


def attack_id(value: Any) -> str | None:
    """Return an upper-cased ATT&CK technique (`T1036.003`) or software (`S0195`) id."""
    if not isinstance(value, str):
        return None
    text = value.strip().upper()
    return text if _ATTACK_ID.match(text) else None


# Normalizers a knowledge pack can name as its key.
KEY_NORMALIZERS: dict[str, Callable[[Any], str | None]] = {
    "program": program_name,
    "path": windows_path,
    "domain": domain,
    "attack_id": attack_id,
    "unix_program": unix_program,
}
