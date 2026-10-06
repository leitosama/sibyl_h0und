"""Rules the agent applies by default."""

from typing import Any

from sibyl_h0und.flags import HIGH, LevelRule, Properties, Rule
from sibyl_h0und.nextron import NEXTRON_RULES, PROCESS_TYPES

WEB_SERVER_IMAGES = frozenset({"w3wp.exe", "httpd.exe", "nginx.exe", "tomcat9.exe", "php-cgi.exe"})
SHELL_IMAGES = frozenset({"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe"})


def _basename(value: Any) -> str:
    """Return the lower-cased file name of a Windows path, or an empty string."""
    if not isinstance(value, str):
        return ""
    return value.replace("/", "\\").rsplit("\\", 1)[-1].lower()


def _web_server_spawns_shell(properties: Properties) -> str | None:
    """Explain a shell whose parent is a web server worker, otherwise return `None`."""
    parent, image = (
        _basename(properties.get("parent_image")),
        _basename(properties.get("image_path")),
    )
    if parent in WEB_SERVER_IMAGES and image in SHELL_IMAGES:
        return f"{parent} spawned {image}"
    return None


WEB_SERVER_SPAWNS_SHELL = LevelRule(
    name="web_server_spawns_shell",
    node_types=PROCESS_TYPES,
    level=HIGH,
    match=_web_server_spawns_shell,
)

DEFAULT_RULES: tuple[Rule, ...] = (*NEXTRON_RULES, WEB_SERVER_SPAWNS_SHELL)
