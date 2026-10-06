"""Rules the agent applies by default."""

from sibyl_h0und.flags import HIGH, LevelRule, Properties, Rule
from sibyl_h0und.lolbas import LOLBAS_RULES
from sibyl_h0und.nextron import NEXTRON_RULES, PROCESS_TYPES
from sibyl_h0und.normalize import program_name

WEB_SERVER_IMAGES = frozenset({"w3wp.exe", "httpd.exe", "nginx.exe", "tomcat9.exe", "php-cgi.exe"})
SHELL_IMAGES = frozenset({"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe"})


def _web_server_spawns_shell(properties: Properties) -> str | None:
    """Explain a shell whose parent is a web server worker, otherwise return `None`."""
    parent = program_name(properties.get("parent_image"))
    image = program_name(properties.get("image_path"))
    if parent in WEB_SERVER_IMAGES and image in SHELL_IMAGES:
        return f"{parent} spawned {image}"
    return None


WEB_SERVER_SPAWNS_SHELL = LevelRule(
    name="web_server_spawns_shell",
    node_types=PROCESS_TYPES,
    level=HIGH,
    match=_web_server_spawns_shell,
)

DEFAULT_RULES: tuple[Rule, ...] = (*NEXTRON_RULES, WEB_SERVER_SPAWNS_SHELL, *LOLBAS_RULES)
