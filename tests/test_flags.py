from typing import Any

import pytest

from sibyl_h0und.flags import FlagBoard
from sibyl_h0und.rules import DEFAULT_RULES


def process(**properties: Any) -> dict[str, Any]:
    """Build a process entity as the runtime returns it."""
    return {"id": "proc-1", "type": "windows_process", "properties": properties}


def file(path: str) -> dict[str, Any]:
    """Build a file entity as the runtime returns it."""
    return {"id": "file-1", "type": "windows_file", "properties": {"path": path}}


def judge(node: dict[str, Any]) -> dict[str, tuple[str, dict[str, int]]]:
    """Return level and ratings of each rule that spoke about a node."""
    return {
        finding.rule: (finding.level, finding.ratings)
        for finding in FlagBoard(DEFAULT_RULES).observe(node)
    }


@pytest.mark.parametrize(
    ("path", "level", "ratings"),
    [
        ("C:\\Users\\Public\\update.ps1", "medium", {"location": 1, "form": 2}),
        ("c:/windows/temp/Run.HTA", "medium", {"location": 1, "form": 2}),
        ("C:\\Windows\\System32\\drivers\\x.ps1", "high", {"location": 2, "form": 2}),
        ("\\\\host\\C$\\tools\\run.bat", "high", {"location": 2, "form": 2}),
        ("C:\\Users\\bob\\AppData\\Local\\Temp\\a.zip", "low", {"location": 1, "form": 0}),
        ("C:\\Windows\\System32\\kernel32.dll", "low", {"location": 2}),
        ("D:\\Shares\\a.rar", "low", {"location": 0, "form": 1}),
    ],
)
def test_file_rating_follows_the_cheat_sheet(
    path: str, level: str, ratings: dict[str, int]
) -> None:
    """Location and extension are rated per the sheet and summed into a level."""
    assert judge(file(path)) == {"nextron_file": (level, ratings)}


def test_linux_file_is_not_rated() -> None:
    """Without data for any attribute the rule stays silent instead of scoring 0."""
    assert judge(file("/tmp/payload")) == {}


@pytest.mark.parametrize(
    ("properties", "level", "ratings"),
    [
        # Running from System32 is normal, the sheet's "highly relevant" is for dropped files.
        (
            {"image_path": "C:\\Windows\\System32\\net.exe", "user_sid": "S-1-5-21-1-2-3-1105"},
            "low",
            {"location": 0, "user": 0},
        ),
        (
            {"image_path": "C:\\PerfLogs\\a.exe", "user_sid": "S-1-5-18"},
            "high",
            {"location": 1, "user": 1},
        ),
        (
            {"image_path": "C:\\ProgramData\\a.exe", "integrity_level": "high"},
            "low",
            {"location": 0, "user": 1},
        ),
        ({"user_sid": "S-1-5-21-1-2-3-500"}, "low", {"user": 1}),
    ],
)
def test_process_rating_expects_system_directories(
    properties: dict[str, Any], level: str, ratings: dict[str, int]
) -> None:
    """A process image in a Windows directory is not suspicious, its account still counts."""
    assert judge(process(**properties)) == {"nextron_process": (level, ratings)}


def test_web_server_spawning_a_shell_is_high_by_itself() -> None:
    """A level rule gives its fixed level whatever the attributes say."""
    findings = judge(
        process(
            image_path="C:\\Windows\\System32\\cmd.exe",
            parent_image="C:\\Windows\\System32\\inetsrv\\w3wp.exe",
            user_sid="S-1-5-21-1-2-3-1105",
        )
    )

    assert findings["web_server_spawns_shell"][0] == "high"
    assert findings["nextron_process"][0] == "low"


def test_board_reports_a_node_once_and_again_only_when_it_changes() -> None:
    """Repeated results stay quiet, a later response with more properties is re-judged."""
    board = FlagBoard(DEFAULT_RULES)
    partial = process(image_path="C:\\ProgramData\\a.exe")
    full = process(image_path="C:\\ProgramData\\a.exe", user_sid="S-1-5-18")

    assert len(board.observe({"entities": [partial]})) == 1
    assert board.observe({"result": partial}) == []
    changed = board.observe(full)

    assert [finding.ratings for finding in changed] == [{"location": 0, "user": 1}]
