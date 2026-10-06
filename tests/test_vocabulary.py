from typing import Any

import pytest

from sibyl_h0und.knowledge import load_pack
from sibyl_h0und.nextron import extension_row, location_row, user_row
from sibyl_h0und.vocabulary import shared


def sources(answer: dict[str, Any]) -> set[str]:
    """Return the sources that have an entry in an answer."""
    return {match["source"] for match in answer["matches"]}


def test_a_program_name_finds_the_software_it_names_under_any_spelling() -> None:
    """A renamed copy is not found by its image, but its original name is: same lookup."""
    for query in ("sdelete.exe", "SDelete", "C:\\Users\\Public\\SDELETE.EXE"):
        (match, *_) = shared().lookup(query)["matches"]

        assert (match["source"], match["id"], match["name"]) == ("attack", "S0195", "SDelete")
        assert {technique["id"] for technique in match["techniques"]} >= {"T1485"}


def test_a_technique_id_brings_the_technique_and_the_software_documented_to_use_it() -> None:
    """The model can go from a hypothesis to the tools known for it."""
    (match, *_) = shared().lookup("t1036.003")["matches"]

    assert (match["id"], match["name"]) == ("T1036.003", "Rename Legitimate Utilities")
    assert match["tactics"]
    assert 0 < len(match["software_using_it"]) <= match["software_using_it_total"]
    assert all({"id", "name"} == set(item) for item in match["software_using_it"])


def test_words_describing_behavior_find_the_technique_first() -> None:
    """A description of the behavior, not a name, leads to the technique."""
    matches = shared().lookup("rename system utility")["matches"]

    assert matches[0]["id"] == "T1036.003"


def test_rmm_tools_are_found_by_executable_and_by_domain_or_subdomain() -> None:
    """The same tool answers to its binary and to a subdomain of its listed domain."""
    by_binary = shared().lookup("AnyDesk.exe")["matches"]
    by_domain = shared().lookup("relay.net.anydesk.com")["matches"]

    assert [match["tool"] for match in by_binary if match["source"] == "lolrmm"] == ["AnyDesk"]
    assert [match["tool"] for match in by_domain] == ["AnyDesk"]
    assert by_domain[0]["domain"].endswith("anydesk.com")
    assert by_domain[0]["queried"] == "relay.net.anydesk.com"


def test_wtfbins_entry_is_found_by_the_program_it_is_about_and_not_by_one_it_mentions() -> None:
    """`cmd.exe` is only mentioned in an entry about another program, so it is not that entry."""
    about = shared().lookup("explorer.exe")["matches"]
    mentioned = shared().lookup("cmd.exe")["matches"]

    assert "wtfbins" in sources({"matches": about})
    assert "wtfbins" not in sources({"matches": mentioned})


def test_unix_program_finds_gtfobins_and_gtfoargs_whatever_the_path() -> None:
    """The functions come with their description, an example and the ATT&CK technique names."""
    for query in ("find", "/usr/bin/Find"):
        found = {m["source"]: m for m in shared().lookup(query)["matches"]}

        assert {"gtfobins", "gtfoargs"} <= set(found)
    shell = found["gtfobins"]["functions"]["shell"]
    assert shell["example"].startswith("find")
    assert shell["description"]
    assert {"id": "T1059", "name": "Command and Scripting Interpreter"} in shell["techniques"]
    assert "shell" in found["gtfoargs"]["functions"]
    assert "suid" in found["gtfobins"]["contexts"]


def test_a_windows_binary_gets_no_unix_abuse_entries() -> None:
    """`find.exe` is not Unix `find`: GTFOBins and GTFOArgs answer only Unix names."""
    for query in ("find.exe", "C:\\Windows\\System32\\find.exe"):
        assert not {"gtfobins", "gtfoargs"} & sources(shared().lookup(query))


def test_a_path_with_spaces_still_names_its_file() -> None:
    """Install directories contain spaces; the file name is what identifies the program."""
    matches = shared().lookup("C:\\Program Files\\AnyDesk\\AnyDesk.exe")["matches"]

    assert "lolrmm" in sources({"matches": matches})


def test_one_word_for_a_concept_finds_the_technique_named_by_it() -> None:
    """A single behavior word is not mistaken for an unknown file name."""
    matches = shared().lookup("masquerading")["matches"]

    assert [match["id"] for match in matches] == ["T1036"]


def test_nothing_found_says_so_without_calling_the_term_safe() -> None:
    """Silence of the sources is not evidence of anything."""
    answer = shared().lookup("zzzqq-no-such-thing")

    assert answer["matches"] == []
    assert "says nothing about whether the term is benign or hostile" in answer["note"]


@pytest.mark.parametrize("query", [None, 5, "", "   "])
def test_an_unusable_query_gets_an_empty_answer_not_an_error(query: Any) -> None:
    """The tool never raises on what a model sends."""
    answer = shared().lookup(query)

    assert answer["matches"] == []


@pytest.mark.parametrize(
    ("query", "row"),
    [
        ("C:\\Users\\Public\\run.ps1", "location"),
        ("C:\\Temp\\a.rar", "extension"),
        ("S-1-5-18", "account"),
    ],
)
def test_cheat_sheet_rows_come_back_as_the_sheet_states_them(query: str, row: str) -> None:
    """A path, extension or SID gets its row, unsummed and unadjusted."""
    (match,) = [m for m in shared().lookup(query)["matches"] if m["source"] == "nextron"]

    assert row in match
    assert "antivirus" in str(match[row]["note"])


def test_cheat_sheet_rates_a_windows_directory_as_the_sheet_does_for_a_flagged_file() -> None:
    """No process adjustment: a Windows directory is highly relevant, with the scope stated."""
    row = location_row("C:\\Windows\\System32\\cmd.exe")

    assert row is not None
    assert row["rating"] == "highly relevant"
    assert "not rate running processes" in row["note"]
    assert location_row("relative\\path") is None
    assert extension_row("notes.txt")["rating"] == "highly relevant"
    assert extension_row("tool.exe") is None
    assert user_row("S-1-5-21-1-2-3-1001")["account"] == "standard user"


def test_a_registry_value_path_finds_the_autostart_key_that_holds_it() -> None:
    """The match is on the key or a parent, whatever the hive spelling or value name."""
    for query in (
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\GoogleUpdate",
        "HKEY_USERS\\S-1-5-21-1-2-3-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    ):
        (match, *_) = shared().lookup(query)["matches"]

        assert (match["source"], match["kind"]) == ("forensicartifacts", "autostart_location")
        assert [item["artifact"] for item in match["artifacts"]] == ["WindowsRunKeys"]


def test_a_service_key_finds_the_services_location() -> None:
    answer = shared().lookup("HKLM\\System\\ControlSet001\\Services\\PSEXESVC")

    assert [item["artifact"] for item in answer["matches"][0]["artifacts"]] == ["WindowsServices"]


def test_a_key_with_no_autostart_entry_gets_no_answer_and_no_verdict() -> None:
    """Application settings are not in the source, and the answer says nothing about safety."""
    answer = shared().lookup("HKLM\\Software\\Vendor\\App\\Settings")

    assert answer["matches"] == []
    assert "nothing about whether" in answer["note"]


@pytest.mark.parametrize(
    "query",
    [
        "C:\\AzAgent\\_work\\1\\s\\build.exe",
        "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\a.lnk",
    ],
)
def test_benign_build_and_programdata_paths_get_no_autostart_entry(query: str) -> None:
    assert "forensicartifacts" not in sources(shared().lookup(query))


def test_a_driver_is_found_by_file_name_under_any_path_and_by_sha256() -> None:
    by_name = shared().lookup("C:\\Windows\\Temp\\RTCore64.SYS")
    (loldrivers,) = [m for m in by_name["matches"] if m["source"] == "loldrivers"]
    digest = next(key for key in load_pack("loldrivers").entries if len(key) == 64)
    (by_hash,) = [
        m for m in shared().lookup(digest.upper())["matches"] if m["source"] == "loldrivers"
    ]

    assert loldrivers["matched_on"] == "name"
    assert all({"id", "category", "url"} <= set(driver) for driver in loldrivers["drivers"])
    assert by_hash["matched_on"] == "sha256"


def test_a_dll_name_brings_where_its_legitimate_copy_lives() -> None:
    """The model compares the path it saw with the locations the source states."""
    (match,) = [
        m
        for m in shared().lookup("C:\\Users\\Public\\Version.dll")["matches"]
        if m["source"] == "hijacklibs"
    ]

    assert match["name"] == "version.dll"
    assert "%SYSTEM32%" in match["entries"][0]["expected_locations"]


@pytest.mark.parametrize(
    "query",
    ["C:\\AzAgent\\_work\\1\\s\\bin\\app.dll", "C:\\ProgramData\\x\\helper.sys", "hidusb.sys"],
)
def test_benign_drops_get_no_driver_or_dll_entry(query: str) -> None:
    assert not sources(shared().lookup(query)) & {"loldrivers", "hijacklibs"}
