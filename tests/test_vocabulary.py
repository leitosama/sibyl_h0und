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


def test_a_technique_names_the_data_it_is_detected_in_when_attack_has_a_detection() -> None:
    """A remote session technique points at the logon and connection behind it."""
    (winrm, *_) = shared().lookup("T1021.006")["matches"]
    (scanning, *_) = shared().lookup("T1590")["matches"]

    assert {"Logon Session Creation", "Network Traffic Flow"} <= set(
        winrm["data_components"]["Windows"]
    )
    assert "data_components" not in scanning


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


def found_by_terms(answer: dict[str, Any]) -> set[tuple[str, str, str]]:
    """Return the term, source and id or name of each entry a term inside the query found."""
    return {
        (match["term"], match["source"], match.get("id") or match["name"])
        for match in answer["matches"]
        if match.get("term", answer["query"]) != answer["query"]
    }


def named(answer: dict[str, Any]) -> dict[str, list[str]]:
    """Map each word the answer names to the entries it would bring."""
    return {name["term"]: name["entries"] for name in answer.get("names", [])}


@pytest.mark.parametrize(
    ("query", "entries", "names"),
    [
        ("sdelete.exe anti-forensics", {("sdelete.exe", "attack", "S0195")}, {}),
        ("rundll32 comsvcs dump", set(), {"rundll32": ["lolbas rundll32.exe"]}),
        ("sekurlsa::logonpasswords mimikatz", set(), {"mimikatz": ["attack S0002 Mimikatz"]}),
        (
            "vssadmin delete shadows T1490",
            {("T1490", "attack", "T1490")},
            {"vssadmin": ["lolbas vssadmin.exe"]},
        ),
        ("shadows deleted (vssadmin.exe).", {("vssadmin.exe", "lolbas", "vssadmin.exe")}, {}),
        ("/tmp/x.sh was run by vssadmin", set(), {"vssadmin": ["lolbas vssadmin.exe"]}),
    ],
)
def test_terms_inside_a_description_are_answered_and_program_names_are_named(
    query: str, entries: set[tuple[str, str, str]], names: dict[str, list[str]]
) -> None:
    """Context words no longer hide a term (issue #40); a bare program name is pointed to."""
    answer = shared().lookup(query)

    assert found_by_terms(answer) == entries
    assert named(answer) == names


def test_an_ordinary_word_that_names_a_program_is_pointed_to_not_answered() -> None:
    """Whether `play` means the Play ransomware is the model's call, not the code's."""
    answer = shared().lookup("something play happened")

    assert answer["matches"] == []
    assert named(answer) == {"play": ["attack S1162 Playcrypt"]}
    assert "note" not in answer


def test_a_named_word_asked_in_terms_brings_its_entry_and_is_not_named_again() -> None:
    """The model gets the entry by asking for the name as a term."""
    answer = shared().lookup("vssadmin delete shadows T1490", ["vssadmin"])

    assert found_by_terms(answer) == {
        ("T1490", "attack", "T1490"),
        ("vssadmin", "lolbas", "vssadmin.exe"),
    }
    assert "names" not in answer


@pytest.mark.parametrize("query", ["wsmprovhost.exe", "w3wp.exe", "sdclt.exe"])
def test_an_unknown_program_stays_an_honest_miss(query: str) -> None:
    """A program no source lists gets no entry, alone or among other terms."""
    assert shared().lookup(query)["matches"] == []
    assert shared().lookup("vssadmin", [query])["not_found"] == [query]
    assert shared().lookup("something play happened", [query])["not_found"] == [query]


@pytest.mark.parametrize(
    ("query", "row"),
    [
        ("logon by S-1-5-18", "account"),
        ("dropped a .ps1 script", "extension"),
        ('"C:\\Windows\\Temp\\x.ps1"', "location"),
    ],
)
def test_cheat_sheet_rows_come_back_for_terms_in_descriptions_and_quoted_paths(
    query: str, row: str
) -> None:
    """Every kind of term a single query can be is also found inside a description."""
    (match,) = [m for m in shared().lookup(query)["matches"] if m["source"] == "nextron"]

    assert row in match


@pytest.mark.parametrize(
    "query", ['"C:\\Program Files\\AnyDesk\\AnyDesk.exe"', "/opt/my tools/bin/anydesk"]
)
def test_a_path_with_spaces_is_one_term_not_a_description(query: str) -> None:
    """A quoted Windows path or a Unix path is not split into words."""
    assert "lolrmm" in sources(shared().lookup(query))


def test_one_meaningful_word_in_a_sentence_does_not_match_on_summaries() -> None:
    """Stop words around `powershell` do not lower the bar for a word match."""

    def ids(query: str) -> list[str]:
        return [match.get("id") for match in shared().lookup(query)["matches"]]

    assert ids("use of powershell") == ids("powershell")


def test_a_lookup_stops_after_ten_searches_with_entries_and_names_the_rest() -> None:
    """Many terms cannot flood the answer; the ones past the limit are named."""
    terms = sorted(load_pack("attack_techniques").entries)[:15]

    answer = shared().lookup(terms[0], terms[1:])

    assert answer["skipped"] == terms[10:]
    assert "not_found" not in answer
    assert {match["term"] for match in answer["matches"]} == set(terms[:10])


def test_ordinary_words_of_a_long_description_do_not_use_up_its_word_search() -> None:
    """Program lookups that find nothing do not count toward the limit."""
    query = (
        "attacker deleted volume shadow copies and backups on the file server "
        "to stop system recovery before encrypting shared documents"
    )

    answer = shared().lookup(query)

    assert "skipped" not in answer
    assert "T1490" in {match.get("id") for match in answer["matches"]}


def test_several_terms_in_one_lookup_say_which_term_found_each_entry() -> None:
    """One local call answers each term once and names the ones with no entry."""
    answer = shared().lookup("vssadmin", ["T1490", "w3wp.exe", "vssadmin.exe", "T1490"])

    assert [(match["term"], match["source"]) for match in answer["matches"]] == [
        ("vssadmin", "lolbas"),
        ("T1490", "attack"),
    ]
    assert answer["not_found"] == ["w3wp.exe"]


def test_a_hyphenated_name_finds_the_technique_spelled_with_spaces() -> None:
    """`pass-the-hash` meets "Pass the Hash"."""
    matches = shared().lookup("pass-the-hash")["matches"]

    assert "T1550.002" in {match["id"] for match in matches}


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


@pytest.mark.parametrize(
    ("query", "artifact"),
    [
        ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\GoogleUpdate", "WindowsRunKeys"),
        (
            "HKEY_USERS\\S-1-5-21-1-2-3-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "WindowsRunKeys",
        ),
        ("HKLM\\System\\ControlSet001\\Services\\PSEXESVC", "WindowsServices"),
        ("HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "WindowsRunKeys"),
    ],
)
def test_a_registry_path_finds_the_autostart_location_that_holds_it(
    query: str, artifact: str
) -> None:
    """The match is on the key or a parent, whatever the hive spelling or value name."""
    (match, *_) = shared().lookup(query)["matches"]

    assert (match["source"], match["kind"]) == ("forensicartifacts", "autostart_location")
    assert [item["artifact"] for item in match["artifacts"]] == [artifact]


def test_a_key_with_no_autostart_entry_gets_no_answer_and_no_verdict() -> None:
    """Application settings are not in the source, and the answer says nothing about safety."""
    answer = shared().lookup("HKLM\\Software\\Vendor\\App\\Settings")

    assert answer["matches"] == []
    assert "nothing about whether" in answer["note"]


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


def test_an_artifact_that_names_one_value_does_not_cover_the_keys_below_its_key() -> None:
    """`Control` is listed for one value only; a key below it gets no entry from it."""
    below = shared().lookup("HKLM\\System\\CurrentControlSet\\Control\\Terminal Server")
    exact = shared().lookup("HKLM\\System\\CurrentControlSet\\Control")

    assert below["matches"] == []
    assert [m["relation"] for m in exact["matches"]] == ["same_key"]
    assert (
        shared().lookup("HKLM\\System\\CurrentControlSet\\Services\\x")["matches"][0]["relation"]
        == "key_is_below"
    )
