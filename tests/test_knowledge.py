import json
import sys
from pathlib import Path

import pytest

from sibyl_h0und.knowledge import PackError, load_pack, pack_names, read_pack

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from build_attack_pack import build as build_attack  # noqa: E402
from build_forensicartifacts_pack import build as build_autostart  # noqa: E402
from build_gtfoargs_pack import build as build_gtfoargs  # noqa: E402
from build_gtfobins_pack import build as build_gtfobins  # noqa: E402
from build_hijacklibs_pack import build as build_hijacklibs  # noqa: E402
from build_lolbas_pack import build  # noqa: E402
from build_loldrivers_pack import build as build_loldrivers  # noqa: E402
from build_lolrmm_pack import build as build_lolrmm  # noqa: E402
from build_wtfbins_pack import build as build_wtfbins  # noqa: E402

PACK = {
    "name": "toy",
    "source": "Toy",
    "url": "https://example.invalid/toy.json",
    "version": "1",
    "retrieved": "2026-10-06",
    "licence": "MIT",
    "key": "program",
    "entries": {"certutil.exe": {"categories": ["Download"]}},
}


def write(path: Path, data: object) -> Path:
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


@pytest.mark.parametrize("name", pack_names())
def test_shipped_packs_load_offline_within_budget(name: str) -> None:
    """Every committed pack parses, records provenance and fits the size budget."""
    pack = load_pack(name)

    assert pack.name == name
    assert pack.licence and pack.retrieved and pack.version
    assert pack.entries


def test_lookup_normalizes_the_raw_value(tmp_path: Path) -> None:
    """A rule passes the raw property; the pack's key normalizer finds the entry."""
    pack = read_pack(write(tmp_path / "toy.json", PACK))

    assert pack.lookup("C:\\Windows\\System32\\CERTUTIL.exe") == {"categories": ["Download"]}
    assert pack.lookup("C:\\Windows\\notepad.exe") is None
    assert pack.lookup(None) is None


@pytest.mark.parametrize(
    "data",
    [
        {**PACK, "key": "unknown"},
        {key: value for key, value in PACK.items() if key != "licence"},
        {**PACK, "entries": []},
    ],
)
def test_malformed_pack_is_rejected(tmp_path: Path, data: dict) -> None:
    """A pack without provenance or with an unknown key form never loads."""
    with pytest.raises(PackError):
        read_pack(write(tmp_path / "bad.json", data))


def test_pack_over_budget_is_rejected(tmp_path: Path) -> None:
    """The size budget is enforced at load time, not only by the build script."""
    path = write(tmp_path / "toy.json", PACK)

    with pytest.raises(PackError, match="budget"):
        read_pack(path, budget=path.stat().st_size - 1)


def test_lolbas_build_keys_match_runtime_lookup(tmp_path: Path) -> None:
    """Keys the build script writes are found by the lookup a rule makes at runtime."""
    upstream = [
        {
            "Name": "CertUtil.exe",
            "Commands": [
                {"Category": "Download", "MitreID": "T1105"},
                {"Category": "Encode", "MitreID": "T1027"},
                {"Category": "Download", "MitreID": "T1105"},
            ],
        }
    ]
    pack = read_pack(write(tmp_path / "lolbas.json", build(json.dumps(upstream).encode(), "x")))

    assert pack.lookup("C:\\Windows\\System32\\certutil.exe") == {
        "categories": ["Download", "Encode"],
        "mitre": ["T1027", "T1105"],
    }


def test_attack_build_links_software_to_techniques_and_skips_revoked_objects(
    tmp_path: Path,
) -> None:
    """Names and program-like aliases lead to the software id; revoked objects and prose do not."""
    bundle = {
        "objects": [
            {
                "type": "tool",
                "id": "tool--1",
                "name": "SDelete",
                "description": "SDelete wipes files. (Citation: X)\nSecond paragraph.",
                "x_mitre_aliases": ["SDelete", "Secure Delete"],
                "external_references": [{"source_name": "mitre-attack", "external_id": "S0195"}],
            },
            {
                "type": "tool",
                "id": "tool--2",
                "name": "OldTool",
                "revoked": True,
                "external_references": [{"source_name": "mitre-attack", "external_id": "S0001"}],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "name": "Data Destruction",
                "description": "Adversaries may destroy data.",
                "kill_chain_phases": [{"phase_name": "impact"}],
                "x_mitre_platforms": ["Windows"],
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1485"}],
            },
            {
                "type": "relationship",
                "relationship_type": "uses",
                "source_ref": "tool--1",
                "target_ref": "attack-pattern--1",
            },
        ]
    }
    packs = {
        pack.name: pack
        for pack in (
            read_pack(write(tmp_path / f"{index}.json", data))
            for index, data in enumerate(build_attack(json.dumps(bundle).encode(), "x"))
        )
    }

    assert packs["attack_software_names"].lookup("C:\\Users\\Public\\SDelete.exe") == {
        "id": "S0195"
    }
    assert packs["attack_software_names"].lookup("secure delete") is None
    assert packs["attack_software_names"].lookup("oldtool.exe") is None
    assert packs["attack_software"].lookup("s0195") == {
        "name": "SDelete",
        "type": "tool",
        "summary": "SDelete wipes files.",
        "techniques": ["T1485"],
    }
    assert packs["attack_techniques"].lookup("T1485")["tactics"] == ["impact"]


def test_attack_build_names_the_data_components_a_technique_is_detected_by(
    tmp_path: Path,
) -> None:
    """A technique keeps its analytics' data components by platform; one without has none."""

    def technique(index: int, attack_id: str) -> dict:
        return {
            "type": "attack-pattern",
            "id": f"attack-pattern--{index}",
            "name": attack_id,
            "external_references": [{"source_name": "mitre-attack", "external_id": attack_id}],
        }

    def component(index: int, name: str, **flags: bool) -> dict:
        return {"type": "x-mitre-data-component", "id": f"dc--{index}", "name": name, **flags}

    bundle = {
        "objects": [
            technique(1, "T1021.006"),
            technique(2, "T1595"),
            component(1, "Logon Session Creation"),
            component(2, "Process Creation"),
            component(3, "Old Component", x_mitre_deprecated=True),
            {
                "type": "x-mitre-analytic",
                "id": "analytic--1",
                "x_mitre_platforms": ["Windows"],
                "x_mitre_log_source_references": [
                    {"x_mitre_data_component_ref": "dc--1", "name": "WinEventLog:Security"},
                    {"x_mitre_data_component_ref": "dc--3", "name": "WinEventLog:Security"},
                ],
            },
            {
                "type": "x-mitre-analytic",
                "id": "analytic--2",
                "x_mitre_platforms": ["Windows"],
                "x_mitre_log_source_references": [
                    {"x_mitre_data_component_ref": "dc--2", "name": "WinEventLog:Sysmon"},
                    {"x_mitre_data_component_ref": "dc--1", "name": "WinEventLog:Security"},
                ],
            },
            {
                "type": "x-mitre-analytic",
                "id": "analytic--3",
                "x_mitre_platforms": ["Linux"],
                "x_mitre_log_source_references": [
                    {"x_mitre_data_component_ref": "dc--2", "name": "auditd:SYSCALL"},
                ],
            },
            {
                "type": "x-mitre-detection-strategy",
                "id": "strategy--1",
                "x_mitre_analytic_refs": ["analytic--1", "analytic--2", "analytic--3"],
            },
            {
                "type": "relationship",
                "relationship_type": "detects",
                "source_ref": "strategy--1",
                "target_ref": "attack-pattern--1",
            },
        ]
    }
    techniques = read_pack(
        write(tmp_path / "techniques.json", build_attack(json.dumps(bundle).encode(), "x")[0])
    )

    assert techniques.lookup("T1021.006")["data_components"] == {
        "Linux": ["Process Creation"],
        "Windows": ["Logon Session Creation", "Process Creation"],
    }
    assert "data_components" not in techniques.lookup("T1595")


def test_lolrmm_build_keys_executables_and_domains_and_drops_generic_names(tmp_path: Path) -> None:
    """Executable names and wildcard domains are keyed as the lookup normalizes them."""
    upstream = [
        {
            "Name": "AnyDesk",
            "Details": {
                "PEMetadata": [{"Filename": "anydesk.exe", "OriginalFileName": "AnyDesk.exe"}],
                "InstallationPaths": ["C:\\Program Files\\AnyDesk\\*", "svchost.exe"],
            },
            "Artifacts": {"Network": [{"Domains": ["*.anydesk.com"]}]},
        }
    ]
    programs, domains = (
        read_pack(write(tmp_path / f"{index}.json", data))
        for index, data in enumerate(build_lolrmm(json.dumps(upstream).encode(), "x"))
    )

    assert programs.lookup("C:\\Program Files\\AnyDesk\\AnyDesk.exe") == {"tool": "AnyDesk"}
    assert programs.lookup("svchost.exe") is None
    assert domains.lookup("anydesk.com") == {"tool": "AnyDesk"}


def test_wtfbins_build_keys_an_entry_by_the_first_executable_in_its_title(tmp_path: Path) -> None:
    """A program an entry only mentions does not lead to it; one without a program is searchable."""
    about = (
        '+++\nid = 7\ntitle = "IBM pcsnp.exe triggers cmd.exe"\n[taxonomies]\ntags = ["ibm"]\n+++\n'
        "Runs a shell. <!-- more -->"
    )
    plain = '+++\nid = 8\ntitle = "Windows Terminal"\n+++\nOpens consoles.'
    pack = read_pack(write(tmp_path / "w.json", build_wtfbins([about, plain], b"x", "x")))

    assert pack.lookup("pcsnp.exe")[0]["id"] == 7
    assert pack.lookup("cmd.exe") is None
    assert pack.lookup("pcsnp.exe")[0]["summary"] == "Runs a shell."
    assert [doc["id"] for doc in pack.documents] == [7, 8]


def test_gtfobins_build_keys_unix_names_and_keeps_one_example_per_function(tmp_path: Path) -> None:
    """Names are found without an extension, and function notes travel as documents."""
    upstream = {
        "functions": {
            "shell": {"label": "Shell", "description": "Spawns a shell.", "mitre": ["T1059"]}
        },
        "contexts": {},
        "executables": {
            "Find": {
                "functions": {
                    "shell": [
                        {"code": "find . -exec /bin/sh \\;", "contexts": {"sudo": None}},
                        {"code": "second", "contexts": {"suid": {"shell": True}}},
                    ]
                }
            }
        },
    }
    pack = read_pack(write(tmp_path / "g.json", build_gtfobins(json.dumps(upstream).encode(), "x")))

    assert pack.lookup("/usr/bin/find") == {
        "functions": {"shell": "find . -exec /bin/sh \\;"},
        "contexts": ["sudo", "suid"],
    }
    assert pack.lookup("find.exe") is not None
    assert pack.documents[0]["mitre"] == ["T1059"]


def test_gtfoargs_build_reads_a_section_per_program(tmp_path: Path) -> None:
    """Each program section gives its functions, an example per function and its URL."""
    text = (
        "# GTFOArgs\n\n## Function Types\n\nIntro.\n\n---\n\n"
        "## curl\n\nURL: https://gtfoargs.github.io/gtfoargs/curl/\n"
        "Functions: file-read, file-write\n\n### File read\n\nRead.\n\n```\ncurl file:///etc/passwd\n```\n"
    )
    pack = read_pack(write(tmp_path / "a.json", build_gtfoargs(text.encode(), "x")))

    assert pack.lookup("curl") == {
        "functions": ["file-read", "file-write"],
        "examples": {"file-read": "curl file:///etc/passwd"},
        "url": "https://gtfoargs.github.io/gtfoargs/curl/",
    }
    assert pack.lookup("function types") is None


AUTOSTART_YAML = """
name: WindowsPersistenceRegistryKeys
sources:
- {type: ARTIFACT_GROUP, attributes: {names: [Group]}}
---
name: Group
sources:
- {type: ARTIFACT_GROUP, attributes: {names: [RunKeys, Winlogon, ClassesShell]}}
---
name: RunKeys
doc: Run keys.
urls: ['https://example.test/run']
sources:
- type: REGISTRY_KEY
  attributes: {keys: ['HKEY_USERS\\%%users.sid%%\\Software\\Run\\*']}
---
name: Winlogon
sources:
- type: REGISTRY_VALUE
  attributes:
    key_value_pairs: [{key: 'HKEY_LOCAL_MACHINE\\Software\\Winlogon', value: 'Shell'}]
---
name: ClassesShell
sources:
- type: REGISTRY_KEY
  attributes: {keys: ['HKEY_LOCAL_MACHINE\\Software\\Classes\\*\\shell']}
---
name: Unlisted
sources:
- type: REGISTRY_KEY
  attributes: {keys: ['HKEY_LOCAL_MACHINE\\Software\\Other']}
"""


def test_autostart_build_follows_groups_and_keeps_only_matchable_keys(tmp_path: Path) -> None:
    """Artifacts outside the root group and keys with a mid-path wildcard are left out."""
    pack = read_pack(write(tmp_path / "a.json", build_autostart(AUTOSTART_YAML, "x")))

    assert pack.lookup("HKCU\\Software\\Run") == [
        {"artifact": "RunKeys", "summary": "Run keys.", "urls": ["https://example.test/run"]}
    ]
    assert pack.lookup("HKLM\\Software\\Winlogon")[0]["value"] == "Shell"
    assert pack.lookup("HKLM\\Software\\Other") is None
    assert len(pack.entries) == 2


def test_loldrivers_build_keys_drivers_by_sys_name_and_sha256_only(tmp_path: Path) -> None:
    """A product name in the tags is no file name; a hash finds its driver, a name all of them."""
    sha = "ab" * 32
    drivers = [
        {
            "Id": "id-1",
            "Category": "vulnerable driver",
            "MitreID": "T1068",
            "Tags": ["Evil.sys", "Some Product"],
            "Commands": {"Usecase": "Elevate privileges", "Description": "Exposes memory."},
            "KnownVulnerableSamples": [{"OriginalFilename": "orig.sys", "SHA256": sha.upper()}],
        },
        {"Id": "id-2", "Tags": ["evil.sys"], "Commands": [{"Usecase": "x"}]},
        {"Tags": ["no-id.sys"]},
    ]
    pack = read_pack(write(tmp_path / "d.json", build_loldrivers(drivers, b"x", "x")))

    assert [pack.documents[i]["id"] for i in pack.lookup("C:\\Temp\\EVIL.SYS")] == ["id-1", "id-2"]
    assert [pack.documents[i]["id"] for i in pack.lookup(sha)] == ["id-1"]
    assert pack.lookup("orig.sys") == [0]
    assert pack.lookup("Some Product") is None
    assert pack.lookup("no-id.sys") is None
    assert pack.documents[0]["use"] == "Elevate privileges"


def test_hijacklibs_build_keeps_the_legitimate_location_and_caps_the_executables(
    tmp_path: Path,
) -> None:
    """The executables list is shortened, with its true size kept."""
    executables = "".join(
        f"- {{Path: '%SYSTEM32%\\\\a{n}.exe', Type: Sideloading}}\n" for n in range(15)
    )
    entry = (
        "Name: Version.dll\nVendor: Microsoft\nCVE: CVE-2000-1\n"
        "ExpectedLocations:\n- '%SYSTEM32%'\nVulnerableExecutables:\n" + executables
    )
    pack = read_pack(
        write(
            tmp_path / "h.json",
            build_hijacklibs(
                {"yml/microsoft/built-in/version.yml": entry, "yml/x/bad.yml": "[]"}, "x"
            ),
        )
    )

    (found,) = pack.lookup("C:\\Users\\Public\\VERSION.dll")
    assert found["expected_locations"] == ["%SYSTEM32%"]
    assert (len(found["vulnerable_executables"]), found["vulnerable_executables_total"]) == (10, 15)
    assert found["cve"] == "CVE-2000-1"
    assert found["url"] == "https://hijacklibs.net/entries/microsoft/built-in/version.html"
    assert len(pack.entries) == 1
