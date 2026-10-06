import json
import sys
from pathlib import Path

import pytest

from sibyl_h0und.knowledge import PackError, load_pack, pack_names, read_pack

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
from build_lolbas_pack import build  # noqa: E402

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
