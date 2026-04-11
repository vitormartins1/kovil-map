import json
import os
from pathlib import Path
from types import SimpleNamespace

from app.services import rawsniffer_service as rs_module
from app.tests.conftest import write_test_pcap


def _service_with_paths(tmp_path, monkeypatch):
    bruce_dir = tmp_path / "BrucePCAP"
    raw_dir = bruce_dir / "rawsniffer"
    hand_dir = tmp_path / "handshakes"
    raw_dir.mkdir(parents=True)
    hand_dir.mkdir()
    monkeypatch.setattr(rs_module, "BRUCE_PCAP_DIR", str(bruce_dir))
    monkeypatch.setattr(rs_module, "HANDSHAKES_DIR", str(hand_dir))
    service = rs_module.RawSnifferService()
    return service, raw_dir, hand_dir


def _write_output_and_success(cmd, **_kwargs):
    output_path = Path(cmd[cmd.index("-w") + 1])
    output_path.write_bytes(b"focused-pcap")
    return SimpleNamespace(returncode=0, stdout="", stderr="")


def _hash_line(mac_no_colon: str, suffix: str) -> str:
    return f"WPA*02*11223344*{mac_no_colon}*AABBCCDDEEFF*{suffix}"


def test_prepare_canonical_hash_success_merges_and_dedupes(tmp_path, monkeypatch):
    service, raw_dir, hand_dir = _service_with_paths(tmp_path, monkeypatch)
    write_test_pcap(raw_dir / "raw_1.pcap")
    write_test_pcap(raw_dir / "raw_2.pcap")

    monkeypatch.setattr(
        service,
        "get_raw_context_for_bssid",
        lambda _bssid: {
            "present": True,
            "files": [
                {"source_file": "raw_1.pcap", "ssid": "Rio Centro"},
                {"source_file": "raw_2.pcap", "ssid": "Rio Centro"},
            ],
        },
    )
    monkeypatch.setattr(
        service,
        "extract_metadata",
        lambda _filename, force=False: {"status": "success", "cached": True},
    )
    monkeypatch.setattr(service, "_check_tshark", lambda: "tshark")
    monkeypatch.setattr(rs_module.subprocess, "run", _write_output_and_success)

    mac_clean = "aabbccddeeff"
    calls = {"idx": 0}

    def _fake_convert(_pcap_filename, output_filename=None):
        calls["idx"] += 1
        if calls["idx"] == 1:
            lines = [
                _hash_line(mac_clean, "746573745f31"),
                _hash_line(mac_clean, "746573745f64"),
            ]
        else:
            lines = [
                _hash_line(mac_clean, "746573745f64"),
                _hash_line(mac_clean, "746573745f32"),
            ]
        Path(output_filename).write_text("\n".join(lines) + "\n", encoding="utf-8")
        return {"status": "success", "output_file": os.path.basename(output_filename)}

    result = service.prepare_canonical_hash_for_bssid(
        "aa:bb:cc:dd:ee:ff",
        convert_func=_fake_convert,
    )

    assert result["status"] == "success"
    assert result["processed"] == 2
    assert result["succeeded"] == 2
    assert result["failed"] == 0
    assert result["canonical_hash"].endswith("__wdrs__.22000")

    canonical_path = hand_dir / result["canonical_hash"]
    assert canonical_path.exists()
    canonical_lines = [
        line.strip()
        for line in canonical_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(canonical_lines) == 3
    assert all("AABBCCDDEEFF".lower() in line.lower() for line in canonical_lines)
    assert result["artifacts"]["pcap_file"] is None
    assert result["artifacts"]["hash_file"] == result["canonical_hash"]

    names = sorted(path.name for path in hand_dir.iterdir())
    assert result["canonical_hash"] in names
    assert f"{result['canonical_hash']}.wdrs.json" in names
    assert not any("__wdrs__raw_" in name for name in names)
    assert not any(name.endswith(".pcap") for name in names)


def test_prepare_canonical_hash_up_to_date_uses_sidecar(tmp_path, monkeypatch):
    service, raw_dir, hand_dir = _service_with_paths(tmp_path, monkeypatch)
    source_file = raw_dir / "raw_city_center.pcap"
    write_test_pcap(source_file)

    monkeypatch.setattr(
        service,
        "get_raw_context_for_bssid",
        lambda _bssid: {
            "present": True,
            "files": [{"source_file": "raw_city_center.pcap", "ssid": ""}],
        },
    )
    monkeypatch.setattr(service, "_check_tshark", lambda: "tshark")

    canonical_name = service._canonical_hash_filename("AA:BB:CC:DD:EE:FF", "")
    canonical_path = hand_dir / canonical_name
    canonical_path.write_text(_hash_line("aabbccddeeff", "74657374"), encoding="utf-8")

    signature_map = service._build_signature_map(["raw_city_center.pcap"])
    sidecar = {
        "schema_version": 2,
        "bssid": "AA:BB:CC:DD:EE:FF",
        "canonical_hash": canonical_name,
        "full_signature": signature_map,
        "per_source_signature": signature_map,
    }
    sidecar_path = hand_dir / f"{canonical_name}.wdrs.json"
    sidecar_path.write_text(json.dumps(sidecar), encoding="utf-8")

    monkeypatch.setattr(
        rs_module.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("must not run")),
    )

    result = service.prepare_canonical_hash_for_bssid(
        "aa:bb:cc:dd:ee:ff",
        convert_func=lambda *_args, **_kwargs: {
            "status": "error",
            "message": "must not run",
        },
    )
    assert result["status"] == "up_to_date"
    assert result["canonical_hash"] == canonical_name
    assert result["processed"] == 0


def test_prepare_canonical_hash_returns_partial_on_mixed_results(tmp_path, monkeypatch):
    service, raw_dir, hand_dir = _service_with_paths(tmp_path, monkeypatch)
    write_test_pcap(raw_dir / "raw_1.pcap")
    write_test_pcap(raw_dir / "raw_2.pcap")

    monkeypatch.setattr(
        service,
        "get_raw_context_for_bssid",
        lambda _bssid: {
            "present": True,
            "files": [
                {"source_file": "raw_1.pcap", "ssid": "Hidden"},
                {"source_file": "raw_2.pcap", "ssid": "Hidden"},
            ],
        },
    )
    monkeypatch.setattr(
        service,
        "extract_metadata",
        lambda _filename, force=False: {"status": "success", "cached": False},
    )
    monkeypatch.setattr(service, "_check_tshark", lambda: "tshark")
    monkeypatch.setattr(rs_module.subprocess, "run", _write_output_and_success)

    calls = {"idx": 0}

    def _fake_convert(_pcap_filename, output_filename=None):
        calls["idx"] += 1
        if calls["idx"] == 1:
            Path(output_filename).write_text(
                _hash_line("aabbccddeeff", "74657374"),
                encoding="utf-8",
            )
            return {
                "status": "success",
                "output_file": os.path.basename(output_filename),
            }
        return {"status": "error", "message": "hcx failed"}

    result = service.prepare_canonical_hash_for_bssid(
        "aa:bb:cc:dd:ee:ff",
        convert_func=_fake_convert,
    )

    assert result["status"] == "success_partial"
    assert result["processed"] == 2
    assert result["succeeded"] == 1
    assert result["failed"] == 1
    assert (hand_dir / result["canonical_hash"]).exists()


def test_prepare_canonical_hash_rejects_source_outside_context(tmp_path, monkeypatch):
    service, raw_dir, _ = _service_with_paths(tmp_path, monkeypatch)
    write_test_pcap(raw_dir / "raw_city_center.pcap")

    monkeypatch.setattr(
        service,
        "get_raw_context_for_bssid",
        lambda _bssid: {
            "present": True,
            "files": [{"source_file": "raw_other.pcap", "ssid": "Other"}],
        },
    )

    result = service.prepare_canonical_hash_for_bssid(
        "aa:bb:cc:dd:ee:ff",
        source_files=["raw_city_center.pcap"],
    )
    assert result["status"] == "error"
    assert result["code"] == "source_not_in_context"


def test_prepare_focused_capture_wrapper_uses_subset_pipeline(tmp_path, monkeypatch):
    service, raw_dir, _ = _service_with_paths(tmp_path, monkeypatch)
    write_test_pcap(raw_dir / "raw_city_center.pcap")

    monkeypatch.setattr(
        service,
        "get_raw_context_for_bssid",
        lambda _bssid: {
            "present": True,
            "files": [
                {"source_file": "/legacy/path/raw_city_center.pcap", "ssid": "Rio"},
                {"source_file": "raw_other.pcap", "ssid": "Rio"},
            ],
        },
    )
    monkeypatch.setattr(
        service,
        "extract_metadata",
        lambda _filename, force=False: {"status": "success", "cached": True},
    )
    monkeypatch.setattr(service, "_check_tshark", lambda: "tshark")
    monkeypatch.setattr(rs_module.subprocess, "run", _write_output_and_success)

    def _fake_convert(_pcap_filename, output_filename=None):
        Path(output_filename).write_text(
            _hash_line("aabbccddeeff", "74657374"),
            encoding="utf-8",
        )
        return {"status": "success", "output_file": os.path.basename(output_filename)}

    result = service.prepare_focused_capture_for_bssid(
        "aa:bb:cc:dd:ee:ff",
        "../raw_city_center.pcap",
        convert_func=_fake_convert,
    )

    assert result["status"] == "success"
    assert result["processed"] == 1
    assert result["succeeded"] == 1


def test_prepare_canonical_hash_accepts_hash_item_source(tmp_path, monkeypatch):
    service, raw_dir, hand_dir = _service_with_paths(tmp_path, monkeypatch)
    write_test_pcap(raw_dir / "raw_city_center.pcap")
    (hand_dir / "raw_12.22000").write_text(
        "\n".join(
            [
                _hash_line("aabbccddeeff", "746573745f31"),
                _hash_line("112233445566", "746573745f32"),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        service,
        "get_raw_context_for_bssid",
        lambda _bssid: {
            "present": True,
            "files": [{"source_file": "raw_city_center.pcap", "ssid": "Rio Centro"}],
            "hash_files": [
                {
                    "filename": "raw_12.22000",
                    "valid_hash_lines": 2,
                    "source_raw_file": "raw_city_center.pcap",
                }
            ],
        },
    )
    monkeypatch.setattr(
        rs_module.subprocess,
        "run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("must not run tshark for hash source")
        ),
    )
    monkeypatch.setattr(
        service,
        "_check_tshark",
        lambda: (_ for _ in ()).throw(
            AssertionError("must not check tshark for hash source")
        ),
    )

    result = service.prepare_canonical_hash_for_bssid(
        "aa:bb:cc:dd:ee:ff",
        source_files=["raw_12.22000"],
    )

    assert result["status"] == "success"
    assert result["processed"] == 1
    assert result["succeeded"] == 1
    assert result["failed"] == 0
    assert result["canonical_hash"].endswith("__wdrs__.22000")
    canonical_lines = [
        line.strip()
        for line in (hand_dir / result["canonical_hash"])
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    assert len(canonical_lines) == 1
    assert "AABBCCDDEEFF".lower() in canonical_lines[0].lower()


def test_prepare_canonical_hash_full_refresh_hash_first_then_fallback_to_pcap(
    tmp_path, monkeypatch
):
    service, raw_dir, hand_dir = _service_with_paths(tmp_path, monkeypatch)
    write_test_pcap(raw_dir / "raw_city_center.pcap")
    (hand_dir / "raw_12.22000").write_text(
        _hash_line("112233445566", "74657374") + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        service,
        "get_raw_context_for_bssid",
        lambda _bssid: {
            "present": True,
            "files": [{"source_file": "raw_city_center.pcap", "ssid": "Rio Centro"}],
            "hash_files": [
                {
                    "filename": "raw_12.22000",
                    "valid_hash_lines": 1,
                    "source_raw_file": "raw_city_center.pcap",
                }
            ],
        },
    )
    monkeypatch.setattr(
        service,
        "extract_metadata",
        lambda _filename, force=False: {"status": "success", "cached": True},
    )
    monkeypatch.setattr(service, "_check_tshark", lambda: "tshark")
    monkeypatch.setattr(rs_module.subprocess, "run", _write_output_and_success)

    def _fake_convert(_pcap_filename, output_filename=None):
        Path(output_filename).write_text(
            _hash_line("aabbccddeeff", "74657374"),
            encoding="utf-8",
        )
        return {"status": "success", "output_file": os.path.basename(output_filename)}

    result = service.prepare_canonical_hash_for_bssid(
        "aa:bb:cc:dd:ee:ff",
        convert_func=_fake_convert,
    )

    assert result["status"] == "success_partial"
    assert result["processed"] == 2
    assert result["succeeded"] == 1
    assert result["failed"] == 1
    assert (hand_dir / result["canonical_hash"]).exists()


def test_prepare_canonical_hash_uses_matched_ssid_not_primary_from_mixed_hash(
    tmp_path, monkeypatch
):
    service, _raw_dir, hand_dir = _service_with_paths(tmp_path, monkeypatch)
    mixed_hash = hand_dir / "raw_15.22000"
    mixed_hash.write_text(
        "\n".join(
            [
                _hash_line("cc6cccaabbdd", "436173615f363247"),  # Casa_62G (dominant)
                _hash_line("cc6cccaabbdd", "436173615f363247"),
                _hash_line("38a6591b2e80", "456c6f6e204d75736b"),  # Elon Musk (target)
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    context = service.get_raw_context_for_bssid("38:A6:59:1B:2E:80")
    assert context["present"] is True
    assert context["hash_files_count"] == 1
    assert context["hash_files"][0]["filename"] == "raw_15.22000"
    assert context["hash_files"][0]["matched_ssid"] == "Elon Musk"
    assert context["hash_files"][0]["primary_ssid"] == "Casa_62G"

    result = service.prepare_canonical_hash_for_bssid(
        "38:A6:59:1B:2E:80",
        source_files=["raw_15.22000"],
    )

    assert result["status"] == "success"
    assert result["canonical_hash"].startswith("elon-musk_38a6591b2e80__wdrs__")
    canonical_lines = [
        line.strip()
        for line in (hand_dir / result["canonical_hash"])
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    assert len(canonical_lines) == 1
    assert "38a6591b2e80" in canonical_lines[0].lower()
    assert "cc6cccaabbdd" not in canonical_lines[0].lower()
