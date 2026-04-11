import json
import os
from types import SimpleNamespace

import pytest

from app.services import rawsniffer_service as rs_module
from app.tests.conftest import write_test_pcap


def _service_with_dirs(tmp_path, monkeypatch):
    bruce_dir = tmp_path / "BrucePCAP"
    raw_dir = bruce_dir / "rawsniffer"
    hand_dir = tmp_path / "handshakes"
    raw_dir.mkdir(parents=True, exist_ok=True)
    hand_dir.mkdir(exist_ok=True)
    (bruce_dir / ".metadata").mkdir(exist_ok=True)
    monkeypatch.setattr(rs_module, "BRUCE_PCAP_DIR", str(bruce_dir))
    monkeypatch.setattr(rs_module, "HANDSHAKES_DIR", str(hand_dir))
    return rs_module.RawSnifferService(), raw_dir, hand_dir


def test_tshark_checks_build_and_run_branches(tmp_path, monkeypatch):
    service = rs_module.RawSnifferService()

    monkeypatch.setattr(rs_module, "load_config", lambda: {"tshark_path": "tshark"})
    monkeypatch.setattr(service, "_should_use_wsl", lambda _bin: True)
    monkeypatch.setattr(rs_module.shutil, "which", lambda name: None)
    assert service._check_tshark() is None

    monkeypatch.setattr(
        rs_module.shutil,
        "which",
        lambda name: "/usr/bin/wsl" if name == "wsl" else None,
    )
    assert service._check_tshark() == "tshark"

    abs_tshark = tmp_path / "bin" / "tshark"
    abs_tshark.parent.mkdir()
    abs_tshark.write_text("bin", encoding="utf-8")
    monkeypatch.setattr(
        rs_module, "load_config", lambda: {"tshark_path": str(abs_tshark)}
    )
    monkeypatch.setattr(service, "_should_use_wsl", lambda _bin: False)
    assert service._check_tshark() == str(abs_tshark)

    monkeypatch.setattr(
        rs_module, "load_config", lambda: {"tshark_path": str(abs_tshark) + ".missing"}
    )
    assert service._check_tshark() is None

    monkeypatch.setattr(rs_module, "load_config", lambda: {"tshark_path": "tshark"})
    monkeypatch.setattr(service, "_should_use_wsl", lambda _bin: False)
    native_cmd, native_cmd_str = service._build_command("/tmp/capture.pcap")
    assert native_cmd[0] == "tshark"
    assert "-Y" in native_cmd
    assert "tshark" in native_cmd_str

    monkeypatch.setattr(service, "_should_use_wsl", lambda _bin: True)
    monkeypatch.setattr(
        service, "_to_wsl_path", lambda _path: "/mnt/c/tmp/capture.pcap"
    )
    wsl_cmd, _ = service._build_command("/tmp/capture.pcap")
    assert wsl_cmd[0:2] == ["wsl", "tshark"]
    assert "/mnt/c/tmp/capture.pcap" in wsl_cmd

    monkeypatch.setattr(
        service,
        "_build_command",
        lambda _path: (["tshark", "-r", "x"], "tshark -r x"),
    )

    def _raise_fnf(*_args, **_kwargs):
        raise FileNotFoundError("missing")

    monkeypatch.setattr(rs_module.subprocess, "run", _raise_fnf)
    with pytest.raises(RuntimeError, match="tshark not found"):
        service._run_tshark("x.pcap")

    monkeypatch.setattr(
        rs_module.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=2, stdout="", stderr="boom"
        ),
    )
    with pytest.raises(RuntimeError, match="boom"):
        service._run_tshark("x.pcap")

    monkeypatch.setattr(
        rs_module.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=1,
            stdout="partial-output\n",
            stderr="warn-a\nwarn-b\n",
        ),
    )
    stdout, warnings = service._run_tshark("x.pcap")
    assert "partial-output" in stdout
    assert "warn-a" in warnings
    assert any("partial output" in w for w in warnings)


def test_resolve_paths_and_cache_fresh_validation(tmp_path, monkeypatch):
    service, raw_dir, _ = _service_with_dirs(tmp_path, monkeypatch)
    raw_file = raw_dir / "raw_1.pcap"
    write_test_pcap(raw_file)

    assert service._resolve_raw_file("") is None
    assert service._resolve_raw_file("HS_ABCDEF.pcap") is None
    assert service._resolve_raw_file(str(tmp_path / "outside.pcap")) is None
    assert service._resolve_raw_file(str(raw_file)) == str(raw_file)
    assert service._resolve_raw_file("raw_1.pcap") == str(raw_file)

    metadata = {
        "schema_version": service.SCHEMA_VERSION,
        "source_file": "raw_1.pcap",
        "source_size": raw_file.stat().st_size,
        "source_mtime": raw_file.stat().st_mtime,
    }
    assert service._is_cache_fresh(metadata, str(raw_file)) is True

    real_stat = rs_module.os.stat
    monkeypatch.setattr(
        rs_module.os,
        "stat",
        lambda _path: (_ for _ in ()).throw(OSError("stat-error")),
    )
    assert service._is_cache_fresh(metadata, str(raw_file)) is False

    monkeypatch.setattr(rs_module.os, "stat", real_stat)
    assert (
        service._is_cache_fresh({**metadata, "schema_version": 999}, str(raw_file))
        is False
    )
    assert (
        service._is_cache_fresh(
            {**metadata, "source_file": "other.pcap"}, str(raw_file)
        )
        is False
    )


def test_generated_hash_parse_and_cache_cleanup_edge_paths(tmp_path, monkeypatch):
    service, raw_dir, hand_dir = _service_with_dirs(tmp_path, monkeypatch)

    missing = service._parse_generated_hash_file(str(hand_dir / "missing.22000"))
    assert missing["size"] == 0
    assert missing["modified"] == 0.0
    assert missing["valid_hash_lines"] == 0
    assert missing["has_context"] is False

    hash_file = hand_dir / "raw_demo.22000"
    hash_file.write_text("\ninvalid\n", encoding="utf-8")
    real_open = open

    def _boom_open(path, *args, **kwargs):
        if str(path) == str(hash_file):
            raise OSError("read failed")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", _boom_open)
    parsed = service._parse_generated_hash_file(str(hash_file))
    assert parsed["valid_hash_lines"] == 0
    assert parsed["bssid_count"] == 0

    metadata_file = raw_dir.parent / ".metadata" / "stale.json"
    metadata_file.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        rs_module.os,
        "remove",
        lambda _path: (_ for _ in ()).throw(OSError("cannot delete")),
    )
    clear_result = service.clear_metadata_cache(remove_files=True)
    assert clear_result["deleted_count"] == 0
    assert clear_result["failed_count"] == 1


def test_metadata_signature_and_aggregate_builder_skip_invalid_entries(
    tmp_path, monkeypatch
):
    service, raw_dir, _ = _service_with_dirs(tmp_path, monkeypatch)
    metadata_path = (
        raw_dir.parent / ".metadata" / "brucegotchi__rawsniffer__raw_1.pcap.json"
    )
    metadata_path.write_text(
        json.dumps(
            {
                "source_file": "raw_1.pcap",
                "processed_at": 123,
                "warnings": ["", None, "warn-a"],
                "networks": [
                    1,
                    {
                        "bssid": "AA:BB:CC:DD:EE:FF",
                        "beacon_count": "2",
                        "eapol_count": "1",
                        "probe_client_count": "4",
                        "last_seen_offset_s": "6.75",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    real_stat = rs_module.os.stat

    def _stat_with_error(path):
        if str(path).endswith("raw_1.pcap.json"):
            raise OSError("skip-signature-entry")
        return real_stat(path)

    monkeypatch.setattr(rs_module.os, "stat", _stat_with_error)
    signature = service._metadata_index_signature()
    assert signature == (service.SCHEMA_VERSION,)

    monkeypatch.setattr(rs_module.os, "stat", real_stat)
    index = service._build_aggregate_index()
    assert "AA:BB:CC:DD:EE:FF" in index
    entry = index["AA:BB:CC:DD:EE:FF"][0]
    assert entry["processed_at"] is None
    assert entry["beacon_count"] == 2
    assert entry["eapol_count"] == 1
    assert entry["probe_client_count"] == 4
    assert entry["last_seen_offset_s"] == 6.75
    assert entry["warnings"] == ["None", "warn-a"]


def test_raw_context_sanitizes_invalid_shapes(monkeypatch, tmp_path):
    service, _, _ = _service_with_dirs(tmp_path, monkeypatch)

    monkeypatch.setattr(
        service,
        "get_aggregated_metadata_for_bssid",
        lambda _bssid: {"present": False},
    )
    monkeypatch.setattr(service, "get_generated_hashes_for_bssid", lambda _bssid: "bad")
    assert service.get_raw_context_for_bssid("AA:BB:CC:DD:EE:FF") == {"present": False}

    monkeypatch.setattr(
        service,
        "get_aggregated_metadata_for_bssid",
        lambda _bssid: {
            "present": True,
            "bssid": "AA:BB:CC:DD:EE:FF",
            "aggregate": {},
            "files": [1, {"source_file": ""}],
        },
    )
    monkeypatch.setattr(
        service,
        "get_generated_hashes_for_bssid",
        lambda _bssid: [
            1,
            {"filename": ""},
            {
                "filename": "raw_1.22000",
                "valid_hash_lines": "3",
                "matched_lines": "2",
                "source_raw_file": "",
                "matched_ssid": "",
                "primary_ssid": "ssid",
                "modified": None,
                "size": "4",
            },
        ],
    )
    context = service.get_raw_context_for_bssid("AA:BB:CC:DD:EE:FF")
    assert context["present"] is True
    assert context["files_count"] == 0
    assert context["hash_files_count"] == 1
    assert context["hash_files"][0]["filename"] == "raw_1.22000"


def test_signature_helpers_subset_and_up_to_date_matrix(tmp_path, monkeypatch):
    service, raw_dir, hand_dir = _service_with_dirs(tmp_path, monkeypatch)

    assert service._canonical_hash_path("AA:BB:CC:DD:EE:FF").endswith("__wdrs__.22000")

    bad_json = hand_dir / "bad.json"
    bad_json.write_text("{", encoding="utf-8")
    assert service._safe_read_json(str(bad_json)) is None

    assert service._signature_for_source_file("missing.pcap") is None
    raw_file = raw_dir / "raw_ok.pcap"
    write_test_pcap(raw_file)
    real_stat = rs_module.os.stat
    monkeypatch.setattr(
        rs_module.os,
        "stat",
        lambda _path: (_ for _ in ()).throw(OSError("stat-fail")),
    )
    assert service._signature_for_source_file("raw_ok.pcap") is None
    monkeypatch.setattr(rs_module.os, "stat", real_stat)

    assert service._signature_for_hash_file("") is None
    assert service._signature_for_hash_file("missing.22000") is None
    hash_file = hand_dir / "raw_demo.22000"
    hash_file.write_text("demo", encoding="utf-8")
    monkeypatch.setattr(
        rs_module.os,
        "stat",
        lambda _path: (_ for _ in ()).throw(OSError("hash-stat-fail")),
    )
    assert service._signature_for_hash_file("raw_demo.22000") is None
    monkeypatch.setattr(rs_module.os, "stat", real_stat)

    assert service._build_signature_map(["", "missing.pcap"]) == {}
    monkeypatch.setattr(service, "_signature_for_hash_file", lambda _name: None)
    assert (
        service._build_signature_map_for_sources(
            ["", "raw_demo.22000"], hash_sources={"raw_demo.22000"}
        )
        == {}
    )

    selected_default, missing_default = service._normalize_source_subset(
        None, [{"source_file": "/tmp/a.pcap"}, {"source_file": "b.pcap"}]
    )
    assert selected_default == ["a.pcap", "b.pcap"]
    assert missing_default == []

    selected_filtered, missing_filtered = service._normalize_source_subset(
        ["A.PCAP", "missing.pcap", "a.pcap", ""],
        [{"source_file": "a.pcap"}],
    )
    assert selected_filtered == ["a.pcap"]
    assert missing_filtered == ["missing.pcap"]

    assert service._signature_matches("bad", {}) is False

    canonical = hand_dir / "canonical.22000"
    canonical.write_text("line\n", encoding="utf-8")
    signature_map = {"a": {"size": 1, "mtime": 1.0}}
    assert (
        service._is_canonical_up_to_date({}, signature_map, str(canonical), True)
        is False
    )
    assert (
        service._is_canonical_up_to_date(
            {"full_signature": {}}, {}, str(canonical), True
        )
        is False
    )
    assert (
        service._is_canonical_up_to_date(
            {"full_signature": {}}, signature_map, str(hand_dir / "none"), True
        )
        is False
    )

    empty_file = hand_dir / "empty.22000"
    empty_file.write_text("", encoding="utf-8")
    assert (
        service._is_canonical_up_to_date(
            {"full_signature": signature_map}, signature_map, str(empty_file), True
        )
        is False
    )

    assert (
        service._is_canonical_up_to_date(
            {"full_signature": []}, signature_map, str(canonical), True
        )
        is False
    )
    assert (
        service._is_canonical_up_to_date(
            {"full_signature": {"b": signature_map["a"]}},
            signature_map,
            str(canonical),
            True,
        )
        is False
    )
    assert (
        service._is_canonical_up_to_date(
            {"full_signature": {"a": {"size": 99, "mtime": 1.0}}},
            signature_map,
            str(canonical),
            True,
        )
        is False
    )
    assert (
        service._is_canonical_up_to_date(
            {"per_source_signature": []}, signature_map, str(canonical), False
        )
        is False
    )
    assert (
        service._is_canonical_up_to_date(
            {"per_source_signature": {"a": {"size": 99, "mtime": 1.0}}},
            signature_map,
            str(canonical),
            False,
        )
        is False
    )
    assert (
        service._is_canonical_up_to_date(
            {"per_source_signature": signature_map},
            signature_map,
            str(canonical),
            False,
        )
        is True
    )


def test_hash_extraction_helpers_and_atomic_writes(tmp_path, monkeypatch):
    service, _, hand_dir = _service_with_dirs(tmp_path, monkeypatch)

    monkeypatch.setattr(service, "_should_use_wsl", lambda _bin: True)
    monkeypatch.setattr(
        service, "_to_wsl_path", lambda path: f"/mnt/{os.path.basename(path)}"
    )
    focused_cmd = service._build_focused_extract_command(
        "tshark",
        "/tmp/source.pcap",
        "/tmp/out.pcap",
        "AA:BB:CC:DD:EE:FF",
    )
    assert focused_cmd[0:2] == ["wsl", "tshark"]

    assert service._parse_hash_line("") == (False, None)
    assert service._parse_hash_line("INVALID*LINE") == (False, None)

    hash_file = hand_dir / "raw_1.22000"
    hash_file.write_text(
        "\n".join(
            [
                "",
                "WPA*02*1111*aabbccddeeff*001122334455*74657374",
                "WPA*02*1111*001122334455*001122334455*74657374",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    lines = service._extract_hash_lines_for_bssid(str(hash_file), "AA:BB:CC:DD:EE:FF")
    assert len(lines) == 1
    assert "aabbccddeeff" in lines[0].lower()

    real_open = open

    def _raise_open(path, *args, **kwargs):
        if str(path) == str(hash_file):
            raise OSError("read-fail")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr("builtins.open", _raise_open)
    assert (
        service._extract_hash_lines_for_bssid(str(hash_file), "AA:BB:CC:DD:EE:FF") == []
    )

    out_file = hand_dir / "empty-out.22000"
    service._write_canonical_hash_atomic(str(out_file), [])
    assert out_file.read_text(encoding="utf-8") == ""


def test_prepare_canonical_reports_errors_and_progress(tmp_path, monkeypatch):
    service, raw_dir, hand_dir = _service_with_dirs(tmp_path, monkeypatch)

    invalid = service.prepare_canonical_hash_for_bssid("bad-mac")
    assert invalid["status"] == "error"
    assert invalid["code"] == "invalid_bssid"

    monkeypatch.setattr(
        service, "get_raw_context_for_bssid", lambda _bssid: {"present": False}
    )
    missing_ctx = service.prepare_canonical_hash_for_bssid("AA:BB:CC:DD:EE:FF")
    assert missing_ctx["code"] == "raw_context_missing"

    monkeypatch.setattr(
        service,
        "get_raw_context_for_bssid",
        lambda _bssid: {"present": True, "files": "bad", "hash_files": "bad"},
    )
    empty_ctx = service.prepare_canonical_hash_for_bssid("AA:BB:CC:DD:EE:FF")
    assert empty_ctx["code"] == "raw_context_empty"

    monkeypatch.setattr(
        service,
        "get_raw_context_for_bssid",
        lambda _bssid: {
            "present": True,
            "files": [],
            "hash_files": [{"filename": "raw_ctx.22000"}],
        },
    )
    out_of_context = service.prepare_canonical_hash_for_bssid(
        "AA:BB:CC:DD:EE:FF",
        source_files=["outside.22000"],
    )
    assert out_of_context["code"] == "source_not_in_context"

    progress_events = []
    hash_missing = service.prepare_canonical_hash_for_bssid(
        "AA:BB:CC:DD:EE:FF",
        source_files=["raw_ctx.22000", "raw_ctx.22000"],
        progress_callback=progress_events.append,
    )
    assert hash_missing["status"] == "error"
    assert hash_missing["code"] == "no_hash_lines"
    assert progress_events and progress_events[0]["status"] == "error"
    assert progress_events[0]["reason"] == "raw_hash_missing"

    monkeypatch.setattr(
        service,
        "get_raw_context_for_bssid",
        lambda _bssid: {
            "present": True,
            "files": [{"source_file": "raw_fail.pcap", "ssid": ""}],
            "hash_files": [],
        },
    )
    pcap_missing = service.prepare_canonical_hash_for_bssid("AA:BB:CC:DD:EE:FF")
    assert pcap_missing["status"] == "error"
    assert pcap_missing["items"][0]["reason"] == "raw_source_missing"

    raw_file = raw_dir / "raw_fail.pcap"
    write_test_pcap(raw_file)
    monkeypatch.setattr(
        service,
        "extract_metadata",
        lambda *_args, **_kwargs: {"status": "error", "message": "metadata exploded"},
    )
    metadata_fail = service.prepare_canonical_hash_for_bssid("AA:BB:CC:DD:EE:FF")
    assert metadata_fail["status"] == "error"
    assert "metadata exploded" in metadata_fail["items"][0]["reason"]

    monkeypatch.setattr(
        service,
        "extract_metadata",
        lambda *_args, **_kwargs: {"status": "success"},
    )
    monkeypatch.setattr(service, "_check_tshark", lambda: None)
    tshark_missing = service.prepare_canonical_hash_for_bssid("AA:BB:CC:DD:EE:FF")
    assert tshark_missing["status"] == "error"
    assert tshark_missing["items"][0]["reason"] == "tshark_missing"

    canonical = hand_dir / service._canonical_hash_filename("AA:BB:CC:DD:EE:FF", "")
    canonical.write_text(
        "WPA*02*1111*aabbccddeeff*001122334455*74657374\n", encoding="utf-8"
    )
    monkeypatch.setattr(
        service,
        "get_raw_context_for_bssid",
        lambda _bssid: {
            "present": True,
            "files": [{"source_file": "raw_fail.pcap", "ssid": ""}],
            "hash_files": [],
        },
    )
    monkeypatch.setattr(
        service,
        "_extract_hash_lines_for_bssid",
        lambda path, _bssid: (
            ["WPA*02*1111*aabbccddeeff*001122334455*74657374"]
            if str(path).endswith("__wdrs__.22000")
            else []
        ),
    )
    final_error = service.prepare_canonical_hash_for_bssid(
        "AA:BB:CC:DD:EE:FF",
        source_files=["raw_fail.pcap"],
    )
    assert final_error["status"] == "error"
    assert "failed to update" in final_error["message"].lower()


def test_extract_metadata_handles_corrupt_cached_json(tmp_path, monkeypatch):
    service, raw_dir, _ = _service_with_dirs(tmp_path, monkeypatch)
    raw_file = raw_dir / "raw_1.pcap"
    write_test_pcap(raw_file)
    metadata_path = (
        raw_dir.parent / ".metadata" / "brucegotchi__rawsniffer__raw_1.pcap.json"
    )
    metadata_path.write_text("{invalid-json", encoding="utf-8")

    monkeypatch.setattr(service, "_check_tshark", lambda: "tshark")
    monkeypatch.setattr(service, "_run_tshark", lambda _path: ("", []))

    result = service.extract_metadata("raw_1.pcap")
    assert result["status"] == "success"
    assert result["cached"] is False
