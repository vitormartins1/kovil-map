import json

from app.services import history_service as hs_module


def test_history_add_update_clear(tmp_path, monkeypatch):
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))

    service = hs_module.HistoryService()
    entry_id = service.add_entry("test.pcap", "hashcat", ["hashcat", "-h"])
    assert entry_id is not None

    history_path = tmp_path / "test.try"
    assert history_path.exists()

    service.update_entry("test.pcap", entry_id, "RUNNING")
    service.update_entry("test.pcap", entry_id, "DONE", result="ok")

    data = json.loads(history_path.read_text())
    assert data["entries"][0]["status"] == "DONE"

    count = service.clear_all_history()
    assert count == 1
    assert not history_path.exists()


def test_get_history_path_for_known_extensions(tmp_path, monkeypatch):
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    service = hs_module.HistoryService()
    assert service.get_history_path("a.pcap").endswith("a.try")
    assert service.get_history_path("a.22000").endswith("a.try")
    assert service.get_history_path("a.cracked").endswith("a.try")


def test_get_history_path_with_capture_id(tmp_path, monkeypatch):
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))

    def mock_get_capture(capture_id, *args, **kwargs):
        if capture_id == "cap1":
            return f"/captures/{capture_id}/test.try"
        return None

    monkeypatch.setattr(hs_module, "get_capture_source_artifact_path", mock_get_capture)

    service = hs_module.HistoryService()
    path = service.get_history_path("test.pcap", capture_id="cap1")
    assert path == "/captures/cap1/test.try"


def test_get_history_path_with_combined_build_id(tmp_path, monkeypatch):
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))

    # Mock get_combined_artifact_path to return a specific path
    def mock_get_combined(mac, combined_build_id, *args, **kwargs):
        if combined_build_id == "build1":
            return f"/combined/{mac}/{combined_build_id}/history.try"
        return None

    monkeypatch.setattr(hs_module, "get_combined_artifact_path", mock_get_combined)

    service = hs_module.HistoryService()
    path = service.get_history_path(
        "test.pcap", combined_build_id="build1", mac="AA:BB:CC:DD:EE:FF"
    )
    assert path == "/combined/AA:BB:CC:DD:EE:FF/build1/history.try"


def test_get_history_path_with_combined_build_id_without_mac_falls_back(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))

    def mock_get_combined(mac, combined_build_id, *args, **kwargs):
        raise AssertionError("combined artifact lookup should not run without a mac")

    monkeypatch.setattr(hs_module, "get_combined_artifact_path", mock_get_combined)

    service = hs_module.HistoryService()
    path = service.get_history_path("combined.22000", combined_build_id="build1")
    assert path == str(tmp_path / "combined.try")


def test_add_entry_filters_params_and_corrupt_history(tmp_path, monkeypatch):
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    history_path = tmp_path / "x.try"
    history_path.write_text("{", encoding="utf-8")
    service = hs_module.HistoryService()

    entry_id = service.add_entry(
        "x.pcap",
        "hashcat",
        ["hashcat", "-a", "0"],
        params={
            "wordlist": "/tmp/wordlists/top.txt",
            "empty": "",
            "none_value": None,
            "disabled": False,
            "mask": "?d?d",
        },
    )
    assert entry_id
    data = json.loads(history_path.read_text(encoding="utf-8"))
    params = data["entries"][-1]["params"]
    assert params["wordlist"] == "top.txt"
    assert "empty" not in params
    assert "none_value" not in params
    assert "disabled" not in params
    assert params["mask"] == "?d?d"


def test_format_duration_variants():
    service = hs_module.HistoryService()
    assert service._format_duration(12.4) == "12s"
    assert service._format_duration(65) == "1m 5s"
    assert service._format_duration(3665) == "1h 1m 5s"


def test_update_entry_with_missing_file(tmp_path, monkeypatch):
    """Test update_entry handles missing files gracefully."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    service = hs_module.HistoryService()

    # This should return silently when file doesn't exist
    service.update_entry("missing.pcap", "id123", "DONE")
    # No exception should be raised - should just log warning


def test_update_entry_incomplete_meta_and_invalid_dates(tmp_path, monkeypatch):
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    service = hs_module.HistoryService()
    entry1 = service.add_entry("z.pcap", "hashcat", "cmd1")
    entry2 = service.add_entry("z.pcap", "hashcat", "cmd2")
    path = tmp_path / "z.try"

    service.update_entry("z.pcap", entry1, "RUNNING")
    service.update_entry("z.pcap", entry2, "RUNNING", meta={"k": "v"})
    service.update_entry("z.pcap", entry2, "DONE", meta=["m1", "m2"], result="ok")
    service.update_entry("z.pcap", entry2, "DONE2", meta="single")

    data = json.loads(path.read_text(encoding="utf-8"))
    first, second = data["entries"][0], data["entries"][1]
    assert first["status"] == "INCOMPLETE"
    assert "Auto-marked as INCOMPLETE" in first["meta"][0]
    assert second["result"] == "ok"
    assert "single" in second["meta"]
    assert "{'k': 'v'}" in second["meta"]

    second["start_time"] = "not-a-date"
    second["end_time"] = "also-bad"
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    service.update_entry("z.pcap", entry2, "DONE3")
    reloaded = json.loads(path.read_text(encoding="utf-8"))
    assert reloaded["entries"][1]["status"] == "DONE3"


def test_update_entry_and_clear_history_edge_cases(tmp_path, monkeypatch):
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    service = hs_module.HistoryService()
    service.update_entry("missing.pcap", "x", "RUNNING")

    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path / "none"))
    assert service.clear_all_history() == 0

    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    bad = tmp_path / "bad.try"
    bad.write_text("x", encoding="utf-8")

    original_remove = hs_module.os.remove

    def _fail_remove(path):
        if path.endswith("bad.try"):
            raise OSError("boom")
        return original_remove(path)

    monkeypatch.setattr(hs_module.os, "remove", _fail_remove)
    assert service.clear_all_history() == 0


def test_add_entry_handles_io_error(tmp_path, monkeypatch):
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    service = hs_module.HistoryService()

    import builtins

    original_open = builtins.open

    def fail_open(file, mode="r", *args, **kwargs):
        if "w" in mode:
            raise IOError("disk full")
        return original_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", fail_open)
    result = service.add_entry("test.pcap", "hashcat", ["hashcat", "-h"])
    assert result is None


def test_update_entry_handles_invalid_json(tmp_path, monkeypatch):
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    history_path = tmp_path / "broken.try"
    history_path.write_text("{ invalid json", encoding="utf-8")

    service = hs_module.HistoryService()
    service.update_entry("broken.pcap", "id", "DONE")
    # No exception should be raised when JSON is corrupted


def test_update_entry_not_found_logs_warning(tmp_path, monkeypatch):
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    service = hs_module.HistoryService()
    valid_path = tmp_path / "valid.try"
    valid_path.write_text(json.dumps({"entries": []}), encoding="utf-8")

    service.update_entry("valid.pcap", "missing", "DONE")
    # Should not raise and should handle missing entry gracefully


def test_update_entry_write_failure_logs_error(tmp_path, monkeypatch):
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    history_path = tmp_path / "write.try"
    history_path.write_text(
        json.dumps({"entries": [{"id": "entry1", "status": "RUNNING"}]}),
        encoding="utf-8",
    )

    service = hs_module.HistoryService()

    original_json_dump = json.dump

    def fail_json_dump(obj, fp, *args, **kwargs):
        raise IOError("disk full")

    monkeypatch.setattr("json.dump", fail_json_dump)
    service.update_entry("write.pcap", "entry1", "DONE")
    # No exception should bubble up
    monkeypatch.setattr("json.dump", original_json_dump)
