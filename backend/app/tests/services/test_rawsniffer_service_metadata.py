import json
from pathlib import Path


from app.services.rawsniffer_service import RawSnifferService
from app.tests.conftest import write_test_pcap


def _service_with_dirs(tmp_path, monkeypatch):
    bruce_dir = tmp_path / "bruce"
    raw_dir = bruce_dir / "rawsniffer"
    handshakes_dir = tmp_path / "handshakes"
    for path in (raw_dir, handshakes_dir):
        path.mkdir(parents=True)
    metadata_dir = bruce_dir / ".metadata"
    metadata_dir.mkdir()

    monkeypatch.setattr(
        "app.services.rawsniffer_service.BRUCE_PCAP_DIR", str(bruce_dir)
    )
    monkeypatch.setattr(
        "app.services.rawsniffer_service.HANDSHAKES_DIR", str(handshakes_dir)
    )
    monkeypatch.setattr(
        "app.services.rawsniffer_service.M5EVIL_RAWSNIFFER_DIR",
        str(tmp_path / "nonexistent_m5evil_raw"),
    )
    monkeypatch.setattr(
        "app.services.rawsniffer_service.M5EVIL_MASTERSNIFFER_DIR",
        str(tmp_path / "nonexistent_m5evil_master"),
    )
    monkeypatch.setattr("app.services.rawsniffer_service.load_config", lambda: {})

    return RawSnifferService()


def test_check_tshark_missing(monkeypatch):
    monkeypatch.setattr(
        "app.services.rawsniffer_service.load_config",
        lambda: {"tshark_path": "missing"},
    )
    monkeypatch.setattr(
        "app.services.rawsniffer_service.shutil.which", lambda path: None
    )
    service = RawSnifferService()
    assert service._check_tshark() is None


def test_list_and_pending_with_metadata(tmp_path, monkeypatch):
    service = _service_with_dirs(tmp_path, monkeypatch)
    pcap = tmp_path / "bruce" / "rawsniffer" / "capture.pcap"
    write_test_pcap(pcap)
    metadata_path = (
        tmp_path / "bruce" / ".metadata" / "brucegotchi__rawsniffer__capture.pcap.json"
    )
    metadata_content = {
        "schema_version": service.SCHEMA_VERSION,
        "source_file": "capture.pcap",
        "source_size": pcap.stat().st_size,
        "source_mtime": pcap.stat().st_mtime,
        "stats": {"networks_count": 2, "beacon_frames": 4, "eapol_frames": 1},
        "warnings": ["warn"],
        "processed_at": "now",
    }
    metadata_path.write_text(json.dumps(metadata_content), encoding="utf-8")

    files = service.list_files()
    assert len(files) == 1
    entry = files[0]
    assert entry["cached_up_to_date"]
    assert entry["warnings_count"] == 1
    assert service.get_pending_files() == []


def test_list_files_handles_bad_metadata(tmp_path, monkeypatch):
    service = _service_with_dirs(tmp_path, monkeypatch)
    pcap = tmp_path / "bruce" / "rawsniffer" / "orphan.pcap"
    write_test_pcap(pcap)
    meta = (
        tmp_path / "bruce" / ".metadata" / "brucegotchi__rawsniffer__orphan.pcap.json"
    )
    meta.write_text("not-json", encoding="utf-8")

    files = service.list_files()
    assert files[0]["metadata_path"] is None
    assert not files[0]["cached_up_to_date"]
    assert service.get_pending_files() == ["orphan.pcap"]


def test_generated_hashes(tmp_path, monkeypatch):
    service = _service_with_dirs(tmp_path, monkeypatch)
    hash_file = tmp_path / "handshakes" / "raw_test.22000"
    hash_file.write_text(
        "WPA*02*1234*00:11:22:33:44:55*AA:BB*ssid*1\n", encoding="utf-8"
    )

    parsed = service.list_generated_hashes()
    assert parsed and parsed[0]["bssid_count"] == 1
    matches = service.get_generated_hashes_for_bssid("00:11:22:33:44:55")
    assert matches and matches[0]["valid_hash_lines"] == 1
    assert service.get_generated_hashes_for_bssid("bad") == []


def _write_metadata_entry(base_dir, name, networks, warnings=None):
    metadata_path = base_dir / ".metadata" / f"{name}.json"
    metadata_path.write_text(
        json.dumps(
            {
                "source_file": name,
                "schema_version": 1,
                "processed_at": name,
                "networks": networks,
                "warnings": warnings,
            }
        ),
        encoding="utf-8",
    )
    return metadata_path


def test_aggregate_index_collects(monkeypatch, tmp_path, caplog):
    service = _service_with_dirs(tmp_path, monkeypatch)
    metadata_dir = Path(service.metadata_dir)

    networks = [
        {"bssid": "00:11:22:33:44:55", "ssid": "net", "channel": 6, "beacon_count": 5},
        {
            "bssid": "00:11:22:33:44:55",
            "ssid": "net2",
            "frequency_mhz": 2412,
            "eapol_count": 3,
        },
    ]
    _write_metadata_entry(metadata_dir.parent, "capture1", networks, warnings=["foo"])
    index = service._build_aggregate_index()
    assert "00:11:22:33:44:55" in index
    agg = service.get_aggregated_metadata_for_bssid("00:11:22:33:44:55")
    assert agg["present"]
    assert agg["files_count"] == 1
    assert agg["aggregate"]["beacon_count_total"] == 5
    assert "foo" in agg["aggregate"]["warnings"][0]


def test_clear_metadata_cache(tmp_path, monkeypatch):
    service = _service_with_dirs(tmp_path, monkeypatch)
    metadata_dir = Path(service.metadata_dir)
    (metadata_dir / "to_remove.json").write_text("{}", encoding="utf-8")
    result = service.clear_metadata_cache()
    assert result["deleted_count"] == 1
