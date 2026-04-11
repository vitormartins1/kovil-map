import json
import os

from app.services import rawsniffer_service as rs_module
from app.tests.conftest import write_test_pcap


def _set_bruce_layout(tmp_path, monkeypatch):
    bruce_dir = tmp_path / "BrucePCAP"
    raw_dir = bruce_dir / "rawsniffer"
    raw_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(rs_module, "BRUCE_PCAP_DIR", str(bruce_dir))
    return bruce_dir, raw_dir


def test_extract_metadata_parses_and_uses_cache(tmp_path, monkeypatch):
    bruce_dir, raw_dir = _set_bruce_layout(tmp_path, monkeypatch)

    raw_file = raw_dir / "raw_1.pcap"
    write_test_pcap(raw_file)

    output = "\n".join(
        [
            "10.0\t0x0008\taa:bb:cc:dd:ee:ff\taa:bb:cc:dd:ee:ff\tff:ff:ff:ff:ff:ff\t4e65744f6e65\t6\t\t",
            "11.0\t0x0004\tff:ff:ff:ff:ff:ff\t11:22:33:44:55:66\taa:bb:cc:dd:ee:ff\t4e65744f6e65\t6\t\t",
            "12.5\t0x0028\taa:bb:cc:dd:ee:ff\t11:22:33:44:55:66\taa:bb:cc:dd:ee:ff\t\t\t2\t3",
        ]
    )

    monkeypatch.setattr(rs_module.rawsniffer_service, "_check_tshark", lambda: "tshark")
    monkeypatch.setattr(
        rs_module.rawsniffer_service,
        "_run_tshark",
        lambda _path: (output, ["partial capture"]),
    )

    first = rs_module.rawsniffer_service.extract_metadata("raw_1.pcap", force=False)
    assert first["status"] == "success"
    assert first["cached"] is False
    data = first["data"]
    assert data["stats"]["beacon_frames"] == 1
    assert data["stats"]["probe_requests"] == 1
    assert data["stats"]["eapol_frames"] == 1
    assert data["stats"]["networks_count"] == 1
    assert data["warnings"] == ["partial capture"]

    net = data["networks"][0]
    assert net["bssid"] == "AA:BB:CC:DD:EE:FF"
    assert net["ssid"] == "NetOne"
    assert net["ssid_raw_hex"] == "4e65744f6e65"
    assert net["channel"] == 6
    assert net["frequency_mhz"] == 2437
    assert net["beacon_count"] == 1
    assert net["probe_client_count"] == 1
    assert net["eapol_count"] == 1

    monkeypatch.setattr(
        rs_module.rawsniffer_service,
        "_run_tshark",
        lambda _path: (_ for _ in ()).throw(RuntimeError("should not run")),
    )
    second = rs_module.rawsniffer_service.extract_metadata("raw_1.pcap", force=False)
    assert second["status"] == "success"
    assert second["cached"] is True


def test_list_files_and_pending_detection(tmp_path, monkeypatch):
    bruce_dir, raw_dir = _set_bruce_layout(tmp_path, monkeypatch)
    monkeypatch.setattr(
        rs_module, "M5EVIL_RAWSNIFFER_DIR", str(tmp_path / "nonexistent_m5evil_raw")
    )
    monkeypatch.setattr(
        rs_module,
        "M5EVIL_MASTERSNIFFER_DIR",
        str(tmp_path / "nonexistent_m5evil_master"),
    )

    raw_a = raw_dir / "raw_a.pcap"
    raw_b = raw_dir / "raw_b.pcap"
    hs = raw_dir / "HS_AABBCCDDEEFF.pcap"
    write_test_pcap(raw_a)
    write_test_pcap(raw_b)
    write_test_pcap(hs)

    meta_dir = bruce_dir / ".metadata"
    meta_dir.mkdir()

    stat_a = raw_a.stat()
    (meta_dir / "brucegotchi__rawsniffer__raw_a.pcap.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_file": "raw_a.pcap",
                "source_size": stat_a.st_size,
                "source_mtime": stat_a.st_mtime,
                "processed_at": "2026-03-16T00:00:00Z",
                "warnings": [],
                "stats": {"networks_count": 1, "beacon_frames": 10, "eapol_frames": 0},
                "networks": [],
            }
        ),
        encoding="utf-8",
    )

    files = rs_module.rawsniffer_service.list_files()
    names = {f["filename"] for f in files}
    assert names == {"raw_a.pcap", "raw_b.pcap"}

    pending = rs_module.rawsniffer_service.get_pending_files()
    assert pending == ["raw_b.pcap"]


def test_extract_metadata_returns_error_when_tshark_missing(tmp_path, monkeypatch):
    _bruce_dir, raw_dir = _set_bruce_layout(tmp_path, monkeypatch)
    write_test_pcap(raw_dir / "raw_1.pcap")

    monkeypatch.setattr(rs_module.rawsniffer_service, "_check_tshark", lambda: None)
    out = rs_module.rawsniffer_service.extract_metadata("raw_1.pcap")
    assert out["status"] == "error"
    assert "tshark" in out["message"].lower()


def test_extract_metadata_returns_error_when_tshark_filenotfound(tmp_path, monkeypatch):
    _bruce_dir, raw_dir = _set_bruce_layout(tmp_path, monkeypatch)
    write_test_pcap(raw_dir / "raw_1.pcap")

    monkeypatch.setattr(rs_module.rawsniffer_service, "_check_tshark", lambda: "tshark")
    monkeypatch.setattr(
        rs_module.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            FileNotFoundError("tshark not found")
        ),
    )
    out = rs_module.rawsniffer_service.extract_metadata("raw_1.pcap")
    assert out["status"] == "error"
    assert "tshark not found" in out["message"]


def test_aggregate_metadata_for_bssid(tmp_path, monkeypatch):
    bruce_dir, _raw_dir = _set_bruce_layout(tmp_path, monkeypatch)
    meta_dir = bruce_dir / ".metadata"
    meta_dir.mkdir()

    (meta_dir / "brucegotchi__rawsniffer__raw_1.pcap.json").write_text(
        json.dumps(
            {
                "source_file": "raw_1.pcap",
                "processed_at": "2026-03-16T01:00:00Z",
                "warnings": ["truncated capture"],
                "networks": [
                    {
                        "bssid": "aa-bb-cc-dd-ee-ff",
                        "ssid": "NetOne",
                        "ssid_raw_hex": "4e65744f6e65",
                        "channel": 6,
                        "frequency_mhz": 2437,
                        "beacon_count": 120,
                        "eapol_count": 2,
                        "probe_client_count": 10,
                        "last_seen_offset_s": 18.5,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (meta_dir / "brucegotchi__rawsniffer__raw_2.pcap.json").write_text(
        json.dumps(
            {
                "source_file": "raw_2.pcap",
                "processed_at": "2026-03-16T02:00:00Z",
                "warnings": ["radio warning"],
                "networks": [
                    {
                        "bssid": "AA:BB:CC:DD:EE:FF",
                        "ssid": "NetOne-Alt",
                        "channel": 11,
                        "frequency_mhz": 2462,
                        "beacon_count": 80,
                        "eapol_count": 5,
                        "probe_client_count": 6,
                        "last_seen_offset_s": 40.25,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    aggregated = rs_module.rawsniffer_service.get_aggregated_metadata_for_bssid(
        "aa:bb:cc:dd:ee:ff"
    )
    assert aggregated["present"] is True
    assert aggregated["bssid"] == "AA:BB:CC:DD:EE:FF"
    assert aggregated["files_count"] == 2

    agg = aggregated["aggregate"]
    assert agg["beacon_count_total"] == 200
    assert agg["beacon_count_peak"] == 120
    assert agg["eapol_count_total"] == 7
    assert agg["eapol_count_peak"] == 5
    assert agg["probe_client_count_peak"] == 10
    assert agg["channels"] == [6, 11]
    assert agg["frequencies_mhz"] == [2437, 2462]
    assert agg["last_seen_offset_s_max"] == 40.25
    assert "[raw_1.pcap] truncated capture" in agg["warnings"]
    assert "[raw_2.pcap] radio warning" in agg["warnings"]

    assert len(aggregated["files"]) == 2
    first = aggregated["files"][0]
    assert first["source_file"] == "raw_1.pcap"
    assert first["ssid"] == "NetOne"
    assert first["ssid_raw_hex"] == "4e65744f6e65"

    assert rs_module.rawsniffer_service.get_aggregated_metadata_for_bssid(
        "11:22:33:44:55:66"
    ) == {"present": False}


def test_get_raw_context_for_bssid_uses_bssid_specific_raw_details(
    tmp_path, monkeypatch
):
    bruce_dir = tmp_path / "BrucePCAP"
    raw_dir = bruce_dir / "rawsniffer"
    hand_dir = tmp_path / "handshakes"
    raw_dir.mkdir(parents=True)
    hand_dir.mkdir()
    monkeypatch.setattr(rs_module, "BRUCE_PCAP_DIR", str(bruce_dir))
    monkeypatch.setattr(rs_module, "HANDSHAKES_DIR", str(hand_dir))

    write_test_pcap(raw_dir / "raw_1.pcap")
    meta_dir = bruce_dir / ".metadata"
    meta_dir.mkdir()
    (meta_dir / "brucegotchi__rawsniffer__raw_1.pcap.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_file": "raw_1.pcap",
                "source_size": 24,
                "source_mtime": (raw_dir / "raw_1.pcap").stat().st_mtime,
                "processed_at": "2026-03-16T01:00:00Z",
                "warnings": [],
                "networks": [
                    {
                        "bssid": "AA:BB:CC:DD:EE:FF",
                        "ssid": "NetOne",
                        "channel": 6,
                        "frequency_mhz": 2437,
                        "beacon_count": 3,
                        "eapol_count": 1,
                        "probe_client_count": 1,
                    },
                    {
                        "bssid": "11:22:33:44:55:66",
                        "ssid": "NetTwo",
                        "channel": 1,
                        "frequency_mhz": 2412,
                        "beacon_count": 2,
                        "eapol_count": 0,
                        "probe_client_count": 0,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    (hand_dir / "__rawdetails__raw_1_aabbccddeeff.details").write_text(
        "{}", encoding="utf-8"
    )
    (hand_dir / "__rawdetails__raw_1_112233445566.details").write_text(
        "{}", encoding="utf-8"
    )

    context_one = rs_module.rawsniffer_service.get_raw_context_for_bssid(
        "AA:BB:CC:DD:EE:FF"
    )
    assert context_one["present"] is True
    assert context_one["files"][0]["details_present"] is True
    assert context_one["files"][0]["details_size"] == 2
    assert context_one["files"][0]["bssid"] == "AA:BB:CC:DD:EE:FF"
    assert (
        context_one["files"][0]["details_filename"]
        == "__rawdetails__raw_1_aabbccddeeff.details"
    )

    context_two = rs_module.rawsniffer_service.get_raw_context_for_bssid(
        "11:22:33:44:55:66"
    )
    assert context_two["present"] is True
    assert context_two["files"][0]["details_present"] is True
    assert context_two["files"][0]["details_size"] == 2
    assert context_two["files"][0]["bssid"] == "11:22:33:44:55:66"
    assert (
        context_two["files"][0]["details_filename"]
        == "__rawdetails__raw_1_112233445566.details"
    )


def test_extract_analysis_builds_cached_capture_report(tmp_path, monkeypatch):
    bruce_dir = tmp_path / "BrucePCAP"
    raw_dir = bruce_dir / "rawsniffer"
    raw_dir.mkdir(parents=True)
    monkeypatch.setattr(rs_module, "BRUCE_PCAP_DIR", str(bruce_dir))

    raw_path = raw_dir / "raw_drive.pcap"
    write_test_pcap(raw_path)

    output = "\n".join(
        [
            "10.0\t0x0008\taa:bb:cc:dd:ee:ff\taa:bb:cc:dd:ee:ff\tff:ff:ff:ff:ff:ff\t4e65744f6e65\t6\t\t",
            "11.0\t0x0004\tff:ff:ff:ff:ff:ff\t11:22:33:44:55:66\taa:bb:cc:dd:ee:ff\t4e65744f6e65\t6\t\t",
            "12.0\t0x0028\taa:bb:cc:dd:ee:ff\t11:22:33:44:55:66\taa:bb:cc:dd:ee:ff\t\t\t2\t3",
            "13.0\t0x0028\taa:bb:cc:dd:ee:ff\taa:bb:cc:dd:ee:ff\t11:22:33:44:55:66\t\t\t3\t3",
            "14.0\t0x0008\t11:22:33:44:55:66\t11:22:33:44:55:66\tff:ff:ff:ff:ff:ff\t\t1\t\t",
            "15.0\t0x0008\t11:22:33:44:55:66\t11:22:33:44:55:66\tff:ff:ff:ff:ff:ff\t4e657454776f\t1\t\t",
        ]
    )

    service = rs_module.RawSnifferService()
    monkeypatch.setattr(service, "_check_tshark", lambda: "tshark")
    monkeypatch.setattr(
        service, "_run_tshark", lambda _path: (output, ["partial capture"])
    )

    record = service._resolve_raw_record("raw_drive.pcap")
    result = service.extract_analysis(record["raw_item_id"], force=True)
    assert result["status"] == "success"
    assert result["cached"] is False
    data = result["data"]
    assert data["capture"]["networks_count"] == 2
    assert data["capture"]["clients_count"] == 1
    assert data["highlights"]["handshake_candidate_count"] == 1
    assert data["networks"][0]["handshake_evidence"]["message_numbers"] == [2, 3]
    assert data["highlights"]["revealed_hidden_count"] == 1
    assert data["clients"][0]["mac"] == "11:22:33:44:55:66"

    cached = service.get_analysis(record["raw_item_id"])
    assert cached is not None
    assert cached["highlights"]["handshake_candidate_count"] == 1


def test_aggregate_metadata_index_is_invalidated_on_file_change(tmp_path, monkeypatch):
    monkeypatch.setattr(rs_module, "BRUCE_PCAP_DIR", str(tmp_path))
    meta_dir = tmp_path / ".metadata"
    meta_dir.mkdir()

    metadata_path = meta_dir / "raw_1.pcap.json"
    metadata_path.write_text(
        json.dumps(
            {
                "source_file": "raw_1.pcap",
                "processed_at": "2026-03-16T01:00:00Z",
                "warnings": [],
                "networks": [
                    {
                        "bssid": "AA:BB:CC:DD:EE:FF",
                        "beacon_count": 1,
                        "eapol_count": 0,
                        "probe_client_count": 0,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    first = rs_module.rawsniffer_service.get_aggregated_metadata_for_bssid(
        "AA:BB:CC:DD:EE:FF"
    )
    assert first["present"] is True
    assert first["aggregate"]["beacon_count_total"] == 1

    metadata_path.write_text(
        json.dumps(
            {
                "source_file": "raw_1.pcap",
                "processed_at": "2026-03-16T01:01:00Z",
                "warnings": [],
                "networks": [
                    {
                        "bssid": "AA:BB:CC:DD:EE:FF",
                        "beacon_count": 9,
                        "eapol_count": 0,
                        "probe_client_count": 0,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    second = rs_module.rawsniffer_service.get_aggregated_metadata_for_bssid(
        "AA:BB:CC:DD:EE:FF"
    )
    assert second["present"] is True
    assert second["aggregate"]["beacon_count_total"] == 9


def test_list_generated_hashes_and_primary_context(tmp_path, monkeypatch):
    hand_dir = tmp_path / "handshakes"
    hand_dir.mkdir()
    monkeypatch.setattr(rs_module, "HANDSHAKES_DIR", str(hand_dir))

    raw_hash = hand_dir / "raw_1.22000"
    raw_hash.write_text(
        "\n".join(
            [
                "WPA*02*aaaabbbbccccddddeeeeffff00001111*aa11bb22cc33*112233445566*4e65744f6e65*00",
                "WPA*02*11112222333344445555666677778888*aa11bb22cc33*223344556677*4e65744f6e65*00",
                "WPA*02*99990000aaaabbbbccccddddeeeeffff*ccddeeff0011*aabbccddeeff*546573744e6574*00",
            ]
        ),
        encoding="utf-8",
    )
    invalid_hash = hand_dir / "raw_2.22000"
    invalid_hash.write_text("invalid-line\n", encoding="utf-8")
    non_raw = hand_dir / "other.22000"
    non_raw.write_text("WPA*02*x*x*x*x*00\n", encoding="utf-8")

    hashes = rs_module.rawsniffer_service.list_generated_hashes()
    names = [item["filename"] for item in hashes]
    assert "raw_1.22000" in names
    assert "raw_2.22000" in names
    assert "other.22000" not in names

    first = next(item for item in hashes if item["filename"] == "raw_1.22000")
    assert first["source_raw_file"] == "raw_1.pcap"
    assert first["valid_hash_lines"] == 3
    assert first["primary_bssid"] == "AA:11:BB:22:CC:33"
    assert first["primary_ssid"] == "NetOne"
    assert first["bssid_count"] == 2
    assert first["has_context"] is True

    second = next(item for item in hashes if item["filename"] == "raw_2.22000")
    assert second["valid_hash_lines"] == 0
    assert second["has_context"] is False
    assert second["primary_bssid"] is None


def test_get_generated_hashes_for_bssid_filters_related_hashes(tmp_path, monkeypatch):
    hand_dir = tmp_path / "handshakes"
    hand_dir.mkdir()
    monkeypatch.setattr(rs_module, "HANDSHAKES_DIR", str(hand_dir))

    (hand_dir / "raw_1.22000").write_text(
        "WPA*02*aaaabbbbccccddddeeeeffff00001111*aabbccddeeff*112233445566*4e65744f6e65*00\n",
        encoding="utf-8",
    )
    (hand_dir / "raw_2.22000").write_text(
        "WPA*02*aaaabbbbccccddddeeeeffff00001111*001122334455*112233445566*54657374*00\n",
        encoding="utf-8",
    )

    related = rs_module.rawsniffer_service.get_generated_hashes_for_bssid(
        "AA:BB:CC:DD:EE:FF"
    )
    assert len(related) == 1
    assert related[0]["filename"] == "raw_1.22000"


def test_get_generated_hashes_for_bssid_invalid_mac(tmp_path, monkeypatch):
    """get_generated_hashes_for_bssid returns empty for invalid MAC."""
    monkeypatch.setattr(rs_module, "HANDSHAKES_DIR", str(tmp_path))
    assert rs_module.rawsniffer_service.get_generated_hashes_for_bssid(None) == []
    assert rs_module.rawsniffer_service.get_generated_hashes_for_bssid("") == []
    assert rs_module.rawsniffer_service.get_generated_hashes_for_bssid("invalid") == []


def test_list_files_empty_directory(tmp_path, monkeypatch):
    """list_files returns empty when BRUCE_PCAP_DIR does not exist."""
    monkeypatch.setattr(rs_module, "BRUCE_PCAP_DIR", str(tmp_path / "nonexistent"))
    monkeypatch.setattr(
        rs_module, "M5EVIL_RAWSNIFFER_DIR", str(tmp_path / "nonexistent_m5evil_raw")
    )
    monkeypatch.setattr(
        rs_module,
        "M5EVIL_MASTERSNIFFER_DIR",
        str(tmp_path / "nonexistent_m5evil_master"),
    )
    assert rs_module.rawsniffer_service.list_files() == []


def test_list_files_filters_non_pcap(tmp_path, monkeypatch):
    """list_files ignores files that are not .pcap."""
    bruce_dir, raw_dir = _set_bruce_layout(tmp_path, monkeypatch)
    monkeypatch.setattr(
        rs_module, "M5EVIL_RAWSNIFFER_DIR", str(tmp_path / "nonexistent_m5evil_raw")
    )
    monkeypatch.setattr(
        rs_module,
        "M5EVIL_MASTERSNIFFER_DIR",
        str(tmp_path / "nonexistent_m5evil_master"),
    )
    (raw_dir / "data.txt").write_text("x", encoding="utf-8")
    write_test_pcap(raw_dir / "raw_1.pcap")
    files = rs_module.rawsniffer_service.list_files()
    assert len(files) == 1
    assert files[0]["filename"] == "raw_1.pcap"


def test_list_files_skips_directories(tmp_path, monkeypatch):
    """list_files ignores directories named *.pcap."""
    _bruce_dir, raw_dir = _set_bruce_layout(tmp_path, monkeypatch)
    monkeypatch.setattr(
        rs_module, "M5EVIL_RAWSNIFFER_DIR", str(tmp_path / "nonexistent_m5evil_raw")
    )
    monkeypatch.setattr(
        rs_module,
        "M5EVIL_MASTERSNIFFER_DIR",
        str(tmp_path / "nonexistent_m5evil_master"),
    )
    (raw_dir / "raw_dir.pcap").mkdir()
    files = rs_module.rawsniffer_service.list_files()
    assert files == []


def test_list_files_handles_corrupt_metadata(tmp_path, monkeypatch):
    """list_files treats corrupt metadata JSON as None."""
    bruce_dir, raw_dir = _set_bruce_layout(tmp_path, monkeypatch)
    write_test_pcap(raw_dir / "raw_1.pcap")
    meta_dir = bruce_dir / ".metadata"
    meta_dir.mkdir()
    (meta_dir / "brucegotchi__rawsniffer__raw_1.pcap.json").write_text(
        "{invalid json", encoding="utf-8"
    )
    files = rs_module.rawsniffer_service.list_files()
    assert files[0]["cached_up_to_date"] is False


def test_list_files_ignores_bruce_root_raw_files_outside_canonical_rawsniffer(
    tmp_path, monkeypatch
):
    bruce_dir = tmp_path / "BrucePCAP"
    rawsniffer_dir = bruce_dir / "rawsniffer"
    bruce_dir.mkdir()
    rawsniffer_dir.mkdir()
    monkeypatch.setattr(rs_module, "BRUCE_PCAP_DIR", str(bruce_dir))
    monkeypatch.setattr(
        rs_module, "M5EVIL_RAWSNIFFER_DIR", str(tmp_path / "nonexistent_m5evil_raw")
    )
    monkeypatch.setattr(
        rs_module,
        "M5EVIL_MASTERSNIFFER_DIR",
        str(tmp_path / "nonexistent_m5evil_master"),
    )

    legacy = bruce_dir / "raw_18.pcap"
    newer = rawsniffer_dir / "raw_18.pcap"
    write_test_pcap(legacy)
    write_test_pcap(newer)
    os.utime(legacy, (1000, 1000))
    os.utime(newer, (2000, 2000))

    files = rs_module.rawsniffer_service.list_files()
    matching = [item for item in files if item["filename"] == "raw_18.pcap"]
    assert len(matching) == 1
    assert matching[0]["source_path_role"] == "rawsniffer"


def test_clear_metadata_cache_no_files(tmp_path, monkeypatch):
    """clear_metadata_cache returns zeros when no metadata exists."""
    monkeypatch.setattr(rs_module, "BRUCE_PCAP_DIR", str(tmp_path))
    monkeypatch.setattr(
        rs_module, "M5EVIL_DIR", str(tmp_path / "nonexistent_m5evil_root")
    )
    monkeypatch.setattr(
        rs_module, "M5EVIL_RAWSNIFFER_DIR", str(tmp_path / "nonexistent_m5evil")
    )
    monkeypatch.setattr(
        rs_module,
        "M5EVIL_MASTERSNIFFER_DIR",
        str(tmp_path / "nonexistent_m5evil_master"),
    )
    result = rs_module.rawsniffer_service.clear_metadata_cache(remove_files=True)
    assert result["deleted_count"] == 0
    assert result["failed_count"] == 0
    assert result["removed_files"] is True


def test_clear_metadata_cache_remove_false(tmp_path, monkeypatch):
    """clear_metadata_cache skips deletion when remove_files=False."""
    bruce_dir, _raw_dir = _set_bruce_layout(tmp_path, monkeypatch)
    monkeypatch.setattr(
        rs_module, "M5EVIL_RAWSNIFFER_DIR", str(tmp_path / "nonexistent_m5evil")
    )
    monkeypatch.setattr(
        rs_module,
        "M5EVIL_MASTERSNIFFER_DIR",
        str(tmp_path / "nonexistent_m5evil_master"),
    )
    meta_dir = bruce_dir / ".metadata"
    meta_dir.mkdir()
    (meta_dir / "test.json").write_text("{}", encoding="utf-8")
    result = rs_module.rawsniffer_service.clear_metadata_cache(remove_files=False)
    assert result["deleted_count"] == 0
    assert result["removed_files"] is False
    assert (meta_dir / "test.json").exists()


def test_delete_file_removes_raw_metadata_and_hash(tmp_path, monkeypatch):
    hand_dir = tmp_path / "handshakes"
    hand_dir.mkdir()
    bruce_dir, raw_dir = _set_bruce_layout(tmp_path, monkeypatch)
    monkeypatch.setattr(rs_module, "HANDSHAKES_DIR", str(hand_dir))

    raw_file = raw_dir / "raw_1.pcap"
    write_test_pcap(raw_file)

    meta_dir = bruce_dir / ".metadata"
    meta_dir.mkdir()
    metadata_file = meta_dir / "brucegotchi__rawsniffer__raw_1.pcap.json"
    metadata_file.write_text("{}", encoding="utf-8")

    hash_file = hand_dir / "raw_1.22000"
    hash_file.write_text("hash", encoding="utf-8")

    result = rs_module.rawsniffer_service.delete_file("raw_1.pcap")

    assert result["status"] == "success"
    assert result["source_file"] == "raw_1.pcap"
    assert result["metadata_deleted"] is True
    assert result["hash_deleted"] is True
    assert result["deleted"] == [
        "raw_1.pcap",
        "brucegotchi__rawsniffer__raw_1.pcap.json",
        "raw_1.22000",
    ]
    assert not raw_file.exists()
    assert not metadata_file.exists()
    assert not hash_file.exists()


def test_delete_file_returns_error_for_missing_raw(tmp_path, monkeypatch):
    monkeypatch.setattr(rs_module, "BRUCE_PCAP_DIR", str(tmp_path))
    result = rs_module.rawsniffer_service.delete_file("raw_missing.pcap")
    assert result["status"] == "error"
    assert "not found" in result["message"].lower()


def test_extract_metadata_missing_raw_file(tmp_path, monkeypatch):
    """extract_metadata errors when raw file does not exist."""
    monkeypatch.setattr(rs_module, "BRUCE_PCAP_DIR", str(tmp_path))
    monkeypatch.setattr(rs_module.rawsniffer_service, "_check_tshark", lambda: "tshark")
    result = rs_module.rawsniffer_service.extract_metadata("nonexistent.pcap")
    assert result["status"] == "error"
    assert "not found" in result["message"].lower()


def test_extract_metadata_tshark_file_not_found(tmp_path, monkeypatch):
    """extract_metadata handles FileNotFoundError from tshark."""
    _bruce_dir, raw_dir = _set_bruce_layout(tmp_path, monkeypatch)
    write_test_pcap(raw_dir / "raw_1.pcap")
    monkeypatch.setattr(rs_module.rawsniffer_service, "_check_tshark", lambda: "tshark")

    def _raise_fnf(_path):
        raise FileNotFoundError("tshark not found")

    monkeypatch.setattr(rs_module.rawsniffer_service, "_run_tshark", _raise_fnf)
    result = rs_module.rawsniffer_service.extract_metadata("raw_1.pcap")
    assert result["status"] == "error"
    assert "tshark" in result["message"].lower()


def test_extract_metadata_tshark_runtime_error(tmp_path, monkeypatch):
    """extract_metadata handles RuntimeError from tshark."""
    _bruce_dir, raw_dir = _set_bruce_layout(tmp_path, monkeypatch)
    write_test_pcap(raw_dir / "raw_1.pcap")
    monkeypatch.setattr(rs_module.rawsniffer_service, "_check_tshark", lambda: "tshark")

    def _raise_rt(_path):
        raise RuntimeError("tshark failed")

    monkeypatch.setattr(rs_module.rawsniffer_service, "_run_tshark", _raise_rt)
    result = rs_module.rawsniffer_service.extract_metadata("raw_1.pcap")
    assert result["status"] == "error"
    assert "tshark failed" in result["message"]


def test_extract_metadata_force_overwrites_cache(tmp_path, monkeypatch):
    """extract_metadata with force=True ignores existing cache."""
    _bruce_dir, raw_dir = _set_bruce_layout(tmp_path, monkeypatch)
    write_test_pcap(raw_dir / "raw_1.pcap")
    monkeypatch.setattr(rs_module.rawsniffer_service, "_check_tshark", lambda: "tshark")
    monkeypatch.setattr(
        rs_module.rawsniffer_service,
        "_run_tshark",
        lambda _path: ("", []),
    )

    result1 = rs_module.rawsniffer_service.extract_metadata("raw_1.pcap", force=True)
    assert result1["cached"] is False

    result2 = rs_module.rawsniffer_service.extract_metadata("raw_1.pcap", force=True)
    assert result2["cached"] is False


def test_get_metadata_missing_file(tmp_path, monkeypatch):
    """get_metadata returns None when metadata file does not exist."""
    monkeypatch.setattr(rs_module, "BRUCE_PCAP_DIR", str(tmp_path))
    result = rs_module.rawsniffer_service.get_metadata("nonexistent.pcap")
    assert result is None


def test_get_metadata_corrupt_file(tmp_path, monkeypatch):
    """get_metadata returns None for corrupt JSON."""
    monkeypatch.setattr(rs_module, "BRUCE_PCAP_DIR", str(tmp_path))
    meta_dir = tmp_path / ".metadata"
    meta_dir.mkdir()
    (meta_dir / "raw_1.pcap.json").write_text("{invalid", encoding="utf-8")
    result = rs_module.rawsniffer_service.get_metadata("raw_1.pcap")
    assert result is None


def test_get_pending_files_all_cached(tmp_path, monkeypatch):
    """get_pending_files returns empty when all files are cached."""
    monkeypatch.setattr(rs_module, "BRUCE_PCAP_DIR", str(tmp_path))
    monkeypatch.setattr(
        rs_module, "M5EVIL_RAWSNIFFER_DIR", str(tmp_path / "nonexistent_m5evil_raw")
    )
    monkeypatch.setattr(
        rs_module,
        "M5EVIL_MASTERSNIFFER_DIR",
        str(tmp_path / "nonexistent_m5evil_master"),
    )
    write_test_pcap(tmp_path / "raw_1.pcap")
    meta_dir = tmp_path / ".metadata"
    meta_dir.mkdir()
    stat = (tmp_path / "raw_1.pcap").stat()
    (meta_dir / "raw_1.pcap.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_file": "raw_1.pcap",
                "source_size": stat.st_size,
                "source_mtime": stat.st_mtime,
                "processed_at": "2026-01-01T00:00:00Z",
                "warnings": [],
                "stats": {},
                "networks": [],
            }
        ),
        encoding="utf-8",
    )
    assert rs_module.rawsniffer_service.get_pending_files() == []


def test_list_generated_hashes_empty_directory(tmp_path, monkeypatch):
    """list_generated_hashes returns empty when HANDSHAKES_DIR does not exist."""
    monkeypatch.setattr(rs_module, "HANDSHAKES_DIR", str(tmp_path / "nonexistent"))
    assert rs_module.rawsniffer_service.list_generated_hashes() == []


def test_list_generated_hashes_skips_non_raw(tmp_path, monkeypatch):
    """list_generated_hashes ignores files not matching raw_*.22000."""
    hand_dir = tmp_path / "handshakes"
    hand_dir.mkdir()
    monkeypatch.setattr(rs_module, "HANDSHAKES_DIR", str(hand_dir))
    (hand_dir / "other.22000").write_text("WPA*02*x*x*x*x*00\n", encoding="utf-8")
    (hand_dir / "raw_1.22000").write_text("WPA*02*x*x*x*x*00\n", encoding="utf-8")
    hashes = rs_module.rawsniffer_service.list_generated_hashes()
    assert len(hashes) == 1
    assert hashes[0]["filename"] == "raw_1.22000"


def test_list_generated_hashes_skips_directories(tmp_path, monkeypatch):
    """list_generated_hashes ignores directories."""
    hand_dir = tmp_path / "handshakes"
    hand_dir.mkdir()
    monkeypatch.setattr(rs_module, "HANDSHAKES_DIR", str(hand_dir))
    (hand_dir / "raw_dir.22000").mkdir()
    assert rs_module.rawsniffer_service.list_generated_hashes() == []


def test_aggregate_metadata_invalid_networks(tmp_path, monkeypatch):
    """get_aggregated_metadata_for_bssid handles metadata with non-list networks."""
    monkeypatch.setattr(rs_module, "BRUCE_PCAP_DIR", str(tmp_path))
    meta_dir = tmp_path / ".metadata"
    meta_dir.mkdir()
    (meta_dir / "raw_1.pcap.json").write_text(
        json.dumps({"source_file": "raw_1.pcap", "networks": "not_a_list"}),
        encoding="utf-8",
    )
    result = rs_module.rawsniffer_service.get_aggregated_metadata_for_bssid(
        "AA:BB:CC:DD:EE:FF"
    )
    assert result["present"] is False


def test_aggregate_metadata_empty_bssid(tmp_path, monkeypatch):
    """get_aggregated_metadata_for_bssid handles networks with empty BSSID."""
    monkeypatch.setattr(rs_module, "BRUCE_PCAP_DIR", str(tmp_path))
    meta_dir = tmp_path / ".metadata"
    meta_dir.mkdir()
    (meta_dir / "raw_1.pcap.json").write_text(
        json.dumps(
            {
                "source_file": "raw_1.pcap",
                "networks": [{"bssid": "", "beacon_count": 1}],
            }
        ),
        encoding="utf-8",
    )
    result = rs_module.rawsniffer_service.get_aggregated_metadata_for_bssid(
        "AA:BB:CC:DD:EE:FF"
    )
    assert result["present"] is False


def test_aggregate_metadata_corrupt_json(tmp_path, monkeypatch):
    """get_aggregated_metadata_for_bssid handles corrupt metadata JSON."""
    monkeypatch.setattr(rs_module, "BRUCE_PCAP_DIR", str(tmp_path))
    meta_dir = tmp_path / ".metadata"
    meta_dir.mkdir()
    (meta_dir / "raw_1.pcap.json").write_text("{invalid", encoding="utf-8")
    result = rs_module.rawsniffer_service.get_aggregated_metadata_for_bssid(
        "AA:BB:CC:DD:EE:FF"
    )
    assert result["present"] is False


def test_aggregate_metadata_duplicate_warnings(tmp_path, monkeypatch):
    """get_aggregated_metadata_for_bssid deduplicates warnings."""
    monkeypatch.setattr(rs_module, "BRUCE_PCAP_DIR", str(tmp_path))
    meta_dir = tmp_path / ".metadata"
    meta_dir.mkdir()
    (meta_dir / "raw_1.pcap.json").write_text(
        json.dumps(
            {
                "source_file": "raw_1.pcap",
                "warnings": ["same warning"],
                "networks": [
                    {
                        "bssid": "AA:BB:CC:DD:EE:FF",
                        "beacon_count": 1,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    result = rs_module.rawsniffer_service.get_aggregated_metadata_for_bssid(
        "AA:BB:CC:DD:EE:FF"
    )
    assert result["present"] is True
    assert result["aggregate"]["warnings"] == ["[raw_1.pcap] same warning"]


def test_normalize_compact_mac():
    """Test _normalize_compact_mac utility method."""
    service = rs_module.rawsniffer_service

    # None should return None
    assert service._normalize_compact_mac(None) is None

    # Empty string should return None
    assert service._normalize_compact_mac("") is None

    # Valid MAC with colons should be returned without colons
    result = service._normalize_compact_mac("AA:BB:CC:DD:EE:FF")
    assert result == "aabbccddeeff"

    # Already compact MAC
    result = service._normalize_compact_mac("aabbccddeeff")
    assert result == "aabbccddeeff"


def test_raw_details_filename():
    """Test _raw_details_filename utility method."""
    service = rs_module.rawsniffer_service

    # Without BSSID uses legacy format
    result = service._raw_details_filename("raw_001::test", "capture.pcap", None)
    assert "__rawdetails__" in result
    assert "test" in result

    # With BSSID includes compact MAC
    result = service._raw_details_filename(
        "raw_001::test", "capture.pcap", "AA:BB:CC:DD:EE:FF"
    )
    assert "__rawdetails__" in result
    assert "aabbccddeeff" in result


def test_legacy_raw_details_filename():
    """Test _legacy_raw_details_filename utility method."""
    service = rs_module.rawsniffer_service

    result = service._legacy_raw_details_filename("raw_001::abc123", "capture.pcap")
    assert "__rawdetails__" in result
    assert "abc123" in result
    assert "capture" in result


def test_analysis_path_for_record():
    """Test _analysis_path_for_record utility method."""
    service = rs_module.rawsniffer_service

    record = {
        "source": "brucegotchi",
        "raw_item_id": "raw_001::test",
        "filename": "capture.pcap",
    }

    result = service._analysis_path_for_record(record)
    assert "analysis__" in result
    assert "test" in result
    assert ".json" in result


def test_device_label_for_source():
    """Test _device_label_for_source utility method."""
    service = rs_module.rawsniffer_service

    # m5evil should return M5Evil
    assert service._device_label_for_source("m5evil") == "M5Evil"
    assert service._device_label_for_source("M5EVIL") == "M5Evil"

    # Anything else should return Bruce
    assert service._device_label_for_source("brucegotchi") == "Bruce"
    assert service._device_label_for_source("other") == "Bruce"
    assert service._device_label_for_source(None) == "Bruce"


def test_prepare_raw_item_for_bssid_requires_source_file():
    """Test prepare_raw_item_for_bssid requires source_file or raw_item_id."""
    service = rs_module.rawsniffer_service

    result = service.prepare_raw_item_for_bssid("00:11:22:33:44:55")
    assert result["status"] == "error"
    assert "required" in result["message"].lower()


def test_prepare_raw_item_for_bssid_uses_prepare_focused_capture(monkeypatch):
    """Test prepare_raw_item_for_bssid falls back to prepare_focused_capture_for_bssid."""
    service = rs_module.rawsniffer_service

    def prepare_focused_capture_for_bssid(
        bssid,
        source_file,
        force=False,
        ssid_hint=None,
        convert_func=None,
    ):
        if ssid_hint is not None:
            raise TypeError
        return {"status": "success", "info": True}

    monkeypatch.setattr(
        service,
        "prepare_focused_capture_for_bssid",
        prepare_focused_capture_for_bssid,
    )

    result = service.prepare_raw_item_for_bssid(
        "00:11:22:33:44:55",
        source_file="capture.pcap",
        ssid_hint="hint",
    )

    assert result["status"] == "success"
    assert result["source_file"] == "capture.pcap"


def test_prepare_raw_item_for_bssid_raw_item_id_not_linked(monkeypatch):
    """Test prepare_raw_item_for_bssid returns error when raw_item_id is not linked."""
    service = rs_module.rawsniffer_service

    monkeypatch.setattr(
        service,
        "get_raw_context_for_bssid",
        lambda bssid: {"present": True, "files": [], "hash_files": []},
    )

    result = service.prepare_raw_item_for_bssid(
        "00:11:22:33:44:55",
        raw_item_id="raw_001",
    )

    assert result["status"] == "error"
    assert "not linked" in result["message"].lower()


def test_prepare_raw_item_for_bssid_with_raw_item_id_calls_canonical_hash(monkeypatch):
    """Test prepare_raw_item_for_bssid routes known raw_item_id to canonical hash preparation."""
    service = rs_module.rawsniffer_service

    context = {
        "present": True,
        "files": [
            {
                "raw_item_id": "raw_001",
                "artifact_type": "22000",
                "filename": "hash.22000",
            }
        ],
        "hash_files": [],
    }

    monkeypatch.setattr(service, "get_raw_context_for_bssid", lambda bssid: context)
    monkeypatch.setattr(
        service,
        "prepare_canonical_hash_for_bssid",
        lambda bssid, force=False, source_files=None, ssid_hint=None, convert_func=None: {
            "status": "success",
            "prepared": True,
        },
    )

    result = service.prepare_raw_item_for_bssid(
        "00:11:22:33:44:55",
        raw_item_id="raw_001",
    )

    assert result["status"] == "success"
    assert result["raw_item_id"] == "raw_001"
    assert result["source_file"] == "hash.22000"
