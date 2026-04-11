import json
import builtins
import os

import pytest

from app.services import data_loader as dl_module


@pytest.fixture(autouse=True)
def reset_wardrive_runtime_state(monkeypatch, tmp_path):
    monkeypatch.setattr(dl_module, "_DATA_CACHE", None)
    monkeypatch.setattr(dl_module, "_WARDRIVE_SESSIONS", [])
    monkeypatch.setattr(
        dl_module,
        "_WARDRIVE_SUMMARY",
        {"files_count": 0, "networks_count": 0, "sessions_count": 0},
    )
    monkeypatch.setattr(dl_module, "_WARDRIVE_SESSION_TAGS", None)
    monkeypatch.setattr(dl_module, "_WARDRIVE_MANIFEST", None)
    monkeypatch.setattr(dl_module, "_WARDRIVE_MANIFEST_PATH", None)
    monkeypatch.setattr(dl_module, "WARDRIVE_DIR", str(tmp_path / "wardrive_empty"))
    monkeypatch.setattr(dl_module, "BRUCE_PCAP_DIR", str(tmp_path / "bruce_empty"))
    monkeypatch.setattr(
        dl_module, "BRUCE_HANDSHAKES_DIR", str(tmp_path / "bruce_empty" / "handshakes")
    )
    monkeypatch.setattr(dl_module, "M5EVIL_DIR", str(tmp_path / "m5_empty"))
    monkeypatch.setattr(
        dl_module, "M5EVIL_HANDSHAKES_DIR", str(tmp_path / "m5_empty" / "handshakes")
    )


def _write_wardrive_csv(path, rows, wigle_header="WigleWifi-1.4,appRelease=1"):
    header = (
        "MAC,SSID,AuthMode,FirstSeen,LastSeen,Channel,Frequency,RSSI,"
        "CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n"
    )
    body = "".join(rows)
    path.write_text(f"{wigle_header}\n{header}{body}", encoding="utf-8")


def test_reload_data_parses_gps_and_cracked(tmp_path, monkeypatch):
    monkeypatch.setattr(dl_module, "HANDSHAKES_DIR", str(tmp_path))

    gps_file = tmp_path / "Test_aabbccddeeff.gps.json"
    gps_file.write_text(
        json.dumps(
            {
                "lat": -22.0,
                "lng": -43.0,
                "HDOP": 2,
                "Updated": "2024-01-01T00:00:00Z",
            }
        )
    )

    pcap_file = tmp_path / "Test_aabbccddeeff.pcap"
    pcap_file.write_text("pcap")

    cracked_file = tmp_path / "Test_aabbccddeeff.pcap.cracked"
    cracked_file.write_text("secret")

    data = dl_module.reload_data()
    key = "AA:BB:CC:DD:EE:FF"
    assert key in data
    assert data[key]["pass"] == "secret"
    assert "Test_aabbccddeeff.pcap" in data[key]["handshake_files"]
    assert data[key]["device_type"] == "unknown"
    assert data[key]["device_confidence"] == 0.0


def test_reload_data_reads_device_classification_from_details(tmp_path, monkeypatch):
    monkeypatch.setattr(dl_module, "HANDSHAKES_DIR", str(tmp_path))

    (tmp_path / "Test_aabbccddeeff.gps.json").write_text(
        json.dumps({"lat": -22.0, "lng": -43.0, "HDOP": 2}),
        encoding="utf-8",
    )
    (tmp_path / "Test_aabbccddeeff.pcap").write_text("pcap", encoding="utf-8")
    (tmp_path / "Test_aabbccddeeff.details").write_text(
        json.dumps(
            {
                "ssid": "Test",
                "classification": {"type": "phone_hotspot", "confidence": 0.84},
                "security": {"wpa_version": "WPA2"},
            }
        ),
        encoding="utf-8",
    )

    data = dl_module.reload_data()
    key = "AA:BB:CC:DD:EE:FF"
    assert key in data
    assert data[key]["device_type"] == "phone_hotspot"
    assert data[key]["device_confidence"] == 0.84


def test_reload_data_adds_no_gps(tmp_path, monkeypatch):
    monkeypatch.setattr(dl_module, "HANDSHAKES_DIR", str(tmp_path))

    pcap_file = tmp_path / "NoGPS_112233445566.pcap"
    pcap_file.write_text("pcap")

    data = dl_module.reload_data()
    key = "11:22:33:44:55:66"
    assert key in data
    assert data[key]["type"] == "no-gps"
    assert data[key]["lat"] is None


def test_load_real_data_cache_and_reload(monkeypatch):
    calls = {"n": 0}

    def _fake_load():
        calls["n"] += 1
        return {"x": calls["n"]}

    monkeypatch.setattr(dl_module, "_load_from_disk", _fake_load)
    monkeypatch.setattr(dl_module, "_DATA_CACHE", None)

    first = dl_module.load_real_data()
    second = dl_module.load_real_data()
    assert first == second == {"x": 1}
    assert calls["n"] == 1

    reloaded = dl_module.reload_data()
    assert reloaded == {"x": 2}
    assert calls["n"] == 2


def test_data_revision_increments_on_disk_load_and_reload(tmp_path, monkeypatch):
    monkeypatch.setattr(dl_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(dl_module, "_DATA_CACHE", None)
    monkeypatch.setattr(dl_module, "_DATA_REVISION", 0)

    assert dl_module.get_data_revision() == 0
    dl_module.load_real_data()
    revision_after_load = dl_module.get_data_revision()
    assert revision_after_load == 1

    dl_module.reload_data()
    revision_after_reload = dl_module.get_data_revision()
    assert revision_after_reload == 2


def test_reload_data_handles_fallback_paths_and_read_errors(tmp_path, monkeypatch):
    monkeypatch.setattr(dl_module, "HANDSHAKES_DIR", str(tmp_path))

    # Nome sem "_": força fallback para BSSID/SSID dentro do conteúdo.
    gps_file = tmp_path / "fallback.gps.json"
    gps_file.write_text(
        json.dumps(
            {
                "BSSID": "aa11bb22cc33",
                "SSID": "Fallback",
                "lat": -20.0,
                "lng": -40.0,
                "HDOP": "not-a-number",
                "Updated": "not-iso",
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "fallback.pcap").write_text("pcap", encoding="utf-8")
    (tmp_path / "fallback.pcap.cracked").write_text("secret", encoding="utf-8")
    (tmp_path / "fallback.empty").write_text("", encoding="utf-8")

    # Arquivo JSON inválido cobre o branch de erro de parse.
    (tmp_path / "broken_aabbccddeeff.gps.json").write_text("{", encoding="utf-8")

    # Rede sem GPS + arquivo cracked que falha leitura.
    no_gps = tmp_path / "NoGPS_112233445566.pcap"
    no_gps.write_text("pcap", encoding="utf-8")
    (tmp_path / "NoGPS_112233445566.pcap.cracked").write_text(
        "will-fail-read", encoding="utf-8"
    )

    real_open = builtins.open

    def _open_with_fail(path, mode="r", *args, **kwargs):
        path_str = str(path)
        if "pcap.cracked" in path_str and "r" in mode:
            raise OSError("cannot read cracked file")
        return real_open(path, mode, *args, **kwargs)

    monkeypatch.setattr("builtins.open", _open_with_fail)
    monkeypatch.setattr(dl_module, "_DATA_CACHE", None)

    data = dl_module.reload_data()
    fallback_key = "AA11BB22CC33"
    no_gps_key = "11:22:33:44:55:66"

    assert fallback_key in data
    assert data[fallback_key]["ssid"] == "Fallback"
    assert data[fallback_key]["acc"] == 50
    assert data[fallback_key]["pass"] is None
    assert "fallback.pcap" in data[fallback_key]["handshake_files"]
    assert "fallback.empty" not in data[fallback_key]["handshake_files"]

    assert no_gps_key in data
    assert data[no_gps_key]["type"] == "no-gps"
    assert data[no_gps_key]["pass"] is None


def test_reload_data_parses_wardrive_csv(tmp_path, monkeypatch):
    hand_dir = tmp_path / "handshakes"
    ward_dir = tmp_path / "wardrive"
    hand_dir.mkdir()
    ward_dir.mkdir()

    monkeypatch.setattr(dl_module, "HANDSHAKES_DIR", str(hand_dir))
    monkeypatch.setattr(dl_module, "WARDRIVE_DIR", str(ward_dir))
    monkeypatch.setattr(dl_module, "_DATA_CACHE", None)

    csv_content = (
        "WigleWifi-1.4,appRelease=1\n"
        "MAC,SSID,AuthMode,FirstSeen,LastSeen,Channel,Frequency,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n"
        "AA:BB:CC:DD:EE:FF,NetOne,[WPA2-PSK-CCMP],2024-01-01 00:00:00,2024-01-02 00:00:00,1,2412,-40,-22.0,-43.0,0,12,WIFI\n"
        "AABBCCDDEEFF,NetOne,[WPA2-PSK-CCMP],2024-01-01 00:00:00,2024-01-01 00:00:00,1,2412,-40,-22.1,-43.1,0,30,WIFI\n"
    )
    (ward_dir / "drive.csv").write_text(csv_content, encoding="utf-8")

    data = dl_module.reload_data()
    key = "AA:BB:CC:DD:EE:FF"
    assert key in data
    assert data[key]["handshake"] is False
    assert data[key]["handshake_files"] == []
    assert data[key]["sources"] == ["wardrive"]
    assert data[key]["encryption"] == "WPA2"
    assert data[key]["lat"] == -22.0
    assert data[key]["channel"] == 1
    assert data[key]["frequency"] == 2412
    assert data[key]["rssi"] == -40.0
    assert data[key]["altitude"] == 0.0
    assert data[key]["ts_first"] <= data[key]["ts_last"]
    assert data[key]["sessionId"] == "drive"
    assert data[key]["sessionSourceFile"] == "drive.csv"
    assert len(data[key]["wardrive_sessions"]) == 1
    assert data[key]["wardrive_sessions"][0]["session_id"] == "drive"
    summary = dl_module.get_wardrive_summary()
    assert summary["files_count"] == 1
    assert summary["networks_count"] == 1
    assert summary["sessions_count"] == 1

    sessions = dl_module.get_wardrive_sessions()
    assert len(sessions) == 1
    assert sessions[0]["session_id"] == "drive"
    assert sessions[0]["source_file"] == "drive.csv"
    assert sessions[0]["networks_count"] == 1
    assert sessions[0]["points_count"] == 2


def test_reload_data_merges_wardrive_into_pwn_entry(tmp_path, monkeypatch):
    hand_dir = tmp_path / "handshakes"
    ward_dir = tmp_path / "wardrive"
    hand_dir.mkdir()
    ward_dir.mkdir()

    monkeypatch.setattr(dl_module, "HANDSHAKES_DIR", str(hand_dir))
    monkeypatch.setattr(dl_module, "WARDRIVE_DIR", str(ward_dir))
    monkeypatch.setattr(dl_module, "_DATA_CACHE", None)

    gps_file = hand_dir / "Test_aabbccddeeff.gps.json"
    gps_file.write_text(
        json.dumps(
            {
                "lat": -10.0,
                "lng": -20.0,
                "HDOP": 2,
                "Updated": "2024-01-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )

    csv_content = (
        "WigleWifi-1.4,appRelease=1\n"
        "BSSID,SSID,AuthMode,FirstSeen,LastSeen,Channel,Frequency,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n"
        "AA:BB:CC:DD:EE:FF,NetOne,OPEN,2024-01-01 00:00:00,2024-01-02 00:00:00,1,2412,-40,-30.0,-40.0,0,8,WIFI\n"
    )
    (ward_dir / "drive.csv").write_text(csv_content, encoding="utf-8")

    data = dl_module.reload_data()
    key = "AA:BB:CC:DD:EE:FF"
    assert key in data
    assert data[key]["sources"] == ["pwnagotchi", "wardrive"]
    assert data[key]["lat"] == -10.0
    assert data[key]["encryption"] == "WPA2"
    assert data[key]["ts_last"] >= 1704067200
    assert data[key]["wardrive_sessions"][0]["session_id"] == "drive"


def test_reload_data_keeps_zero_latitude_without_falsy_drop(tmp_path, monkeypatch):
    hand_dir = tmp_path / "handshakes"
    hand_dir.mkdir()
    monkeypatch.setattr(dl_module, "HANDSHAKES_DIR", str(hand_dir))
    monkeypatch.setattr(dl_module, "_DATA_CACHE", None)

    gps_file = hand_dir / "ZeroLat_aabbccddeeff.gps.json"
    gps_file.write_text(
        json.dumps(
            {
                "lat": 0.0,
                "lng": -43.2,
                "Accuracy": 0.0,
                "Updated": "2024-01-01T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    (hand_dir / "ZeroLat_aabbccddeeff.pcap").write_text("pcap", encoding="utf-8")

    data = dl_module.reload_data()
    key = "AA:BB:CC:DD:EE:FF"
    assert key in data
    assert data[key]["lat"] == 0.0
    assert data[key]["lng"] == -43.2
    assert data[key]["acc"] == 0.0


def test_reload_data_merges_wardrive_into_bruce_entry(tmp_path, monkeypatch):
    hand_dir = tmp_path / "handshakes"
    ward_dir = tmp_path / "wardrive"
    bruce_dir = tmp_path / "BrucePCAP"
    bruce_hand = bruce_dir / "handshakes"
    hand_dir.mkdir()
    ward_dir.mkdir()
    bruce_dir.mkdir()
    bruce_hand.mkdir()

    monkeypatch.setattr(dl_module, "HANDSHAKES_DIR", str(hand_dir))
    monkeypatch.setattr(dl_module, "WARDRIVE_DIR", str(ward_dir))
    monkeypatch.setattr(dl_module, "BRUCE_PCAP_DIR", str(bruce_dir))
    monkeypatch.setattr(dl_module, "BRUCE_HANDSHAKES_DIR", str(bruce_hand))
    monkeypatch.setattr(dl_module, "_DATA_CACHE", None)

    details = {"ssid": "BruceNet", "security": {"wpa_version": "WPA2"}}
    (hand_dir / "HS_AABBCCDDEEFF.details").write_text(
        json.dumps(details), encoding="utf-8"
    )

    (bruce_hand / "HS_AABBCCDDEEFF.pcap").write_text("pcap", encoding="utf-8")

    csv_content = (
        "WigleWifi-1.4,appRelease=1\n"
        "BSSID,SSID,AuthMode,FirstSeen,LastSeen,Channel,Frequency,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n"
        "AA:BB:CC:DD:EE:FF,NetOne,OPEN,2024-01-01 00:00:00,2024-01-02 00:00:00,1,2412,-40,-30.0,-40.0,0,8,WIFI\n"
    )
    (ward_dir / "drive.csv").write_text(csv_content, encoding="utf-8")

    data = dl_module.reload_data()
    key = "AA:BB:CC:DD:EE:FF"
    assert key in data
    assert data[key]["sources"] == ["brucegotchi", "wardrive"]
    assert data[key]["lat"] == -30.0
    assert data[key]["type"] == "ap"
    assert data[key]["encryption"] == "WPA2"
    assert "HS_AABBCCDDEEFF.pcap" in data[key]["handshake_files"]
    assert "HS_AABBCCDDEEFF.details" in data[key]["handshake_files"]


def test_reload_data_merges_m5evil_entries_and_preserves_local_source(
    tmp_path, monkeypatch
):
    hand_dir = tmp_path / "handshakes"
    ward_dir = tmp_path / "wardrive"
    bruce_dir = tmp_path / "BrucePCAP"
    bruce_hand = bruce_dir / "handshakes"
    m5evil_dir = tmp_path / "m5evil"
    m5evil_hand = m5evil_dir / "handshakes"
    hand_dir.mkdir()
    ward_dir.mkdir()
    bruce_dir.mkdir()
    bruce_hand.mkdir()
    m5evil_dir.mkdir()
    m5evil_hand.mkdir()

    monkeypatch.setattr(dl_module, "HANDSHAKES_DIR", str(hand_dir))
    monkeypatch.setattr(dl_module, "WARDRIVE_DIR", str(ward_dir))
    monkeypatch.setattr(dl_module, "BRUCE_PCAP_DIR", str(bruce_dir))
    monkeypatch.setattr(dl_module, "BRUCE_HANDSHAKES_DIR", str(bruce_hand))
    monkeypatch.setattr(dl_module, "M5EVIL_HANDSHAKES_DIR", str(m5evil_hand))
    monkeypatch.setattr(dl_module, "_DATA_CACHE", None)

    (hand_dir / "HS_AABBCCDDEEFF.details").write_text(
        json.dumps({"ssid": "M5 Merge", "security": {"wpa_version": "WPA2"}}),
        encoding="utf-8",
    )
    (hand_dir / "HS_112233445566.details").write_text(
        json.dumps({"ssid": "M5 Solo", "security": {"wpa_version": "WPA3"}}),
        encoding="utf-8",
    )
    (m5evil_hand / "HS_AABBCCDDEEFF.pcap").write_text("pcap", encoding="utf-8")
    (m5evil_hand / "HS_112233445566.pcap").write_text("pcap", encoding="utf-8")

    csv_content = (
        "WigleWifi-1.4,appRelease=1\n"
        "BSSID,SSID,AuthMode,FirstSeen,LastSeen,Channel,Frequency,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n"
        "AA:BB:CC:DD:EE:FF,MergeNet,OPEN,2024-01-01 00:00:00,2024-01-02 00:00:00,1,2412,-40,-30.0,-40.0,0,8,WIFI\n"
    )
    (ward_dir / "drive.csv").write_text(csv_content, encoding="utf-8")

    data = dl_module.reload_data()

    merged_key = "AA:BB:CC:DD:EE:FF"
    assert data[merged_key]["sources"] == ["m5evil", "wardrive"]
    assert data[merged_key]["type"] == "ap"
    assert "HS_AABBCCDDEEFF.pcap" in data[merged_key]["handshake_files"]
    assert "HS_AABBCCDDEEFF.details" in data[merged_key]["handshake_files"]

    solo_key = "11:22:33:44:55:66"
    assert data[solo_key]["sources"] == ["m5evil"]
    assert data[solo_key]["type"] == "no-gps"
    assert data[solo_key]["ssid"] == "M5 Solo"
    assert data[solo_key]["encryption"] == "WPA3"


def test_reload_data_merges_rawsniffer_metadata_with_normalized_bssid(
    tmp_path, monkeypatch
):
    hand_dir = tmp_path / "handshakes"
    ward_dir = tmp_path / "wardrive"
    bruce_dir = tmp_path / "BrucePCAP"
    m5_dir = tmp_path / "m5evil"
    meta_dir = bruce_dir / ".metadata"
    hand_dir.mkdir()
    ward_dir.mkdir()
    bruce_dir.mkdir()
    m5_dir.mkdir()
    meta_dir.mkdir()

    monkeypatch.setattr(dl_module, "HANDSHAKES_DIR", str(hand_dir))
    monkeypatch.setattr(dl_module, "WARDRIVE_DIR", str(ward_dir))
    monkeypatch.setattr(dl_module, "BRUCE_PCAP_DIR", str(bruce_dir))
    monkeypatch.setattr(dl_module, "M5EVIL_DIR", str(m5_dir))
    monkeypatch.setattr(dl_module, "_DATA_CACHE", None)

    csv_content = (
        "WigleWifi-1.4,appRelease=1\n"
        "BSSID,SSID,AuthMode,FirstSeen,LastSeen,Channel,Frequency,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n"
        "AA:BB:CC:DD:EE:FF,NetOne,OPEN,2024-01-01 00:00:00,2024-01-02 00:00:00,1,2412,-40,-30.0,-40.0,0,8,WIFI\n"
    )
    (ward_dir / "drive.csv").write_text(csv_content, encoding="utf-8")

    raw_metadata = {
        "schema_version": 1,
        "source_file": "raw_1.pcap",
        "source_size": 123,
        "source_mtime": 456,
        "processed_at": "2026-03-16T00:00:00Z",
        "warnings": [],
        "stats": {"beacon_frames": 100, "eapol_frames": 3, "networks_count": 1},
        "networks": [
            {
                "bssid": "aabbccddeeff",
                "ssid": "NetOne",
                "channel": 6,
                "frequency_mhz": 2437,
                "beacon_count": 100,
                "probe_client_count": 10,
                "eapol_count": 3,
                "last_seen_offset_s": 9.1,
            }
        ],
    }
    (meta_dir / "raw_1.pcap.json").write_text(
        json.dumps(raw_metadata), encoding="utf-8"
    )

    data = dl_module.reload_data()
    key = "AA:BB:CC:DD:EE:FF"
    assert key in data
    assert data[key]["channel"] == 1  # Wardrive value remains priority if already set
    assert data[key]["raw_beacon_count"] == 100
    assert data[key]["raw_eapol_count"] == 3
    assert data[key]["raw_probe_peak_count"] == 10
    assert "bruce_raw_sniffing" in data[key]["sources"]


def test_list_bruce_handshake_files_uses_deterministic_selection(tmp_path, monkeypatch):
    bruce_dir = tmp_path / "BrucePCAP"
    bruce_hand = bruce_dir / "handshakes"
    bruce_dir.mkdir()
    bruce_hand.mkdir()

    monkeypatch.setattr(dl_module, "BRUCE_PCAP_DIR", str(bruce_dir))
    monkeypatch.setattr(dl_module, "BRUCE_HANDSHAKES_DIR", str(bruce_hand))

    newer = bruce_hand / "HS_AABBCCDDEEFF_new.pcap"
    older = bruce_dir / "HS_AABBCCDDEEFF_old.pcap"
    newer.write_text("newer", encoding="utf-8")
    older.write_text("older", encoding="utf-8")
    os.utime(newer, (200, 200))
    os.utime(older, (100, 100))

    root_pref = bruce_hand / "HS_112233445566_rootA.pcap"
    root_alt = bruce_dir / "HS_112233445566_rootB.pcap"
    root_pref.write_text("root-a", encoding="utf-8")
    root_alt.write_text("root-b", encoding="utf-8")
    os.utime(root_pref, (300, 300))
    os.utime(root_alt, (300, 300))

    lex_first = bruce_hand / "HS_778899AABBCC_alpha.pcap"
    lex_second = bruce_hand / "HS_778899AABBCC_zeta.pcap"
    lex_first.write_text("alpha", encoding="utf-8")
    lex_second.write_text("zeta", encoding="utf-8")
    os.utime(lex_first, (400, 400))
    os.utime(lex_second, (400, 400))

    files = dl_module.list_bruce_handshake_files()
    assert files == sorted(
        [
            "HS_AABBCCDDEEFF_new.pcap",
            "HS_112233445566_rootA.pcap",
            "HS_778899AABBCC_alpha.pcap",
        ]
    )


def test_reload_data_marks_bruce_raw_for_beacon_only_metadata(tmp_path, monkeypatch):
    hand_dir = tmp_path / "hand"
    ward_dir = tmp_path / "ward"
    bruce_dir = tmp_path / "BrucePCAP"
    m5_dir = tmp_path / "m5evil"
    meta_dir = bruce_dir / ".metadata"
    hand_dir.mkdir()
    ward_dir.mkdir()
    bruce_dir.mkdir()
    m5_dir.mkdir()
    meta_dir.mkdir()

    monkeypatch.setattr(dl_module, "HANDSHAKES_DIR", str(hand_dir))
    monkeypatch.setattr(dl_module, "WARDRIVE_DIR", str(ward_dir))
    monkeypatch.setattr(dl_module, "BRUCE_PCAP_DIR", str(bruce_dir))
    monkeypatch.setattr(dl_module, "M5EVIL_DIR", str(m5_dir))
    monkeypatch.setattr(
        dl_module, "BRUCE_HANDSHAKES_DIR", str(bruce_dir / "handshakes")
    )
    monkeypatch.setattr(dl_module, "M5EVIL_HANDSHAKES_DIR", str(tmp_path / "m5hand"))

    csv_content = (
        "WigleWifi-1.4,appRelease=1\n"
        "MAC,SSID,AuthMode,FirstSeen,LastSeen,Channel,Frequency,RSSI,"
        "CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n"
        "AA:BB:CC:DD:EE:FF,NetOne,[WPA2-PSK],2026-03-16 10:00:00,2026-03-16 10:00:02,1,2412,-60,-22.9,-43.2,12.0,5.0,WIFI\n"
    )
    (ward_dir / "drive.csv").write_text(csv_content, encoding="utf-8")

    raw_metadata = {
        "schema_version": 1,
        "source_file": "raw_2.pcap",
        "source_size": 123,
        "source_mtime": 456,
        "processed_at": "2026-03-16T00:00:00Z",
        "warnings": [],
        "stats": {"beacon_frames": 40, "eapol_frames": 0, "networks_count": 1},
        "networks": [
            {
                "bssid": "aabbccddeeff",
                "ssid": "NetOne",
                "channel": 6,
                "frequency_mhz": 2437,
                "beacon_count": 40,
                "probe_client_count": 2,
                "eapol_count": 0,
                "last_seen_offset_s": 2.1,
            }
        ],
    }
    (meta_dir / "raw_2.pcap.json").write_text(
        json.dumps(raw_metadata), encoding="utf-8"
    )

    data = dl_module.reload_data()
    key = "AA:BB:CC:DD:EE:FF"
    assert key in data
    assert data[key]["raw_beacon_count"] == 40
    assert data[key]["raw_eapol_count"] == 0
    assert "bruce_raw_sniffing" in data[key]["sources"]


def test_reload_data_merges_m5evil_raw_and_master_metadata(tmp_path, monkeypatch):
    hand_dir = tmp_path / "handshakes"
    ward_dir = tmp_path / "wardrive"
    bruce_dir = tmp_path / "BrucePCAP"
    m5_dir = tmp_path / "m5evil"
    m5_meta_dir = m5_dir / ".metadata"
    hand_dir.mkdir()
    ward_dir.mkdir()
    bruce_dir.mkdir()
    m5_dir.mkdir()
    m5_meta_dir.mkdir()

    monkeypatch.setattr(dl_module, "HANDSHAKES_DIR", str(hand_dir))
    monkeypatch.setattr(dl_module, "WARDRIVE_DIR", str(ward_dir))
    monkeypatch.setattr(dl_module, "BRUCE_PCAP_DIR", str(bruce_dir))
    monkeypatch.setattr(dl_module, "M5EVIL_DIR", str(m5_dir))
    monkeypatch.setattr(dl_module, "_DATA_CACHE", None)

    csv_content = (
        "WigleWifi-1.4,appRelease=1\n"
        "BSSID,SSID,AuthMode,FirstSeen,LastSeen,Channel,Frequency,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n"
        "AA:BB:CC:DD:EE:01,NetRaw,[WPA2-PSK],2024-01-01 00:00:00,2024-01-02 00:00:00,1,2412,-40,-30.0,-40.0,0,8,WIFI\n"
        "AA:BB:CC:DD:EE:02,NetMaster,[WPA2-PSK],2024-01-01 00:00:00,2024-01-02 00:00:00,6,2437,-42,-30.0,-40.1,0,8,WIFI\n"
    )
    (ward_dir / "drive.csv").write_text(csv_content, encoding="utf-8")

    (m5_meta_dir / "m5evil__rawsniffer__rawsniff_1.pcap.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source": "m5evil",
                "source_path_role": "rawsniffer",
                "source_file": "rawsniff_1.pcap",
                "processed_at": "2026-03-16T00:00:00Z",
                "warnings": [],
                "stats": {"beacon_frames": 25, "eapol_frames": 1, "networks_count": 1},
                "networks": [
                    {
                        "bssid": "aabbccddee01",
                        "ssid": "NetRaw",
                        "channel": 11,
                        "frequency_mhz": 2462,
                        "beacon_count": 25,
                        "probe_client_count": 2,
                        "eapol_count": 1,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (m5_meta_dir / "m5evil__master_sniffer__mastersniffer_1.pcap.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source": "m5evil",
                "source_path_role": "master_sniffer",
                "source_file": "mastersniffer_1.pcap",
                "processed_at": "2026-03-16T00:00:00Z",
                "warnings": [],
                "stats": {"beacon_frames": 18, "eapol_frames": 0, "networks_count": 1},
                "networks": [
                    {
                        "bssid": "aabbccddee02",
                        "ssid": "NetMaster",
                        "channel": 6,
                        "frequency_mhz": 2437,
                        "beacon_count": 18,
                        "probe_client_count": 1,
                        "eapol_count": 0,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    data = dl_module.reload_data()

    raw_key = "AA:BB:CC:DD:EE:01"
    master_key = "AA:BB:CC:DD:EE:02"
    assert "m5evil_raw_sniffing" in data[raw_key]["sources"]
    assert data[raw_key]["raw_eapol_count"] == 1
    assert data[raw_key]["raw_beacon_count"] == 25
    assert "m5evil_master_raw_sniffing" in data[master_key]["sources"]
    assert data[master_key]["raw_eapol_count"] == 0
    assert data[master_key]["raw_beacon_count"] == 18


def test_reload_data_bootstraps_wardrive_manifest_from_existing_csvs(
    tmp_path, monkeypatch
):
    hand_dir = tmp_path / "handshakes"
    ward_dir = tmp_path / "wardrive"
    bruce_dir = tmp_path / "BrucePCAP"
    bruce_hand = bruce_dir / "handshakes"
    hand_dir.mkdir()
    ward_dir.mkdir()
    bruce_dir.mkdir()
    bruce_hand.mkdir()

    monkeypatch.setattr(dl_module, "HANDSHAKES_DIR", str(hand_dir))
    monkeypatch.setattr(dl_module, "WARDRIVE_DIR", str(ward_dir))
    monkeypatch.setattr(dl_module, "BRUCE_PCAP_DIR", str(bruce_dir))
    monkeypatch.setattr(dl_module, "BRUCE_HANDSHAKES_DIR", str(bruce_hand))

    _write_wardrive_csv(
        ward_dir / "session-a.csv",
        [
            "AA:BB:CC:DD:EE:01,NetOne,WPA2,2024-01-01 00:00:00,2024-01-01 00:01:00,1,2412,-40,-22.90,-43.20,0,8,WIFI\n",
        ],
    )

    data = dl_module.reload_data()
    assert "AA:BB:CC:DD:EE:01" in data

    manifest_path = ward_dir / "manifest.json"
    assert manifest_path.exists()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["version"] == 1
    assert manifest["files"][0]["session_id"] == "session-a"
    assert manifest["files"][0]["status"] == "active"
    assert manifest["files"][0]["role"] == "original"
    assert manifest["files"][0]["relative_path"] == "session-a.csv"


def test_merge_wardrive_sessions_creates_merged_active_session_and_ignores_inputs(
    tmp_path, monkeypatch
):
    hand_dir = tmp_path / "handshakes"
    ward_dir = tmp_path / "wardrive"
    bruce_dir = tmp_path / "BrucePCAP"
    bruce_hand = bruce_dir / "handshakes"
    hand_dir.mkdir()
    ward_dir.mkdir()
    bruce_dir.mkdir()
    bruce_hand.mkdir()

    monkeypatch.setattr(dl_module, "HANDSHAKES_DIR", str(hand_dir))
    monkeypatch.setattr(dl_module, "WARDRIVE_DIR", str(ward_dir))
    monkeypatch.setattr(dl_module, "BRUCE_PCAP_DIR", str(bruce_dir))
    monkeypatch.setattr(dl_module, "BRUCE_HANDSHAKES_DIR", str(bruce_hand))

    _write_wardrive_csv(
        ward_dir / "session-a.csv",
        [
            "AA:BB:CC:DD:EE:01,NetOne,WPA2,2024-01-01 00:00:00,2024-01-01 00:01:00,1,2412,-40,-22.90,-43.20,0,8,WIFI\n",
            "AA:BB:CC:DD:EE:02,NetTwo,OPEN,2024-01-01 00:02:00,2024-01-01 00:03:00,6,2437,-50,-22.91,-43.21,0,9,WIFI\n",
        ],
    )
    _write_wardrive_csv(
        ward_dir / "session-b.csv",
        [
            "AA:BB:CC:DD:EE:03,NetThree,WPA2,2024-01-02 00:00:00,2024-01-02 00:01:00,11,2462,-55,-22.93,-43.23,0,10,WIFI\n",
        ],
    )

    dl_module.reload_data()
    merged = dl_module.merge_wardrive_sessions(["session-a", "session-b"])
    merged_session_id = merged["session_id"]
    merged_path = ward_dir / "merged" / f"{merged_session_id}.csv"

    assert merged_session_id.startswith("merged-")
    assert merged_path.exists()
    merged_text = merged_path.read_text(encoding="utf-8")
    assert merged_text.count("WigleWifi-1.4") == 1
    assert merged_text.count("MAC,SSID,AuthMode") == 1
    assert "NetOne" in merged_text
    assert "NetThree" in merged_text

    manifest = json.loads((ward_dir / "manifest.json").read_text(encoding="utf-8"))
    manifest_by_session = {item["session_id"]: item for item in manifest["files"]}
    assert manifest_by_session["session-a"]["status"] == "ignored"
    assert manifest_by_session["session-b"]["status"] == "ignored"
    assert manifest_by_session[merged_session_id]["status"] == "active"
    assert manifest_by_session[merged_session_id]["role"] == "merged"
    assert manifest_by_session[merged_session_id]["merged_from_session_ids"] == [
        "session-a",
        "session-b",
    ]

    dl_module.reload_data()
    sessions = dl_module.get_wardrive_sessions()
    assert [item["session_id"] for item in sessions] == [merged_session_id]
    assert sessions[0]["session_type"] == "merged"
    assert sessions[0]["merged_from_session_ids"] == ["session-a", "session-b"]
    assert dl_module.get_wardrive_summary()["files_count"] == 1


def test_reimported_ignored_sources_stay_inactive_and_merge_lineage_flattens(
    tmp_path, monkeypatch
):
    hand_dir = tmp_path / "handshakes"
    ward_dir = tmp_path / "wardrive"
    bruce_dir = tmp_path / "BrucePCAP"
    bruce_hand = bruce_dir / "handshakes"
    hand_dir.mkdir()
    ward_dir.mkdir()
    bruce_dir.mkdir()
    bruce_hand.mkdir()

    monkeypatch.setattr(dl_module, "HANDSHAKES_DIR", str(hand_dir))
    monkeypatch.setattr(dl_module, "WARDRIVE_DIR", str(ward_dir))
    monkeypatch.setattr(dl_module, "BRUCE_PCAP_DIR", str(bruce_dir))
    monkeypatch.setattr(dl_module, "BRUCE_HANDSHAKES_DIR", str(bruce_hand))

    _write_wardrive_csv(
        ward_dir / "session-a.csv",
        [
            "AA:BB:CC:DD:EE:01,NetOne,WPA2,2024-01-01 00:00:00,2024-01-01 00:01:00,1,2412,-40,-22.90,-43.20,0,8,WIFI\n",
        ],
    )
    _write_wardrive_csv(
        ward_dir / "session-b.csv",
        [
            "AA:BB:CC:DD:EE:02,NetTwo,OPEN,2024-01-02 00:00:00,2024-01-02 00:01:00,6,2437,-50,-22.91,-43.21,0,9,WIFI\n",
        ],
    )
    dl_module.reload_data()

    merged_one = dl_module.merge_wardrive_sessions(["session-a", "session-b"])
    merged_one_id = merged_one["session_id"]
    merged_one_path = ward_dir / "merged" / f"{merged_one_id}.csv"

    (ward_dir / "session-a-copy.csv").write_text(
        (ward_dir / "session-a.csv").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (ward_dir / "merged-copy.csv").write_text(
        merged_one_path.read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    dl_module.reload_data()
    sessions_after_reimport = dl_module.get_wardrive_sessions()
    assert [item["session_id"] for item in sessions_after_reimport] == [merged_one_id]

    manifest = json.loads((ward_dir / "manifest.json").read_text(encoding="utf-8"))
    ignored_copy_map = {
        item["relative_path"]: item["status"] for item in manifest["files"]
    }
    assert ignored_copy_map["session-a-copy.csv"] == "ignored"
    assert ignored_copy_map["merged-copy.csv"] == "ignored"

    _write_wardrive_csv(
        ward_dir / "session-c.csv",
        [
            "AA:BB:CC:DD:EE:03,NetThree,WPA2,2024-01-03 00:00:00,2024-01-03 00:01:00,11,2462,-55,-22.93,-43.23,0,10,WIFI\n",
        ],
    )
    dl_module.reload_data()

    merged_two = dl_module.merge_wardrive_sessions([merged_one_id, "session-c"])
    dl_module.reload_data()
    active_sessions = dl_module.get_wardrive_sessions()
    assert [item["session_id"] for item in active_sessions] == [
        merged_two["session_id"]
    ]
    assert active_sessions[0]["merged_from_session_ids"] == [
        "session-a",
        "session-b",
        "session-c",
    ]
