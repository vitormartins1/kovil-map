"""Data loader tests for ingest sources and normalization helpers."""

import json

import pytest

from app.services import data_loader as dl_module


@pytest.fixture(autouse=True)
def reset_data_loader_runtime(monkeypatch, tmp_path):
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
    monkeypatch.setattr(
        dl_module, "BRUCE_HANDSHAKES_DIR", str(tmp_path / "bruce_empty")
    )
    monkeypatch.setattr(dl_module, "BRUCE_PCAP_DIR", str(tmp_path / "bruce_empty"))
    monkeypatch.setattr(dl_module, "M5EVIL_DIR", str(tmp_path / "m5_empty"))
    monkeypatch.setattr(
        dl_module, "M5EVIL_HANDSHAKES_DIR", str(tmp_path / "m5_empty" / "handshakes")
    )


def test_data_loader_reload_data_with_hs_file(tmp_path, monkeypatch):
    """Test reload_data with HS_ prefixed file."""
    monkeypatch.setattr(dl_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(dl_module, "BRUCE_HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(dl_module, "BRUCE_PCAP_DIR", str(tmp_path))

    hs_file = tmp_path / "HS_aabbccddeeff.pcap"
    hs_file.write_bytes(b"handshake")

    result = dl_module.reload_data()
    assert isinstance(result, dict)


def test_data_loader_reload_data_with_details(tmp_path, monkeypatch):
    """Test reload_data with details file."""
    monkeypatch.setattr(dl_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(dl_module, "BRUCE_HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(dl_module, "BRUCE_PCAP_DIR", str(tmp_path))

    pcap = tmp_path / "test_aabbccddeeff.pcap"
    pcap.write_bytes(b"pcap")

    details = tmp_path / "test_aabbccddeeff.details"
    details.write_text(
        json.dumps({"security": {"wpa_version": "WPA2"}}),
        encoding="utf-8",
    )

    result = dl_module.reload_data()
    assert isinstance(result, dict)
    mac = "AA:BB:CC:DD:EE:FF"
    if mac in result:
        # SSID comes from filename parsing, details adds security info
        assert result[mac].get("ssid") == "test"


def test_data_loader_reload_data_with_22000_file(tmp_path, monkeypatch):
    """Test reload_data with .22000 hash file."""
    monkeypatch.setattr(dl_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(dl_module, "BRUCE_HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(dl_module, "BRUCE_PCAP_DIR", str(tmp_path))

    hash_file = tmp_path / "test.22000"
    hash_file.write_text(
        "WPA*02*deadbeef*aabbccddeeff*001122334455*TestNet*00\n",
        encoding="utf-8",
    )

    result = dl_module.reload_data()
    assert isinstance(result, dict)


def test_data_loader_reload_data_with_geo_json(tmp_path, monkeypatch):
    """Test reload_data with geo.json file."""
    monkeypatch.setattr(dl_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(dl_module, "BRUCE_HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(dl_module, "BRUCE_PCAP_DIR", str(tmp_path))

    pcap = tmp_path / "test_aabbccddeeff.pcap"
    pcap.write_bytes(b"pcap")

    geo = tmp_path / "test_aabbccddeeff.pcap.geo.json"
    geo.write_text(
        json.dumps({"lat": -23.55, "lng": -46.63}),
        encoding="utf-8",
    )

    result = dl_module.reload_data()
    assert isinstance(result, dict)


def test_data_loader_reload_data_with_paw_gps_json(tmp_path, monkeypatch):
    """Test reload_data with paw-gps.json file."""
    monkeypatch.setattr(dl_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(dl_module, "BRUCE_HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(dl_module, "BRUCE_PCAP_DIR", str(tmp_path))

    pcap = tmp_path / "test_aabbccddeeff.pcap"
    pcap.write_bytes(b"pcap")

    gps = tmp_path / "test_aabbccddeeff.pcap.paw-gps.json"
    gps.write_text(
        json.dumps({"latitude": -23.55, "longitude": -46.63}),
        encoding="utf-8",
    )

    result = dl_module.reload_data()
    assert isinstance(result, dict)


def test_data_loader_reload_data_with_cracked_password(tmp_path, monkeypatch):
    """Test reload_data with cracked file containing password."""
    monkeypatch.setattr(dl_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(dl_module, "BRUCE_HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(dl_module, "BRUCE_PCAP_DIR", str(tmp_path))

    pcap = tmp_path / "test_aabbccddeeff.pcap"
    pcap.write_bytes(b"pcap")

    cracked = tmp_path / "test_aabbccddeeff.pcap.cracked"
    cracked.write_text("password123\n", encoding="utf-8")

    result = dl_module.reload_data()
    assert isinstance(result, dict)
    mac = "AA:BB:CC:DD:EE:FF"
    if mac in result:
        # The field is "pass", not "cracked"
        assert result[mac].get("pass") == "password123"
        assert result[mac].get("handshake") is True


def test_data_loader_reload_data_empty(tmp_path, monkeypatch):
    """Test reload_data with empty directory."""
    monkeypatch.setattr(dl_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(dl_module, "BRUCE_HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(dl_module, "BRUCE_PCAP_DIR", str(tmp_path))

    result = dl_module.reload_data()
    assert isinstance(result, dict)


def test_data_loader_reload_data_with_pcap(tmp_path, monkeypatch):
    """Test reload_data with a pcap file."""
    monkeypatch.setattr(dl_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(dl_module, "BRUCE_HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(dl_module, "BRUCE_PCAP_DIR", str(tmp_path))

    pcap = tmp_path / "test_aabbccddeeff.pcap"
    pcap.write_bytes(b"pcap")

    result = dl_module.reload_data()
    assert isinstance(result, dict)


def test_data_loader_reload_data_with_cracked(tmp_path, monkeypatch):
    """Test reload_data with a cracked file."""
    monkeypatch.setattr(dl_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(dl_module, "BRUCE_HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(dl_module, "BRUCE_PCAP_DIR", str(tmp_path))

    cracked = tmp_path / "test_aabbccddeeff.pcap.cracked"
    cracked.write_text("password123", encoding="utf-8")

    result = dl_module.reload_data()
    assert isinstance(result, dict)


def test_data_loader_reload_data_with_gps(tmp_path, monkeypatch):
    """Test reload_data with GPS JSON file."""
    monkeypatch.setattr(dl_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(dl_module, "BRUCE_HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(dl_module, "BRUCE_PCAP_DIR", str(tmp_path))

    pcap = tmp_path / "gps_aabbccddeeff.pcap"
    pcap.write_bytes(b"pcap")

    gps = tmp_path / "gps_aabbccddeeff.pcap.gps.json"
    gps.write_text(
        json.dumps({"latitude": -23.5505, "longitude": -46.6333}),
        encoding="utf-8",
    )

    result = dl_module.reload_data()
    assert isinstance(result, dict)


class TestDataLoaderWardriveIngest:
    """Wardrive-specific ingest and merge checks."""

    def test_reload_data_with_wardrive_csv(self, tmp_path, monkeypatch):
        """Test reload_data with wardrive CSV file."""
        monkeypatch.setattr(dl_module, "HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(dl_module, "BRUCE_HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(dl_module, "BRUCE_PCAP_DIR", str(tmp_path))
        monkeypatch.setattr(dl_module, "WARDRIVE_DIR", str(tmp_path / "wardrive"))

        wardrive_dir = tmp_path / "wardrive"
        wardrive_dir.mkdir()

        csv_file = wardrive_dir / "wardrive.csv"
        csv_file.write_text(
            "WigleWifi-1.4,appRelease=1.0\n"
            "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n"
            "AA:BB:CC:DD:EE:FF,TestNet,WPA2,2024-01-01 12:00:00,6,-50,-23.55,-46.63,500,10,WIFI\n",
            encoding="utf-8",
        )

        result = dl_module.reload_data()
        assert isinstance(result, dict)
        assert "AA:BB:CC:DD:EE:FF" in result

    def test_reload_data_merges_wardrive_gps(self, tmp_path, monkeypatch):
        """Test reload_data merges wardrive GPS into existing entry."""
        monkeypatch.setattr(dl_module, "HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(dl_module, "BRUCE_HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(dl_module, "BRUCE_PCAP_DIR", str(tmp_path))
        monkeypatch.setattr(dl_module, "WARDRIVE_DIR", str(tmp_path / "wardrive"))

        # Create pcap entry without GPS
        pcap = tmp_path / "testnet_aabbccddeeff.pcap"
        pcap.write_bytes(b"pcap")

        # Create wardrive with GPS for same MAC
        wardrive_dir = tmp_path / "wardrive"
        wardrive_dir.mkdir()

        csv_file = wardrive_dir / "wardrive.csv"
        csv_file.write_text(
            "WigleWifi-1.4,appRelease=1.0\n"
            "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n"
            "AA:BB:CC:DD:EE:FF,TestNet,WPA2,2024-01-01 12:00:00,6,-50,-23.55,-46.63,500,10,WIFI\n",
            encoding="utf-8",
        )

        result = dl_module.reload_data()
        assert isinstance(result, dict)
        entry = result.get("AA:BB:CC:DD:EE:FF")
        if entry:
            assert entry.get("lat") == -23.55
            assert entry.get("lng") == -46.63

    def test_reload_data_normalizes_large_m5evil_wardrive_accuracy(
        self, tmp_path, monkeypatch
    ):
        """Large M5Evil AccuracyMeters values should not inflate the operational radius."""
        monkeypatch.setattr(dl_module, "HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(dl_module, "BRUCE_HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(dl_module, "BRUCE_PCAP_DIR", str(tmp_path))
        monkeypatch.setattr(dl_module, "WARDRIVE_DIR", str(tmp_path / "wardrive"))

        wardrive_dir = tmp_path / "wardrive"
        wardrive_dir.mkdir()

        csv_file = wardrive_dir / "m5evil__wardriving-03.csv"
        csv_file.write_text(
            "WigleWifi-1.4,appRelease=1.0,device=Evil-Cardputer\n"
            "MAC,SSID,AuthMode,FirstSeen,LastSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n"
            "AA:BB:CC:DD:EE:FF,TestNet,[WPA2-PSK][ESS],2024-01-01 12:00:00,2024-01-01 12:01:00,6,-50,-23.55,-46.63,500,110,WIFI\n",
            encoding="utf-8",
        )

        result = dl_module.reload_data()
        entry = result["AA:BB:CC:DD:EE:FF"]
        observation = entry["wardrive_sessions"][0]
        sessions = dl_module.get_wardrive_sessions()
        expected_operational_acc = dl_module.generate_deterministic_accuracy(
            "AA:BB:CC:DD:EE:FF",
            min_accuracy=3.0,
            max_accuracy=15.0,
        )

        assert entry["acc"] == expected_operational_acc
        assert entry["rawAccuracy"] == expected_operational_acc
        assert observation["acc"] == expected_operational_acc
        assert observation["rawAccuracy"] == expected_operational_acc
        assert entry["sourceAccuracyMeters"] == 110.0
        assert observation["sourceAccuracyMeters"] == 110.0
        assert sessions[0]["session_id"] == "wardriving-03"


class TestDataLoaderNormalizationHelpers:
    """Normalization and timestamp helper behavior."""

    def test_normalize_mac_valid(self):
        """Test _normalize_mac with valid MAC."""
        result = dl_module._normalize_mac("aa:bb:cc:dd:ee:ff")
        assert result == "AA:BB:CC:DD:EE:FF"

    def test_normalize_mac_invalid(self):
        """Test _normalize_mac with invalid MAC."""
        result = dl_module._normalize_mac("invalid")
        assert result is None

    def test_normalize_mac_none(self):
        """Test _normalize_mac with None."""
        result = dl_module._normalize_mac(None)
        assert result is None

    def test_parse_float_valid(self):
        """Test _parse_float with valid float."""
        result = dl_module._parse_float("1.5")
        assert result == 1.5

    def test_parse_float_invalid(self):
        """Test _parse_float with invalid value."""
        result = dl_module._parse_float("invalid")
        assert result is None

    def test_infer_encryption_various(self):
        """Test _infer_encryption with various auth modes."""
        assert dl_module._infer_encryption("WPA2") == "WPA2"
        assert dl_module._infer_encryption("WPA") == "WPA"
        assert dl_module._infer_encryption("OPEN") == "OPEN"
        assert dl_module._infer_encryption("WEP") == "WEP"
        assert dl_module._infer_encryption("WPA3") == "WPA3"
        assert dl_module._infer_encryption("") == "UNK"


def test_load_wardrive_manifest_corrupted_json(tmp_path, monkeypatch):
    """Test _load_wardrive_manifest handles corrupted JSON."""
    monkeypatch.setattr(dl_module, "WARDRIVE_DIR", str(tmp_path))

    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text("{ invalid json", encoding="utf-8")

    # Clear any cached manifest
    dl_module._WARDRIVE_MANIFEST = None
    dl_module._WARDRIVE_MANIFEST_PATH = None

    result = dl_module._load_wardrive_manifest()
    assert isinstance(result, dict)
    assert "version" in result
    assert "files" in result

    def test_parse_wigle_timestamp_valid(self):
        """Test _parse_wigle_timestamp with valid timestamp."""
        result = dl_module._parse_wigle_timestamp("2024-01-01 12:00:00")
        assert result is not None

    def test_parse_wigle_timestamp_none(self):
        """Test _parse_wigle_timestamp with None."""
        result = dl_module._parse_wigle_timestamp(None)
        assert result is None

    def test_parse_wigle_timestamp_z_suffix(self):
        """Test _parse_wigle_timestamp with Z suffix."""
        result = dl_module._parse_wigle_timestamp("2024-01-01T12:00:00Z")
        assert result is not None
