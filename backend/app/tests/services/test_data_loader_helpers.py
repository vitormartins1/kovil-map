import json
import os

import pytest

from app.services import data_loader


@pytest.fixture(autouse=True)
def tmp_dirs(tmp_path, monkeypatch):
    bruce = tmp_path / "bruce"
    m5evil = tmp_path / "m5evil"
    m5evil_handshakes = m5evil / "handshakes"
    handshakes = tmp_path / "handshakes"
    wardrive = tmp_path / "wardrive"
    bruce.mkdir()
    m5evil.mkdir()
    m5evil_handshakes.mkdir()
    handshakes.mkdir()
    wardrive.mkdir()

    monkeypatch.setattr(data_loader, "BRUCE_PCAP_DIR", str(bruce))
    monkeypatch.setattr(data_loader, "BRUCE_HANDSHAKES_DIR", str(handshakes))
    monkeypatch.setattr(data_loader, "M5EVIL_HANDSHAKES_DIR", str(m5evil_handshakes))
    monkeypatch.setattr(data_loader, "WARDRIVE_DIR", str(wardrive))
    monkeypatch.setattr(data_loader, "_DATA_CACHE", {})
    monkeypatch.setattr(data_loader, "_WARDRIVE_SESSION_TAGS", None)
    monkeypatch.setattr(data_loader, "_WARDRIVE_SESSIONS", [])

    return bruce, handshakes, wardrive, m5evil_handshakes


def test_collect_bruce_handshakes_prefers_newer(tmp_dirs):
    bruce, handshakes, _wardrive, _m5evil_handshakes = tmp_dirs
    filename = "HS_001122334455.pcap"
    f1 = handshakes / filename
    f1.write_text("")
    f2 = bruce / filename
    f2.write_text("")
    os.utime(f1, (1, 1))
    os.utime(f2, (10, 10))

    result = data_loader._collect_bruce_handshakes()
    assert result["00:11:22:33:44:55"] == filename


def test_merge_wardrive_observations():
    current = [
        {"session_id": "s1", "ts_last": "10", "acc": "5", "ts_first": "1"},
    ]
    obs = {"session_id": "s1", "ts_last": "20", "acc": "4", "ts_first": "0"}
    merged = data_loader._merge_wardrive_session_observation(current, obs)
    assert merged[0]["ts_last"] == "20"
    assert merged[0]["ts_first"] == "0"


@pytest.mark.parametrize(
    "value,expected",
    [("AABBCCDDEEFF", "AA:BB:CC:DD:EE:FF"), ("invalid", None), (None, None)],
)
def test_normalize_mac(value, expected):
    assert data_loader._normalize_mac(value) == expected


def test_parse_wigle_timestamp():
    assert data_loader._parse_wigle_timestamp("2023-01-01T00:00:00Z") is not None
    assert data_loader._parse_wigle_timestamp(" ") is None
    assert data_loader._parse_wigle_timestamp(None) is None


def test_list_bruce_handshake_files_returns_sorted(tmp_dirs):
    handshakes = tmp_dirs[1]
    file = handshakes / "HS_111111111111.pcap"
    file.write_text("x")
    assert data_loader.list_bruce_handshake_files()


def test_list_m5evil_handshake_files_returns_sorted(tmp_dirs):
    m5evil_handshakes = tmp_dirs[3]
    file = m5evil_handshakes / "HS_222222222222.pcap"
    file.write_text("x")
    assert data_loader.list_m5evil_handshake_files() == ["HS_222222222222.pcap"]


def test_parse_float():
    assert data_loader._parse_float("1.5") == pytest.approx(1.5)
    assert data_loader._parse_float("bad") is None


def test_set_wardrive_session_tag_persists_and_clears(tmp_dirs):
    wardrive_dir = tmp_dirs[2]
    data_loader._WARDRIVE_SESSIONS = [
        {
            "session_id": "session-a",
            "source_file": "session-a.csv",
            "networks_count": 2,
            "points_count": 2,
            "transport_mode": None,
        }
    ]

    updated = data_loader.set_wardrive_session_tag("session-a", "car")
    assert updated["transport_mode"] == "car"
    tags_file = wardrive_dir / "session_tags.json"
    assert tags_file.exists()
    payload = json.loads(tags_file.read_text(encoding="utf-8"))
    assert payload == {"session-a": "car"}
    assert data_loader.get_wardrive_sessions()[0]["transport_mode"] == "car"

    updated = data_loader.set_wardrive_session_tag("session-a", None)
    assert updated["transport_mode"] is None
    payload = json.loads(tags_file.read_text(encoding="utf-8"))
    assert payload == {}
    assert data_loader.get_wardrive_sessions()[0]["transport_mode"] is None


def test_set_wardrive_session_tag_validates_inputs(tmp_dirs):
    data_loader._WARDRIVE_SESSIONS = [{"session_id": "session-a"}]

    with pytest.raises(ValueError, match="session_id not found"):
        data_loader.set_wardrive_session_tag("missing", "car")

    with pytest.raises(ValueError, match="Invalid transport_mode"):
        data_loader.set_wardrive_session_tag("session-a", "rocket")
