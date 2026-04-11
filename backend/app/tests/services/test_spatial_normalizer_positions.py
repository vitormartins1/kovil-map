import math

from app.services import spatial_normalizer as sn


def test_generate_deterministic_accuracy_range():
    mac = "AA:BB:CC:DD:EE:FF"
    first = sn.generate_deterministic_accuracy(mac)
    second = sn.generate_deterministic_accuracy(mac)
    assert first == second
    assert 3.0 <= first <= 35.0


def test_calculate_jitter_strong_and_weak_signals():
    strong = sn.calculate_deterministic_jitter("AA", "session", 10, rssi=-40)
    medium = sn.calculate_deterministic_jitter("AA", "session", 10, rssi=-65)
    weak = sn.calculate_deterministic_jitter("AA", "session", 10, rssi=-90)
    assert abs(strong[0]) < abs(medium[0])
    assert abs(weak[0]) > abs(medium[0])


def test_calculate_jitter_with_clusters():
    base = sn.calculate_deterministic_jitter(
        "AA", "session", 10, cluster_index=2, cluster_size=3
    )
    assert isinstance(base[0], float)
    assert isinstance(base[1], float)


def test_normalize_positions_without_jitter():
    networks = {
        "AA": {"lat": 12.0, "lng": 34.0, "sources": ["wardrive"]},
        "BB": {"lat": 13.0, "lng": 35.0, "sources": ["pwnagotchi"]},
    }
    out = sn.normalize_network_positions(networks, apply_jitter=False)
    assert out["AA"]["positionMode"] == sn.PositionMode.RAW.value
    assert out["BB"]["sourceType"] == "pwnagotchi"
    assert math.isclose(out["AA"]["sourcePriority"], 3)


def test_detect_position_clusters_and_prepare_display():
    networks = {
        "AA": {"lat": 0, "lng": 0, "sessionId": "s1"},
        "BB": {"lat": 0, "lng": 0, "sessionId": "s1"},
        "CC": {"lat": 1, "lng": 1},
        "DD": "invalid",
    }
    clusters = sn.detect_position_clusters(networks)
    assert len(clusters) == 2
    prepared = sn.prepare_network_for_display(
        {"displayLatitude": 9, "displayLongitude": 10}
    )
    assert prepared["lat"] == 9


def test_normalize_positions_with_cluster_jitter(monkeypatch):
    networks = {
        "AA": {"lat": 0, "lng": 0, "sources": ["wardrive"]},
        "BB": {"lat": 0, "lng": 0, "sources": ["wardrive"], "rssi": -80},
    }
    out = sn.normalize_network_positions(networks, apply_jitter=True)
    assert out["AA"]["positionMode"] == sn.PositionMode.DERIVED_JITTER.value
    assert "displayLatitude" in out["BB"]


def test_normalize_positions_enriches_wardrive_observations_without_mutating_raw_path():
    networks = {
        "AA": {
            "mac": "AA",
            "lat": 10.0,
            "lng": 20.0,
            "sources": ["wardrive"],
            "sessionId": "session-a",
            "wardrive_sessions": [
                {"session_id": "session-a", "lat": 10.0, "lng": 20.0, "acc": 7},
                {"session_id": "session-b", "lat": 11.0, "lng": 21.0, "acc": 6},
            ],
        },
        "BB": {
            "mac": "BB",
            "lat": 10.0,
            "lng": 20.0,
            "sources": ["wardrive"],
            "sessionId": "session-a",
            "wardrive_sessions": [
                {"session_id": "session-a", "lat": 10.0, "lng": 20.0, "acc": 8},
            ],
        },
    }

    out = sn.normalize_network_positions(networks, apply_jitter=True)
    obs_a = out["AA"]["wardrive_sessions"][0]
    obs_b = out["BB"]["wardrive_sessions"][0]
    other_session = out["AA"]["wardrive_sessions"][1]

    assert obs_a["rawLatitude"] == 10.0
    assert obs_a["rawLongitude"] == 20.0
    assert obs_a["lat"] == 10.0
    assert obs_a["lng"] == 20.0
    assert "displayLatitude" in obs_a
    assert "displayLongitude" in obs_a
    assert (
        obs_a["displayLatitude"] != obs_b["displayLatitude"]
        or obs_a["displayLongitude"] != obs_b["displayLongitude"]
    )
    assert other_session["displayLatitude"] == 11.0
    assert other_session["displayLongitude"] == 21.0


def test_resolve_source_priority_defaults():
    assert sn.resolve_source_priority([])[0] == "unknown"


def test_apply_jitter_to_position_alters_coordinates():
    display = sn.apply_jitter_to_position(10.0, 20.0, "AA", "s", 10.0)
    assert display != (10.0, 20.0)
