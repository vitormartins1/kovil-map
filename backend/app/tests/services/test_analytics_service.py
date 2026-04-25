import pytest

from app.services import analytics_service as analytics_module


@pytest.fixture(autouse=True)
def patch_wardrive_sessions(monkeypatch):
    monkeypatch.setattr(analytics_module, "get_wardrive_sessions", lambda: [])


def _sample_dataset():
    return {
        "AA:AA:AA:AA:AA:01": {
            "mac": "AA:AA:AA:AA:AA:01",
            "ssid": "Net-1",
            "lat": -22.9038,
            "lng": -43.2096,
            "ts_last": 1_700_000_000,
            "encryption": "WPA2",
            "handshake": True,
            "usable_hash_artifact": True,
            "pass": None,
            "channel": 1,
            "frequency": 2412,
            "sources": ["pwnagotchi", "bruce_raw"],
            "raw_beacon_count": 120,
            "raw_eapol_count": 4,
            "raw_probe_peak_count": 3,
            "device_type": "router_ap",
            "device_confidence": 0.82,
        },
        "AA:AA:AA:AA:AA:02": {
            "mac": "AA:AA:AA:AA:AA:02",
            "ssid": "Net-2",
            "lat": -22.9042,
            "lng": -43.2091,
            "ts_last": 1_700_000_100,
            "encryption": "OPEN",
            "handshake": False,
            "pass": None,
            "channel": 6,
            "frequency": 2437,
            "sources": ["wardrive"],
            "raw_beacon_count": 15,
            "raw_eapol_count": 0,
            "raw_probe_peak_count": 1,
            "device_type": "unknown",
            "device_confidence": 0.21,
        },
        "AA:AA:AA:AA:AA:03": {
            "mac": "AA:AA:AA:AA:AA:03",
            "ssid": "Net-3",
            "lat": -22.9050,
            "lng": -43.2084,
            "ts_last": 1_700_000_200,
            "encryption": "WPA2",
            "handshake": True,
            "usable_hash_artifact": True,
            "pass": "already-cracked",
            "channel": 11,
            "frequency": 2462,
            "sources": ["pwnagotchi"],
            "raw_beacon_count": 40,
            "raw_eapol_count": 2,
            "raw_probe_peak_count": 2,
            "device_type": "phone_hotspot",
            "device_confidence": 0.77,
        },
        "AA:AA:AA:AA:AA:04": {
            "mac": "AA:AA:AA:AA:AA:04",
            "ssid": "NoGps",
            "lat": None,
            "lng": None,
            "ts_last": 1_700_000_300,
            "encryption": "WPA2",
            "handshake": True,
            "pass": None,
            "device_type": "camera_ap",
            "device_confidence": 0.91,
        },
    }


def test_heatmap_applies_filters_and_returns_cells(monkeypatch):
    service = analytics_module.AnalyticsService()
    monkeypatch.setattr(analytics_module, "load_real_data", lambda: _sample_dataset())

    payload = service.get_heatmap(
        metric="opportunity",
        time_window="all",
        source="all",
        security="locked",
        channel=None,
        cell_size_m=120,
    )

    assert payload["schema_version"] == service.SCHEMA_VERSION
    assert payload["filters"]["security"] == "locked"
    assert payload["stats"]["networks_count"] == 1
    assert payload["stats"]["cells_count"] == 1
    assert len(payload["cells"]) == 1
    assert payload["cells"][0]["locked_count"] == 1
    assert payload["cells"][0]["raw_eapol_sum"] == 4


def test_channel_summary_returns_expected_fields(monkeypatch):
    service = analytics_module.AnalyticsService()
    monkeypatch.setattr(analytics_module, "load_real_data", lambda: _sample_dataset())

    payload = service.get_channel_summary(
        metric="opportunity",
        time_window="all",
        source="all",
        security="all",
        channel=None,
    )

    assert payload["schema_version"] == service.SCHEMA_VERSION
    assert payload["channels"]
    first = payload["channels"][0]
    assert "channel" in first
    assert "frequency_mhz" in first
    assert "networks" in first
    assert "opportunity_score" in first
    assert 0 <= int(first["opportunity_score"]) <= 100
    assert "device_summary" in payload
    assert payload["device_summary"]
    assert payload["device_summary"][0]["device_type"] in {
        "router_ap",
        "phone_hotspot",
        "unknown",
    }


def test_device_type_filter_applies_to_rows(monkeypatch):
    service = analytics_module.AnalyticsService()
    monkeypatch.setattr(analytics_module, "load_real_data", lambda: _sample_dataset())

    payload = service.get_channel_summary(
        metric="opportunity",
        time_window="all",
        source="all",
        security="all",
        device_type="router_ap",
        channel=None,
    )

    channels = payload.get("channels") or []
    assert channels
    assert all(int(item["networks"]) == 1 for item in channels)


def test_device_type_filter_accepts_legacy_router_alias(monkeypatch):
    service = analytics_module.AnalyticsService()
    dataset = _sample_dataset()
    dataset["AA:AA:AA:AA:AA:01"]["device_type"] = "router"
    monkeypatch.setattr(analytics_module, "load_real_data", lambda: dataset)

    payload = service.get_channel_summary(
        metric="opportunity",
        time_window="all",
        source="all",
        security="all",
        device_type="router_ap",
        channel=None,
    )

    channels = payload.get("channels") or []
    assert channels
    assert sum(int(item.get("networks") or 0) for item in channels) == 1


def test_hotspots_rank_and_recommended_action(monkeypatch):
    service = analytics_module.AnalyticsService()
    monkeypatch.setattr(analytics_module, "load_real_data", lambda: _sample_dataset())
    monkeypatch.setattr(analytics_module, "get_wardrive_sessions", lambda: [])

    payload = service.get_hotspots(
        metric="eapol",
        time_window="all",
        source="all",
        security="all",
        channel=None,
        cell_size_m=120,
        limit=5,
    )

    assert payload["schema_version"] == service.SCHEMA_VERSION
    assert payload["metric"] == "eapol"
    assert isinstance(payload["hotspots"], list)
    assert payload["hotspots"]
    hotspot = payload["hotspots"][0]
    assert hotspot["id"].startswith("H")
    assert isinstance(hotspot["sample_macs"], list)
    assert isinstance(hotspot["candidate_macs"], list)
    assert hotspot["sample_macs"] == hotspot["candidate_macs"][:8]
    assert isinstance(hotspot["mesh"], list)
    assert len(hotspot["mesh"]) >= 3
    assert "recommended_action" in hotspot
    assert isinstance(hotspot["decision_factors"], list)
    assert hotspot["decision_factors"]
    assert payload["algorithm"]["name"] == "adaptive_dbscan"
    assert hotspot["radius_m"] >= 35


def test_hotspots_candidates_are_prioritized(monkeypatch):
    service = analytics_module.AnalyticsService()
    dataset = _sample_dataset()
    dataset["AA:AA:AA:AA:AA:04"] = {
        "mac": "AA:AA:AA:AA:AA:04",
        "ssid": "Net-4",
        "lat": -22.9039,
        "lng": -43.2094,
        "ts_last": 1_700_000_300,
        "encryption": "WPA2",
        "handshake": True,
        "usable_hash_artifact": True,
        "pass": None,
        "channel": 1,
        "frequency": 2412,
        "sources": ["bruce_raw"],
        "raw_beacon_count": 90,
        "raw_eapol_count": 9,
        "raw_probe_peak_count": 2,
        "device_type": "router_ap",
        "device_confidence": 0.8,
    }
    monkeypatch.setattr(analytics_module, "load_real_data", lambda: dataset)
    monkeypatch.setattr(analytics_module, "get_wardrive_sessions", lambda: [])

    payload = service.get_hotspots(metric="opportunity", source="all", limit=5)
    assert payload["hotspots"]
    hotspot = payload["hotspots"][0]
    assert hotspot["candidate_macs"][0] == "AA:AA:AA:AA:AA:04"


def test_channel_summary_includes_wardrive_context(monkeypatch):
    service = analytics_module.AnalyticsService()
    monkeypatch.setattr(analytics_module, "load_real_data", lambda: _sample_dataset())
    monkeypatch.setattr(
        analytics_module,
        "get_wardrive_sessions",
        lambda: [
            {
                "session_id": "s1",
                "started_at": 1_700_000_000,
                "ended_at": 1_700_000_100,
                "networks_count": 11,
                "points_count": 11,
                "transport_mode": "car",
            },
            {
                "session_id": "s2",
                "started_at": 1_700_000_200,
                "ended_at": 1_700_000_300,
                "networks_count": 7,
                "points_count": 7,
                "transport_mode": "walk",
            },
        ],
    )

    payload = service.get_channel_summary(metric="opportunity", time_window="all")
    context = payload["wardrive_context"]
    assert context["sessions_count"] == 2
    assert context["networks_count"] == 18
    assert context["points_count"] == 18
    assert len(context["top_transport_modes"]) == 2


def test_haversine_meters_and_percentile_helpers():
    assert analytics_module.AnalyticsService._haversine_meters(0, 0, 0, 0) == 0.0
    distance = analytics_module.AnalyticsService._haversine_meters(0, 0, 0, 1)
    assert 110_000.0 < distance < 112_000.0

    assert analytics_module.AnalyticsService._percentile([], 50.0) == 0.0
    assert analytics_module.AnalyticsService._percentile([42.0], 0.0) == 42.0
    assert (
        analytics_module.AnalyticsService._percentile([10.0, 20.0, 30.0], 50.0) == 20.0
    )
    assert (
        analytics_module.AnalyticsService._percentile([10.0, 20.0, 30.0], 25.0) == 15.0
    )
    assert (
        analytics_module.AnalyticsService._percentile([10.0, 20.0, 30.0], 110.0) == 30.0
    )


def test_convex_hull_and_fallback_mesh():
    service = analytics_module.AnalyticsService()

    assert service._convex_hull_mesh([]) == []
    assert (
        service._convex_hull_mesh([{"lat": 0.0, "lng": 0.0}, {"lat": 1.0, "lng": 1.0}])
        == []
    )

    hull = service._convex_hull_mesh(
        [
            {"lat": 0.0, "lng": 0.0},
            {"lat": 1.0, "lng": 0.0},
            {"lat": 0.0, "lng": 1.0},
            {"lat": 0.2, "lng": 0.2},
        ]
    )
    assert len(hull) == 3
    assert {tuple(sorted(point.items())) for point in hull} == {
        tuple(sorted({"lat": 0.0, "lng": 0.0}.items())),
        tuple(sorted({"lat": 1.0, "lng": 0.0}.items())),
        tuple(sorted({"lat": 0.0, "lng": 1.0}.items())),
    }

    fallback = service._fallback_mesh(45.0, 10.0, 10.0)
    assert len(fallback) == 5
    assert all("lat" in point and "lng" in point for point in fallback)

    assert service._build_hotspot_mesh(
        [{"lat": 0.0, "lng": 0.0}, {"lat": 1.0, "lng": 0.0}], 0.0, 0.0, 10.0
    ) == service._fallback_mesh(0.0, 0.0, 10.0)


def test_cluster_metric_value_and_eps_computation():
    service = analytics_module.AnalyticsService()

    assert service._cluster_metric_value({"members_count": 3}, "density") == 3.0
    assert service._cluster_metric_value({"raw_eapol_sum": 5}, "eapol") == 5.0
    assert service._cluster_metric_value({"raw_beacon_sum": 7}, "beacon") == 7.0
    assert service._cluster_metric_value({"raw_probe_peak_sum": 2}, "probe") == 2.0
    assert service._cluster_metric_value({"opportunity_avg": 4.5}, "whatever") == 4.5

    eps_m, nearest_p75 = service._compute_adaptive_eps_m(
        [
            {"lat": 0.0, "lng": 0.0},
            {"lat": 0.0, "lng": 1.0},
            {"lat": 1.0, "lng": 0.0},
        ]
    )
    assert nearest_p75 > 0.0
    assert 70.0 <= eps_m <= 220.0


def test_nearest_neighbor_distances_edge_cases():
    service = analytics_module.AnalyticsService()
    assert service._nearest_neighbor_distances([]) == []
    assert service._nearest_neighbor_distances([{"lat": 0.0, "lng": 0.0}]) == []

    distances = service._nearest_neighbor_distances(
        [
            {"lat": 0.0, "lng": 0.0},
            {"lat": 0.0, "lng": 1.0},
            {"lat": 1.0, "lng": 0.0},
        ]
    )
    assert len(distances) == 3
    assert all(distance > 0.0 for distance in distances)


def test_clamp_normalizes_values():
    assert analytics_module.AnalyticsService._clamp(5.0, 10.0, 20.0) == 10.0
    assert analytics_module.AnalyticsService._clamp(25.0, 10.0, 20.0) == 20.0
    assert analytics_module.AnalyticsService._clamp(15.0, 10.0, 20.0) == 15.0
