from app.api.routers import wardrive as wardrive_router


def _error_message(resp):
    payload = resp.json()
    if isinstance(payload.get("error"), dict):
        return payload["error"].get("message", "")
    detail = payload.get("detail")
    if isinstance(detail, dict):
        return detail.get("message", "")
    return str(detail or "")


def test_wardrive_hierarchy_endpoint(client, monkeypatch):
    captured = {}

    def _fake_hierarchy(**kwargs):
        captured.update(kwargs)
        return {
            "maps_summary": {"loaded_files": 1},
            "regions": [
                {"id": "city:3304557", "level": "city", "stats": {"networks_count": 3}}
            ],
            "unmapped_summary": {"networks_count": 0},
        }

    monkeypatch.setattr(
        wardrive_router.wardrive_regions_service,
        "get_hierarchy",
        _fake_hierarchy,
    )

    resp = client.get(
        "/api/wardrive/hierarchy?time_window=24h&source=pwn&session_ids=session-a,session-b"
    )
    assert resp.status_code == 200
    payload = resp.json()["data"]
    assert payload["maps_summary"]["loaded_files"] == 1
    assert payload["regions"][0]["id"] == "city:3304557"
    assert captured["session_ids"] == ["session-a", "session-b"]


def test_wardrive_hierarchy_invalid_params(client):
    resp = client.get("/api/wardrive/hierarchy?time_window=1h")
    assert resp.status_code == 400
    assert "Invalid time_window" in _error_message(resp)

    resp = client.get("/api/wardrive/hierarchy?source=unknown")
    assert resp.status_code == 400
    assert "Invalid source" in _error_message(resp)


def test_wardrive_zones_endpoint(client, monkeypatch):
    captured = {}

    def _fake_zones(**kwargs):
        captured.update(kwargs)
        return {
            "region": {"id": kwargs["region_id"], "level": "city"},
            "zones": [{"id": 0, "count": 4}],
            "stats": {"networks_count": 4},
            "params": kwargs,
        }

    monkeypatch.setattr(
        wardrive_router.wardrive_regions_service,
        "get_region_zones",
        _fake_zones,
    )

    resp = client.post(
        "/api/wardrive/zones",
        json={
            "region_id": "city:3304557",
            "eps_m": 220,
            "min_samples": 3,
            "time_window": "all",
            "source": "all",
            "session_ids": ["session-a"],
        },
    )
    assert resp.status_code == 200
    assert resp.json()["data"]["zones"][0]["count"] == 4
    assert captured["session_ids"] == ["session-a"]


def test_wardrive_inventory_and_sessions_endpoints(client, monkeypatch):
    monkeypatch.setattr(
        wardrive_router.wardrive_regions_service,
        "get_maps_inventory",
        lambda: {"loaded_files": 5, "active_datasets": []},
    )
    monkeypatch.setattr(
        wardrive_router.wardrive_regions_service,
        "get_sessions",
        lambda **kwargs: {
            "time_window": kwargs["time_window"],
            "sessions": [
                {"session_id": "session-a", "points_count": 2, "distance_m": 420}
            ],
            "summary": {"sessions_count": 1},
        },
    )

    inventory = client.get("/api/wardrive/inventory")
    assert inventory.status_code == 200
    assert inventory.json()["data"]["loaded_files"] == 5

    sessions = client.get("/api/wardrive/sessions?time_window=24h")
    assert sessions.status_code == 200
    assert sessions.json()["data"]["sessions"][0]["session_id"] == "session-a"
    assert sessions.json()["data"]["sessions"][0]["distance_m"] == 420
    assert sessions.json()["data"]["time_window"] == "24h"


def test_wardrive_sessions_tag_endpoint(client, monkeypatch):
    monkeypatch.setattr(
        wardrive_router.wardrive_regions_service,
        "set_session_tag",
        lambda **kwargs: {
            "session": {
                "session_id": kwargs["session_id"],
                "transport_mode": kwargs["transport_mode"],
            },
            "summary": {
                "sessions_count": 1,
                "transport_modes": [{"transport_mode": "car", "sessions_count": 1}],
            },
            "time_window": "all",
        },
    )

    resp = client.post(
        "/api/wardrive/sessions/tag",
        json={"session_id": "session-a", "transport_mode": "car"},
    )
    assert resp.status_code == 200
    payload = resp.json()["data"]
    assert payload["session"]["session_id"] == "session-a"
    assert payload["session"]["transport_mode"] == "car"


def test_wardrive_sessions_tracks_endpoint(client, monkeypatch):
    monkeypatch.setattr(
        wardrive_router.wardrive_regions_service,
        "get_session_tracks",
        lambda **kwargs: {
            "tracks": [
                {
                    "session_id": "session-a",
                    "label": "Session A",
                    "source_file": "session-a.csv",
                    "bbox": {
                        "min_lat": -22.91,
                        "min_lng": -43.2,
                        "max_lat": -22.9,
                        "max_lng": -43.19,
                    },
                    "center": {"lat": -22.905, "lng": -43.195},
                    "points": [{"lat": -22.91, "lng": -43.2, "ts_last": 1, "acc": 8.0}],
                    "distance_m": 0,
                    "duration_s": 0,
                    "points_count": 1,
                    "avg_accuracy_m": 8.0,
                }
            ],
            "summary": {"requested_sessions": 1, "returned_tracks": 1},
        },
    )

    resp = client.post(
        "/api/wardrive/sessions/tracks",
        json={"session_ids": ["session-a"]},
    )
    assert resp.status_code == 200
    payload = resp.json()["data"]
    assert payload["tracks"][0]["session_id"] == "session-a"
    assert payload["summary"]["returned_tracks"] == 1


def test_wardrive_sessions_merge_endpoint(client, monkeypatch):
    captured = {}
    emitted = []

    async def _fake_broadcast(message):
        emitted.append(message)

    monkeypatch.setattr(
        wardrive_router.wardrive_regions_service,
        "merge_sessions",
        lambda **kwargs: (
            {
                "session": {
                    "session_id": "merged-20260326-120000",
                    "session_type": "merged",
                    "merged_from_session_ids": ["session-a", "session-b"],
                },
                "merge_sources": [
                    {"session_id": "session-a"},
                    {"session_id": "session-b"},
                ],
                "summary": {"sessions_count": 1},
                "time_window": "all",
            }
            if not captured.update(kwargs)
            else None
        ),
    )
    monkeypatch.setattr(wardrive_router.manager, "broadcast", _fake_broadcast)

    resp = client.post(
        "/api/wardrive/sessions/merge",
        json={"session_ids": ["session-a", "session-b"]},
    )
    assert resp.status_code == 200
    payload = resp.json()["data"]
    assert payload["session"]["session_id"] == "merged-20260326-120000"
    assert payload["session"]["session_type"] == "merged"
    assert captured["session_ids"] == ["session-a", "session-b"]
    assert emitted == [{"type": "data_update", "payload": "map_data"}]


def test_wardrive_sessions_tracks_endpoint_handles_validation_error(
    client, monkeypatch
):
    def _raise(**_kwargs):
        raise ValueError("session_ids supports up to 3 sessions")

    monkeypatch.setattr(
        wardrive_router.wardrive_regions_service, "get_session_tracks", _raise
    )
    resp = client.post(
        "/api/wardrive/sessions/tracks",
        json={"session_ids": ["a", "b", "c", "d"]},
    )
    assert resp.status_code == 400
    assert "supports up to 3 sessions" in _error_message(resp)


def test_wardrive_sessions_tag_endpoint_handles_validation_error(client, monkeypatch):
    def _raise(**_kwargs):
        raise ValueError("Invalid transport_mode. Allowed: walk, bike")

    monkeypatch.setattr(
        wardrive_router.wardrive_regions_service, "set_session_tag", _raise
    )
    resp = client.post(
        "/api/wardrive/sessions/tag",
        json={"session_id": "session-a", "transport_mode": "rocket"},
    )
    assert resp.status_code == 400
    assert "Invalid transport_mode" in _error_message(resp)


def test_wardrive_sessions_merge_endpoint_handles_validation_error(client, monkeypatch):
    def _raise(**_kwargs):
        raise ValueError("session_ids supports up to 3 sessions")

    monkeypatch.setattr(
        wardrive_router.wardrive_regions_service, "merge_sessions", _raise
    )
    resp = client.post(
        "/api/wardrive/sessions/merge",
        json={"session_ids": ["a", "b", "c", "d"]},
    )
    assert resp.status_code == 400
    assert "supports up to 3 sessions" in _error_message(resp)


def test_wardrive_refresh_endpoint(client, monkeypatch):
    captured = {}

    def _fake_refresh_runtime(**kwargs):
        captured.update(kwargs)
        return {
            "status": "ok",
            "reload_data": kwargs["reload_data_enabled"],
            "reload_maps": kwargs["reload_maps"],
            "wardrive_summary": {
                "files_count": 1,
                "networks_count": 2,
                "sessions_count": 1,
            },
            "sessions_count": 1,
            "maps_revision": 2,
            "data_revision": 5,
        }

    monkeypatch.setattr(
        wardrive_router.wardrive_regions_service,
        "refresh_runtime",
        _fake_refresh_runtime,
    )

    resp = client.post(
        "/api/wardrive/refresh", json={"reload_data": True, "reload_maps": True}
    )
    assert resp.status_code == 200
    payload = resp.json()["data"]
    assert payload["status"] == "ok"
    assert payload["reload_maps"] is True
    assert captured["reload_data_enabled"] is True
    assert captured["reload_maps"] is True


def test_wardrive_zones_validates_params_and_not_found(client, monkeypatch):
    resp = client.post(
        "/api/wardrive/zones",
        json={
            "region_id": "city:3304557",
            "eps_m": 0,
            "min_samples": 3,
            "time_window": "all",
            "source": "all",
        },
    )
    assert resp.status_code == 400
    assert "eps_m must be greater than 0" in _error_message(resp)

    resp = client.post(
        "/api/wardrive/zones",
        json={
            "region_id": "city:3304557",
            "eps_m": 100,
            "min_samples": 0,
            "time_window": "all",
            "source": "all",
        },
    )
    assert resp.status_code == 400
    assert "min_samples must be greater than or equal to 1" in _error_message(resp)

    def _raise_not_found(**_kwargs):
        raise ValueError("region_id not found")

    monkeypatch.setattr(
        wardrive_router.wardrive_regions_service, "get_region_zones", _raise_not_found
    )
    resp = client.post(
        "/api/wardrive/zones",
        json={
            "region_id": "city:unknown",
            "eps_m": 100,
            "min_samples": 2,
            "time_window": "all",
            "source": "all",
        },
    )
    assert resp.status_code == 404
    assert "region_id not found" in _error_message(resp)


def test_wardrive_hierarchy_rejects_unknown_session_ids(client, monkeypatch):
    def _raise(**_kwargs):
        raise ValueError("session_ids not found: missing-session")

    monkeypatch.setattr(
        wardrive_router.wardrive_regions_service, "get_hierarchy", _raise
    )
    resp = client.get("/api/wardrive/hierarchy?session_ids=missing-session")
    assert resp.status_code == 400
    assert "session_ids not found" in _error_message(resp)
