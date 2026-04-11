from app.api.routers import zones as zones_router
import pytest
from types import SimpleNamespace


def test_zones_endpoints(client, monkeypatch):
    monkeypatch.setattr(
        zones_router, "build_conquered_zones", lambda *args, **kwargs: [{"id": 1}]
    )
    monkeypatch.setattr(
        zones_router, "build_to_conquer_zones", lambda *args, **kwargs: [{"id": 2}]
    )

    resp = client.post(
        "/api/zones",
        json={
            "points": [{"lat": 1, "lng": 2, "acc": 3}],
            "eps_m": 200,
            "min_samples": 1,
        },
    )
    assert resp.status_code == 200
    assert resp.json()["data"]["zones"][0]["id"] == 1

    resp = client.post(
        "/api/zones/to-conquer",
        json={
            "conquered_points": [{"lat": 1, "lng": 2, "acc": 3}],
            "to_conquer_points": [{"lat": 3, "lng": 4, "acc": 5}],
            "eps_m": 200,
            "min_samples": 1,
            "acc_segments": 8,
            "min_zone_points": 5,
        },
    )
    assert resp.status_code == 200
    assert resp.json()["data"]["zones"][0]["id"] == 2


def test_zones_invalid_params_and_sanitize(client, monkeypatch):
    monkeypatch.setattr(zones_router, "build_conquered_zones", lambda *a, **k: [])
    monkeypatch.setattr(zones_router, "build_to_conquer_zones", lambda *a, **k: [])

    resp = client.post(
        "/api/zones",
        json={"points": [], "eps_m": "bad", "min_samples": 1},
    )
    assert resp.status_code == 422

    resp = client.post(
        "/api/zones",
        json={
            "points": [{"lat": 1, "lng": 2, "acc": None}, {"lat": "x", "lng": 2}],
            "eps_m": 200,
            "min_samples": 1,
        },
    )
    assert resp.status_code == 200

    resp = client.post(
        "/api/zones/to-conquer",
        json={
            "conquered_points": [],
            "to_conquer_points": [],
            "eps_m": 200,
            "min_samples": "bad",
            "acc_segments": 8,
        },
    )
    assert resp.status_code == 422


def test_get_zones_direct_invalid_params_calls_fail(monkeypatch):
    monkeypatch.setattr(
        zones_router, "fail", lambda msg: (_ for _ in ()).throw(RuntimeError(msg))
    )
    payload = SimpleNamespace(points=[], eps_m="bad", min_samples="bad")
    with pytest.raises(RuntimeError, match="Invalid eps_m or min_samples"):
        zones_router.get_zones(payload)


def test_get_to_conquer_direct_invalid_params_calls_fail(monkeypatch):
    monkeypatch.setattr(
        zones_router, "fail", lambda msg: (_ for _ in ()).throw(RuntimeError(msg))
    )
    payload = SimpleNamespace(
        conquered_points=[],
        to_conquer_points=[],
        eps_m=200,
        min_samples=1,
        acc_segments="bad",
        min_zone_points=2,
    )
    with pytest.raises(RuntimeError, match="Invalid params"):
        zones_router.get_to_conquer_zones(payload)


def test_zones_direct_sanitize_filters_non_dict_and_invalid_numbers(monkeypatch):
    captured = {}

    def _build_conquered(points, **kwargs):
        captured["points"] = points
        captured["kwargs"] = kwargs
        return [{"id": 99}]

    monkeypatch.setattr(zones_router, "build_conquered_zones", _build_conquered)

    payload = SimpleNamespace(
        points=[
            "not-a-dict",
            {"lat": None, "lng": 1},
            {"lat": "x", "lng": 1},
            {"lat": 1, "lng": 2, "acc": None},
        ],
        eps_m="200.5",
        min_samples="2",
    )
    out = zones_router.get_zones(payload)
    assert captured["points"] == [{"lat": 1.0, "lng": 2.0, "acc": 0.0}]
    assert captured["kwargs"] == {"eps_m": 200.5, "min_samples": 2}
    assert out["data"]["zones"][0]["id"] == 99


def test_to_conquer_direct_sanitize_filters_points(monkeypatch):
    captured = {}

    def _build_to_conquer(conquered, to_conquer, **kwargs):
        captured["conquered"] = conquered
        captured["to_conquer"] = to_conquer
        captured["kwargs"] = kwargs
        return [{"id": 42}]

    monkeypatch.setattr(zones_router, "build_to_conquer_zones", _build_to_conquer)

    payload = SimpleNamespace(
        conquered_points=[
            {"lat": 1, "lng": 2, "acc": None},
            {"lat": "bad", "lng": 1},
            [],
        ],
        to_conquer_points=[
            {"lat": 3, "lng": 4, "acc": "5"},
            {"lat": 3, "lng": None},
        ],
        eps_m="350",
        min_samples="3",
        acc_segments="16",
        min_zone_points="5",
    )
    out = zones_router.get_to_conquer_zones(payload)
    assert captured["conquered"] == [{"lat": 1.0, "lng": 2.0, "acc": 0.0}]
    assert captured["to_conquer"] == [{"lat": 3.0, "lng": 4.0, "acc": 5.0}]
    assert captured["kwargs"] == {
        "eps_m": 350.0,
        "min_samples": 3,
        "acc_segments": 16,
        "min_zone_points": 5,
    }
    assert out["data"]["zones"][0]["id"] == 42
