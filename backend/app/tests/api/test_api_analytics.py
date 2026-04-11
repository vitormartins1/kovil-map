from app.api.routers import analytics as analytics_router


def test_analytics_endpoints_return_payloads(client, monkeypatch):
    monkeypatch.setattr(
        analytics_router.analytics_service,
        "get_heatmap",
        lambda **kwargs: {
            "schema_version": 1,
            "filters": kwargs,
            "stats": {"cells_count": 1},
            "cells": [{"lat": 0.0, "lng": 0.0, "value": 1}],
        },
    )
    monkeypatch.setattr(
        analytics_router.analytics_service,
        "get_channel_summary",
        lambda **kwargs: {
            "schema_version": 1,
            "filters": kwargs,
            "channels": [{"channel": 1, "opportunity_score": 80}],
            "device_summary": [
                {"device_type": "router_ap", "networks": 1, "opportunity_score": 80}
            ],
            "wardrive_context": {
                "sessions_count": 1,
                "networks_count": 10,
                "points_count": 10,
                "top_transport_modes": [
                    {
                        "transport_mode": "car",
                        "sessions_count": 1,
                        "networks_count": 10,
                        "points_count": 10,
                    }
                ],
            },
        },
    )
    monkeypatch.setattr(
        analytics_router.analytics_service,
        "get_hotspots",
        lambda **kwargs: {
            "schema_version": 1,
            "metric": kwargs.get("metric"),
            "filters": kwargs,
            "hotspots": [
                {
                    "id": "H1",
                    "score": 90,
                    "mesh": [
                        {"lat": -22.9, "lng": -43.2},
                        {"lat": -22.91, "lng": -43.19},
                        {"lat": -22.89, "lng": -43.18},
                    ],
                    "decision_factors": ["2 locked networks concentrate here."],
                }
            ],
        },
    )

    resp = client.get("/api/analytics/heatmap", params={"metric": "opportunity"})
    assert resp.status_code == 200
    assert resp.json()["data"]["stats"]["cells_count"] == 1

    resp = client.get("/api/analytics/channel-summary", params={"source": "all"})
    assert resp.status_code == 200
    assert resp.json()["data"]["channels"][0]["channel"] == 1
    assert resp.json()["data"]["device_summary"][0]["device_type"] == "router_ap"
    assert resp.json()["data"]["wardrive_context"]["sessions_count"] == 1

    resp = client.get("/api/analytics/hotspots", params={"metric": "eapol", "limit": 5})
    assert resp.status_code == 200
    assert resp.json()["data"]["hotspots"][0]["id"] == "H1"
    assert resp.json()["data"]["hotspots"][0]["decision_factors"]


def test_analytics_endpoints_validate_queries(client):
    resp = client.get("/api/analytics/heatmap", params={"metric": "unknown"})
    assert resp.status_code == 400

    resp = client.get("/api/analytics/channel-summary", params={"security": "bad"})
    assert resp.status_code == 400

    resp = client.get("/api/analytics/hotspots", params={"device_type": "bad-type"})
    assert resp.status_code == 400

    resp = client.get("/api/analytics/hotspots", params={"cell_size_m": 500})
    assert resp.status_code == 400
