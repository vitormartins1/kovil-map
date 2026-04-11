from app.api.routers import insights as insights_router


def test_insights_score_and_recommendation_endpoints(client, monkeypatch):
    monkeypatch.setattr(
        insights_router.insights_service,
        "get_attack_score",
        lambda mac=None, filename=None, capture_id=None, combined_build_id=None: {
            "present": True,
            "target": {
                "mac": mac,
                "filename": filename,
                "capture_id": capture_id,
                "combined_build_id": combined_build_id,
            },
            "score": 80,
            "priority": "high",
        },
    )
    monkeypatch.setattr(
        insights_router.insights_service,
        "get_attack_recommendation",
        lambda mac=None, filename=None, capture_id=None, combined_build_id=None: {
            "target": {
                "mac": mac,
                "filename": filename,
                "capture_id": capture_id,
                "combined_build_id": combined_build_id,
            },
            "action": "run",
            "recommended_mode": "rules",
            "attempt_feedback": {
                "scope": "hashcat",
                "totals": {"attempts": 2},
                "by_mode": [],
                "recent": [],
                "tip": None,
            },
        },
    )
    monkeypatch.setattr(
        insights_router.insights_service,
        "evaluate_quality_gate",
        lambda filename, attack_mode=None, capture_id=None, combined_build_id=None, mac=None: {
            "passed": True,
            "filename": filename,
            "attack_mode": attack_mode,
            "capture_id": capture_id,
            "combined_build_id": combined_build_id,
            "mac": mac,
        },
    )
    monkeypatch.setattr(
        insights_router.insights_service,
        "get_handshake_readiness",
        lambda mac=None, filename=None, capture_id=None, combined_build_id=None: {
            "present": True,
            "target": {
                "mac": mac,
                "filename": filename,
                "capture_id": capture_id,
                "combined_build_id": combined_build_id,
            },
            "readiness": {"status": "ready", "score": 80},
        },
    )

    resp = client.get("/api/insights/score", params={"mac": "AA:BB:CC:DD:EE:FF"})
    assert resp.status_code == 200
    assert resp.json()["data"]["score"] == 80

    resp = client.get(
        "/api/insights/attack-recommendation", params={"filename": "test.22000"}
    )
    assert resp.status_code == 200
    assert resp.json()["data"]["recommended_mode"] == "rules"
    assert resp.json()["data"]["attempt_feedback"]["scope"] == "hashcat"

    resp = client.get(
        "/api/insights/quality-gate",
        params={"filename": "test.22000", "attack_mode": "rules"},
    )
    assert resp.status_code == 200
    assert resp.json()["data"]["passed"] is True

    resp = client.get(
        "/api/insights/handshake-readiness", params={"filename": "test.22000"}
    )
    assert resp.status_code == 200
    assert resp.json()["data"]["readiness"]["status"] == "ready"


def test_insights_score_requires_mac_or_filename(client):
    resp = client.get("/api/insights/score")
    assert resp.status_code == 400
    payload = resp.json()
    assert payload.get("status") == "error" or "detail" in payload
