from app.api import deps


def test_health_endpoints(client):
    deps.app_state.update({"status": "ready"})

    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.json()["data"]["status"] == "online"

    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["data"]["status"] == "ready"
