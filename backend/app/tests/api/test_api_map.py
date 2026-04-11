from app.api.routers import map as map_router


def test_map_data(client, monkeypatch):
    monkeypatch.setattr(map_router, "load_real_data", lambda: {"x": 1})
    resp = client.get("/api/map/data")
    assert resp.status_code == 200
    assert resp.json()["data"]["x"] == 1
