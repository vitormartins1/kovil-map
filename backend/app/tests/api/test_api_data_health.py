from app.api.routers import data_health as dh_router


def test_data_health_summary_endpoint(client, monkeypatch):
    fake_summary = {
        "schema_version": 1,
        "dataset": {"total_networks": 10},
    }
    monkeypatch.setattr(
        dh_router.data_health_service, "get_summary", lambda: fake_summary
    )

    resp = client.get("/api/data-health/summary")
    assert resp.status_code == 200
    payload = resp.json()["data"]
    assert payload == fake_summary
