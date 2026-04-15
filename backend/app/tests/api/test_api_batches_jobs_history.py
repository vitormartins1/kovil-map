import json

from app.api.routers import batches as batches_router
from app.api.routers import jobs as jobs_router
from app.api.routers import history as history_router
from app.api.routers import maintenance as maintenance_router


def test_batches_endpoints(client, tmp_path, monkeypatch):
    monkeypatch.setattr(batches_router, "HANDSHAKES_DIR", str(tmp_path))

    batch = tmp_path / "batch_test.22000"
    batch.write_text("hash")
    manifest = tmp_path / "batch_test.22000.batch.json"
    manifest.write_text(json.dumps({"items": [{"filename": "net1.pcap"}]}))

    cracked = tmp_path / "net1.pcap.cracked"
    cracked.write_text("pass")

    resp = client.get("/api/batches")
    assert resp.status_code == 200
    assert resp.json()["data"]

    resp = client.get("/api/batches/batch_test.22000")
    assert resp.status_code == 200
    assert resp.json()["data"]["items"][0]["cracked"] is True

    resp = client.get("/api/batches/batch_test.22000/files")
    assert resp.status_code == 200

    resp = client.delete("/api/batches/batch_test.22000")
    assert resp.status_code == 200
    deleted = resp.json()["data"]["deleted"]
    assert "batch_test.22000" in deleted


def test_jobs_and_history_endpoints(client, monkeypatch):
    monkeypatch.setattr(jobs_router.job_manager, "list_jobs", lambda: [{"id": "1"}])
    monkeypatch.setattr(
        jobs_router.job_manager, "get_job", lambda job_id: {"id": job_id}
    )
    monkeypatch.setattr(
        jobs_router.job_manager, "cancel_job", lambda job_id: (True, "canceled")
    )

    resp = client.get("/api/jobs")
    assert resp.status_code == 200

    resp = client.get("/api/jobs/1")
    assert resp.status_code == 200

    resp = client.patch("/api/jobs/1", json={"status": "canceled"})
    assert resp.status_code == 200

    monkeypatch.setattr(history_router.history_service, "clear_all_history", lambda: 2)
    resp = client.delete("/api/history")
    assert resp.status_code == 200
    assert resp.json()["data"]["deleted_count"] == 2


def test_maintenance_endpoints(client, monkeypatch):
    async def _fake_broadcast(_payload):
        return None

    monkeypatch.setattr(maintenance_router.manager, "broadcast", _fake_broadcast)
    monkeypatch.setattr(
        maintenance_router.maintenance_service,
        "clear_details_files",
        lambda: {"deleted_count": 4, "failed_count": 0},
    )
    monkeypatch.setattr(
        maintenance_router.maintenance_service,
        "clear_cache",
        lambda: {
            "raw_metadata_deleted_count": 7,
            "raw_metadata_failed_count": 0,
            "data_cache_reloaded": True,
            "analytics_cache_cleared": True,
        },
    )
    monkeypatch.setattr(
        maintenance_router.maintenance_service,
        "get_demo_status",
        lambda: {
            "active": False,
            "available_profiles": [{"profile_id": "showcase-core-v4"}],
            "snapshot_available": False,
        },
    )
    monkeypatch.setattr(
        maintenance_router.maintenance_service,
        "start_demo_install",
        lambda profile_id="showcase-core-v4", frontend_state=None: {
            "job_id": "demo-job-1",
            "profile_id": profile_id,
            "ui_seed": {},
        },
    )
    monkeypatch.setattr(
        maintenance_router.maintenance_service,
        "start_demo_remove",
        lambda: {
            "job_id": "demo-job-2",
            "restore_mode": "snapshot",
            "ui_restore": {},
        },
    )

    resp = client.delete("/api/maintenance/details")
    assert resp.status_code == 200
    assert resp.json()["data"]["deleted_count"] == 4

    resp = client.delete("/api/maintenance/cache")
    assert resp.status_code == 200
    assert resp.json()["data"]["raw_metadata_deleted_count"] == 7

    resp = client.get("/api/maintenance/demo")
    assert resp.status_code == 200
    assert resp.json()["data"]["active"] is False

    resp = client.post(
        "/api/maintenance/demo/install",
        json={
            "profile_id": "showcase-core-v4",
            "frontend_state": {"lists": {"targets": []}},
        },
    )
    assert resp.status_code == 200
    assert resp.json()["data"]["job_id"] == "demo-job-1"

    resp = client.delete("/api/maintenance/demo")
    assert resp.status_code == 200
    assert resp.json()["data"]["restore_mode"] == "snapshot"


def test_batches_invalid_and_error_paths(client, tmp_path, monkeypatch):
    monkeypatch.setattr(batches_router, "HANDSHAKES_DIR", str(tmp_path))
    (tmp_path / "batch_bad.22000").write_text("hash", encoding="utf-8")
    (tmp_path / "batch_bad.22000.batch.json").write_text("{", encoding="utf-8")

    resp = client.get("/api/batches/batch_bad.22000")
    assert resp.status_code == 500

    resp = client.get("/api/batches/not_batch.22000")
    assert resp.status_code == 400
    resp = client.get("/api/batches/not_batch.22000/files")
    assert resp.status_code == 400
    resp = client.delete("/api/batches/not_batch.22000")
    assert resp.status_code == 400


def test_jobs_get_not_found_and_cancel_invalid_status(client, monkeypatch):
    monkeypatch.setattr(jobs_router.job_manager, "list_jobs", lambda: [])
    monkeypatch.setattr(jobs_router.job_manager, "get_job", lambda _job_id: None)
    monkeypatch.setattr(
        jobs_router.job_manager, "cancel_job", lambda _job_id: (False, "bad")
    )

    resp = client.get("/api/jobs/missing")
    assert resp.status_code == 404

    resp = client.patch("/api/jobs/1", json={"status": "running"})
    assert resp.status_code == 400

    resp = client.patch("/api/jobs/1", json={"status": "canceled"})
    assert resp.status_code == 400
