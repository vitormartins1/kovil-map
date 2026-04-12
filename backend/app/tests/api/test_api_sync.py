import json
import uuid

import pytest

from app.api import deps
from app.api.routers import sync as sync_router


class _FakeSync:
    def __init__(
        self,
        result,
        trust_result=None,
        probe_result=None,
        pwn_probe_result=None,
        bruce_probe_result=None,
    ):
        self.result = result
        self.trust_result = trust_result or {"status": "success", "message": "trusted"}
        self.probe_result = probe_result or {"status": "success", "message": "probe ok"}
        self.pwn_probe_result = pwn_probe_result or {
            "status": "success",
            "message": "pwn probe ok",
        }
        self.bruce_probe_result = bruce_probe_result or {
            "status": "success",
            "message": "bruce probe ok",
        }
        self.last_trust_args = None
        self.last_probe_overrides = None
        self.last_pwn_probe_overrides = None
        self.last_bruce_probe_overrides = None

    def perform_sync(self, force=False, progress_callback=None, target_force=None):
        self.last_progress_callback = progress_callback
        self.last_target_force = target_force
        return self.result

    def trust_remote_host_key(self, host=None, port=None, replace=False, target=None):
        self.last_trust_args = {
            "host": host,
            "port": port,
            "replace": replace,
            "target": target,
        }
        return self.trust_result

    def probe_m5evil_admin_webui(self, overrides=None):
        self.last_probe_overrides = overrides
        return self.probe_result

    def probe_pwnagotchi_ssh(self, overrides=None):
        self.last_pwn_probe_overrides = overrides
        return self.pwn_probe_result

    def probe_bruce_webui(self, overrides=None):
        self.last_bruce_probe_overrides = overrides
        return self.bruce_probe_result


class _FakeManager:
    def __init__(self):
        self.messages = []

    async def broadcast(self, message):
        self.messages.append(message)


class _FakeJobManager:
    def __init__(self):
        self.started_jobs = []
        self.registered_jobs = []
        self.updated_jobs = []
        self.completed_jobs = []

    def start_multi_job(self, worker, job_type=None, total_steps=1, meta=None):
        job_id = str(uuid.uuid4())
        self.started_jobs.append(
            {
                "job_id": job_id,
                "job_type": job_type,
                "total_steps": total_steps,
                "meta": meta,
            }
        )
        return job_id

    def register_external_job(
        self,
        job_id,
        *,
        job_type="external",
        command="internal:external",
        cwd=None,
        status="running",
        total_steps=1,
        meta=None,
        progress_data=None,
    ):
        self.registered_jobs.append(
            {
                "job_id": job_id,
                "job_type": job_type,
                "command": command,
                "cwd": cwd,
                "status": status,
                "total_steps": total_steps,
                "meta": meta,
                "progress_data": progress_data,
            }
        )
        return job_id

    def update_external_job(self, job_id, *, progress_data=None, status=None):
        self.updated_jobs.append(
            {"job_id": job_id, "progress_data": progress_data, "status": status}
        )
        return True

    def complete_external_job(self, job_id, *, status="success", progress_data=None):
        self.completed_jobs.append(
            {"job_id": job_id, "status": status, "progress_data": progress_data}
        )
        return True


@pytest.fixture(autouse=True)
def patch_sync_runtime(monkeypatch):
    monkeypatch.setattr(
        sync_router,
        "get_wardrive_summary",
        lambda: {"files_count": 0, "networks_count": 0, "sessions_count": 0},
    )


def test_sync_endpoint_triggers_reload(client, monkeypatch):
    fake_result = {"status": "success", "details": {"handshakes": ["a"]}}
    monkeypatch.setattr(deps, "sync_service", _FakeSync(fake_result))
    monkeypatch.setattr(sync_router, "list_bruce_handshake_files", lambda: [])
    monkeypatch.setattr(sync_router, "list_m5evil_handshake_files", lambda: [])
    monkeypatch.setattr(sync_router.rawsniffer_service, "list_files", lambda: [])
    monkeypatch.setattr(sync_router.rawsniffer_service, "get_pending_files", lambda: [])
    monkeypatch.setattr(
        sync_router, "start_rawsniffer_job", lambda files, force=False: None
    )
    monkeypatch.setattr(
        sync_router,
        "get_wardrive_summary",
        lambda: {"files_count": 0, "networks_count": 0, "sessions_count": 0},
    )

    reloaded = {"count": 0}

    def _reload():
        reloaded["count"] += 1

    monkeypatch.setattr(sync_router, "reload_data", _reload)

    manager = _FakeManager()
    monkeypatch.setattr(sync_router, "manager", manager)

    job_manager = _FakeJobManager()
    monkeypatch.setattr(sync_router, "job_manager", job_manager)

    resp = client.post("/api/sync", json={"force": True})
    assert resp.status_code == 200
    payload = resp.json()["data"]
    assert payload["status"] == "success"
    assert payload["details"]["sync_stages"]["remote_sync"]["status"] == "success"
    assert "pwnagotchi_remote_sync" in payload["details"]["sync_stages"]
    assert "m5evil_remote_sync" in payload["details"]["sync_stages"]
    assert "bruce_remote_sync" in payload["details"]["sync_stages"]
    assert (
        "handshake_files_to_download"
        in payload["details"]["sync_stages"]["pwnagotchi_remote_sync"]
    )
    assert (
        "handshake_files_failed"
        in payload["details"]["sync_stages"]["pwnagotchi_remote_sync"]
    )
    assert "handshake_files_to_download" in payload["details"]["pwnagotchi_remote_sync"]
    assert "handshake_files_failed" in payload["details"]["pwnagotchi_remote_sync"]
    assert payload["details"]["sync_stages"]["bruce_fingerprint"]["status"] == "skipped"
    assert (
        payload["details"]["sync_stages"]["rawsniffer_extract"]["status"] == "skipped"
    )
    metrics = payload["details"]["metrics"]
    for key in (
        "remote_sync_ms",
        "fingerprint_plan_ms",
        "fingerprint_queue_ms",
        "rawsniffer_queue_ms",
        "pwnagotchi_remote_sync_ms",
        "m5evil_remote_sync_ms",
        "bruce_remote_sync_ms",
    ):
        assert key in metrics
        assert isinstance(metrics[key], (int, float))
    assert reloaded["count"] == 1
    assert manager.messages


def test_sync_endpoint_passes_m5_progress_callback(client, monkeypatch):
    fake = _FakeSync({"status": "success", "details": {"handshakes": []}})
    monkeypatch.setattr(deps, "sync_service", fake)
    monkeypatch.setattr(sync_router, "list_bruce_handshake_files", lambda: [])
    monkeypatch.setattr(sync_router, "list_m5evil_handshake_files", lambda: [])
    monkeypatch.setattr(sync_router.rawsniffer_service, "list_files", lambda: [])
    monkeypatch.setattr(sync_router.rawsniffer_service, "get_pending_files", lambda: [])
    monkeypatch.setattr(
        sync_router, "start_rawsniffer_job", lambda files, force=False: None
    )
    monkeypatch.setattr(sync_router, "reload_data", lambda: None)
    monkeypatch.setattr(
        sync_router,
        "get_wardrive_summary",
        lambda: {"files_count": 0, "networks_count": 0, "sessions_count": 0},
    )
    monkeypatch.setattr(sync_router, "manager", _FakeManager())

    emitted = []

    class _ProgressJobManager(_FakeJobManager):
        def _fire_and_forget_emit(self, event, payload):
            emitted.append((event, payload))

    monkeypatch.setattr(sync_router, "job_manager", _ProgressJobManager())

    resp = client.post(
        "/api/sync",
        json={
            "force": False,
            "pwn_handshakes_process_id": "pwn-hs-1",
            "m5_handshakes_process_id": "m5-hs-1",
            "m5_wardrive_process_id": "m5-wd-1",
            "bruce_handshakes_process_id": "bruce-hs-1",
            "bruce_rawsniffer_process_id": "bruce-raw-1",
            "bruce_wardrive_process_id": "bruce-wd-1",
        },
    )
    assert resp.status_code == 200
    assert callable(fake.last_progress_callback)

    fake.last_progress_callback(
        "pwnagotchi_handshakes", {"percentage": 25, "stage": "RUNNING"}
    )
    fake.last_progress_callback("handshakes", {"percentage": 50, "stage": "RUNNING"})
    fake.last_progress_callback("wardrive", {"percentage": 75, "stage": "RUNNING"})
    fake.last_progress_callback(
        "bruce_handshakes", {"percentage": 20, "stage": "RUNNING"}
    )
    fake.last_progress_callback(
        "bruce_rawsniffer", {"percentage": 40, "stage": "RUNNING"}
    )
    fake.last_progress_callback(
        "bruce_wardrive", {"percentage": 60, "stage": "RUNNING"}
    )

    assert (
        "job_progress",
        {"job_id": "pwn-hs-1", "data": {"percentage": 25, "stage": "RUNNING"}},
    ) in emitted
    assert (
        "job_progress",
        {"job_id": "m5-hs-1", "data": {"percentage": 50, "stage": "RUNNING"}},
    ) in emitted
    assert (
        "job_progress",
        {"job_id": "m5-wd-1", "data": {"percentage": 75, "stage": "RUNNING"}},
    ) in emitted
    assert (
        "job_progress",
        {
            "job_id": "bruce-hs-1",
            "data": {"percentage": 20, "stage": "RUNNING"},
        },
    ) in emitted
    assert (
        "job_progress",
        {
            "job_id": "bruce-raw-1",
            "data": {"percentage": 40, "stage": "RUNNING"},
        },
    ) in emitted
    assert (
        "job_progress",
        {
            "job_id": "bruce-wd-1",
            "data": {"percentage": 60, "stage": "RUNNING"},
        },
    ) in emitted
    assert any(
        item["job_id"] == "pwn-hs-1" for item in sync_router.job_manager.registered_jobs
    )
    assert any(
        item["job_id"] == "m5-hs-1" for item in sync_router.job_manager.registered_jobs
    )
    assert any(
        item["job_id"] == "bruce-wd-1"
        for item in sync_router.job_manager.registered_jobs
    )
    assert any(
        item["job_id"] == "m5-hs-1" for item in sync_router.job_manager.updated_jobs
    )
    assert any(
        item["job_id"] == "bruce-wd-1" for item in sync_router.job_manager.updated_jobs
    )
    assert any(
        item["job_id"] == "pwn-hs-1" for item in sync_router.job_manager.completed_jobs
    )
    assert any(
        item["job_id"] == "m5-hs-1" for item in sync_router.job_manager.completed_jobs
    )
    assert any(
        item["job_id"] == "bruce-wd-1"
        for item in sync_router.job_manager.completed_jobs
    )


def test_sync_endpoint_plans_hidden_missing_invalid_hs_files(
    client, monkeypatch, tmp_path
):
    fake_result = {
        "status": "success",
        "details": {
            "handshakes": [
                "HS_missing.pcap",
                "HS_invalid.pcap",
            ]
        },
    }
    monkeypatch.setattr(deps, "sync_service", _FakeSync(fake_result))
    monkeypatch.setattr(
        sync_router,
        "list_bruce_handshake_files",
        lambda: [
            "HS_hidden.pcap",
            "HS_valid.pcap",
            "HS_missing.pcap",
            "HS_invalid.pcap",
        ],
    )
    monkeypatch.setattr(sync_router, "list_m5evil_handshake_files", lambda: [])
    monkeypatch.setattr(sync_router, "HANDSHAKES_DIR", str(tmp_path))
    (tmp_path / "HS_hidden.details").write_text(
        json.dumps({"ssid": "   "}), encoding="utf-8"
    )
    (tmp_path / "HS_valid.details").write_text(
        json.dumps({"ssid": "VisibleNet"}), encoding="utf-8"
    )
    (tmp_path / "HS_invalid.details").write_text("{", encoding="utf-8")

    monkeypatch.setattr(
        sync_router.rawsniffer_service,
        "list_files",
        lambda: [{"filename": "raw_1.pcap", "cached_up_to_date": False}],
    )
    monkeypatch.setattr(
        sync_router.rawsniffer_service, "get_pending_files", lambda: ["raw_1.pcap"]
    )
    monkeypatch.setattr(
        sync_router, "start_rawsniffer_job", lambda files, force=False: "raw-job-1"
    )

    reloaded = {"count": 0}

    def _reload():
        reloaded["count"] += 1

    monkeypatch.setattr(sync_router, "reload_data", _reload)

    manager = _FakeManager()
    monkeypatch.setattr(sync_router, "manager", manager)

    job_manager = _FakeJobManager()
    monkeypatch.setattr(sync_router, "job_manager", job_manager)

    resp = client.post("/api/sync", json={"force": False})
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["status"] == "success"
    assert data["details"]["rawsniffer"]["job_id"] == "raw-job-1"

    bruce = data["details"]["bruce"]
    assert bruce["handshakes_seen"] == 4
    assert bruce["handshakes_to_process"] == 3
    assert bruce["handshakes_hidden_refresh"] == 1
    assert bruce["handshakes_missing_details"] == 1
    assert bruce["handshakes_invalid_details"] == 1
    assert bruce["fingerprint_job_id"] is not None
    assert data["details"]["sync_stages"]["bruce_fingerprint"]["status"] == "queued"
    assert data["details"]["sync_stages"]["rawsniffer_extract"]["status"] == "queued"
    assert data["details"]["sync_stages"]["remote_sync"]["status"] == "success"
    assert (
        data["details"]["sync_stages"]["pwnagotchi_remote_sync"]["status"] == "skipped"
    )
    assert data["details"]["sync_stages"]["m5evil_remote_sync"]["status"] == "skipped"

    assert len(job_manager.started_jobs) == 1
    job = job_manager.started_jobs[0]
    assert job["job_type"] == "fingerprint_multi"
    assert job["meta"]["files_to_process"] == [
        "HS_hidden.pcap",
        "HS_missing.pcap",
        "HS_invalid.pcap",
    ]
    assert set(job["meta"]["force_files"]) == {"HS_hidden.pcap", "HS_invalid.pcap"}
    assert job["meta"]["reason_by_file"]["HS_hidden.pcap"] == "hidden_refresh"
    assert job["meta"]["reason_by_file"]["HS_missing.pcap"] == "missing_details"
    assert job["meta"]["reason_by_file"]["HS_invalid.pcap"] == "invalid_details"


def test_sync_endpoint_starts_local_fingerprint_job_even_when_sync_fails(
    client, monkeypatch, tmp_path
):
    fake_result = {"status": "error", "message": "sync failed", "details": {}}
    monkeypatch.setattr(deps, "sync_service", _FakeSync(fake_result))
    monkeypatch.setattr(
        sync_router, "list_bruce_handshake_files", lambda: ["HS_hidden.pcap"]
    )
    monkeypatch.setattr(sync_router, "list_m5evil_handshake_files", lambda: [])
    monkeypatch.setattr(sync_router, "HANDSHAKES_DIR", str(tmp_path))
    (tmp_path / "HS_hidden.details").write_text(
        json.dumps({"ssid": ""}), encoding="utf-8"
    )
    monkeypatch.setattr(sync_router.rawsniffer_service, "list_files", lambda: [])
    monkeypatch.setattr(sync_router.rawsniffer_service, "get_pending_files", lambda: [])
    monkeypatch.setattr(
        sync_router, "start_rawsniffer_job", lambda files, force=False: None
    )
    monkeypatch.setattr(sync_router, "reload_data", lambda: None)

    manager = _FakeManager()
    monkeypatch.setattr(sync_router, "manager", manager)

    job_manager = _FakeJobManager()
    monkeypatch.setattr(sync_router, "job_manager", job_manager)

    resp = client.post("/api/sync", json={"force": False})
    assert resp.status_code == 200


def test_m5evil_probe_endpoint_passes_overrides(client, monkeypatch):
    fake = _FakeSync(
        {"status": "success", "details": {}},
        probe_result={
            "status": "success",
            "message": "M5Evil Admin WebUI connection successful",
            "details": {"handshake_files_found": 1, "wardrive_files_found": 2},
        },
    )
    monkeypatch.setattr(deps, "sync_service", fake)

    resp = client.post(
        "/api/sync/m5evil/probe",
        json={
            "m5_host": "192.168.4.1",
            "m5_port": 80,
            "m5_admin_base_path": "/evil-menu",
            "m5_web_user": "evil",
            "m5_web_password": "test",
            "m5_handshake_remote_path": "evil/handshake",
            "m5_wardrive_remote_path": "evil/wardriving",
        },
    )
    assert resp.status_code == 200
    payload = resp.json()["data"]
    assert payload["status"] == "success"
    assert payload["details"]["handshake_files_found"] == 1
    assert fake.last_probe_overrides["m5_host"] == "192.168.4.1"


def test_pwnagotchi_probe_endpoint_passes_overrides(client, monkeypatch):
    fake = _FakeSync(
        {"status": "success", "details": {}},
        pwn_probe_result={
            "status": "success",
            "message": "Pwnagotchi SSH connection successful",
            "details": {"files_found": 3},
        },
    )
    monkeypatch.setattr(deps, "sync_service", fake)

    resp = client.post(
        "/api/sync/pwnagotchi/probe",
        json={
            "pwn_host": "10.0.0.2",
            "pwn_port": 22,
            "pwn_user": "pi",
            "pwn_pass": "raspberry",
            "remote_path": "/home/pi/handshakes",
        },
    )
    assert resp.status_code == 200
    payload = resp.json()["data"]
    assert payload["status"] == "success"
    assert payload["details"]["files_found"] == 3
    assert fake.last_pwn_probe_overrides["pwn_host"] == "10.0.0.2"


def test_bruce_probe_endpoint_passes_overrides(client, monkeypatch):
    fake = _FakeSync(
        {"status": "success", "details": {}},
        bruce_probe_result={
            "status": "success",
            "message": "Bruce WebUI connection successful",
            "details": {"handshake_files_found": 2, "rawsniffer_files_found": 1},
        },
    )
    monkeypatch.setattr(deps, "sync_service", fake)

    resp = client.post(
        "/api/sync/bruce/probe",
        json={
            "bruce_host": "bruce.local",
            "bruce_port": 80,
            "bruce_web_protocol": "http",
            "bruce_web_user": "admin",
            "bruce_web_password": "bruce",
        },
    )
    assert resp.status_code == 200
    payload = resp.json()["data"]
    assert payload["status"] == "success"
    assert payload["details"]["handshake_files_found"] == 2
    assert fake.last_bruce_probe_overrides["bruce_host"] == "bruce.local"


def test_sync_endpoint_plans_local_m5evil_fingerprints_without_remote_download(
    client, monkeypatch, tmp_path
):
    fake_result = {"status": "success", "details": {"handshakes": []}}
    monkeypatch.setattr(deps, "sync_service", _FakeSync(fake_result))
    monkeypatch.setattr(sync_router, "list_bruce_handshake_files", lambda: [])
    monkeypatch.setattr(
        sync_router,
        "list_m5evil_handshake_files",
        lambda: [
            "HS_hidden_m5.pcap",
            "HS_missing_m5.pcap",
            "HS_invalid_m5.pcap",
            "HS_visible_m5.pcap",
        ],
    )
    monkeypatch.setattr(sync_router, "HANDSHAKES_DIR", str(tmp_path))
    (tmp_path / "HS_hidden_m5.details").write_text(
        json.dumps({"ssid": "   "}), encoding="utf-8"
    )
    (tmp_path / "HS_invalid_m5.details").write_text("{", encoding="utf-8")
    (tmp_path / "HS_visible_m5.details").write_text(
        json.dumps({"ssid": "Visible M5"}), encoding="utf-8"
    )
    monkeypatch.setattr(sync_router.rawsniffer_service, "list_files", lambda: [])
    monkeypatch.setattr(sync_router.rawsniffer_service, "get_pending_files", lambda: [])
    monkeypatch.setattr(
        sync_router, "start_rawsniffer_job", lambda files, force=False: None
    )
    monkeypatch.setattr(sync_router, "reload_data", lambda: None)

    manager = _FakeManager()
    monkeypatch.setattr(sync_router, "manager", manager)

    job_manager = _FakeJobManager()
    monkeypatch.setattr(sync_router, "job_manager", job_manager)

    resp = client.post("/api/sync", json={"force": False})
    assert resp.status_code == 200
    data = resp.json()["data"]

    m5evil = data["details"]["m5evil"]
    assert m5evil["handshakes_seen"] == 4
    assert m5evil["handshakes_to_process"] == 3
    assert m5evil["handshakes_hidden_refresh"] == 1
    assert m5evil["handshakes_missing_details"] == 1
    assert m5evil["handshakes_invalid_details"] == 1
    assert m5evil["fingerprint_job_id"] is not None
    assert data["details"]["sync_stages"]["m5evil_fingerprint"]["status"] == "queued"

    assert len(job_manager.started_jobs) == 1
    job = job_manager.started_jobs[0]
    assert job["job_type"] == "fingerprint_multi"
    assert job["meta"]["files_to_process"] == [
        "HS_hidden_m5.pcap",
        "HS_missing_m5.pcap",
        "HS_invalid_m5.pcap",
    ]
    assert set(job["meta"]["force_files"]) == {
        "HS_hidden_m5.pcap",
        "HS_invalid_m5.pcap",
    }


def test_fingerprint_worker_respects_force_files(monkeypatch, tmp_path):
    monkeypatch.setattr(sync_router, "HANDSHAKES_DIR", str(tmp_path))
    (tmp_path / "HS_force.details").write_text(
        json.dumps({"ssid": ""}), encoding="utf-8"
    )
    (tmp_path / "HS_skip.details").write_text(
        json.dumps({"ssid": "Visible"}), encoding="utf-8"
    )

    calls = []

    def _extract(filename, force):
        calls.append((filename, force))
        return {"status": "success", "details_count": 1}

    monkeypatch.setattr(sync_router.fingerprint_service, "extract", _extract)
    monkeypatch.setattr(sync_router, "reload_data", lambda: None)

    emitted = []

    def _emit(event, payload):
        emitted.append((event, payload))

    job = {
        "id": "job-1",
        "meta": {
            "files_to_process": [
                "HS_force.pcap",
                "HS_skip.pcap",
                "HS_missing.pcap",
            ],
            "force_files": ["HS_force.pcap"],
            "reason_by_file": {
                "HS_force.pcap": "hidden_refresh",
                "HS_missing.pcap": "missing_details",
            },
        },
        "progress_data": {},
    }

    sync_router._fingerprint_worker(job, _emit)

    assert calls == [("HS_force.pcap", True), ("HS_missing.pcap", False)]
    items = {item["file"]: item for item in job["progress_data"]["items"]}
    assert items["HS_force.pcap"]["status"] == "SUCCESS"
    assert items["HS_force.pcap"]["reason"] == "hidden_refresh"
    assert items["HS_skip.pcap"]["status"] == "SKIPPED"
    assert items["HS_skip.pcap"]["reason"] == "details_already_exist"
    assert items["HS_missing.pcap"]["status"] == "SUCCESS"
    assert items["HS_missing.pcap"]["reason"] == "missing_details"
    assert any(event == "data_update" for event, _ in emitted)


def test_sync_trust_host_key_endpoint(client, monkeypatch):
    fake = _FakeSync({"status": "success", "details": {"handshakes": []}})
    monkeypatch.setattr(deps, "sync_service", fake)
    monkeypatch.setattr(sync_router, "list_bruce_handshake_files", lambda: [])
    monkeypatch.setattr(sync_router.rawsniffer_service, "list_files", lambda: [])
    monkeypatch.setattr(sync_router.rawsniffer_service, "get_pending_files", lambda: [])
    monkeypatch.setattr(
        sync_router, "start_rawsniffer_job", lambda files, force=False: None
    )

    job_manager = _FakeJobManager()
    monkeypatch.setattr(sync_router, "job_manager", job_manager)

    resp = client.post(
        "/api/sync/trust-host-key",
        json={"host": "10.0.0.2", "port": 22, "replace": True},
    )
    assert resp.status_code == 200
    payload = resp.json()["data"]
    assert payload["status"] == "success"
    assert fake.last_trust_args == {
        "host": "10.0.0.2",
        "port": 22,
        "replace": True,
        "target": None,
    }
