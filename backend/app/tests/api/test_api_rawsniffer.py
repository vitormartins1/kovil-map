from app.api.routers import rawsniffer as raw_router


def test_list_rawsniffer_files_endpoint(client, monkeypatch):
    monkeypatch.setattr(
        raw_router.rawsniffer_service,
        "list_files",
        lambda: [{"filename": "raw_1.pcap", "cached_up_to_date": False}],
    )

    resp = client.get("/api/rawsniffer/files")
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert len(data) == 1
    assert data[0]["filename"] == "raw_1.pcap"


def test_delete_rawsniffer_file_endpoint(client, monkeypatch):
    monkeypatch.setattr(
        raw_router.rawsniffer_service,
        "delete_file",
        lambda filename: {
            "status": "success",
            "source_file": filename,
            "deleted": [filename, f"{filename}.json", "raw_1.22000"],
            "metadata_deleted": True,
            "hash_deleted": True,
            "hash_file": "raw_1.22000",
        },
    )

    resp = client.delete("/api/rawsniffer/files/raw_1.pcap")
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["source_file"] == "raw_1.pcap"
    assert "raw_1.22000" in data["deleted"]


def test_delete_rawsniffer_file_endpoint_returns_not_found(client, monkeypatch):
    monkeypatch.setattr(
        raw_router.rawsniffer_service,
        "delete_file",
        lambda filename: {
            "status": "error",
            "message": f"Raw PCAP not found: {filename}",
        },
    )

    resp = client.delete("/api/rawsniffer/files/raw_missing.pcap")
    assert resp.status_code == 404


def test_list_rawsniffer_hashes_endpoint(client, monkeypatch):
    monkeypatch.setattr(
        raw_router.rawsniffer_service,
        "list_generated_hashes",
        lambda: [
            {
                "filename": "raw_1.22000",
                "size": 123,
                "modified": 1700000000.0,
                "source_raw_file": "raw_1.pcap",
                "valid_hash_lines": 2,
                "primary_bssid": "AA:BB:CC:DD:EE:FF",
                "primary_ssid": "NetOne",
                "bssid_count": 1,
                "has_context": True,
            }
        ],
    )

    resp = client.get("/api/rawsniffer/hashes")
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert len(data) == 1
    assert data[0]["filename"] == "raw_1.22000"
    assert data[0]["has_context"] is True


def test_extract_rawsniffer_endpoint_starts_job(client, monkeypatch):
    monkeypatch.setattr(
        raw_router.rawsniffer_service,
        "get_pending_files",
        lambda: ["raw_1.pcap", "raw_2.pcap"],
    )
    monkeypatch.setattr(
        raw_router, "start_rawsniffer_job", lambda files, force=False: "job-raw-1"
    )

    resp = client.post(
        "/api/rawsniffer/extract",
        json={"only_pending": True, "force": False},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["status"] == "started"
    assert data["job_id"] == "job-raw-1"
    assert data["total_files"] == 2


def test_extract_rawsniffer_endpoint_noop_when_empty(client, monkeypatch):
    monkeypatch.setattr(raw_router.rawsniffer_service, "list_files", lambda: [])

    resp = client.post("/api/rawsniffer/extract", json={})
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["status"] == "noop"
    assert data["job_id"] is None


def test_get_rawsniffer_metadata_endpoint(client, monkeypatch):
    monkeypatch.setattr(
        raw_router.rawsniffer_service,
        "get_metadata",
        lambda filename, raw_item_id=None: {
            "source_file": filename,
            "raw_item_id": raw_item_id,
            "stats": {"networks_count": 1},
        },
    )

    resp = client.get("/api/rawsniffer/metadata", params={"filename": "raw_1.pcap"})
    assert resp.status_code == 200
    payload = resp.json()["data"]
    assert payload["source_file"] == "raw_1.pcap"


def test_get_rawsniffer_metadata_refresh(client, monkeypatch):
    monkeypatch.setattr(
        raw_router.rawsniffer_service,
        "extract_metadata",
        lambda filename, force=False, raw_item_id=None: {
            "status": "success",
            "cached": False,
            "data": {"source_file": filename, "raw_item_id": raw_item_id},
        },
    )

    resp = client.get(
        "/api/rawsniffer/metadata", params={"filename": "raw_1.pcap", "refresh": True}
    )
    assert resp.status_code == 200
    payload = resp.json()["data"]
    assert payload["status"] == "success"
    assert payload["data"]["source_file"] == "raw_1.pcap"


def test_get_rawsniffer_metadata_accepts_raw_item_id(client, monkeypatch):
    monkeypatch.setattr(
        raw_router.rawsniffer_service,
        "get_metadata",
        lambda filename, raw_item_id=None: {
            "source_file": filename or "raw_1.pcap",
            "raw_item_id": raw_item_id,
        },
    )

    resp = client.get(
        "/api/rawsniffer/metadata", params={"raw_item_id": "raw::pcap::abc123"}
    )
    assert resp.status_code == 200
    payload = resp.json()["data"]
    assert payload["raw_item_id"] == "raw::pcap::abc123"


def test_rawsniffer_analyze_endpoint(client, monkeypatch):
    monkeypatch.setattr(
        raw_router.rawsniffer_service,
        "extract_analysis",
        lambda raw_item_id, force=False: {
            "status": "success",
            "cached": False,
            "analysis_path": "/tmp/analysis.json",
            "data": {"raw_item_id": raw_item_id, "capture": {"networks_count": 2}},
        },
    )

    resp = client.post(
        "/api/rawsniffer/analyze",
        json={"raw_item_id": "raw::pcap::abc123", "force": True},
    )
    assert resp.status_code == 200
    payload = resp.json()["data"]
    assert payload["status"] == "success"
    assert payload["data"]["raw_item_id"] == "raw::pcap::abc123"


def test_rawsniffer_get_analysis_endpoint(client, monkeypatch):
    monkeypatch.setattr(
        raw_router.rawsniffer_service,
        "get_analysis",
        lambda raw_item_id: {
            "raw_item_id": raw_item_id,
            "capture": {"networks_count": 1},
        },
    )

    resp = client.get("/api/rawsniffer/analysis/raw::pcap::abc123")
    assert resp.status_code == 200
    payload = resp.json()["data"]
    assert payload["raw_item_id"] == "raw::pcap::abc123"


def test_rawsniffer_worker_auto_enriches_hash_when_eapol_found(monkeypatch):
    monkeypatch.setattr(
        raw_router.rawsniffer_service,
        "extract_metadata",
        lambda filename, force=False: {
            "status": "success",
            "cached": False,
            "data": {
                "stats": {"networks_count": 1, "beacon_frames": 10, "eapol_frames": 2}
            },
        },
    )
    monkeypatch.setattr(raw_router, "_needs_hash_enrichment", lambda filename: True)
    monkeypatch.setattr(
        raw_router.rawsniffer_service,
        "resolve_raw_record",
        lambda filename: None,
    )
    monkeypatch.setattr(
        raw_router.crack_service,
        "convert_pcap_now",
        lambda filename, **_kwargs: {
            "status": "success",
            "output_file": "raw_1.22000",
        },
    )
    monkeypatch.setattr(raw_router, "reload_data", lambda: None)

    emitted = []
    job = {
        "id": "job-1",
        "meta": {"files_to_process": ["raw_1.pcap"]},
        "progress_data": {},
    }
    raw_router._rawsniffer_worker(
        job, lambda event, data: emitted.append((event, data))
    )

    enrichment = job["progress_data"]["enrichment"]
    assert enrichment["attempted"] == 1
    assert enrichment["success"] == 1
    assert enrichment["failed"] == 0
    assert any(event == "job_progress" for event, _ in emitted)


def test_rawsniffer_worker_skips_enrichment_without_eapol(monkeypatch):
    monkeypatch.setattr(
        raw_router.rawsniffer_service,
        "extract_metadata",
        lambda filename, force=False: {
            "status": "success",
            "cached": False,
            "data": {
                "stats": {"networks_count": 1, "beacon_frames": 10, "eapol_frames": 0}
            },
        },
    )
    monkeypatch.setattr(raw_router, "reload_data", lambda: None)

    job = {
        "id": "job-2",
        "meta": {"files_to_process": ["raw_2.pcap"]},
        "progress_data": {},
    }
    raw_router._rawsniffer_worker(job, lambda *_args, **_kwargs: None)

    enrichment = job["progress_data"]["enrichment"]
    assert enrichment["attempted"] == 0
    assert enrichment["skipped"] == 1
