import json

from app.api.routers import handshakes as handshakes_router
from app.api.routers import files as files_router
from app.tests.conftest import write_test_pcap


def test_handshakes_and_files(client, tmp_path, monkeypatch):
    monkeypatch.setattr(handshakes_router, "HANDSHAKES_DIR", str(tmp_path))
    bruce_dir = tmp_path / "BrucePCAP"
    bruce_hand = bruce_dir / "handshakes"
    m5evil_dir = tmp_path / "m5evil"
    m5evil_hand = m5evil_dir / "handshakes"
    bruce_dir.mkdir()
    bruce_hand.mkdir()
    m5evil_dir.mkdir()
    m5evil_hand.mkdir()
    monkeypatch.setattr(handshakes_router, "BRUCE_HANDSHAKES_DIR", str(bruce_hand))
    monkeypatch.setattr(handshakes_router, "BRUCE_PCAP_DIR", str(bruce_dir))
    monkeypatch.setattr(handshakes_router, "M5EVIL_HANDSHAKES_DIR", str(m5evil_hand))
    monkeypatch.setattr(
        handshakes_router.rawsniffer_service,
        "get_generated_hashes_for_bssid",
        lambda _mac: [],
    )
    monkeypatch.setattr(files_router, "HANDSHAKES_DIR", str(tmp_path))

    pcap_name = "Test_aabbccddeeff.pcap"
    pcap_path = tmp_path / pcap_name
    write_test_pcap(pcap_path)

    gps = tmp_path / "Test_aabbccddeeff.gps.json"
    gps.write_text("{}")

    bruce_name = "HS_AABBCCDDEEFF.pcap"
    write_test_pcap(bruce_hand / bruce_name)
    m5_name = "HS_AABBCCDDEEFF_m5.pcap"
    write_test_pcap(m5evil_hand / m5_name)

    resp = client.get("/api/handshakes/aa:bb:cc:dd:ee:ff/files")
    assert resp.status_code == 200
    names = [f["name"] for f in resp.json()["data"]]
    assert pcap_name in names
    assert bruce_name in names
    assert m5_name in names
    assert "Test_aabbccddeeff.gps.json" not in names

    resp = client.get(f"/api/files/{pcap_name}")
    assert resp.status_code == 200
    assert resp.json()["data"]  # non-empty content

    resp = client.get("/api/files/missing.pcap")
    assert resp.status_code == 404


def test_handshakes_files_hide_raw_hashes_from_main_list(client, tmp_path, monkeypatch):
    monkeypatch.setattr(handshakes_router, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(
        handshakes_router, "BRUCE_HANDSHAKES_DIR", str(tmp_path / "missing")
    )
    monkeypatch.setattr(
        handshakes_router, "BRUCE_PCAP_DIR", str(tmp_path / "missing-pcap")
    )
    monkeypatch.setattr(
        handshakes_router, "M5EVIL_HANDSHAKES_DIR", str(tmp_path / "missing-m5")
    )

    raw_hash = tmp_path / "raw_aabbccddeeff.22000"
    raw_hash.write_text("hash", encoding="utf-8")
    (tmp_path / "hidden_aabbccddeeff__wdrs__.22000").write_text(
        "hash", encoding="utf-8"
    )

    resp = client.get("/api/handshakes/aa:bb:cc:dd:ee:ff/files")
    assert resp.status_code == 200
    names = [f["name"] for f in resp.json()["data"]]
    assert "raw_aabbccddeeff.22000" not in names
    assert "hidden_aabbccddeeff__wdrs__.22000" in names


def test_handshakes_raw_context_endpoint(client, monkeypatch):
    monkeypatch.setattr(
        handshakes_router.rawsniffer_service,
        "get_raw_context_for_bssid",
        lambda mac: {
            "present": True,
            "bssid": "AA:BB:CC:DD:EE:FF",
            "files_count": 1,
            "files": [
                {
                    "raw_item_id": "raw::pcap::abc123",
                    "artifact_type": "pcap",
                    "source": "brucegotchi",
                    "device_label": "Bruce",
                    "filename": "raw_city_center.pcap",
                    "source_file": "raw_city_center.pcap",
                    "bssid": "AA:BB:CC:DD:EE:FF",
                    "eapol_count": 3,
                    "beacon_count": 10,
                    "details_present": True,
                    "details_filename": "__rawdetails__raw_city_center_abc123.details",
                    "details_size": 512,
                    "details_modified": 1700000000,
                }
            ],
            "hash_files_count": 1,
            "hash_files": [
                {
                    "raw_item_id": "raw::22000::def456",
                    "artifact_type": "22000",
                    "source": "brucegotchi",
                    "device_label": "Bruce",
                    "filename": "raw_12.22000",
                    "bssid": "AA:BB:CC:DD:EE:FF",
                    "valid_hash_lines": 8,
                    "source_raw_file": "raw_city_center.pcap",
                    "details_present": True,
                    "details_filename": "__rawdetails__raw_city_center_abc123.details",
                    "details_size": 512,
                    "details_modified": 1700000000,
                }
            ],
        },
    )

    resp = client.get("/api/handshakes/aa:bb:cc:dd:ee:ff/raw-context")
    assert resp.status_code == 200
    payload = resp.json()["data"]
    assert payload["present"] is True
    assert payload["files_count"] == 1
    assert payload["files"][0]["source_file"] == "raw_city_center.pcap"
    assert payload["files"][0]["raw_item_id"] == "raw::pcap::abc123"
    assert payload["files"][0]["details_size"] == 512
    assert payload["files"][0]["bssid"] == "AA:BB:CC:DD:EE:FF"
    assert payload["files"][0]["source"] == "brucegotchi"
    assert payload["hash_files_count"] == 1
    assert payload["hash_files"][0]["filename"] == "raw_12.22000"
    assert payload["hash_files"][0]["raw_item_id"] == "raw::22000::def456"


def test_handshakes_raw_prepare_accepts_raw_item_id(client, monkeypatch):
    called = {}
    monkeypatch.setattr(
        handshakes_router.rawsniffer_service,
        "prepare_raw_item_for_bssid",
        lambda mac, raw_item_id=None, source_file=None, force=False: (
            called.update(
                {
                    "mac": mac,
                    "raw_item_id": raw_item_id,
                    "source_file": source_file,
                    "force": force,
                }
            )
            or {
                "status": "success",
                "raw_item_id": raw_item_id,
                "artifacts": {"hash_file": "hidden_aabbccddeeff__wdrs__.22000"},
            }
        ),
    )
    monkeypatch.setattr(handshakes_router, "reload_data", lambda: None)

    resp = client.post(
        "/api/handshakes/aa:bb:cc:dd:ee:ff/raw-prepare",
        json={"raw_item_id": "raw::pcap::abc123", "force": True},
    )
    assert resp.status_code == 200
    assert called == {
        "mac": "aa:bb:cc:dd:ee:ff",
        "raw_item_id": "raw::pcap::abc123",
        "source_file": None,
        "force": True,
    }


def test_handshake_set_endpoint_groups_captures(client, tmp_path, monkeypatch):
    hand_dir = tmp_path / "handshakes"
    bruce_dir = tmp_path / "BrucePCAP"
    bruce_hand_dir = bruce_dir / "handshakes"
    m5evil_dir = tmp_path / "m5evil"
    m5evil_hand_dir = m5evil_dir / "handshakes"
    hand_dir.mkdir()
    bruce_dir.mkdir()
    bruce_hand_dir.mkdir()
    m5evil_dir.mkdir()
    m5evil_hand_dir.mkdir()

    monkeypatch.setattr(handshakes_router, "HANDSHAKES_DIR", str(hand_dir))
    monkeypatch.setattr(handshakes_router, "BRUCE_HANDSHAKES_DIR", str(bruce_hand_dir))
    monkeypatch.setattr(handshakes_router, "BRUCE_PCAP_DIR", str(bruce_dir))
    monkeypatch.setattr(
        handshakes_router, "M5EVIL_HANDSHAKES_DIR", str(m5evil_hand_dir)
    )

    write_test_pcap(hand_dir / "Cafe_aabbccddeeff.pcap")
    (hand_dir / "Cafe_aabbccddeeff.22000").write_text(
        "WPA*02*abc*001122334455*aabbccddeeff*74657374*00\n",
        encoding="utf-8",
    )
    (hand_dir / "Cafe_aabbccddeeff.details").write_text(
        '{"ssid":"Cafe","security":{"wpa_version":"WPA2"}}',
        encoding="utf-8",
    )
    write_test_pcap(bruce_hand_dir / "HS_AABBCCDDEEFF.pcap")
    write_test_pcap(m5evil_hand_dir / "HS_AABBCCDDEEFF.pcap")

    combined_dir = hand_dir / "combined" / "aabbccddeeff" / "build-123456"
    combined_dir.mkdir(parents=True)
    (combined_dir / "combined.22000").write_text(
        "WPA*02*abc*001122334455*aabbccddeeff*74657374*00\n",
        encoding="utf-8",
    )
    (combined_dir / "manifest.json").write_text(
        json.dumps(
            {
                "build_id": "build-123456",
                "included_capture_ids": ["cap-1"],
                "included_captures": [
                    {
                        "capture_id": "cap-1",
                        "source": "pwnagotchi",
                        "device_label": "Pwnagotchi",
                        "source_filename": "Cafe_aabbccddeeff.pcap",
                        "source_kind": "existing_hash",
                        "valid_hash_lines": 1,
                    }
                ],
                "deduped_hash_count": 1,
            }
        ),
        encoding="utf-8",
    )

    resp = client.get("/api/handshakes/aa:bb:cc:dd:ee:ff/set")
    assert resp.status_code == 200
    payload = resp.json()["data"]
    assert payload["mac"] == "AA:BB:CC:DD:EE:FF"
    assert payload["resolved_ssid"] == "Cafe"
    assert payload["artifact_summary"]["pcap"] == 3
    assert len(payload["captures"]) == 3
    assert (
        payload["combined_candidates"][0]["included_captures"][0]["device_label"]
        == "Pwnagotchi"
    )
    assert (
        payload["combined_candidates"][0]["included_captures"][0]["source_kind"]
        == "existing_hash"
    )

    preferred = next(item for item in payload["captures"] if item["is_preferred"])
    assert preferred["source"] == "pwnagotchi"
    assert preferred["artifacts"]["hash_22000"][0]["valid_hash_lines"] == 1


def test_capture_scoped_file_content_is_resolved_by_capture_id(
    client, tmp_path, monkeypatch
):
    monkeypatch.setattr(files_router, "HANDSHAKES_DIR", str(tmp_path))
    capture_dir = tmp_path / "captures" / "cap-123"
    capture_dir.mkdir(parents=True)
    (capture_dir / "capture.details").write_text("capture-details", encoding="utf-8")

    resp = client.get("/api/files/capture.details?capture_id=cap-123")
    assert resp.status_code == 200
    assert resp.json()["data"] == "capture-details"


def test_handshake_combine_captures_endpoint_triggers_build_and_reload(
    client, monkeypatch
):
    called = {"reload": 0}
    monkeypatch.setattr(
        handshakes_router.crack_service,
        "build_combined_candidate",
        lambda mac, capture_ids=None: {
            "status": "success",
            "build_id": "build-123456",
            "output_file": "combined.22000",
            "included_capture_ids": capture_ids or [],
            "deduped_hash_count": 2,
        },
    )
    monkeypatch.setattr(
        handshakes_router,
        "reload_data",
        lambda: called.__setitem__("reload", called["reload"] + 1),
    )

    resp = client.post(
        "/api/handshakes/aa:bb:cc:dd:ee:ff/combine-captures",
        json={"capture_ids": ["cap-a", "cap-b"]},
    )
    assert resp.status_code == 200
    payload = resp.json()["data"]
    assert payload["build_id"] == "build-123456"
    assert payload["included_capture_ids"] == ["cap-a", "cap-b"]
    assert called["reload"] == 1


def test_handshakes_raw_prepare_success_triggers_reload(client, monkeypatch):
    called = {"reload": 0}

    monkeypatch.setattr(
        handshakes_router.rawsniffer_service,
        "prepare_focused_capture_for_bssid",
        lambda mac, source_file, force=False: {
            "status": "success",
            "bssid": "AA:BB:CC:DD:EE:FF",
            "source_file": source_file,
            "artifacts": {
                "pcap_file": "hidden_aabbccddeeff__wdrs__raw_city_center.pcap",
                "hash_file": "hidden_aabbccddeeff__wdrs__raw_city_center.22000",
            },
        },
    )
    monkeypatch.setattr(
        handshakes_router,
        "reload_data",
        lambda: called.__setitem__("reload", called["reload"] + 1),
    )

    resp = client.post(
        "/api/handshakes/aa:bb:cc:dd:ee:ff/raw-prepare",
        json={"source_file": "raw_city_center.pcap", "force": False},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["status"] == "success"
    assert data["reloaded"] is True
    assert called["reload"] == 1


def test_handshakes_raw_prepare_normalizes_source_file_path(client, monkeypatch):
    called = {}
    monkeypatch.setattr(
        handshakes_router.rawsniffer_service,
        "prepare_focused_capture_for_bssid",
        lambda mac, source_file, force=False: (
            called.update({"mac": mac, "source_file": source_file, "force": force})
            or {
                "status": "up_to_date",
                "source_file": source_file,
                "artifacts": {
                    "pcap_file": "focused.pcap",
                    "hash_file": "focused.22000",
                },
            }
        ),
    )

    resp = client.post(
        "/api/handshakes/aa:bb:cc:dd:ee:ff/raw-prepare",
        json={"source_file": "../raw_city_center.pcap"},
    )
    assert resp.status_code == 200
    assert called["source_file"] == "raw_city_center.pcap"


def test_handshakes_raw_prepare_accepts_hash_source(client, monkeypatch):
    called = {}
    monkeypatch.setattr(
        handshakes_router.rawsniffer_service,
        "prepare_focused_capture_for_bssid",
        lambda mac, source_file, force=False: (
            called.update({"mac": mac, "source_file": source_file, "force": force})
            or {
                "status": "success",
                "canonical_hash": "hidden_aabbccddeeff__wdrs__.22000",
                "artifacts": {
                    "pcap_file": None,
                    "hash_file": "hidden_aabbccddeeff__wdrs__.22000",
                },
            }
        ),
    )
    monkeypatch.setattr(handshakes_router, "reload_data", lambda: None)

    resp = client.post(
        "/api/handshakes/aa:bb:cc:dd:ee:ff/raw-prepare",
        json={"source_file": "raw_5.22000"},
    )
    assert resp.status_code == 200
    assert called["source_file"] == "raw_5.22000"


def test_handshakes_raw_prepare_surfaces_service_error(client, monkeypatch):
    monkeypatch.setattr(
        handshakes_router.rawsniffer_service,
        "prepare_focused_capture_for_bssid",
        lambda mac, source_file, force=False: {
            "status": "error",
            "message": "source_file is not linked to this BSSID RAW context",
        },
    )

    resp = client.post(
        "/api/handshakes/aa:bb:cc:dd:ee:ff/raw-prepare",
        json={"source_file": "raw_other.pcap"},
    )
    assert resp.status_code == 400
    payload = resp.json()
    message = (payload.get("error") or payload.get("detail") or {}).get("message", "")
    assert "not linked" in message


def test_handshakes_files_hide_legacy_wdrs_artifacts(client, tmp_path, monkeypatch):
    monkeypatch.setattr(handshakes_router, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(
        handshakes_router, "BRUCE_HANDSHAKES_DIR", str(tmp_path / "missing")
    )
    monkeypatch.setattr(
        handshakes_router, "BRUCE_PCAP_DIR", str(tmp_path / "missing-pcap")
    )
    monkeypatch.setattr(
        handshakes_router, "M5EVIL_HANDSHAKES_DIR", str(tmp_path / "missing-m5")
    )
    monkeypatch.setattr(
        handshakes_router.rawsniffer_service,
        "get_generated_hashes_for_bssid",
        lambda _mac: [],
    )

    legacy_hash = tmp_path / "hidden_aabbccddeeff__wdrs__raw_city.22000"
    legacy_hash.write_text("hash", encoding="utf-8")
    (tmp_path / "hidden_aabbccddeeff__wdrs__raw_city.22000.wdrs.json").write_text(
        "{}",
        encoding="utf-8",
    )
    canonical_hash = tmp_path / "hidden_aabbccddeeff__wdrs__.22000"
    canonical_hash.write_text("hash", encoding="utf-8")

    resp = client.get("/api/handshakes/aa:bb:cc:dd:ee:ff/files")
    assert resp.status_code == 200
    names = [f["name"] for f in resp.json()["data"]]
    assert "hidden_aabbccddeeff__wdrs__.22000" in names
    assert "hidden_aabbccddeeff__wdrs__raw_city.22000" not in names
    assert "hidden_aabbccddeeff__wdrs__raw_city.22000.wdrs.json" not in names


def test_handshakes_raw_prepare_all_starts_async_job(client, monkeypatch):
    monkeypatch.setattr(
        handshakes_router.rawsniffer_service,
        "get_raw_context_for_bssid",
        lambda _mac: {
            "present": True,
            "files": [
                {"source_file": "raw_1.pcap"},
                {"source_file": "raw_2.pcap"},
            ],
            "hash_files": [],
        },
    )
    called = {}
    monkeypatch.setattr(
        handshakes_router,
        "start_raw_prepare_all_job",
        lambda mac, force=False, source_files=None, ssid_hint=None, total_steps=None: (
            called.update(
                {
                    "mac": mac,
                    "force": force,
                    "source_files": source_files,
                    "ssid_hint": ssid_hint,
                    "total_steps": total_steps,
                }
            )
            or "job-raw-all"
        ),
    )

    resp = client.post(
        "/api/handshakes/aa:bb:cc:dd:ee:ff/raw-prepare-all",
        json={"force": True},
    )
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["status"] == "started"
    assert data["job_id"] == "job-raw-all"
    assert data["total_files"] == 2
    assert called["mac"] == "aa:bb:cc:dd:ee:ff"
    assert called["force"] is True
    assert called["source_files"] is None
    assert called["total_steps"] == 2


def test_handshakes_raw_prepare_all_prefers_hash_count_when_available(
    client, monkeypatch
):
    monkeypatch.setattr(
        handshakes_router.rawsniffer_service,
        "get_raw_context_for_bssid",
        lambda _mac: {
            "present": True,
            "files": [
                {"source_file": "raw_1.pcap"},
                {"source_file": "raw_2.pcap"},
                {"source_file": "raw_3.pcap"},
            ],
            "hash_files": [
                {"filename": "raw_1.22000"},
                {"filename": "raw_2.22000"},
            ],
        },
    )
    called = {}
    monkeypatch.setattr(
        handshakes_router,
        "start_raw_prepare_all_job",
        lambda mac, force=False, source_files=None, ssid_hint=None, total_steps=None: (
            called.update({"total_steps": total_steps}) or "job-raw-all"
        ),
    )

    resp = client.post("/api/handshakes/aa:bb:cc:dd:ee:ff/raw-prepare-all", json={})
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["total_files"] == 2
    assert called["total_steps"] == 2


def test_handshakes_raw_prepare_all_requires_raw_context(client, monkeypatch):
    monkeypatch.setattr(
        handshakes_router.rawsniffer_service,
        "get_raw_context_for_bssid",
        lambda _mac: {"present": False},
    )

    resp = client.post("/api/handshakes/aa:bb:cc:dd:ee:ff/raw-prepare-all", json={})
    assert resp.status_code == 400
    payload = resp.json()
    message = (payload.get("error") or payload.get("detail") or {}).get("message", "")
    assert "No RAW context" in message
