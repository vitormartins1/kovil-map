import json

from app.api.routers import fingerprint as fingerprint_router


class _FakeFingerprintService:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def extract(
        self,
        filename,
        force=False,
        capture_id=None,
        raw_item_id=None,
        bssid=None,
    ):
        self.calls.append(
            {
                "filename": filename,
                "force": force,
                "capture_id": capture_id,
                "raw_item_id": raw_item_id,
                "bssid": bssid,
            }
        )
        return self.result


def test_fingerprint_extract_success(client, monkeypatch):
    fake = _FakeFingerprintService(
        {
            "status": "success",
            "saved_path": "/tmp/Test.details",
            "cached": False,
            "details": {"ssid": "Test"},
            "timestamp": "2026-01-01T00:00:00Z",
        }
    )
    monkeypatch.setattr(fingerprint_router, "fingerprint_service", fake)

    resp = client.post(
        "/api/fingerprint/extract",
        json={"filename": "Test_aabbccddeeff.pcap", "force": True},
    )
    assert resp.status_code == 200
    assert resp.json()["data"]["status"] == "success"
    assert fake.calls == [
        {
            "filename": "Test_aabbccddeeff.pcap",
            "force": True,
            "capture_id": None,
            "raw_item_id": None,
            "bssid": None,
        }
    ]


def test_fingerprint_extract_error(client, monkeypatch):
    fake = _FakeFingerprintService({"status": "error", "message": "tshark missing"})
    monkeypatch.setattr(fingerprint_router, "fingerprint_service", fake)

    resp = client.post(
        "/api/fingerprint/extract", json={"filename": "Test_aabbccddeeff.pcap"}
    )
    assert resp.status_code == 400
    assert "tshark missing" in str(resp.json()["detail"])


def test_fingerprint_extract_accepts_raw_item_id(client, monkeypatch):
    fake = _FakeFingerprintService(
        {
            "status": "success",
            "saved_path": "/tmp/__rawdetails__.details",
            "cached": False,
            "details": {"ssid": "Raw"},
            "timestamp": "2026-01-01T00:00:00Z",
        }
    )
    monkeypatch.setattr(fingerprint_router, "fingerprint_service", fake)

    resp = client.post(
        "/api/fingerprint/extract",
        json={"raw_item_id": "raw::pcap::abc123", "force": False},
    )
    assert resp.status_code == 200
    assert fake.calls == [
        {
            "filename": "",
            "force": False,
            "capture_id": None,
            "raw_item_id": "raw::pcap::abc123",
            "bssid": None,
        }
    ]


def test_fingerprint_extract_accepts_raw_item_id_and_bssid(client, monkeypatch):
    fake = _FakeFingerprintService(
        {
            "status": "success",
            "saved_path": "/tmp/__rawdetails__raw_city_aabbccddeeff.details",
            "cached": False,
            "details": {"ssid": "Raw"},
            "timestamp": "2026-01-01T00:00:00Z",
        }
    )
    monkeypatch.setattr(fingerprint_router, "fingerprint_service", fake)

    resp = client.post(
        "/api/fingerprint/extract",
        json={
            "raw_item_id": "raw::pcap::abc123",
            "bssid": "AA:BB:CC:DD:EE:FF",
            "force": False,
        },
    )
    assert resp.status_code == 200
    assert fake.calls == [
        {
            "filename": "",
            "force": False,
            "capture_id": None,
            "raw_item_id": "raw::pcap::abc123",
            "bssid": "AA:BB:CC:DD:EE:FF",
        }
    ]


def test_fingerprint_details_by_filename_and_mac(client, tmp_path, monkeypatch):
    monkeypatch.setattr(fingerprint_router, "HANDSHAKES_DIR", str(tmp_path))
    content = {
        "ssid": "TestSSID",
        "bssid": "AA:BB:CC:DD:EE:FF",
        "classification": {
            "type": "router_ap",
            "confidence": 0.81,
            "tier": "high",
            "version": "v2",
            "scores": {"router_ap": 0.81},
            "signals": {"vendor": True},
            "evidence": ["Vendor family is common in router/AP devices."],
        },
        "meta": {"source": "tshark"},
    }
    content_without_bssid = {"ssid": "NoBssid", "meta": {"source": "tshark"}}

    def fake_raw_agg(bssid):
        if not bssid:
            return {"present": False}
        return {
            "present": True,
            "bssid": "AA:BB:CC:DD:EE:FF",
            "files_count": 1,
            "aggregate": {
                "beacon_count_total": 10,
                "beacon_count_peak": 10,
                "eapol_count_total": 2,
                "eapol_count_peak": 2,
                "probe_client_count_peak": 4,
                "channels": [6],
                "frequencies_mhz": [2437],
                "last_seen_offset_s_max": 12.3,
                "warnings": [],
            },
            "files": [],
        }

    monkeypatch.setattr(
        fingerprint_router.rawsniffer_service,
        "get_aggregated_metadata_for_bssid",
        fake_raw_agg,
    )

    details_name = "Test_aabbccddeeff.details"
    (tmp_path / details_name).write_text(json.dumps(content), encoding="utf-8")
    no_bssid_name = "NoBssid_aabbccddeeff.details"
    (tmp_path / no_bssid_name).write_text(
        json.dumps(content_without_bssid), encoding="utf-8"
    )

    by_name = client.get(f"/api/fingerprint/details?filename={details_name}")
    assert by_name.status_code == 200
    assert by_name.json()["data"]["ssid"] == "TestSSID"
    assert by_name.json()["data"]["classification"]["type"] == "router_ap"
    assert by_name.json()["data"]["classification"]["version"] == "v2"
    assert by_name.json()["data"]["raw_sniffer"]["present"] is True
    assert (
        by_name.json()["data"]["raw_sniffer"]["aggregate"]["beacon_count_total"] == 10
    )

    by_mac = client.get("/api/fingerprint/details?mac=AA:BB:CC:DD:EE:FF")
    assert by_mac.status_code == 200
    assert by_mac.json()["data"]["meta"]["source"] == "tshark"
    assert by_mac.json()["data"]["raw_sniffer"]["present"] is True

    no_bssid = client.get(f"/api/fingerprint/details?filename={no_bssid_name}")
    assert no_bssid.status_code == 200
    assert no_bssid.json()["data"]["raw_sniffer"] == {"present": False}

    missing = client.get("/api/fingerprint/details?filename=missing.details")
    assert missing.status_code == 404


def test_fingerprint_details_filename_without_extension_and_rawsniffer_failure(
    client, tmp_path, monkeypatch
):
    monkeypatch.setattr(fingerprint_router, "HANDSHAKES_DIR", str(tmp_path))
    (tmp_path / "Short_aabbccddeeff.details").write_text(
        json.dumps({"ssid": "ShortName", "meta": {"source": "cache"}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        fingerprint_router.rawsniffer_service,
        "get_aggregated_metadata_for_bssid",
        lambda _bssid: (_ for _ in ()).throw(RuntimeError("raw agg failed")),
    )

    resp = client.get("/api/fingerprint/details?filename=Short_aabbccddeeff")
    assert resp.status_code == 200
    payload = resp.json()["data"]
    assert payload["ssid"] == "ShortName"
    assert payload["raw_sniffer"] == {"present": False}


def test_fingerprint_details_uses_mac_when_bssid_missing(client, tmp_path, monkeypatch):
    monkeypatch.setattr(fingerprint_router, "HANDSHAKES_DIR", str(tmp_path))
    (tmp_path / "NoBssid_aabbccddeeff.details").write_text(
        json.dumps({"ssid": "NoBssid", "meta": {"source": "cache"}}),
        encoding="utf-8",
    )

    captured = {}

    def fake_raw_agg(bssid):
        captured["bssid"] = bssid
        return {"present": bool(bssid), "bssid": bssid}

    monkeypatch.setattr(
        fingerprint_router.rawsniffer_service,
        "get_aggregated_metadata_for_bssid",
        fake_raw_agg,
    )

    resp = client.get("/api/fingerprint/details?mac=AA:BB:CC:DD:EE:FF")
    assert resp.status_code == 200
    assert captured["bssid"] == "AA:BB:CC:DD:EE:FF"
    assert resp.json()["data"]["raw_sniffer"]["present"] is True


def test_fingerprint_details_returns_500_for_invalid_json(
    client, tmp_path, monkeypatch
):
    monkeypatch.setattr(fingerprint_router, "HANDSHAKES_DIR", str(tmp_path))
    (tmp_path / "Broken_aabbccddeeff.details").write_text("{", encoding="utf-8")

    resp = client.get("/api/fingerprint/details?filename=Broken_aabbccddeeff.details")
    assert resp.status_code == 500
    assert (
        "Expecting property name enclosed in double quotes"
        in resp.json()["detail"]["message"]
    )
