from app.api.routers import wordlists as wordlists_router
from app.api.routers import hashcat as hashcat_router
from app.api.routers import aircrack as aircrack_router
from app.api.routers import convert as convert_router


class _FakeCrack:
    def __init__(self):
        self.last_run_hashcat_args = None
        self.last_run_hashcat_kwargs = None
        self.last_preview_args = None
        self.last_preview_kwargs = None

    def get_custom_wordlists(self):
        return [{"name": "wl.txt"}]

    def get_hashcat_rules(self):
        return [{"name": "rule"}]

    def get_hashcat_masks(self):
        return [{"name": "mask", "path": "/tmp/a.hcmask"}]

    def get_hashcat_devices(self):
        return [{"id": "1"}]

    def run_hashcat(self, *args, **kwargs):
        self.last_run_hashcat_args = args
        self.last_run_hashcat_kwargs = kwargs
        return {"status": "started"}

    def preview_hashcat_association(self, *args, **kwargs):
        self.last_preview_args = args
        self.last_preview_kwargs = kwargs
        return {
            "status": "success",
            "candidate_count": 10,
            "capped": False,
            "sample_candidates": ["a", "b"],
            "sources": {"seed_counts": {}, "transformations": []},
            "warnings": [],
        }

    def run_aircrack_attack(self, *args, **kwargs):
        return {"status": "started"}

    def convert_pcap(self, *args, **kwargs):
        return {"status": "started"}

    def convert_pcap_multi(self, *args, **kwargs):
        return {"status": "started"}


def test_wordlists_hashcat_aircrack_convert(client, monkeypatch):
    fake = _FakeCrack()
    monkeypatch.setattr(wordlists_router, "crack_service", fake)
    monkeypatch.setattr(hashcat_router, "crack_service", fake)
    monkeypatch.setattr(aircrack_router, "crack_service", fake)
    monkeypatch.setattr(convert_router, "crack_service", fake)

    resp = client.get("/api/wordlists/custom")
    assert resp.status_code == 200
    assert resp.json()["data"][0]["name"] == "wl.txt"

    resp = client.get("/api/hashcat/rules")
    assert resp.status_code == 200
    resp = client.get("/api/hashcat/masks")
    assert resp.status_code == 200
    resp = client.get("/api/hashcat/devices")
    assert resp.status_code == 200

    resp = client.post("/api/hashcat/jobs", json={"filename": "test.22000"})
    assert resp.status_code == 200
    assert fake.last_run_hashcat_kwargs["skip_quality_gate"] is False

    resp = client.post(
        "/api/hashcat/jobs",
        json={
            "filename": "test.22000",
            "attack_mode": "association_hint_first",
            "association_hints": "router_hint\nanother_hint",
            "skip_quality_gate": True,
        },
    )
    assert resp.status_code == 200
    # run_hashcat args order:
    # (..., mask_file, association_hint, association_hints)
    assert fake.last_run_hashcat_args[-1] == "router_hint\nanother_hint"
    assert fake.last_run_hashcat_kwargs["skip_quality_gate"] is True

    resp = client.post(
        "/api/hashcat/association/preview",
        json={
            "filename": "test.22000",
            "mode": "association_hint_first",
            "association_hints": "router_hint\nanother_hint",
        },
    )
    assert resp.status_code == 200
    assert fake.last_preview_args[0] == "test.22000"
    assert fake.last_preview_kwargs["mode"] == "association_hint_first"

    resp = client.post(
        "/api/aircrack/jobs",
        json={"filename": "test.pcap", "bssid": "aa", "wordlist": "wl"},
    )
    assert resp.status_code == 200

    resp = client.post(
        "/api/aircrack/jobs",
        json={"raw_item_id": "raw::pcap::abc123", "bssid": "aa", "wordlist": "wl"},
    )
    assert resp.status_code == 200

    resp = client.post("/api/convert/hcx", json={"filename": "test.pcap"})
    assert resp.status_code == 200

    resp = client.post("/api/convert/hcx", json={"raw_item_id": "raw::pcap::abc123"})
    assert resp.status_code == 200

    resp = client.post("/api/convert/hcx/batch", json={"filenames": ["test.pcap"]})
    assert resp.status_code == 200


def test_hashcat_association_preview_rejects_invalid_mode(client):
    resp = client.post(
        "/api/hashcat/association/preview",
        json={"filename": "test.22000", "mode": "bad_mode"},
    )
    assert resp.status_code == 400


def test_aircrack_missing_credentials(client, monkeypatch):
    """Test aircrack endpoint rejects requests with no filename/capture_id/raw_item_id."""
    fake = _FakeCrack()
    monkeypatch.setattr(aircrack_router, "crack_service", fake)

    # No filename, capture_id, or raw_item_id should fail
    resp = client.post(
        "/api/aircrack/jobs",
        json={"bssid": "aa:bb:cc:dd:ee:ff", "wordlist": "wl"},
    )
    assert resp.status_code == 400
    response_data = resp.json()
    message = (
        response_data.get("detail", {}).get("message", "")
        if isinstance(response_data.get("detail"), dict)
        else response_data.get("message", "")
    )
    assert "filename, capture_id or raw_item_id required" in message
