"""Tests for the Recon Center API endpoints (recon.py).

Covers:
  1. GET /api/recon/kill-chain
  2. GET /api/recon/vulnerability-matrix
  3. GET /api/recon/attack-effectiveness
  4. GET /api/recon/temporal-intel
  5. GET /api/recon/audit-report
  6. POST/GET /api/recon/kill-chain/snapshot, /history (S-F3)
  7. POST/GET /api/recon/audit-report/snapshot, /snapshots, /compare (R-F5)
  8. POST /api/recon/attack-plan (O-F6)
  9. GET /api/recon/comms/device-fingerprints (C-F2)
  10. GET /api/recon/comms/colocation (C-F3)
  11. GET /api/recon/comms/relationship-graph (C-F1)
  12. GET /api/recon/probe-intel/derandom (SI-F5)
  13. GET /api/recon/probe-intel/geocorrelation (SI-F7)

Also tests internal helpers: _scan_hash_files, _classify_network, _quick_score,
_build_vuln_flags – exercised indirectly through endpoints.
"""

from __future__ import annotations

import json
import os
import textwrap
import time
from datetime import datetime, timezone

import pytest

from app.api.routers import recon as recon_module
from app.core import config as config_module
from app.services import recon_runtime_service as recon_runtime_module


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_dataset(**overrides):
    """Return a small realistic dataset dict (mac → net)."""
    base = {
        "aa:bb:cc:dd:ee:01": {
            "ssid": "HomeNet",
            "encryption": "WPA2",
            "handshake": True,
            "raw_eapol_count": 4,
            "raw_beacon_count": 20,
            "raw_probe_peak_count": 3,
            "sources": ["pwnagotchi"],
            "device_type": "router_ap",
            "ts_last": "2025-04-01T12:00:00Z",
            "channel": 6,
            "frequency": 2437,
            "rssi": -55.0,
            "lat": 40.7128,
            "lng": -74.0060,
        },
        "aa:bb:cc:dd:ee:02": {
            "ssid": "OpenCafe",
            "encryption": "OPEN",
            "handshake": False,
            "raw_eapol_count": 0,
            "raw_beacon_count": 5,
            "raw_probe_peak_count": 0,
            "sources": ["wardrive"],
            "device_type": "router_ap",
            "ts_last": "2025-04-01T10:00:00Z",
            "channel": 1,
            "frequency": 2412,
            "rssi": -72.0,
            "lat": 40.7128,
            "lng": -74.0061,
        },
        "aa:bb:cc:dd:ee:03": {
            "ssid": "SecureOffice",
            "encryption": "WPA3",
            "handshake": True,
            "raw_eapol_count": 2,
            "raw_beacon_count": 10,
            "raw_probe_peak_count": 1,
            "pass": "s3cur3!",
            "sources": ["pwnagotchi", "wardrive"],
            "device_type": "router_ap",
            "ts_last": "2025-03-20T08:30:00Z",
            "channel": 6,
            "frequency": 2437,
            "rssi": -48.0,
            "lat": 40.7128,
            "lng": -74.0060,
        },
        "aa:bb:cc:dd:ee:04": {
            "ssid": "Linksys_Default",
            "encryption": "WEP",
            "handshake": False,
            "raw_eapol_count": 0,
            "raw_beacon_count": 1,
            "raw_probe_peak_count": 0,
            "sources": ["wardrive"],
            "device_type": "unknown",
            "ts_last": "2024-01-15T06:00:00Z",
            "channel": 11,
            "frequency": 2462,
            "rssi": -85.0,
        },
    }
    base.update(overrides)
    return base


def _write_hash_file(tmp_path, mac_clean: str, lines: list[str], suffix=".22000"):
    """Write a mock .22000 file into tmp_path."""
    fname = f"{mac_clean}{suffix}"
    filepath = tmp_path / fname
    filepath.write_text("\n".join(lines) + "\n")
    return filepath


def _write_try_file(tmp_path, mac_clean: str, entries: list[dict]):
    """Write a mock .try history file into tmp_path."""
    fname = f"{mac_clean}.try"
    filepath = tmp_path / fname
    filepath.write_text(json.dumps({"entries": entries}))
    return filepath


@pytest.fixture()
def fake_dataset():
    return _make_dataset()


@pytest.fixture()
def patch_recon(monkeypatch, tmp_path, fake_dataset):
    """Patch all external dependencies of recon module."""
    monkeypatch.setattr(recon_module, "load_real_data", lambda: fake_dataset)
    monkeypatch.setattr(recon_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(recon_runtime_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(
        recon_module.job_manager, "list_jobs", lambda: []
    )
    monkeypatch.setattr(
        recon_runtime_module.job_manager, "list_jobs", lambda: []
    )
    monkeypatch.setattr(
        recon_module.probe_service, "get_cache_status", lambda: {"cached": False}
    )
    # Reset module-level caches so tests don't leak state into each other
    monkeypatch.setattr(recon_runtime_module, "_dir_listing_cache", None)
    monkeypatch.setattr(recon_runtime_module, "_hash_scan_cache", {})
    monkeypatch.setattr(recon_runtime_module, "_artifact_signature_cache", None)
    monkeypatch.setattr(recon_runtime_module, "_recon_response_cache", {})
    return tmp_path


# ---------------------------------------------------------------------------
# 1. Kill Chain
# ---------------------------------------------------------------------------


class TestKillChain:
    def test_basic_response_structure(self, client, patch_recon):
        resp = client.get("/api/recon/kill-chain")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert "total" in data
        assert "stages" in data
        assert "hash_intel" in data
        assert data["total"] == 4
        assert len(data["stages"]) == 6

    def test_stage_names(self, client, patch_recon):
        resp = client.get("/api/recon/kill-chain")
        stages = resp.json()["data"]["stages"]
        names = [s["stage"] for s in stages]
        assert names == [
            "discovered",
            "captured",
            "fingerprinted",
            "hash_ready",
            "under_attack",
            "cracked",
        ]

    def test_cracked_network_classified(self, client, patch_recon):
        """Network with 'pass' field → cracked stage."""
        resp = client.get("/api/recon/kill-chain")
        cracked = next(s for s in resp.json()["data"]["stages"] if s["stage"] == "cracked")
        macs = [n["mac"] for n in cracked["networks"]]
        assert "aa:bb:cc:dd:ee:03" in macs

    def test_open_network_discovered(self, client, patch_recon):
        """Open network without handshake → lower stages."""
        resp = client.get("/api/recon/kill-chain")
        stages = resp.json()["data"]["stages"]
        # OpenCafe has beacons but no handshake
        discovered = next(s for s in stages if s["stage"] == "discovered")
        macs = [n["mac"] for n in discovered["networks"]]
        # Open café and WEP default only have beacons, no pcap captures
        assert "aa:bb:cc:dd:ee:02" in macs

    def test_hash_ready_with_22000_file(self, client, patch_recon):
        """Network with .22000 file → hash_ready stage."""
        tmp_path = patch_recon
        _write_hash_file(tmp_path, "aabbccddee01", [
            "WPA*01*aabbcc*001122*SSID*hash_data",
            "WPA*02*aabbcc*001122*SSID*eapol_data",
        ])
        resp = client.get("/api/recon/kill-chain")
        hash_ready = next(s for s in resp.json()["data"]["stages"] if s["stage"] == "hash_ready")
        macs = [n["mac"] for n in hash_ready["networks"]]
        assert "aa:bb:cc:dd:ee:01" in macs

    def test_hash_intel_counters(self, client, patch_recon):
        """hash_intel counters reflect PMKID/EAPOL classification."""
        tmp_path = patch_recon
        # Net 01: both PMKID and EAPOL
        _write_hash_file(tmp_path, "aabbccddee01", [
            "WPA*01*abcd*1234*HN*pmkid_data",
            "WPA*02*abcd*1234*HN*eapol_data",
        ])
        # Net 04: PMKID only
        _write_hash_file(tmp_path, "aabbccddee04", [
            "WPA*01*efgh*5678*LD*pmkid_only",
        ])

        resp = client.get("/api/recon/kill-chain")
        hi = resp.json()["data"]["hash_intel"]
        assert hi["total_with_hash"] == 2
        assert hi["total_pmkid"] == 2
        assert hi["total_eapol_hash"] == 1
        assert hi["pmkid_only"] == 1   # net 04
        assert hi["eapol_only"] == 0
        assert hi["both"] == 1         # net 01

    def test_network_entry_has_pmkid_fields(self, client, patch_recon):
        """Network entries with hash include pmkid/eapol fields."""
        tmp_path = patch_recon
        _write_hash_file(tmp_path, "aabbccddee01", [
            "WPA*01*a*b*c*d",
            "WPA*01*e*f*g*h",
        ])
        resp = client.get("/api/recon/kill-chain")
        stages = resp.json()["data"]["stages"]
        # Find net 01 in any stage
        for stage in stages:
            for n in stage["networks"]:
                if n["mac"] == "aa:bb:cc:dd:ee:01":
                    assert n["has_pmkid"] is True
                    assert n["has_eapol_hash"] is False
                    assert n["pmkid_count"] == 2
                    assert n["eapol_count"] == 0
                    return
        pytest.fail("Network aa:bb:cc:dd:ee:01 not found in any stage")

    def test_empty_dataset(self, client, monkeypatch, tmp_path):
        monkeypatch.setattr(recon_module, "load_real_data", lambda: {})
        monkeypatch.setattr(recon_module, "HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(recon_runtime_module, "HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(recon_module.job_manager, "list_jobs", lambda: [])
        monkeypatch.setattr(recon_runtime_module.job_manager, "list_jobs", lambda: [])
        resp = client.get("/api/recon/kill-chain")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["total"] == 0
        assert data["hash_intel"]["total_with_hash"] == 0

    def test_under_attack_stage(self, client, monkeypatch, tmp_path, fake_dataset):
        """Running cracking job → network is 'under_attack'."""
        monkeypatch.setattr(recon_module, "load_real_data", lambda: fake_dataset)
        monkeypatch.setattr(recon_module, "HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(recon_runtime_module, "HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(
            recon_module.job_manager,
            "list_jobs",
            lambda: [
                {
                    "status": "running",
                    "type": "cracking",
                    "command": ["hashcat", "-m", "22000", "aabbccddee01.22000"],
                }
            ],
        )
        monkeypatch.setattr(
            recon_runtime_module.job_manager,
            "list_jobs",
            lambda: [
                {
                    "status": "running",
                    "type": "cracking",
                    "command": ["hashcat", "-m", "22000", "aabbccddee01.22000"],
                }
            ],
        )
        recon_runtime_module.clear_recon_runtime_cache()
        resp = client.get("/api/recon/kill-chain")
        under_attack = next(s for s in resp.json()["data"]["stages"] if s["stage"] == "under_attack")
        macs = [n["mac"] for n in under_attack["networks"]]
        assert "aa:bb:cc:dd:ee:01" in macs

    def test_kill_chain_response_cache_skips_repeat_recompute_until_cleared(self, client, patch_recon, monkeypatch):
        calls = {"count": 0}

        def _fake_scan(_mac_clean):
            calls["count"] += 1
            return {
                "has_hash": False,
                "has_pmkid": False,
                "has_eapol_hash": False,
                "pmkid_count": 0,
                "eapol_count": 0,
                "total_lines": 0,
            }

        monkeypatch.setattr(recon_runtime_module, "_scan_hash_files", _fake_scan)
        monkeypatch.setattr(recon_module, "_scan_hash_files", _fake_scan)
        recon_runtime_module.clear_recon_runtime_cache()

        first = client.get("/api/recon/kill-chain")
        assert first.status_code == 200
        first_calls = calls["count"]
        assert first_calls > 0

        second = client.get("/api/recon/kill-chain")
        assert second.status_code == 200
        assert calls["count"] == first_calls

        recon_runtime_module.clear_recon_runtime_cache()
        third = client.get("/api/recon/kill-chain")
        assert third.status_code == 200
        assert calls["count"] > first_calls

    def test_kill_chain_summary_returns_counts_with_lightweight_previews(self, client, patch_recon):
        resp = client.get("/api/recon/kill-chain/summary")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["total"] == 4
        assert len(data["stages"]) == 6
        assert all("networks" not in stage for stage in data["stages"])
        assert all("preview_networks" in stage for stage in data["stages"])
        discovered = next(stage for stage in data["stages"] if stage["stage"] == "discovered")
        assert discovered["preview_count"] == min(discovered["count"], 20)
        assert len(discovered["preview_networks"]) == discovered["preview_count"]

    def test_kill_chain_stage_returns_filtered_members(self, client, patch_recon):
        resp = client.get("/api/recon/kill-chain/stage", params={"stage": "cracked"})
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["stage"] == "cracked"
        assert data["total"] == 1
        assert len(data["networks"]) == 1
        assert data["networks"][0]["mac"] == "aa:bb:cc:dd:ee:03"

    def test_kill_chain_stage_supports_search(self, client, patch_recon):
        resp = client.get(
            "/api/recon/kill-chain/stage",
            params={"stage": "discovered", "search": "OpenCafe"},
        )
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["total"] == 1
        assert data["networks"][0]["ssid"] == "OpenCafe"

    def test_recon_cache_manifest_uses_dataset_and_artifact_signatures(self, client, patch_recon, monkeypatch):
        monkeypatch.setattr(recon_module, "get_data_revision", lambda: 77)
        monkeypatch.setattr(recon_runtime_module, "get_data_revision", lambda: 77)
        monkeypatch.setattr(
            recon_module.probe_service,
            "get_cache_status",
            lambda: {"cached": True, "stale": False, "pcap_count": 2, "result": {"summary": {"total_probes": 7, "unique_clients": 3, "unique_ssids": 4}}},
        )
        monkeypatch.setattr(
            recon_module.packet_analysis_service,
            "get_cache_status",
            lambda: {"cached": True, "stale": False, "pcap_count": 1, "result": {"summary": {"total_deauth": 2, "total_disassoc": 1, "targeted_bssids": 1}}},
        )

        resp = client.get("/api/recon/cache-manifest")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["dataset_revision"] == 77
        assert data["artifacts_signature"]
        assert data["probe_signature"][0] is True
        assert data["deep_analysis_signature"][0] is True
        assert len(data["scope"]) == 24


# ---------------------------------------------------------------------------
# 2. Vulnerability Matrix
# ---------------------------------------------------------------------------


class TestVulnerabilityMatrix:
    def test_basic_structure(self, client, patch_recon):
        resp = client.get("/api/recon/vulnerability-matrix")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert "total" in data
        assert "rows" in data
        assert "offset" in data
        assert "limit" in data

    def test_default_sort_by_attack_score_desc(self, client, patch_recon):
        resp = client.get("/api/recon/vulnerability-matrix")
        rows = resp.json()["data"]["rows"]
        scores = [r["attack_score"] for r in rows]
        assert scores == sorted(scores, reverse=True)

    def test_filter_by_encryption(self, client, patch_recon):
        resp = client.get("/api/recon/vulnerability-matrix", params={"encryption": "OPEN"})
        rows = resp.json()["data"]["rows"]
        assert all(r["encryption"] == "OPEN" for r in rows)
        assert len(rows) == 1

    def test_filter_by_stage(self, client, patch_recon):
        resp = client.get("/api/recon/vulnerability-matrix", params={"stage": "cracked"})
        rows = resp.json()["data"]["rows"]
        assert all(r["stage"] == "cracked" for r in rows)

    def test_sort_asc(self, client, patch_recon):
        resp = client.get(
            "/api/recon/vulnerability-matrix",
            params={"sort_by": "attack_score", "sort_dir": "asc"},
        )
        rows = resp.json()["data"]["rows"]
        scores = [r["attack_score"] for r in rows]
        assert scores == sorted(scores)

    def test_sort_by_ssid(self, client, patch_recon):
        resp = client.get(
            "/api/recon/vulnerability-matrix",
            params={"sort_by": "ssid", "sort_dir": "asc"},
        )
        rows = resp.json()["data"]["rows"]
        ssids = [r["ssid"].lower() for r in rows]
        assert ssids == sorted(ssids)

    def test_sort_by_encryption(self, client, patch_recon):
        resp = client.get(
            "/api/recon/vulnerability-matrix",
            params={"sort_by": "encryption", "sort_dir": "asc"},
        )
        assert resp.status_code == 200

    def test_sort_by_stage(self, client, patch_recon):
        resp = client.get(
            "/api/recon/vulnerability-matrix",
            params={"sort_by": "stage", "sort_dir": "asc"},
        )
        assert resp.status_code == 200

    def test_sort_by_readiness_score(self, client, patch_recon):
        resp = client.get(
            "/api/recon/vulnerability-matrix",
            params={"sort_by": "readiness_score", "sort_dir": "desc"},
        )
        rows = resp.json()["data"]["rows"]
        scores = [r["readiness_score"] for r in rows]
        assert scores == sorted(scores, reverse=True)

    def test_pagination(self, client, patch_recon):
        resp = client.get(
            "/api/recon/vulnerability-matrix",
            params={"limit": 2, "offset": 0},
        )
        data = resp.json()["data"]
        assert len(data["rows"]) == 2
        assert data["total"] == 4
        assert data["offset"] == 0
        assert data["limit"] == 2

        resp2 = client.get(
            "/api/recon/vulnerability-matrix",
            params={"limit": 2, "offset": 2},
        )
        data2 = resp2.json()["data"]
        assert len(data2["rows"]) == 2

    def test_invalid_sort_by(self, client, patch_recon):
        resp = client.get(
            "/api/recon/vulnerability-matrix",
            params={"sort_by": "invalid_field"},
        )
        assert resp.status_code == 400

    def test_invalid_sort_dir(self, client, patch_recon):
        resp = client.get(
            "/api/recon/vulnerability-matrix",
            params={"sort_dir": "up"},
        )
        assert resp.status_code == 400

    def test_invalid_limit(self, client, patch_recon):
        resp = client.get(
            "/api/recon/vulnerability-matrix",
            params={"limit": 999},
        )
        assert resp.status_code == 400

    def test_invalid_offset(self, client, patch_recon):
        resp = client.get(
            "/api/recon/vulnerability-matrix",
            params={"offset": -1},
        )
        assert resp.status_code == 400

    def test_pmkid_fields_present(self, client, patch_recon):
        """Rows include has_pmkid, has_eapol_hash, pmkid_count, eapol_hash_count."""
        tmp_path = patch_recon
        _write_hash_file(tmp_path, "aabbccddee01", [
            "WPA*01*a*b*c*d",
            "WPA*02*e*f*g*h",
            "WPA*02*i*j*k*l",
        ])
        resp = client.get("/api/recon/vulnerability-matrix")
        rows = resp.json()["data"]["rows"]
        net01 = next(r for r in rows if r["mac"] == "aa:bb:cc:dd:ee:01")
        assert net01["has_pmkid"] is True
        assert net01["has_eapol_hash"] is True
        assert net01["pmkid_count"] == 1
        assert net01["eapol_hash_count"] == 2

    def test_vuln_flags_pmkid(self, client, patch_recon):
        """PMKID flag appears with correct severity."""
        tmp_path = patch_recon
        _write_hash_file(tmp_path, "aabbccddee01", ["WPA*01*a*b*c*d"])
        resp = client.get("/api/recon/vulnerability-matrix")
        rows = resp.json()["data"]["rows"]
        net01 = next(r for r in rows if r["mac"] == "aa:bb:cc:dd:ee:01")
        flag_ids = [f["id"] for f in net01["flags"]]
        assert "pmkid" in flag_ids
        pmkid_flag = next(f for f in net01["flags"] if f["id"] == "pmkid")
        assert pmkid_flag["severity"] == "critical"

    def test_vuln_flags_eapol_hash(self, client, patch_recon):
        """EAPOL HASH flag appears when .22000 has WPA*02* lines."""
        tmp_path = patch_recon
        _write_hash_file(tmp_path, "aabbccddee01", ["WPA*02*a*b*c*d"])
        resp = client.get("/api/recon/vulnerability-matrix")
        rows = resp.json()["data"]["rows"]
        net01 = next(r for r in rows if r["mac"] == "aa:bb:cc:dd:ee:01")
        flag_ids = [f["id"] for f in net01["flags"]]
        assert "eapol_hash" in flag_ids
        eapol_flag = next(f for f in net01["flags"] if f["id"] == "eapol_hash")
        assert eapol_flag["severity"] == "good"

    def test_vuln_flags_wep(self, client, patch_recon):
        resp = client.get("/api/recon/vulnerability-matrix")
        rows = resp.json()["data"]["rows"]
        wep_net = next(r for r in rows if r["mac"] == "aa:bb:cc:dd:ee:04")
        flag_ids = [f["id"] for f in wep_net["flags"]]
        assert "wep" in flag_ids

    def test_vuln_flags_wpa3(self, client, patch_recon):
        resp = client.get("/api/recon/vulnerability-matrix")
        rows = resp.json()["data"]["rows"]
        wpa3_net = next(r for r in rows if r["mac"] == "aa:bb:cc:dd:ee:03")
        flag_ids = [f["id"] for f in wpa3_net["flags"]]
        assert "wpa3" in flag_ids

    def test_vuln_flags_weak_ssid(self, client, patch_recon):
        resp = client.get("/api/recon/vulnerability-matrix")
        rows = resp.json()["data"]["rows"]
        linksys_net = next(r for r in rows if r["mac"] == "aa:bb:cc:dd:ee:04")
        flag_ids = [f["id"] for f in linksys_net["flags"]]
        assert "weak_ssid" in flag_ids

    def test_vuln_flags_eapol_seen_no_hash(self, client, patch_recon):
        """Network with EAPOL frames but no .22000 hash → eapol_no_hash flag."""
        resp = client.get("/api/recon/vulnerability-matrix")
        rows = resp.json()["data"]["rows"]
        net01 = next(r for r in rows if r["mac"] == "aa:bb:cc:dd:ee:01")
        flag_ids = [f["id"] for f in net01["flags"]]
        # Net 01 has raw_eapol_count=4 but no .22000 → eapol_no_hash
        assert "eapol_no_hash" in flag_ids

    def test_open_network_score_zero(self, client, patch_recon):
        resp = client.get("/api/recon/vulnerability-matrix")
        rows = resp.json()["data"]["rows"]
        open_net = next(r for r in rows if r["mac"] == "aa:bb:cc:dd:ee:02")
        assert open_net["attack_score"] == 0
        assert open_net["readiness_status"] == "open"

    def test_cracked_network_score_zero(self, client, patch_recon):
        resp = client.get("/api/recon/vulnerability-matrix")
        rows = resp.json()["data"]["rows"]
        cracked = next(r for r in rows if r["mac"] == "aa:bb:cc:dd:ee:03")
        assert cracked["attack_score"] == 0
        assert cracked["readiness_status"] == "already_cracked"

    def test_pmkid_bonus_in_score(self, client, patch_recon):
        """PMKID presence adds +5 to the attack score."""
        tmp_path = patch_recon
        # First get score without PMKID
        resp1 = client.get("/api/recon/vulnerability-matrix")
        rows1 = resp1.json()["data"]["rows"]
        net01_no_pmkid = next(r for r in rows1 if r["mac"] == "aa:bb:cc:dd:ee:01")
        score_without = net01_no_pmkid["attack_score"]

        # Now add PMKID hash file
        _write_hash_file(tmp_path, "aabbccddee01", ["WPA*01*a*b*c*d"])
        recon_runtime_module._clear_caches()  # bust stale dir/hash caches after filesystem change
        resp2 = client.get("/api/recon/vulnerability-matrix")
        rows2 = resp2.json()["data"]["rows"]
        net01_with_pmkid = next(r for r in rows2 if r["mac"] == "aa:bb:cc:dd:ee:01")
        score_with = net01_with_pmkid["attack_score"]

        # With hash (+30) and PMKID bonus (+5), but without hash (-20 removed)
        # The exact diff depends on base scoring; just verify increase
        assert score_with > score_without

    def test_target_detail_returns_single_target_without_matrix_page_fetch_shape_loss(self, client, patch_recon):
        resp = client.get("/api/recon/target-detail", params={"mac": "aa:bb:cc:dd:ee:01"})
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["mac"] == "aa:bb:cc:dd:ee:01"
        assert data["ssid"] == "HomeNet"
        assert "attack_score" in data
        assert "flags" in data

    def test_target_detail_is_case_insensitive(self, client, patch_recon):
        resp = client.get("/api/recon/target-detail", params={"mac": "AA-BB-CC-DD-EE-03"})
        assert resp.status_code == 200
        assert resp.json()["data"]["ssid"] == "SecureOffice"


# ---------------------------------------------------------------------------
# 3. Attack Effectiveness
# ---------------------------------------------------------------------------


class TestAttackEffectiveness:
    def test_basic_structure(self, client, patch_recon):
        resp = client.get("/api/recon/attack-effectiveness")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert "total_attacks" in data
        assert "total_cracked" in data
        assert "total_exhausted" in data
        assert "total_failed" in data
        assert "success_rate" in data
        assert "by_mode" in data
        assert "by_encryption" in data
        assert "top_wordlists" in data
        assert "avg_crack_time_seconds" in data

    def test_no_history_files(self, client, patch_recon):
        """No .try files → zeros."""
        resp = client.get("/api/recon/attack-effectiveness")
        data = resp.json()["data"]
        assert data["total_attacks"] == 0
        assert data["success_rate"] == 0

    def test_with_history(self, client, patch_recon):
        """Parse .try history files correctly."""
        tmp_path = patch_recon
        _write_try_file(tmp_path, "aabbccddee01", [
            {
                "status": "CRACKED",
                "params": {"attack_mode": "dictionary", "wordlist": "/path/rockyou.txt"},
                "start_time": "2025-04-01T10:00:00Z",
                "end_time": "2025-04-01T10:05:00Z",
            },
            {
                "status": "EXHAUSTED",
                "params": {"attack_mode": "dictionary", "wordlist": "/path/common.txt"},
                "start_time": "2025-03-31T09:00:00Z",
                "end_time": "2025-03-31T09:10:00Z",
            },
        ])
        _write_try_file(tmp_path, "aabbccddee04", [
            {
                "status": "FAILED",
                "params": {"attack_mode": "brute_force"},
                "start_time": "2025-04-01T11:00:00Z",
                "end_time": "2025-04-01T11:15:00Z",
            },
        ])

        resp = client.get("/api/recon/attack-effectiveness")
        data = resp.json()["data"]
        assert data["total_attacks"] == 3
        assert data["total_cracked"] == 1
        assert data["total_exhausted"] == 1
        assert data["total_failed"] == 1
        assert data["success_rate"] == pytest.approx(33.3, abs=0.1)

    def test_by_mode_breakdown(self, client, patch_recon):
        tmp_path = patch_recon
        _write_try_file(tmp_path, "aabbccddee01", [
            {"status": "CRACKED", "params": {"attack_mode": "dictionary"}},
            {"status": "EXHAUSTED", "params": {"attack_mode": "dictionary"}},
            {"status": "CRACKED", "params": {"attack_mode": "brute_force"}},
        ])
        resp = client.get("/api/recon/attack-effectiveness")
        data = resp.json()["data"]
        modes = {m["mode"]: m for m in data["by_mode"]}
        assert modes["dictionary"]["attempts"] == 2
        assert modes["dictionary"]["cracked"] == 1
        assert modes["brute_force"]["cracked"] == 1

    def test_top_wordlists(self, client, patch_recon):
        tmp_path = patch_recon
        _write_try_file(tmp_path, "aabbccddee01", [
            {"status": "CRACKED", "params": {"attack_mode": "dictionary", "wordlist": "/path/rockyou.txt"}},
            {"status": "CRACKED", "params": {"attack_mode": "dictionary", "wordlist": "/path/rockyou.txt"}},
            {"status": "CRACKED", "params": {"attack_mode": "dictionary", "wordlist": "/path/common.txt"}},
        ])
        resp = client.get("/api/recon/attack-effectiveness")
        top = resp.json()["data"]["top_wordlists"]
        assert top[0]["name"] == "rockyou.txt"
        assert top[0]["cracks"] == 2

    def test_avg_crack_time(self, client, patch_recon):
        tmp_path = patch_recon
        _write_try_file(tmp_path, "aabbccddee01", [
            {
                "status": "CRACKED",
                "params": {"attack_mode": "dictionary"},
                "start_time": 1000.0,
                "end_time": 1300.0,  # 300 seconds
            },
            {
                "status": "CRACKED",
                "params": {"attack_mode": "dictionary"},
                "start_time": 2000.0,
                "end_time": 2100.0,  # 100 seconds
            },
        ])
        resp = client.get("/api/recon/attack-effectiveness")
        avg = resp.json()["data"]["avg_crack_time_seconds"]
        assert avg == pytest.approx(200.0, abs=0.1)

    def test_by_encryption_breakdown(self, client, patch_recon):
        resp = client.get("/api/recon/attack-effectiveness")
        data = resp.json()["data"]
        enc_map = {e["encryption"]: e for e in data["by_encryption"]}
        assert "WPA2" in enc_map
        assert "OPEN" in enc_map
        assert enc_map["WPA2"]["targets"] == 1


# ---------------------------------------------------------------------------
# 4. Temporal Intelligence
# ---------------------------------------------------------------------------


class TestTemporalIntel:
    def test_basic_structure(self, client, patch_recon):
        resp = client.get("/api/recon/temporal-intel")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert "total_networks" in data
        assert "freshness" in data
        assert "hour_distribution" in data
        assert "day_distribution" in data
        assert "top_active_hours" in data
        assert "top_active_days" in data
        assert "first_seen" in data
        assert "last_seen" in data

    def test_freshness_classification(self, client, patch_recon):
        resp = client.get("/api/recon/temporal-intel")
        freshness = resp.json()["data"]["freshness"]
        total = sum(freshness.values())
        assert total == 4  # all 4 networks

    def test_hour_distribution_has_24_entries(self, client, patch_recon):
        resp = client.get("/api/recon/temporal-intel")
        hours = resp.json()["data"]["hour_distribution"]
        assert len(hours) == 24

    def test_day_distribution_has_7_entries(self, client, patch_recon):
        resp = client.get("/api/recon/temporal-intel")
        days = resp.json()["data"]["day_distribution"]
        assert len(days) == 7

    def test_top_active_hours_max_3(self, client, patch_recon):
        resp = client.get("/api/recon/temporal-intel")
        top = resp.json()["data"]["top_active_hours"]
        assert len(top) <= 3

    def test_first_last_seen(self, client, patch_recon):
        resp = client.get("/api/recon/temporal-intel")
        data = resp.json()["data"]
        assert data["first_seen"] is not None
        assert data["last_seen"] is not None

    def test_empty_dataset_temporal(self, client, monkeypatch, tmp_path):
        monkeypatch.setattr(recon_module, "load_real_data", lambda: {})
        monkeypatch.setattr(recon_module, "HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(recon_module.job_manager, "list_jobs", lambda: [])
        resp = client.get("/api/recon/temporal-intel")
        data = resp.json()["data"]
        assert data["total_networks"] == 0
        assert data["first_seen"] is None
        assert data["last_seen"] is None


# ---------------------------------------------------------------------------
# 5. Audit Report
# ---------------------------------------------------------------------------


class TestAuditReport:
    def test_basic_structure(self, client, patch_recon, monkeypatch):
        monkeypatch.setattr(
            config_module,
            "load_config",
            lambda: {
                "hashcat_path": "/opt/homebrew/bin/hashcat",
                "aircrack_path": "/opt/homebrew/bin/aircrack-ng",
                "hcxpcapngtool_path": "/opt/homebrew/bin/hcxpcapngtool",
                "tshark_path": "/opt/homebrew/bin/tshark",
            },
        )
        resp = client.get("/api/recon/audit-report")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert "generated_at" in data
        assert "methodology" in data
        assert "findings" in data
        assert "statistics" in data

    def test_methodology_tools(self, client, patch_recon, monkeypatch):
        monkeypatch.setattr(
            config_module,
            "load_config",
            lambda: {"hashcat_path": "/bin/hashcat", "tshark_path": "/bin/tshark"},
        )
        resp = client.get("/api/recon/audit-report")
        tools = resp.json()["data"]["methodology"]["tools"]
        assert "hashcat" in tools
        assert "tshark" in tools
        assert "aircrack-ng" not in tools

    def test_findings_counts(self, client, patch_recon, monkeypatch):
        monkeypatch.setattr(config_module, "load_config", lambda: {})
        resp = client.get("/api/recon/audit-report")
        findings = resp.json()["data"]["findings"]
        assert findings["total_networks"] == 4
        assert findings["cracked"] == 1  # SecureOffice has pass
        assert findings["with_handshake"] == 2  # HomeNet + SecureOffice
        assert findings["with_eapol_evidence"] == 2  # HomeNet (4) + SecureOffice (2)

    def test_encryption_distribution(self, client, patch_recon, monkeypatch):
        monkeypatch.setattr(config_module, "load_config", lambda: {})
        resp = client.get("/api/recon/audit-report")
        enc = resp.json()["data"]["findings"]["encryption_distribution"]
        assert "WPA2" in enc
        assert "OPEN" in enc
        assert "WPA3" in enc
        assert "WEP" in enc

    def test_sources_listed(self, client, patch_recon, monkeypatch):
        monkeypatch.setattr(config_module, "load_config", lambda: {})
        resp = client.get("/api/recon/audit-report")
        sources = resp.json()["data"]["methodology"]["sources"]
        assert "pwnagotchi" in sources
        assert "wardrive" in sources


# ---------------------------------------------------------------------------
# Helper coverage: _scan_hash_files edge cases
# ---------------------------------------------------------------------------


class TestScanHashFiles:
    def test_empty_directory(self, monkeypatch, tmp_path):
        monkeypatch.setattr(recon_module, "HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(recon_runtime_module, "HANDSHAKES_DIR", str(tmp_path))
        result = recon_runtime_module._scan_hash_files("aabbccddee01")
        assert result["has_hash"] is False
        assert result["pmkid_count"] == 0
        assert result["eapol_count"] == 0

    def test_nonexistent_directory(self, monkeypatch):
        monkeypatch.setattr(recon_module, "HANDSHAKES_DIR", "/nonexistent/path")
        monkeypatch.setattr(recon_runtime_module, "HANDSHAKES_DIR", "/nonexistent/path")
        result = recon_runtime_module._scan_hash_files("aabbccddee01")
        assert result["has_hash"] is False

    def test_empty_22000_file_ignored(self, monkeypatch, tmp_path):
        monkeypatch.setattr(recon_module, "HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(recon_runtime_module, "HANDSHAKES_DIR", str(tmp_path))
        (tmp_path / "aabbccddee01.22000").write_text("")
        result = recon_runtime_module._scan_hash_files("aabbccddee01")
        assert result["has_hash"] is False

    def test_mixed_lines(self, monkeypatch, tmp_path):
        monkeypatch.setattr(recon_module, "HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(recon_runtime_module, "HANDSHAKES_DIR", str(tmp_path))
        (tmp_path / "aabbccddee01.22000").write_text(
            "WPA*01*a*b*c*d\n"
            "WPA*01*e*f*g*h\n"
            "WPA*02*i*j*k*l\n"
            "# comment line\n"
            "WPA*02*m*n*o*p\n"
        )
        result = recon_runtime_module._scan_hash_files("aabbccddee01")
        assert result["has_hash"] is True
        assert result["has_pmkid"] is True
        assert result["has_eapol_hash"] is True
        assert result["pmkid_count"] == 2
        assert result["eapol_count"] == 2
        assert result["total_lines"] == 4

    def test_mac_case_insensitive_match(self, monkeypatch, tmp_path):
        monkeypatch.setattr(recon_module, "HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(recon_runtime_module, "HANDSHAKES_DIR", str(tmp_path))
        (tmp_path / "AABBCCDDEE01.22000").write_text("WPA*01*a*b*c*d\n")
        result = recon_runtime_module._scan_hash_files("aabbccddee01")
        assert result["has_pmkid"] is True

    def test_multiple_hash_files_for_same_mac(self, monkeypatch, tmp_path):
        monkeypatch.setattr(recon_module, "HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(recon_runtime_module, "HANDSHAKES_DIR", str(tmp_path))
        (tmp_path / "aabbccddee01_1.22000").write_text("WPA*01*a*b*c*d\n")
        (tmp_path / "aabbccddee01_2.22000").write_text("WPA*02*e*f*g*h\n")
        result = recon_runtime_module._scan_hash_files("aabbccddee01")
        assert result["has_hash"] is True
        assert result["has_pmkid"] is True
        assert result["has_eapol_hash"] is True
        assert result["pmkid_count"] == 1
        assert result["eapol_count"] == 1


# ---------------------------------------------------------------------------
# Phase 2: Attack Effectiveness extensions
# ---------------------------------------------------------------------------


class TestAttackEffectivenessPhase2:
    """Tests for period filter, wordlist ROI, crack velocity, and per-mode avg_time."""

    def test_period_field_in_response(self, client, patch_recon):
        resp = client.get("/api/recon/attack-effectiveness")
        assert resp.json()["data"]["period"] == "all"

    def test_period_24h(self, client, patch_recon):
        resp = client.get("/api/recon/attack-effectiveness", params={"period": "24h"})
        assert resp.status_code == 200
        assert resp.json()["data"]["period"] == "24h"

    def test_period_7d(self, client, patch_recon):
        resp = client.get("/api/recon/attack-effectiveness", params={"period": "7d"})
        assert resp.status_code == 200
        assert resp.json()["data"]["period"] == "7d"

    def test_period_30d(self, client, patch_recon):
        resp = client.get("/api/recon/attack-effectiveness", params={"period": "30d"})
        assert resp.status_code == 200
        assert resp.json()["data"]["period"] == "30d"

    def test_invalid_period(self, client, patch_recon):
        resp = client.get("/api/recon/attack-effectiveness", params={"period": "1y"})
        assert resp.status_code == 400

    def test_period_filters_old_entries(self, client, patch_recon):
        """Entries outside the period window should be excluded."""
        tmp_path = patch_recon
        now = time.time()
        _write_try_file(tmp_path, "aabbccddee01", [
            {
                "status": "CRACKED",
                "params": {"attack_mode": "dictionary"},
                "start_time": now - 3600,      # 1h ago — within 24h
                "end_time": now - 3500,
            },
            {
                "status": "EXHAUSTED",
                "params": {"attack_mode": "dictionary"},
                "start_time": now - 200000,     # ~2.3 days ago — outside 24h
                "end_time": now - 199900,
            },
        ])

        resp_all = client.get("/api/recon/attack-effectiveness", params={"period": "all"})
        assert resp_all.json()["data"]["total_attacks"] == 2

        resp_24h = client.get("/api/recon/attack-effectiveness", params={"period": "24h"})
        assert resp_24h.json()["data"]["total_attacks"] == 1
        assert resp_24h.json()["data"]["total_cracked"] == 1

    def test_wordlist_roi_structure(self, client, patch_recon):
        tmp_path = patch_recon
        _write_try_file(tmp_path, "aabbccddee01", [
            {"status": "CRACKED", "params": {"attack_mode": "dictionary", "wordlist": "/path/rockyou.txt"}},
            {"status": "EXHAUSTED", "params": {"attack_mode": "dictionary", "wordlist": "/path/rockyou.txt"}},
            {"status": "CRACKED", "params": {"attack_mode": "dictionary", "wordlist": "/path/common.txt"}},
        ])
        resp = client.get("/api/recon/attack-effectiveness")
        roi = resp.json()["data"]["wordlist_roi"]
        assert len(roi) >= 2
        rockyou = next(w for w in roi if w["name"] == "rockyou.txt")
        assert rockyou["cracks"] == 1
        assert rockyou["uses"] == 2
        assert rockyou["success_rate"] == 50.0
        common = next(w for w in roi if w["name"] == "common.txt")
        assert common["cracks"] == 1
        assert common["uses"] == 1

    def test_wordlist_roi_includes_zero_crack_wordlists(self, client, patch_recon):
        """Wordlists used but with 0 cracks should still appear."""
        tmp_path = patch_recon
        _write_try_file(tmp_path, "aabbccddee01", [
            {"status": "EXHAUSTED", "params": {"attack_mode": "dictionary", "wordlist": "/path/big.txt"}},
        ])
        resp = client.get("/api/recon/attack-effectiveness")
        roi = resp.json()["data"]["wordlist_roi"]
        big = next(w for w in roi if w["name"] == "big.txt")
        assert big["cracks"] == 0
        assert big["uses"] == 1
        assert big["success_rate"] == 0

    def test_crack_velocity_structure(self, client, patch_recon):
        tmp_path = patch_recon
        now = time.time()
        _write_try_file(tmp_path, "aabbccddee01", [
            {
                "status": "CRACKED",
                "params": {"attack_mode": "dictionary"},
                "start_time": now - 7200,
                "end_time": now - 7100,
            },
            {
                "status": "CRACKED",
                "params": {"attack_mode": "brute_force"},
                "start_time": now - 3600,
                "end_time": now - 3500,
            },
        ])
        resp = client.get("/api/recon/attack-effectiveness")
        velocity = resp.json()["data"]["crack_velocity"]
        assert len(velocity) == 2
        assert "ts" in velocity[0]
        assert "mac" in velocity[0]
        assert "ssid" in velocity[0]
        assert "mode" in velocity[0]
        # Events sorted chronologically
        assert velocity[0]["ts"] <= velocity[1]["ts"]

    def test_crack_velocity_empty_when_no_cracks(self, client, patch_recon):
        tmp_path = patch_recon
        _write_try_file(tmp_path, "aabbccddee01", [
            {"status": "EXHAUSTED", "params": {"attack_mode": "dictionary"}},
        ])
        resp = client.get("/api/recon/attack-effectiveness")
        assert resp.json()["data"]["crack_velocity"] == []

    def test_per_mode_avg_time(self, client, patch_recon):
        tmp_path = patch_recon
        _write_try_file(tmp_path, "aabbccddee01", [
            {
                "status": "CRACKED",
                "params": {"attack_mode": "dictionary"},
                "start_time": 1000.0,
                "end_time": 1300.0,  # 300s
            },
            {
                "status": "CRACKED",
                "params": {"attack_mode": "dictionary"},
                "start_time": 2000.0,
                "end_time": 2100.0,  # 100s
            },
            {
                "status": "CRACKED",
                "params": {"attack_mode": "brute_force"},
                "start_time": 3000.0,
                "end_time": 3600.0,  # 600s
            },
        ])
        resp = client.get("/api/recon/attack-effectiveness")
        modes = {m["mode"]: m for m in resp.json()["data"]["by_mode"]}
        assert modes["dictionary"]["avg_time"] == pytest.approx(200.0, abs=0.1)
        assert modes["brute_force"]["avg_time"] == pytest.approx(600.0, abs=0.1)

    def test_per_mode_avg_time_none_without_timing(self, client, patch_recon):
        tmp_path = patch_recon
        _write_try_file(tmp_path, "aabbccddee01", [
            {"status": "CRACKED", "params": {"attack_mode": "dictionary"}},
        ])
        resp = client.get("/api/recon/attack-effectiveness")
        modes = {m["mode"]: m for m in resp.json()["data"]["by_mode"]}
        assert modes["dictionary"]["avg_time"] is None


# ---------------------------------------------------------------------------
# Phase 2: Temporal Intel extensions
# ---------------------------------------------------------------------------


class TestTemporalIntelPhase2:
    """Tests for by_source breakdown and anomaly detection."""

    def test_by_source_present(self, client, patch_recon):
        resp = client.get("/api/recon/temporal-intel")
        data = resp.json()["data"]
        assert "by_source" in data
        assert "anomalies" in data

    def test_by_source_structure(self, client, patch_recon):
        resp = client.get("/api/recon/temporal-intel")
        by_source = resp.json()["data"]["by_source"]
        assert "pwnagotchi" in by_source
        assert "wardrive" in by_source
        pw = by_source["pwnagotchi"]
        assert "hour_distribution" in pw
        assert "day_distribution" in pw
        assert "total" in pw
        assert len(pw["hour_distribution"]) == 24
        assert len(pw["day_distribution"]) == 7

    def test_by_source_totals(self, client, patch_recon):
        """pwnagotchi appears in 2 networks (01+03), wardrive in 3 (02+03+04)."""
        resp = client.get("/api/recon/temporal-intel")
        by_source = resp.json()["data"]["by_source"]
        assert by_source["pwnagotchi"]["total"] == 2
        assert by_source["wardrive"]["total"] == 3

    def test_by_source_supports_specific_raw_variants(self, client, monkeypatch, tmp_path):
        dataset = {
            "aa:bb:cc:dd:ee:01": {
                "ssid": "BruceRaw",
                "encryption": "WPA2",
                "handshake": False,
                "sources": ["bruce_raw_sniffing"],
                "ts_last": "2025-04-01T12:00:00Z",
                "lat": -22.9,
                "lng": -43.2,
            },
            "aa:bb:cc:dd:ee:02": {
                "ssid": "M5Raw",
                "encryption": "WPA2",
                "handshake": False,
                "sources": ["m5evil_raw_sniffing"],
                "ts_last": "2025-04-01T11:00:00Z",
            },
            "aa:bb:cc:dd:ee:03": {
                "ssid": "M5Master",
                "encryption": "WPA2",
                "handshake": False,
                "sources": ["m5evil_master_raw_sniffing"],
                "ts_last": "2025-04-01T10:00:00Z",
            },
        }
        monkeypatch.setattr(recon_module, "load_real_data", lambda: dataset)
        monkeypatch.setattr(recon_module, "HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(recon_module.job_manager, "list_jobs", lambda: [])
        recon_runtime_module.clear_recon_runtime_cache()

        resp = client.get("/api/recon/temporal-intel")
        by_source = resp.json()["data"]["by_source"]
        gps_origin = resp.json()["data"]["gps_origin"]

        assert by_source["bruce_raw_sniffing"]["total"] == 1
        assert by_source["m5evil_raw_sniffing"]["total"] == 1
        assert by_source["m5evil_master_raw_sniffing"]["total"] == 1
        assert gps_origin["bruce_raw_sniffing"] == 1

    def test_anomalies_empty_for_small_dataset(self, client, patch_recon):
        """The 4-network test dataset shouldn't trigger spike anomalies (threshold min 5)."""
        resp = client.get("/api/recon/temporal-intel")
        anomalies = resp.json()["data"]["anomalies"]
        spikes = [a for a in anomalies if a["type"] == "spike"]
        assert len(spikes) == 0

    def test_anomaly_gap_detection(self, client, monkeypatch, tmp_path):
        """Networks with a temporal gap > 2 days should produce a gap anomaly."""
        dataset = {
            f"aa:bb:cc:dd:ee:{i:02x}": {
                "ssid": f"Net{i}",
                "encryption": "WPA2",
                "handshake": False,
                "sources": ["pwnagotchi"],
                "ts_last": f"2025-04-{day:02d}T12:00:00Z",
            }
            for i, day in enumerate([1, 1, 2, 8, 8, 9], start=1)
        }
        monkeypatch.setattr(recon_module, "load_real_data", lambda: dataset)
        monkeypatch.setattr(recon_module, "HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(recon_module.job_manager, "list_jobs", lambda: [])
        recon_runtime_module.clear_recon_runtime_cache()

        resp = client.get("/api/recon/temporal-intel")
        anomalies = resp.json()["data"]["anomalies"]
        gaps = [a for a in anomalies if a["type"] == "gap"]
        assert len(gaps) >= 1
        assert gaps[0]["days"] >= 1  # gap between day 2 and day 8

    def test_anomaly_spike_detection(self, client, monkeypatch, tmp_path):
        """Day with far more observations than average should be a spike."""
        dataset = {}
        # Day 1: 2 networks
        for i in range(2):
            dataset[f"aa:bb:cc:00:00:{i:02x}"] = {
                "ssid": f"A{i}", "encryption": "WPA2", "handshake": False,
                "sources": ["wardrive"], "ts_last": "2025-04-01T10:00:00Z",
            }
        # Day 2: 2 networks
        for i in range(2):
            dataset[f"aa:bb:cc:00:01:{i:02x}"] = {
                "ssid": f"B{i}", "encryption": "WPA2", "handshake": False,
                "sources": ["wardrive"], "ts_last": "2025-04-02T10:00:00Z",
            }
        # Day 3: 20 networks (spike)
        for i in range(20):
            dataset[f"aa:bb:cc:00:02:{i:02x}"] = {
                "ssid": f"C{i}", "encryption": "WPA2", "handshake": False,
                "sources": ["wardrive"], "ts_last": "2025-04-03T10:00:00Z",
            }
        monkeypatch.setattr(recon_module, "load_real_data", lambda: dataset)
        monkeypatch.setattr(recon_module, "HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(recon_module.job_manager, "list_jobs", lambda: [])
        recon_runtime_module.clear_recon_runtime_cache()

        resp = client.get("/api/recon/temporal-intel")
        anomalies = resp.json()["data"]["anomalies"]
        spikes = [a for a in anomalies if a["type"] == "spike"]
        assert len(spikes) >= 1
        assert spikes[0]["date"] == "2025-04-03"
        assert spikes[0]["count"] == 20

    def test_empty_dataset_phase2_fields(self, client, monkeypatch, tmp_path):
        monkeypatch.setattr(recon_module, "load_real_data", lambda: {})
        monkeypatch.setattr(recon_module, "HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(recon_module.job_manager, "list_jobs", lambda: [])
        recon_runtime_module.clear_recon_runtime_cache()
        resp = client.get("/api/recon/temporal-intel")
        data = resp.json()["data"]
        assert data["by_source"] == {}
        assert data["anomalies"] == []


# ---------------------------------------------------------------------------
# Phase 2: Audit Report extensions
# ---------------------------------------------------------------------------


class TestAuditReportPhase2:
    """Tests for recommendations, risk scoring, and coverage analysis."""

    def test_recommendations_present(self, client, patch_recon, monkeypatch):
        monkeypatch.setattr(config_module, "load_config", lambda: {})
        resp = client.get("/api/recon/audit-report")
        data = resp.json()["data"]
        assert "recommendations" in data
        assert "risk_scoring" in data
        assert "coverage" in data

    def test_recommendations_structure(self, client, patch_recon, monkeypatch):
        monkeypatch.setattr(config_module, "load_config", lambda: {})
        resp = client.get("/api/recon/audit-report")
        recs = resp.json()["data"]["recommendations"]
        for rec in recs:
            assert "priority" in rec
            assert "action" in rec
            assert "description" in rec
            assert "count" in rec

    def test_recommendation_convert_hashes(self, client, patch_recon, monkeypatch):
        """HomeNet has raw_eapol_count=4 but no .22000 → suggest convert_hashes."""
        monkeypatch.setattr(config_module, "load_config", lambda: {})
        resp = client.get("/api/recon/audit-report")
        recs = resp.json()["data"]["recommendations"]
        actions = [r["action"] for r in recs]
        assert "convert_hashes" in actions

    def test_recommendation_attack_wep(self, client, patch_recon, monkeypatch):
        """Linksys_Default is WEP → suggest attack_wep."""
        monkeypatch.setattr(config_module, "load_config", lambda: {})
        resp = client.get("/api/recon/audit-report")
        recs = resp.json()["data"]["recommendations"]
        wep_rec = next((r for r in recs if r["action"] == "attack_wep"), None)
        assert wep_rec is not None
        assert wep_rec["count"] == 1

    def test_recommendation_attack_pmkid(self, client, patch_recon, monkeypatch):
        """Network with PMKID hash but not cracked → suggest attack_pmkid."""
        tmp_path = patch_recon
        monkeypatch.setattr(config_module, "load_config", lambda: {})
        # Give HomeNet a PMKID hash (it has no "pass" field → uncracked)
        _write_hash_file(tmp_path, "aabbccddee01", ["WPA*01*a*b*c*d"])
        resp = client.get("/api/recon/audit-report")
        recs = resp.json()["data"]["recommendations"]
        pmkid_rec = next((r for r in recs if r["action"] == "attack_pmkid"), None)
        assert pmkid_rec is not None
        assert pmkid_rec["count"] >= 1

    def test_risk_scoring_structure(self, client, patch_recon, monkeypatch):
        monkeypatch.setattr(config_module, "load_config", lambda: {})
        resp = client.get("/api/recon/audit-report")
        scoring = resp.json()["data"]["risk_scoring"]
        assert len(scoring) >= 1
        for entry in scoring:
            assert "encryption" in entry
            assert "total" in entry
            assert "cracked" in entry
            assert "crack_rate" in entry
            assert "grade" in entry

    def test_risk_scoring_open_na(self, client, patch_recon, monkeypatch):
        """OPEN encryption should get grade N/A."""
        monkeypatch.setattr(config_module, "load_config", lambda: {})
        resp = client.get("/api/recon/audit-report")
        scoring = resp.json()["data"]["risk_scoring"]
        open_entry = next((s for s in scoring if s["encryption"] == "OPEN"), None)
        assert open_entry is not None
        assert open_entry["grade"] == "N/A"

    def test_risk_scoring_wep_grade_f(self, client, patch_recon, monkeypatch):
        """WEP should get grade F."""
        monkeypatch.setattr(config_module, "load_config", lambda: {})
        resp = client.get("/api/recon/audit-report")
        scoring = resp.json()["data"]["risk_scoring"]
        wep_entry = next((s for s in scoring if s["encryption"] == "WEP"), None)
        assert wep_entry is not None
        assert wep_entry["grade"] == "F"

    def test_risk_scoring_wpa3_cracked(self, client, patch_recon, monkeypatch):
        """WPA3 has 1 total, 1 cracked → 100% → grade A."""
        monkeypatch.setattr(config_module, "load_config", lambda: {})
        resp = client.get("/api/recon/audit-report")
        scoring = resp.json()["data"]["risk_scoring"]
        wpa3 = next((s for s in scoring if s["encryption"] == "WPA3"), None)
        assert wpa3 is not None
        assert wpa3["cracked"] == 1
        assert wpa3["crack_rate"] == 100.0
        assert wpa3["grade"] == "A"

    def test_coverage_structure(self, client, patch_recon, monkeypatch):
        monkeypatch.setattr(config_module, "load_config", lambda: {})
        resp = client.get("/api/recon/audit-report")
        cov = resp.json()["data"]["coverage"]
        assert "total" in cov
        assert "with_gps" in cov
        assert "with_gps_pct" in cov
        assert "with_fingerprint" in cov
        assert "with_raw_data" in cov
        assert "with_hash" in cov
        assert "multi_source" in cov

    def test_coverage_raw_data_count(self, client, patch_recon, monkeypatch):
        """All 4 networks have raw data: HomeNet(20+4), OpenCafe(5), SecureOffice(10+2), Linksys(1)."""
        monkeypatch.setattr(config_module, "load_config", lambda: {})
        resp = client.get("/api/recon/audit-report")
        cov = resp.json()["data"]["coverage"]
        assert cov["with_raw_data"] == 4

    def test_coverage_multi_source(self, client, patch_recon, monkeypatch):
        """Only SecureOffice has multiple sources (pwnagotchi + wardrive)."""
        monkeypatch.setattr(config_module, "load_config", lambda: {})
        resp = client.get("/api/recon/audit-report")
        cov = resp.json()["data"]["coverage"]
        assert cov["multi_source"] == 1

    def test_coverage_gps_with_lat_lng(self, client, monkeypatch, tmp_path):
        """Networks with lat/lng → with_gps counted."""
        dataset = {
            "aa:bb:cc:dd:ee:01": {
                "ssid": "GpsNet", "encryption": "WPA2", "handshake": False,
                "sources": ["wardrive"], "ts_last": "2025-04-01T12:00:00Z",
                "lat": 40.7, "lng": -74.0,
                "raw_beacon_count": 0, "raw_eapol_count": 0,
            },
            "aa:bb:cc:dd:ee:02": {
                "ssid": "NoGps", "encryption": "WPA2", "handshake": False,
                "sources": ["pwnagotchi"], "ts_last": "2025-04-01T12:00:00Z",
                "raw_beacon_count": 0, "raw_eapol_count": 0,
            },
        }
        monkeypatch.setattr(recon_module, "load_real_data", lambda: dataset)
        monkeypatch.setattr(recon_module, "HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(recon_module.job_manager, "list_jobs", lambda: [])
        monkeypatch.setattr(config_module, "load_config", lambda: {})

        resp = client.get("/api/recon/audit-report")
        cov = resp.json()["data"]["coverage"]
        assert cov["with_gps"] == 1
        assert cov["with_gps_pct"] == 50.0


# ---------------------------------------------------------------------------
# 6. Kill-Chain Snapshots (S-F3)
# ---------------------------------------------------------------------------


class TestKillChainSnapshot:
    def test_create_snapshot(self, client, patch_recon, monkeypatch, tmp_path):
        snap_dir = tmp_path / "kc_snaps"
        snap_dir.mkdir()
        monkeypatch.setattr(recon_module, "_KC_SNAPSHOT_FILE", str(snap_dir / "kc.json"))

        resp = client.post("/api/recon/kill-chain/snapshot")
        assert resp.status_code == 200
        snap = resp.json()["data"]
        assert "ts" in snap
        assert "counts" in snap
        assert snap["total"] == 4

    def test_history_empty(self, client, patch_recon, monkeypatch, tmp_path):
        snap_dir = tmp_path / "kc_snaps"
        snap_dir.mkdir()
        monkeypatch.setattr(recon_module, "_KC_SNAPSHOT_FILE", str(snap_dir / "kc.json"))

        resp = client.get("/api/recon/kill-chain/history")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["snapshots"] == []
        assert data["count"] == 0

    def test_history_after_snapshot(self, client, patch_recon, monkeypatch, tmp_path):
        snap_dir = tmp_path / "kc_snaps"
        snap_dir.mkdir()
        monkeypatch.setattr(recon_module, "_KC_SNAPSHOT_FILE", str(snap_dir / "kc.json"))

        client.post("/api/recon/kill-chain/snapshot")
        resp = client.get("/api/recon/kill-chain/history")
        data = resp.json()["data"]
        assert data["count"] == 1
        assert len(data["snapshots"]) == 1
        assert data["snapshots"][0]["total"] == 4

    def test_multiple_snapshots(self, client, patch_recon, monkeypatch, tmp_path):
        snap_dir = tmp_path / "kc_snaps"
        snap_dir.mkdir()
        monkeypatch.setattr(recon_module, "_KC_SNAPSHOT_FILE", str(snap_dir / "kc.json"))

        client.post("/api/recon/kill-chain/snapshot")
        client.post("/api/recon/kill-chain/snapshot")
        resp = client.get("/api/recon/kill-chain/history")
        assert resp.json()["data"]["count"] == 2


# ---------------------------------------------------------------------------
# 7. Audit Report Snapshots & Comparison (R-F5)
# ---------------------------------------------------------------------------


class TestReportSnapshots:
    def test_save_snapshot(self, client, patch_recon, monkeypatch, tmp_path):
        snap_dir = tmp_path / "report_snaps"
        snap_dir.mkdir()
        monkeypatch.setattr(recon_module, "_REPORT_SNAPSHOT_DIR", str(snap_dir))
        monkeypatch.setattr(config_module, "load_config", lambda: {})

        resp = client.post("/api/recon/audit-report/snapshot")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert "snapshot_id" in data

    def test_list_snapshots_empty(self, client, patch_recon, monkeypatch, tmp_path):
        snap_dir = tmp_path / "report_snaps"
        snap_dir.mkdir()
        monkeypatch.setattr(recon_module, "_REPORT_SNAPSHOT_DIR", str(snap_dir))

        resp = client.get("/api/recon/audit-report/snapshots")
        assert resp.status_code == 200
        assert resp.json()["data"]["snapshots"] == []

    def test_list_after_save(self, client, patch_recon, monkeypatch, tmp_path):
        snap_dir = tmp_path / "report_snaps"
        snap_dir.mkdir()
        monkeypatch.setattr(recon_module, "_REPORT_SNAPSHOT_DIR", str(snap_dir))
        monkeypatch.setattr(config_module, "load_config", lambda: {})

        client.post("/api/recon/audit-report/snapshot")
        resp = client.get("/api/recon/audit-report/snapshots")
        snaps = resp.json()["data"]["snapshots"]
        assert len(snaps) == 1
        assert "id" in snaps[0]

    def test_compare_not_found(self, client, patch_recon, monkeypatch, tmp_path):
        snap_dir = tmp_path / "report_snaps"
        snap_dir.mkdir()
        monkeypatch.setattr(recon_module, "_REPORT_SNAPSHOT_DIR", str(snap_dir))

        resp = client.get("/api/recon/audit-report/compare?snapshot_id=nonexistent")
        assert resp.status_code == 400

    def test_compare_with_snapshot(self, client, patch_recon, monkeypatch, tmp_path):
        snap_dir = tmp_path / "report_snaps"
        snap_dir.mkdir()
        monkeypatch.setattr(recon_module, "_REPORT_SNAPSHOT_DIR", str(snap_dir))
        monkeypatch.setattr(config_module, "load_config", lambda: {})

        # Save snapshot
        save_resp = client.post("/api/recon/audit-report/snapshot")
        snap_id = save_resp.json()["data"]["snapshot_id"]

        # Compare
        resp = client.get(f"/api/recon/audit-report/compare?snapshot_id={snap_id}")
        assert resp.status_code == 200
        delta = resp.json()["data"]
        assert "snapshot_id" in delta
        assert "total_networks" in delta
        # Same data → delta should be 0
        assert delta["total_networks"]["delta"] == 0


# ---------------------------------------------------------------------------
# 8. Attack Planner (O-F6)
# ---------------------------------------------------------------------------


class TestAttackPlanner:
    def test_plan_basic(self, client, patch_recon):
        resp = client.post(
            "/api/recon/attack-plan",
            json={"targets": ["aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"]},
        )
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["total_targets"] == 2
        assert "operations" in data

    def test_plan_already_cracked(self, client, patch_recon):
        resp = client.post(
            "/api/recon/attack-plan",
            json={"targets": ["aa:bb:cc:dd:ee:03"]},
        )
        ops = resp.json()["data"]["operations"]
        assert len(ops) == 1
        assert ops[0]["skip"] is True
        assert ops[0]["reason"] == "already_cracked"

    def test_plan_not_found(self, client, patch_recon):
        resp = client.post(
            "/api/recon/attack-plan",
            json={"targets": ["ff:ff:ff:ff:ff:ff"]},
        )
        ops = resp.json()["data"]["operations"]
        assert ops[0]["skip"] is True
        assert ops[0]["reason"] == "not_found"

    def test_plan_with_hash(self, client, patch_recon):
        tmp = patch_recon
        _write_hash_file(tmp, "aabbccddee01", ["WPA*01*ab*cd*ef*gh"])

        resp = client.post(
            "/api/recon/attack-plan",
            json={
                "targets": ["aa:bb:cc:dd:ee:01"],
                "strategy": "dictionary",
                "wordlist": "big.txt",
            },
        )
        ops = resp.json()["data"]["operations"]
        assert ops[0]["skip"] is False
        assert ops[0]["strategy"] == "dictionary"
        assert ops[0]["wordlist"] == "big.txt"

    def test_plan_auto_no_hash(self, client, patch_recon):
        resp = client.post(
            "/api/recon/attack-plan",
            json={"targets": ["aa:bb:cc:dd:ee:01"], "strategy": "auto"},
        )
        ops = resp.json()["data"]["operations"]
        assert ops[0]["skip"] is True
        assert ops[0]["reason"] == "no_hash"

    def test_plan_auto_with_pmkid(self, client, patch_recon):
        tmp = patch_recon
        _write_hash_file(tmp, "aabbccddee01", ["WPA*01*ab*cd*ef*gh"])

        resp = client.post(
            "/api/recon/attack-plan",
            json={"targets": ["aa:bb:cc:dd:ee:01"], "strategy": "auto"},
        )
        ops = resp.json()["data"]["operations"]
        assert ops[0]["skip"] is False
        assert ops[0]["strategy"] == "pmk"

    def test_plan_capped_at_50(self, client, patch_recon):
        targets = [f"ff:ff:ff:ff:ff:{i:02x}" for i in range(60)]
        resp = client.post(
            "/api/recon/attack-plan",
            json={"targets": targets},
        )
        ops = resp.json()["data"]["operations"]
        assert len(ops) <= 50


# ---------------------------------------------------------------------------
# 9. COMMS Intelligence (C-F1, C-F2, C-F3)
# ---------------------------------------------------------------------------


class TestDeviceFingerprints:
    def test_basic_response(self, client, patch_recon):
        resp = client.get("/api/recon/comms/device-fingerprints")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["total"] == 4
        assert "by_type" in data
        assert "by_oui" in data
        assert "by_channel" in data
        assert "raw_activity" in data

    def test_device_types(self, client, patch_recon):
        resp = client.get("/api/recon/comms/device-fingerprints")
        types = resp.json()["data"]["by_type"]
        type_map = {t["type"]: t for t in types}
        assert type_map["router_ap"]["count"] == 3
        assert type_map["unknown"]["count"] == 1

    def test_type_enrichment(self, client, patch_recon):
        resp = client.get("/api/recon/comms/device-fingerprints")
        types = resp.json()["data"]["by_type"]
        type_map = {t["type"]: t for t in types}
        # router_ap has encryption breakdown (WPA2, OPEN, WPA3)
        router = type_map["router_ap"]
        assert "encryption" in router
        assert router["encryption"]["WPA2"] == 1
        # router_ap has channel_distribution
        assert "channel_distribution" in router
        # router_ap has rssi_stats
        assert "rssi_stats" in router
        assert router["rssi_stats"]["avg"] is not None

    def test_by_channel(self, client, patch_recon):
        resp = client.get("/api/recon/comms/device-fingerprints")
        by_ch = resp.json()["data"]["by_channel"]
        ch_map = {c["channel"]: c for c in by_ch}
        # channel 6 has 2 networks (HomeNet + SecureOffice)
        assert ch_map[6]["count"] == 2
        assert ch_map[6]["avg_rssi"] is not None

    def test_raw_activity(self, client, patch_recon):
        resp = client.get("/api/recon/comms/device-fingerprints")
        ra = resp.json()["data"]["raw_activity"]
        assert ra["beacons"] == 36  # 20+5+10+1
        assert ra["eapol"] == 6    # 4+0+2+0
        assert ra["probes"] == 4   # 3+0+1+0

    def test_oui_grouping(self, client, patch_recon):
        resp = client.get("/api/recon/comms/device-fingerprints")
        ouis = resp.json()["data"]["by_oui"]
        # All 4 MACs start with "AA:BB:CC" → same OUI → same vendor
        assert len(ouis) >= 1
        total_count = sum(o["count"] for o in ouis)
        assert total_count == 4
        first = ouis[0]
        assert "vendor" in first
        assert "oui_prefixes" in first
        assert "sample_macs" in first
        assert "encryption" in first


class TestColocation:
    def test_no_gps_data(self, client, monkeypatch, tmp_path):
        dataset = {
            "aa:bb:cc:dd:ee:04": {
                "ssid": "NoGPS", "encryption": "WEP",
                "sources": ["wardrive"], "ts_last": "2025-04-01T12:00:00Z",
                "handshake": False, "raw_beacon_count": 1, "raw_eapol_count": 0,
            },
        }
        monkeypatch.setattr(recon_module, "load_real_data", lambda: dataset)
        monkeypatch.setattr(recon_module, "HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(recon_module.job_manager, "list_jobs", lambda: [])
        resp = client.get("/api/recon/comms/colocation")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["total_located"] == 0
        assert data["clusters"] == []

    def test_with_gps_cluster(self, client, patch_recon):
        resp = client.get("/api/recon/comms/colocation")
        data = resp.json()["data"]
        # 3 networks have GPS (net01, net02, net03)
        assert data["total_located"] == 3
        assert len(data["clusters"]) >= 1
        cl = data["clusters"][0]
        assert cl["count"] >= 2
        # Enriched fields
        assert "radius_m" in cl
        assert "dominant_encryption" in cl
        assert "avg_rssi" in cl
        assert "source_breakdown" in cl
        assert "device_breakdown" in cl
        assert "label" in cl
        assert "parts" in cl
        assert isinstance(cl["parts"], list)
        assert len(cl["parts"]) >= 1


class TestSpectrum:
    def test_basic_response(self, client, patch_recon):
        resp = client.get("/api/recon/comms/spectrum")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["total_with_channel"] == 4
        assert len(data["channels"]) == 3  # channels 1, 6, 11
        assert data["band_24ghz"] == 4
        assert data["band_5ghz"] == 0

    def test_channel_detail(self, client, patch_recon):
        resp = client.get("/api/recon/comms/spectrum")
        chs = resp.json()["data"]["channels"]
        ch_map = {c["channel"]: c for c in chs}
        assert ch_map[6]["count"] == 2
        assert ch_map[1]["count"] == 1
        assert ch_map[11]["count"] == 1
        # Encryption breakdown present
        assert "WPA2" in ch_map[6]["encryption"]

    def test_congestion(self, client, patch_recon):
        resp = client.get("/api/recon/comms/spectrum")
        data = resp.json()["data"]
        # channel 6 has 2/4 = 50% > 15% → congested
        assert 6 in data["congested_channels"]

    def test_empty_dataset(self, client, monkeypatch, tmp_path):
        monkeypatch.setattr(recon_module, "load_real_data", lambda: {})
        monkeypatch.setattr(recon_module, "HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(recon_module.job_manager, "list_jobs", lambda: [])
        resp = client.get("/api/recon/comms/spectrum")
        data = resp.json()["data"]
        assert data["total_with_channel"] == 0
        assert data["channels"] == []


class TestSignalLandscape:
    def test_basic_response(self, client, patch_recon):
        resp = client.get("/api/recon/comms/signal-landscape")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["total_with_rssi"] == 4
        assert "histogram" in data
        assert "by_encryption" in data
        assert "by_source" in data
        assert "strong_signals" in data
        assert "summary" in data

    def test_histogram_buckets(self, client, patch_recon):
        resp = client.get("/api/recon/comms/signal-landscape")
        hist = resp.json()["data"]["histogram"]
        # -85 → <-80 bucket; -72 → -80:-70 bucket; -55 → -60:-50 bucket; -48 → -50:-40 bucket
        assert hist["<-80"] == 1
        assert hist["-80:-70"] == 1
        assert hist["-60:-50"] == 1
        assert hist["-50:-40"] == 1

    def test_strong_signals(self, client, patch_recon):
        resp = client.get("/api/recon/comms/signal-landscape")
        strong = resp.json()["data"]["strong_signals"]
        # Only SecureOffice at -48 is > -50
        assert len(strong) == 1
        assert strong[0]["rssi"] == -48.0

    def test_by_encryption(self, client, patch_recon):
        resp = client.get("/api/recon/comms/signal-landscape")
        by_enc = resp.json()["data"]["by_encryption"]
        assert "WPA2" in by_enc
        assert by_enc["WPA2"]["count"] == 1
        assert "OPEN" in by_enc
        assert by_enc["OPEN"]["count"] == 1

    def test_empty_dataset(self, client, monkeypatch, tmp_path):
        monkeypatch.setattr(recon_module, "load_real_data", lambda: {})
        monkeypatch.setattr(recon_module, "HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(recon_module.job_manager, "list_jobs", lambda: [])
        resp = client.get("/api/recon/comms/signal-landscape")
        data = resp.json()["data"]
        assert data["total_with_rssi"] == 0
        assert data["strong_signals"] == []


class TestRelationshipGraph:
    def test_basic_response(self, client, patch_recon):
        resp = client.get("/api/recon/comms/relationship-graph")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert "nodes" in data
        assert "edges" in data
        assert data["ap_count"] == 4
        assert data["ssid_target_count"] == 0
        assert data["edge_breakdown"] == {
            "probe_known": 0,
            "probe_unknown": 0,
        }
        assert data["probe_context"]["cached"] is False

    def test_no_probe_data(self, client, patch_recon, monkeypatch):
        monkeypatch.setattr(
            recon_module.probe_service, "get_cache_status",
            lambda: {"cached": False},
        )
        resp = client.get("/api/recon/comms/relationship-graph")
        data = resp.json()["data"]
        assert data["client_count"] == 0
        assert data["edges"] == []
        assert data["probe_context"]["available"] is False

    def test_with_probe_data(self, client, patch_recon, monkeypatch):
        monkeypatch.setattr(
            recon_module.probe_service, "get_cache_status",
            lambda: {
                "cached": True,
                "stale": False,
                "pcap_count": 2,
                "result": {
                    "available": True,
                    "clients": [
                        {
                            "client_mac": "52:ab:cd:ef:00:01",
                            "probe_count": 5,
                            "ssids_probed": ["HomeNet", "UnknownSSID"],
                            "avg_signal": -60,
                        }
                    ],
                    "summary": {
                        "total_probes": 5,
                        "unique_clients": 1,
                        "unique_ssids": 2,
                        "pcaps_scanned": 2,
                        "broadcast_probes": 0,
                    },
                },
            },
        )
        resp = client.get("/api/recon/comms/relationship-graph")
        data = resp.json()["data"]
        assert data["client_count"] == 1
        assert data["ssid_target_count"] == 1
        # "HomeNet" maps to aa:bb:cc:dd:ee:01 → known edge
        # "UnknownSSID" → unknown edge
        assert len(data["edges"]) == 2
        types = {e["type"] for e in data["edges"]}
        assert "probe_known" in types
        assert "probe_unknown" in types
        assert data["edge_breakdown"] == {
            "probe_known": 1,
            "probe_unknown": 1,
        }
        assert data["probe_context"]["available"] is True
        assert data["probe_context"]["summary"]["total_probes"] == 5
        ssid_nodes = [node for node in data["nodes"] if node["type"] == "ssid_target"]
        assert len(ssid_nodes) == 1
        assert ssid_nodes[0]["label"] == "UnknownSSID"


# ---------------------------------------------------------------------------
# 10. Probe Intelligence Extensions (SI-F5, SI-F7)
# ---------------------------------------------------------------------------


class TestProbeDerandomization:
    def test_no_cache(self, client, patch_recon, monkeypatch):
        monkeypatch.setattr(
            recon_module.probe_service, "get_cache_status",
            lambda: {"cached": False},
        )
        resp = client.get("/api/recon/probe-intel/derandom")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["groups"] == []

    def test_grouping(self, client, patch_recon, monkeypatch):
        # Two random MACs probing same SSIDs → should group
        monkeypatch.setattr(
            recon_module,
            "load_real_data",
            lambda: {
                "aa:bb:cc:dd:ee:01": {
                    "ssid": "NetA",
                    "encryption": "WPA2",
                    "device_type": "router_ap",
                    "sources": ["wardrive"],
                },
                "aa:bb:cc:dd:ee:02": {
                    "ssid": "NetC",
                    "encryption": "OPEN",
                    "device_type": "camera",
                    "sources": ["pwnagotchi"],
                },
            },
        )
        monkeypatch.setattr(
            recon_module.mac_lookup,
            "lookup",
            lambda value: "Acme Wireless" if str(value).startswith(("d2:", "f6:")) else "Unknown",
        )
        monkeypatch.setattr(
            recon_module.probe_service, "get_cache_status",
            lambda: {
                "cached": True,
                "result": {
                    "available": True,
                    "clients": [
                        {"client_mac": "d2:ab:cd:ef:00:01", "probe_count": 5,
                         "ssids_probed": ["NetA", "NetB", "NetC"], "avg_signal": -50, "first_seen": 1712000100, "last_seen": 1712000500},
                        {"client_mac": "f6:ab:cd:ef:00:02", "probe_count": 4,
                         "ssids_probed": ["NetA", "NetB", "NetC"], "avg_signal": -55, "first_seen": 1712000150, "last_seen": 1712000450},
                    ],
                },
            },
        )
        resp = client.get("/api/recon/probe-intel/derandom")
        data = resp.json()["data"]
        assert len(data["groups"]) >= 1
        grp = data["groups"][0]
        assert grp["group_label"] == "Likely Device 01"
        assert grp["total_macs"] >= 2
        assert grp["random_macs"] >= 2
        assert grp["known_ssid_count"] == 2
        assert grp["known_ssid_preview"] == ["NetA", "NetC"]
        assert grp["rule_summary"] == "2 randomized MACs share 3 probed SSIDs. 2 of those SSIDs also match known Recon networks."
        assert grp["first_seen"] == 1712000100
        assert grp["last_seen"] == 1712000500
        assert grp["ssid_fingerprint"] == ["NetA", "NetB", "NetC"]
        assert grp["members"][0]["vendor"] == "Acme Wireless"
        assert grp["members"][0]["randomization_state"] == "randomized"

    def test_single_ssid_ignored(self, client, patch_recon, monkeypatch):
        monkeypatch.setattr(
            recon_module.probe_service, "get_cache_status",
            lambda: {
                "cached": True,
                "result": {
                    "available": True,
                    "clients": [
                        {"client_mac": "d2:aa:bb:cc:dd:01", "probe_count": 5,
                         "ssids_probed": ["OnlyOne"], "avg_signal": -50},
                        {"client_mac": "f6:aa:bb:cc:dd:02", "probe_count": 3,
                         "ssids_probed": ["OnlyOne"], "avg_signal": -55},
                    ],
                },
            },
        )
        resp = client.get("/api/recon/probe-intel/derandom")
        assert resp.json()["data"]["groups"] == []


class TestProbeGeocorrelation:
    def test_no_cache(self, client, patch_recon, monkeypatch):
        monkeypatch.setattr(
            recon_module.probe_service, "get_cache_status",
            lambda: {"cached": False},
        )
        resp = client.get("/api/recon/probe-intel/geocorrelation")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["clients"] == []

    def test_correlation(self, client, monkeypatch, tmp_path):
        dataset = {
            "aa:bb:cc:dd:ee:01": {
                "ssid": "NetA", "encryption": "WPA2", "lat": 40.0, "lng": -74.0,
                "sources": ["wardrive"], "ts_last": "2025-04-01T12:00:00Z",
                "handshake": False, "raw_beacon_count": 1, "raw_eapol_count": 0,
            },
            "aa:bb:cc:dd:ee:02": {
                "ssid": "NetB", "encryption": "WPA2", "lat": 40.0004, "lng": -74.0003,
                "sources": ["wardrive"], "ts_last": "2025-04-01T12:00:00Z",
                "handshake": False, "raw_beacon_count": 1, "raw_eapol_count": 0,
            },
        }
        monkeypatch.setattr(recon_module, "load_real_data", lambda: dataset)
        monkeypatch.setattr(recon_module, "HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(recon_module.job_manager, "list_jobs", lambda: [])
        monkeypatch.setattr(
            recon_module.probe_service, "get_cache_status",
            lambda: {
                "cached": True,
                "result": {
                    "available": True,
                    "clients": [
                        {"client_mac": "52:ab:cd:ef:00:01", "probe_count": 5,
                         "ssids_probed": ["NetA", "NetB"], "avg_signal": -50},
                    ],
                },
            },
        )
        recon_runtime_module.clear_recon_runtime_cache()

        resp = client.get("/api/recon/probe-intel/geocorrelation")
        data = resp.json()["data"]
        assert len(data["clients"]) == 1
        cl = data["clients"][0]
        assert len(cl["located_ssids"]) == 2
        assert cl["estimated_radius_m"] > 0
        assert "estimated_center" in cl
        assert data["summary"]["correlated_clients"] == 1
        assert cl["vendor"] == "Unknown"
        assert cl["matched_ssid_count"] == 2
        assert cl["match_count"] == 2
        assert cl["known_match_ratio"] == 1.0
        assert cl["confidence"] == "medium"
        assert cl["ambiguity_level"] == "low"
        assert cl["source_breakdown"] == {"wardrive": 2}
        assert cl["security_breakdown"] == {"WPA2": 2}
        assert cl["located_ssids"][0]["dominant_device_type"] == "unknown"

    def test_duplicate_ssid_creates_alternative_hypothesis(self, client, monkeypatch):
        dataset = {
            "aa:bb:cc:dd:ee:01": {
                "ssid": "CafeNet", "encryption": "WPA2", "lat": 40.0, "lng": -74.0,
                "device_type": "router_ap", "sources": ["wardrive"],
            },
            "aa:bb:cc:dd:ee:02": {
                "ssid": "CafeNet", "encryption": "WPA2", "lat": 41.0, "lng": -75.0,
                "device_type": "router_ap", "sources": ["wardrive"],
            },
            "aa:bb:cc:dd:ee:03": {
                "ssid": "OfficeWiFi", "encryption": "OPEN", "lat": 40.0004, "lng": -74.0003,
                "device_type": "camera", "sources": ["pwnagotchi"],
            },
            "aa:bb:cc:dd:ee:04": {
                "ssid": "PrinterNet", "encryption": "WPA2", "lat": 40.0005, "lng": -74.0001,
                "device_type": "iot", "sources": ["wardrive"],
            },
            "aa:bb:cc:dd:ee:05": {
                "ssid": "OfficeWiFi", "encryption": "OPEN", "lat": 41.0003, "lng": -75.0002,
                "device_type": "camera", "sources": ["pwnagotchi"],
            },
        }
        monkeypatch.setattr(recon_module, "load_real_data", lambda: dataset)
        monkeypatch.setattr(
            recon_module.mac_lookup,
            "lookup",
            lambda value: "Acme Wireless" if str(value).startswith("52:ab:cd") else "Unknown",
        )
        monkeypatch.setattr(
            recon_module.probe_service, "get_cache_status",
            lambda: {
                "cached": True,
                "result": {
                    "available": True,
                    "clients": [
                        {
                            "client_mac": "52:ab:cd:ef:00:01",
                            "oui_prefix": "52:ab:cd",
                            "probe_count": 8,
                            "ssids_probed": ["CafeNet", "OfficeWiFi", "PrinterNet"],
                            "avg_signal": -51,
                            "first_seen": 1712000000,
                            "last_seen": 1712000600,
                        },
                    ],
                },
            },
        )
        recon_runtime_module.clear_recon_runtime_cache()

        resp = client.get("/api/recon/probe-intel/geocorrelation")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["summary"]["correlated_clients"] == 1
        assert data["summary"]["high_confidence_clients"] == 0
        cl = data["clients"][0]
        assert cl["vendor"] == "Acme Wireless"
        assert cl["matched_ssid_count"] == 3
        assert cl["match_count"] == 3
        assert cl["confidence"] == "medium"
        assert cl["alternative_cluster_count"] >= 1
        assert cl["ambiguity_level"] == "medium"
        assert cl["security_breakdown"]["WPA2"] == 2
        assert cl["security_breakdown"]["OPEN"] == 1
        assert cl["source_breakdown"]["wardrive"] == 2
        assert cl["source_breakdown"]["pwnagotchi"] == 1
        assert any(item["ssid"] == "CafeNet" for item in cl["located_ssids"])
        cafe = next(item for item in cl["located_ssids"] if item["ssid"] == "CafeNet")
        assert cafe["dominant_device_type"] == "router_ap"
        assert cafe["sample_mac"] == "aa:bb:cc:dd:ee:01"
