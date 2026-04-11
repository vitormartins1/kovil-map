"""Tests for Advanced Packet Analysis (analysis router + packet_analysis_service).

Covers:
  1. GET /api/recon/deep-analysis
  2. GET /api/recon/deep-analysis/pcap
  3. PacketAnalysisService internals: _extract_deauth, _extract_disassoc,
     _build_threat_intel, _find_pcaps
  4. _build_vuln_flags 802.11r FT flag
"""

from __future__ import annotations

import json
import os
import struct

import pytest

from app.services import packet_analysis_service as pa_service_module

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Valid PCAP LE global header (24 bytes): magic + v2.4 + snaplen=262144 + ETHERNET
_VALID_PCAP_HEADER = (
    b"\xd4\xc3\xb2\xa1"
    + struct.pack("<HH", 2, 4)
    + struct.pack("<i", 0)
    + struct.pack("<I", 0)
    + struct.pack("<I", 262144)
    + struct.pack("<I", 1)
)

# Valid pcapng Section Header Block (28 bytes)
_VALID_PCAPNG_HEADER = (
    b"\x0a\x0d\x0d\x0a"  # block type
    + b"\x1c\x00\x00\x00"  # block total length = 28
    + b"\x1a\x2b\x3c\x4d"  # byte-order magic
    + b"\x01\x00"  # major version
    + b"\x00\x00"  # minor version
    + b"\xff\xff\xff\xff\xff\xff\xff\xff"  # section length = -1
    + b"\x1c\x00\x00\x00"  # block total length repeated
)


def _write_pcap(tmp_path, name="capture.pcap"):
    p = tmp_path / name
    if name.lower().endswith(".pcapng"):
        p.write_bytes(_VALID_PCAPNG_HEADER)
    else:
        p.write_bytes(_VALID_PCAP_HEADER)
    return str(p)


SAMPLE_DEAUTH_OUTPUT = (
    "1712000100.000000\taa:bb:cc:dd:ee:01\tff:ff:ff:ff:ff:ff\taa:bb:cc:dd:ee:01\t7\n"
    "1712000200.000000\taa:bb:cc:dd:ee:01\t11:22:33:44:55:66\taa:bb:cc:dd:ee:01\t7\n"
    "1712000300.000000\t11:22:33:44:55:66\taa:bb:cc:dd:ee:01\taa:bb:cc:dd:ee:01\t1\n"
    "1712000400.000000\taa:bb:cc:dd:ee:02\tff:ff:ff:ff:ff:ff\taa:bb:cc:dd:ee:02\t3\n"
)

SAMPLE_DISASSOC_OUTPUT = (
    "1712000500.000000\taa:bb:cc:dd:ee:01\t11:22:33:44:55:66\taa:bb:cc:dd:ee:01\t8\n"
    "1712000600.000000\taa:bb:cc:dd:ee:02\tff:ff:ff:ff:ff:ff\taa:bb:cc:dd:ee:02\t4\n"
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def patch_analysis(monkeypatch, tmp_path):
    """Patch packet_analysis_service dependencies for testing."""
    monkeypatch.setattr(
        pa_service_module.packet_analysis_service,
        "_pcap_search_roots",
        lambda: (str(tmp_path),),
    )
    monkeypatch.setattr(
        pa_service_module.packet_analysis_service,
        "_check_tshark",
        lambda: "/usr/bin/tshark",
    )
    return tmp_path


@pytest.fixture()
def patch_tshark_deauth(monkeypatch):
    """Patch _run_tshark to return sample deauth/disassoc data based on filter."""

    def _fake_run(base_cmd):
        cmd_str = " ".join(base_cmd)
        if "0x0c" in cmd_str:
            return (SAMPLE_DEAUTH_OUTPUT, [])
        elif "0x0a" in cmd_str:
            return (SAMPLE_DISASSOC_OUTPUT, [])
        return ("", [])

    monkeypatch.setattr(
        pa_service_module.packet_analysis_service,
        "_run_tshark",
        _fake_run,
    )


# ---------------------------------------------------------------------------
# 1. GET /api/recon/deep-analysis
# ---------------------------------------------------------------------------


class TestDeepAnalysisEndpoint:
    def test_no_tshark_returns_unavailable(self, client, monkeypatch, tmp_path):
        monkeypatch.setattr(
            pa_service_module.packet_analysis_service,
            "_check_tshark",
            lambda: None,
        )
        resp = client.get("/api/recon/deep-analysis")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["available"] is False
        assert "tshark" in data["error"]

    def test_no_pcaps_empty(self, client, patch_analysis):
        resp = client.get("/api/recon/deep-analysis")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["available"] is True
        assert data["summary"]["total_deauth"] == 0
        assert data["summary"]["total_disassoc"] == 0
        assert data["threats_by_bssid"] == {} or data["threats_by_bssid"] == []

    def test_with_threats(self, client, patch_analysis, patch_tshark_deauth):
        _write_pcap(patch_analysis, "test.pcap")
        resp = client.get("/api/recon/deep-analysis")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["available"] is True
        s = data["summary"]
        assert s["total_deauth"] == 4
        assert s["total_disassoc"] == 2
        assert s["targeted_bssids"] == 2
        assert s["pcaps_scanned"] == 1

    def test_threats_sorted_by_total(self, client, patch_analysis, patch_tshark_deauth):
        _write_pcap(patch_analysis, "test.pcap")
        resp = client.get("/api/recon/deep-analysis")
        threats = resp.json()["data"]["threats_by_bssid"]
        totals = [t["total_frames"] for t in threats]
        assert totals == sorted(totals, reverse=True)

    def test_threat_fields(self, client, patch_analysis, patch_tshark_deauth):
        _write_pcap(patch_analysis, "test.pcap")
        resp = client.get("/api/recon/deep-analysis")
        threats = resp.json()["data"]["threats_by_bssid"]
        # aa:bb:cc:dd:ee:01 has 3 deauth + 1 disassoc
        t1 = next(t for t in threats if t["bssid"] == "aa:bb:cc:dd:ee:01")
        assert t1["deauth_count"] == 3
        assert t1["disassoc_count"] == 1
        assert t1["total_frames"] == 4
        assert t1["unique_sources"] >= 2
        assert t1["top_reasons"] is not None
        assert t1["first_seen"] is not None

    def test_limit_parameter(self, client, patch_analysis, patch_tshark_deauth):
        _write_pcap(patch_analysis, "test.pcap")
        resp = client.get("/api/recon/deep-analysis", params={"limit": 1})
        assert resp.status_code == 200
        threats = resp.json()["data"]["threats_by_bssid"]
        assert len(threats) <= 1

    def test_limit_validation(self, client, patch_analysis):
        resp = client.get("/api/recon/deep-analysis", params={"limit": 0})
        assert resp.status_code == 422
        resp = client.get("/api/recon/deep-analysis", params={"limit": 2000})
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 2. GET /api/recon/deep-analysis/pcap
# ---------------------------------------------------------------------------


class TestDeepAnalysisPcapEndpoint:
    def test_missing_path(self, client, patch_analysis):
        resp = client.get("/api/recon/deep-analysis/pcap")
        assert resp.status_code == 422

    def test_nonexistent_file(self, client, patch_analysis):
        resp = client.get(
            "/api/recon/deep-analysis/pcap",
            params={"path": "/nonexistent/file.pcap"},
        )
        assert resp.status_code == 400

    def test_valid_pcap(self, client, patch_analysis, patch_tshark_deauth):
        pcap = _write_pcap(patch_analysis, "single.pcap")
        resp = client.get(
            "/api/recon/deep-analysis/pcap",
            params={"path": pcap},
        )
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["available"] is True
        assert data["summary"]["total_deauth"] == 4
        assert data["summary"]["pcaps_scanned"] == 1


# ---------------------------------------------------------------------------
# 3. PacketAnalysisService internals
# ---------------------------------------------------------------------------


class TestPacketAnalysisInternals:
    def test_find_pcaps(self, patch_analysis):
        _write_pcap(patch_analysis, "a.pcap")
        _write_pcap(patch_analysis, "b.pcapng")
        (patch_analysis / "readme.txt").write_text("hello")
        pcaps = pa_service_module.packet_analysis_service._find_pcaps()
        names = [os.path.basename(p) for p in pcaps]
        assert "a.pcap" in names
        assert "b.pcapng" in names
        assert "readme.txt" not in names

    def test_extract_deauth(self, patch_analysis, patch_tshark_deauth):
        pcap = _write_pcap(patch_analysis, "x.pcap")
        frames = pa_service_module.packet_analysis_service._extract_deauth(pcap)
        assert len(frames) == 4
        assert frames[0]["bssid"] == "aa:bb:cc:dd:ee:01"
        assert frames[0]["reason_code"] == 7
        assert frames[0]["reason_text"] == "Class-3 frame from non-assoc station"

    def test_extract_disassoc(self, patch_analysis, patch_tshark_deauth):
        pcap = _write_pcap(patch_analysis, "x.pcap")
        frames = pa_service_module.packet_analysis_service._extract_disassoc(pcap)
        assert len(frames) == 2
        assert frames[0]["reason_code"] == 8

    def test_build_threat_intel_empty(self):
        result = pa_service_module.packet_analysis_service._build_threat_intel(
            [], [], 0, 100
        )
        assert result["available"] is True
        assert result["summary"]["total_deauth"] == 0
        assert result["summary"]["total_disassoc"] == 0

    def test_build_threat_intel_aggregates(self):
        deauth = [
            {
                "timestamp": 1000.0,
                "src": "a1",
                "dst": "b1",
                "bssid": "aa:bb:cc:01",
                "reason_code": 7,
                "reason_text": "test",
            },
            {
                "timestamp": 1001.0,
                "src": "a2",
                "dst": "b2",
                "bssid": "aa:bb:cc:01",
                "reason_code": 7,
                "reason_text": "test",
            },
            {
                "timestamp": 1002.0,
                "src": "a1",
                "dst": "b1",
                "bssid": "aa:bb:cc:02",
                "reason_code": 1,
                "reason_text": "test",
            },
        ]
        disassoc = [
            {
                "timestamp": 1003.0,
                "src": "a1",
                "dst": "b1",
                "bssid": "aa:bb:cc:01",
                "reason_code": 8,
                "reason_text": "test",
            },
        ]
        result = pa_service_module.packet_analysis_service._build_threat_intel(
            deauth, disassoc, 1, 100
        )
        assert result["summary"]["total_deauth"] == 3
        assert result["summary"]["total_disassoc"] == 1
        assert result["summary"]["targeted_bssids"] == 2
        threats = result["threats_by_bssid"]
        t1 = next(t for t in threats if t["bssid"] == "aa:bb:cc:01")
        assert t1["deauth_count"] == 2
        assert t1["disassoc_count"] == 1
        assert t1["total_frames"] == 3

    def test_flood_detection(self):
        """More than 50 deauth frames should trigger flood indicator."""
        deauth = [
            {
                "timestamp": 1000.0 + i,
                "src": "attacker",
                "dst": "target",
                "bssid": "aa:bb:cc:01",
                "reason_code": 7,
                "reason_text": "test",
            }
            for i in range(60)
        ]
        result = pa_service_module.packet_analysis_service._build_threat_intel(
            deauth, [], 1, 100
        )
        assert result["summary"]["deauth_flood_detected"] is True
        assert result["threats_by_bssid"][0]["flood_indicator"] is True

    def test_no_flood_below_threshold(self):
        deauth = [
            {
                "timestamp": 1000.0 + i,
                "src": "a1",
                "dst": "b1",
                "bssid": "aa:bb:cc:01",
                "reason_code": 7,
                "reason_text": "test",
            }
            for i in range(10)
        ]
        result = pa_service_module.packet_analysis_service._build_threat_intel(
            deauth, [], 1, 100
        )
        assert result["summary"]["deauth_flood_detected"] is False

    def test_limit_respected(self):
        deauth = [
            {
                "timestamp": 1000.0,
                "src": "a",
                "dst": "b",
                "bssid": f"aa:bb:cc:{i:02x}",
                "reason_code": 7,
                "reason_text": "t",
            }
            for i in range(10)
        ]
        result = pa_service_module.packet_analysis_service._build_threat_intel(
            deauth, [], 1, 3
        )
        assert len(result["threats_by_bssid"]) == 3

    def test_corrupt_pcap_handled(self, patch_analysis, monkeypatch):
        import subprocess

        pcap = _write_pcap(patch_analysis, "corrupt.pcap")

        def _fake_run(cmd, **kwargs):
            return (
                subprocess.CompletedResult
                if False
                else subprocess.CompletedProcess(
                    cmd,
                    returncode=2,
                    stdout="",
                    stderr='tshark: The file "corrupt.pcap" appears to be damaged or corrupt.',
                )
            )

        monkeypatch.setattr(pa_service_module.subprocess, "run", _fake_run)
        frames = pa_service_module.packet_analysis_service._extract_deauth(pcap)
        assert frames == []


# ---------------------------------------------------------------------------
# 4. _build_vuln_flags — 802.11r FT flag
# ---------------------------------------------------------------------------


class TestFTVulnFlag:
    def test_ft_flag_present(self, monkeypatch, tmp_path):
        from app.api.routers import recon as recon_module

        mac = "aa:bb:cc:dd:ee:ff"
        mac_clean = mac.replace(":", "").lower()

        # Write a .details file with FT AKM
        monkeypatch.setattr(recon_module, "HANDSHAKES_DIR", str(tmp_path))
        details = {"security": {"akm": ["PSK", "FT/PSK"]}}
        details_file = tmp_path / f"testnet_{mac_clean}.details"
        details_file.write_text(json.dumps(details))

        net = {"ssid": "TestNet", "encryption": "WPA2"}
        score_data = {"readiness_status": "ready"}
        flags, _ = recon_module._build_vuln_flags(
            mac,
            net,
            score_data,
            hash_info={
                "has_hash": False,
                "has_pmkid": False,
                "has_eapol_hash": False,
                "pmkid_count": 0,
                "eapol_count": 0,
            },
        )
        ft_flags = [f for f in flags if f["id"] == "ft_enabled"]
        assert len(ft_flags) == 1
        assert "FT/PSK" in ft_flags[0]["description"]

    def test_no_ft_flag_without_ft(self, monkeypatch, tmp_path):
        from app.api.routers import recon as recon_module

        mac = "aa:bb:cc:dd:ee:ff"
        mac_clean = mac.replace(":", "").lower()

        monkeypatch.setattr(recon_module, "HANDSHAKES_DIR", str(tmp_path))
        details = {"security": {"akm": ["PSK"]}}
        details_file = tmp_path / f"testnet_{mac_clean}.details"
        details_file.write_text(json.dumps(details))

        net = {"ssid": "TestNet", "encryption": "WPA2"}
        score_data = {"readiness_status": "ready"}
        flags, _ = recon_module._build_vuln_flags(
            mac,
            net,
            score_data,
            hash_info={
                "has_hash": False,
                "has_pmkid": False,
                "has_eapol_hash": False,
                "pmkid_count": 0,
                "eapol_count": 0,
            },
        )
        ft_flags = [f for f in flags if f["id"] == "ft_enabled"]
        assert len(ft_flags) == 0

    def test_no_details_file(self, monkeypatch, tmp_path):
        from app.api.routers import recon as recon_module

        monkeypatch.setattr(recon_module, "HANDSHAKES_DIR", str(tmp_path))

        mac = "11:22:33:44:55:66"
        net = {"ssid": "NoDetails", "encryption": "WPA2"}
        score_data = {"readiness_status": "not_ready"}
        flags, _ = recon_module._build_vuln_flags(
            mac,
            net,
            score_data,
            hash_info={
                "has_hash": False,
                "has_pmkid": False,
                "has_eapol_hash": False,
                "pmkid_count": 0,
                "eapol_count": 0,
            },
        )
        ft_flags = [f for f in flags if f["id"] == "ft_enabled"]
        assert len(ft_flags) == 0


# ---------------------------------------------------------------------------
# 5. GET /api/recon/deep-analysis/status
# ---------------------------------------------------------------------------


class TestDeepAnalysisStatusEndpoint:
    def test_status_no_cache(self, client, patch_analysis):
        resp = client.get("/api/recon/deep-analysis/status")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["cached"] is False
        assert data["stale"] is False
        assert data["pcap_count"] == 0
        assert data["result"] is None

    def test_status_with_pcaps_no_cache(self, client, patch_analysis):
        _write_pcap(patch_analysis, "test.pcap")
        resp = client.get("/api/recon/deep-analysis/status")
        data = resp.json()["data"]
        assert data["cached"] is False
        assert data["pcap_count"] == 1

    def test_status_returns_cached_after_scan(
        self, client, patch_analysis, patch_tshark_deauth
    ):
        _write_pcap(patch_analysis, "test.pcap")
        pcaps = pa_service_module.packet_analysis_service._find_pcaps()
        pa_service_module.packet_analysis_service.analyse_with_progress(
            pcaps, limit=200
        )

        resp = client.get("/api/recon/deep-analysis/status")
        data = resp.json()["data"]
        assert data["cached"] is True
        assert data["stale"] is False
        assert data["result"] is not None
        assert data["result"]["summary"]["total_deauth"] == 4

    def test_status_stale_after_new_pcap(
        self, client, patch_analysis, patch_tshark_deauth
    ):
        _write_pcap(patch_analysis, "test.pcap")
        pcaps = pa_service_module.packet_analysis_service._find_pcaps()
        pa_service_module.packet_analysis_service.analyse_with_progress(
            pcaps, limit=200
        )
        # Add new PCAP → stale
        _write_pcap(patch_analysis, "new.pcap")
        resp = client.get("/api/recon/deep-analysis/status")
        data = resp.json()["data"]
        assert data["cached"] is True
        assert data["stale"] is True

    def test_invalidate_cache(self, patch_analysis, patch_tshark_deauth):
        _write_pcap(patch_analysis, "test.pcap")
        pcaps = pa_service_module.packet_analysis_service._find_pcaps()
        pa_service_module.packet_analysis_service.analyse_with_progress(
            pcaps, limit=200
        )
        assert pa_service_module.packet_analysis_service._cache is not None
        pa_service_module.packet_analysis_service.invalidate_cache()
        assert pa_service_module.packet_analysis_service._cache is None


# ---------------------------------------------------------------------------
# 6. POST /api/recon/deep-analysis/scan
# ---------------------------------------------------------------------------


class TestDeepAnalysisScanEndpoint:
    def test_scan_no_pcaps(self, client, patch_analysis):
        resp = client.post("/api/recon/deep-analysis/scan")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["job_id"] is None
        assert data["pcap_count"] == 0

    def test_scan_starts_job(
        self, client, patch_analysis, patch_tshark_deauth, monkeypatch
    ):
        _write_pcap(patch_analysis, "test.pcap")
        from app.jobs import recon_jobs as recon_jobs_module

        captured = {}

        def fake_start(
            worker,
            job_type="",
            total_steps=1,
            meta=None,
            on_complete=None,
            on_start=None,
        ):
            captured["job_type"] = job_type
            captured["total_steps"] = total_steps
            return "fake-deep-job-id"

        monkeypatch.setattr(
            recon_jobs_module.job_manager, "start_multi_job", fake_start
        )

        resp = client.post("/api/recon/deep-analysis/scan")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["job_id"] == "fake-deep-job-id"
        assert data["pcap_count"] == 1
        assert captured["job_type"] == "deep_analysis_scan"


# ---------------------------------------------------------------------------
# 7. analyse_with_progress
# ---------------------------------------------------------------------------


class TestDeepAnalyseWithProgress:
    def test_populates_cache(self, patch_analysis, patch_tshark_deauth):
        _write_pcap(patch_analysis, "test.pcap")
        pcaps = pa_service_module.packet_analysis_service._find_pcaps()
        result = pa_service_module.packet_analysis_service.analyse_with_progress(
            pcaps, limit=200
        )
        assert result["available"] is True
        assert result["summary"]["total_deauth"] == 4
        assert pa_service_module.packet_analysis_service._cache is not None

    def test_emits_progress(self, patch_analysis, patch_tshark_deauth):
        _write_pcap(patch_analysis, "a.pcap")
        _write_pcap(patch_analysis, "b.pcap")
        pcaps = pa_service_module.packet_analysis_service._find_pcaps()
        emissions = []
        fake_job = {
            "id": "test-job",
            "progress_data": {
                "current_step": 0,
                "percentage": 0,
                "stage": "",
                "extra": "",
            },
        }

        def fake_emit(event, data):
            emissions.append((event, data.copy()))

        pa_service_module.packet_analysis_service.analyse_with_progress(
            pcaps,
            limit=200,
            emit=fake_emit,
            job=fake_job,
        )
        assert len(emissions) >= 2
        assert all(e[0] == "job_progress" for e in emissions)
        assert emissions[-1][1]["data"]["percentage"] == 100

    def test_no_tshark(self, patch_analysis, monkeypatch):
        monkeypatch.setattr(
            pa_service_module.packet_analysis_service, "_check_tshark", lambda: None
        )
        result = pa_service_module.packet_analysis_service.analyse_with_progress(
            [], limit=200
        )
        assert result["available"] is False

    def test_empty_pcaps(self, patch_analysis, patch_tshark_deauth):
        result = pa_service_module.packet_analysis_service.analyse_with_progress(
            [], limit=200
        )
        assert result["available"] is True
        assert result["summary"]["total_deauth"] == 0
