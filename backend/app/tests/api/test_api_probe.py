"""Tests for Probe Request Intelligence (probe router + probe_service).

Covers:
  1. GET /api/recon/probe-intel
  2. GET /api/recon/probe-intel/pcap
  3. ProbeService internals: extract_probes, _find_pcaps, _build_intelligence
"""

from __future__ import annotations

import os

import pytest

from app.api.routers import probe as probe_router_module
from app.services import probe_service as probe_service_module

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_pcap(tmp_path, name="capture.pcap"):
    """Create a tiny dummy file acting as a PCAP (real parsing uses tshark)."""
    p = tmp_path / name
    p.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)  # pcap magic header
    return str(p)


SAMPLE_TSHARK_OUTPUT = (
    "1712000100.000000\t00:11:22:33:44:55\tHomeNet\t-45\n"
    "1712000200.000000\t00:11:22:33:44:55\tCoffeeShop\t-60\n"
    "1712000300.000000\taa:bb:cc:dd:ee:ff\tHomeNet\t-50\n"
    "1712000400.000000\taa:bb:cc:dd:ee:ff\t\t-70\n"
    "1712000500.000000\t11:22:33:44:55:66\tCoffeeShop\t-55\n"
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def patch_probe(monkeypatch, tmp_path):
    """Patch probe_service dependencies for testing."""
    # Make service use tmp_path as search root
    monkeypatch.setattr(
        probe_service_module.probe_service,
        "_pcap_search_roots",
        lambda: (str(tmp_path),),
    )
    # Disable tshark check — always "available"
    monkeypatch.setattr(
        probe_service_module.probe_service,
        "_check_tshark",
        lambda: "/usr/bin/tshark",
    )
    monkeypatch.setattr(probe_router_module, "load_real_data", lambda: {})
    return tmp_path


@pytest.fixture()
def patch_tshark_output(monkeypatch):
    """Patch _run_tshark to return sample probe data."""
    monkeypatch.setattr(
        probe_service_module.probe_service,
        "_run_tshark",
        lambda base_cmd: (SAMPLE_TSHARK_OUTPUT, []),
    )


# ---------------------------------------------------------------------------
# 1. GET /api/recon/probe-intel
# ---------------------------------------------------------------------------


class TestProbeIntelEndpoint:
    def test_no_tshark_returns_unavailable(self, client, monkeypatch, tmp_path):
        monkeypatch.setattr(
            probe_service_module.probe_service,
            "_check_tshark",
            lambda: None,
        )
        resp = client.get("/api/recon/probe-intel")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["available"] is False
        assert "tshark" in data["error"]

    def test_no_pcaps_empty_result(self, client, patch_probe):
        resp = client.get("/api/recon/probe-intel")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["available"] is True
        assert data["summary"]["total_probes"] == 0
        assert data["summary"]["pcaps_scanned"] == 0
        assert data["clients"] == []
        assert data["ssids"] == []

    def test_with_probes(self, client, patch_probe, patch_tshark_output):
        _write_pcap(patch_probe, "test.pcap")
        resp = client.get("/api/recon/probe-intel")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["available"] is True
        s = data["summary"]
        assert s["total_probes"] == 5
        assert s["unique_clients"] == 3
        assert s["unique_ssids"] == 2  # HomeNet, CoffeeShop
        assert s["broadcast_probes"] == 1  # aa:bb:cc:dd:ee:ff empty SSID
        assert s["pcaps_scanned"] == 1

    def test_clients_sorted_by_probe_count(
        self, client, patch_probe, patch_tshark_output
    ):
        _write_pcap(patch_probe, "test.pcap")
        resp = client.get("/api/recon/probe-intel")
        clients = resp.json()["data"]["clients"]
        counts = [c["probe_count"] for c in clients]
        assert counts == sorted(counts, reverse=True)

    def test_client_fields(self, client, patch_probe, patch_tshark_output):
        _write_pcap(patch_probe, "test.pcap")
        resp = client.get("/api/recon/probe-intel")
        clients = resp.json()["data"]["clients"]
        # 00:11:22:33:44:55 probed HomeNet and CoffeeShop
        cl = next(c for c in clients if c["client_mac"] == "00:11:22:33:44:55")
        assert cl["probe_count"] == 2
        assert set(cl["ssids_probed"]) == {"HomeNet", "CoffeeShop"}
        assert cl["unique_ssids"] == 2
        assert cl["oui_prefix"] == "00:11:22"
        assert cl["avg_signal"] is not None
        assert cl["first_seen"] is not None
        assert cl["last_seen"] is not None

    def test_ssids_sorted_by_client_count(
        self, client, patch_probe, patch_tshark_output
    ):
        _write_pcap(patch_probe, "test.pcap")
        resp = client.get("/api/recon/probe-intel")
        ssids = resp.json()["data"]["ssids"]
        client_counts = [s["client_count"] for s in ssids]
        assert client_counts == sorted(client_counts, reverse=True)

    def test_ssid_fields(self, client, patch_probe, patch_tshark_output):
        _write_pcap(patch_probe, "test.pcap")
        resp = client.get("/api/recon/probe-intel")
        ssids = resp.json()["data"]["ssids"]
        home = next(s for s in ssids if s["ssid"] == "HomeNet")
        assert home["client_count"] == 2  # 00:11:22 + aa:bb:cc
        assert home["probe_count"] == 2

    def test_probe_intel_enriches_known_context_and_vendor(
        self, client, patch_probe, patch_tshark_output, monkeypatch
    ):
        _write_pcap(patch_probe, "test.pcap")
        monkeypatch.setattr(
            probe_router_module,
            "load_real_data",
            lambda: {
                "aa:bb:cc:dd:ee:01": {
                    "ssid": "HomeNet",
                    "encryption": "WPA2",
                    "device_type": "router_ap",
                    "sources": ["wardrive", "pwnagotchi"],
                },
            },
        )
        monkeypatch.setattr(
            probe_router_module.mac_lookup,
            "lookup",
            lambda value: (
                "Acme Wireless" if str(value).startswith("00:11:22") else "Unknown"
            ),
        )

        resp = client.get("/api/recon/probe-intel")
        data = resp.json()["data"]
        home = next(s for s in data["ssids"] if s["ssid"] == "HomeNet")
        coffee = next(s for s in data["ssids"] if s["ssid"] == "CoffeeShop")
        rich_client = next(
            c for c in data["clients"] if c["client_mac"] == "00:11:22:33:44:55"
        )

        assert home["is_known"] is True
        assert home["name_shape"] == "human"
        assert home["known_context"]["network_count"] == 1
        assert home["known_context"]["dominant_encryption"] == "WPA2"
        assert home["known_context"]["dominant_device_type"] == "router_ap"
        assert home["known_context"]["sources"] == ["pwnagotchi", "wardrive"]
        assert coffee["is_known"] is False
        assert coffee["known_context"]["network_count"] == 0
        assert rich_client["vendor"] == "Acme Wireless"
        assert rich_client["known_ssid_count"] == 1
        assert rich_client["unmatched_ssid_count"] == 1
        assert rich_client["known_ssid_preview"] == ["HomeNet"]
        assert rich_client["unmatched_ssid_preview"] == ["CoffeeShop"]

    def test_probe_intel_classifies_ssid_name_shape(
        self, client, patch_probe, monkeypatch
    ):
        monkeypatch.setattr(
            probe_service_module.probe_service,
            "analyse",
            lambda limit=200: {
                "available": True,
                "clients": [],
                "ssids": [
                    {
                        "ssid": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                        "client_count": 1,
                        "probe_count": 1,
                    },
                    {"ssid": "ABCDEF123456", "client_count": 1, "probe_count": 1},
                    {
                        "ssid": "DIRECT-AB_Printer4F2A",
                        "client_count": 1,
                        "probe_count": 1,
                    },
                ],
                "summary": {
                    "total_probes": 3,
                    "unique_clients": 1,
                    "unique_ssids": 3,
                    "pcaps_scanned": 1,
                    "broadcast_probes": 0,
                },
            },
        )
        monkeypatch.setattr(probe_router_module, "load_real_data", lambda: {})

        resp = client.get("/api/recon/probe-intel")
        data = resp.json()["data"]
        shapes = {item["ssid"]: item["name_shape"] for item in data["ssids"]}
        assert shapes["3fa85f64-5717-4562-b3fc-2c963f66afa6"] == "uuid_like"
        assert shapes["ABCDEF123456"] == "hex_like"
        assert shapes["DIRECT-AB_Printer4F2A"] == "generated_like"

    def test_limit_parameter(self, client, patch_probe, patch_tshark_output):
        _write_pcap(patch_probe, "test.pcap")
        resp = client.get("/api/recon/probe-intel", params={"limit": 1})
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert len(data["clients"]) <= 1
        assert len(data["ssids"]) <= 1

    def test_limit_validation(self, client, patch_probe):
        resp = client.get("/api/recon/probe-intel", params={"limit": 0})
        assert resp.status_code == 422

        resp = client.get("/api/recon/probe-intel", params={"limit": 2000})
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# 2. GET /api/recon/probe-intel/pcap
# ---------------------------------------------------------------------------


class TestProbeIntelPcapEndpoint:
    def test_missing_path(self, client, patch_probe):
        resp = client.get("/api/recon/probe-intel/pcap")
        assert resp.status_code == 422  # required param missing

    def test_nonexistent_file(self, client, patch_probe):
        resp = client.get(
            "/api/recon/probe-intel/pcap",
            params={"path": "/nonexistent/file.pcap"},
        )
        assert resp.status_code == 400

    def test_valid_pcap(self, client, patch_probe, patch_tshark_output):
        pcap = _write_pcap(patch_probe, "single.pcap")
        resp = client.get(
            "/api/recon/probe-intel/pcap",
            params={"path": pcap},
        )
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["available"] is True
        assert data["summary"]["total_probes"] == 5
        assert data["summary"]["pcaps_scanned"] == 1


# ---------------------------------------------------------------------------
# 3. ProbeService internals
# ---------------------------------------------------------------------------


class TestProbeServiceInternals:
    def test_find_pcaps_discovers_files(self, patch_probe):
        _write_pcap(patch_probe, "a.pcap")
        _write_pcap(patch_probe, "b.pcapng")
        (patch_probe / "not_a_pcap.txt").write_text("hello")
        pcaps = probe_service_module.probe_service._find_pcaps()
        names = [os.path.basename(p) for p in pcaps]
        assert "a.pcap" in names
        assert "b.pcapng" in names
        assert "not_a_pcap.txt" not in names

    def test_find_pcaps_deduplicates(self, patch_probe):
        """Same file via symlink should only appear once."""
        pcap = _write_pcap(patch_probe, "real.pcap")
        link = patch_probe / "link.pcap"
        link.symlink_to(pcap)
        pcaps = probe_service_module.probe_service._find_pcaps()
        assert len(pcaps) == 1  # dedup via realpath

    def test_find_pcaps_empty_dir(self, patch_probe):
        pcaps = probe_service_module.probe_service._find_pcaps()
        assert pcaps == []

    def test_extract_probes_parses_tshark(self, patch_probe, patch_tshark_output):
        pcap = _write_pcap(patch_probe, "x.pcap")
        probes = probe_service_module.probe_service.extract_probes(pcap)
        assert len(probes) == 5
        assert probes[0]["client_mac"] == "00:11:22:33:44:55"
        assert probes[0]["ssid"] == "HomeNet"
        assert probes[0]["signal"] == -45
        assert probes[0]["timestamp"] > 0

    def test_extract_probes_broadcast(self, patch_probe, patch_tshark_output):
        pcap = _write_pcap(patch_probe, "x.pcap")
        probes = probe_service_module.probe_service.extract_probes(pcap)
        broadcast = [p for p in probes if p["ssid"] == ""]
        assert len(broadcast) == 1
        assert broadcast[0]["client_mac"] == "aa:bb:cc:dd:ee:ff"

    def test_corrupt_pcap_returns_empty(self, patch_probe, monkeypatch):
        """Corrupt PCAPs (damaged/corrupt stderr) should return empty, not raise."""
        import subprocess

        pcap = _write_pcap(patch_probe, "corrupt.pcap")

        def _fake_run(cmd, **kwargs):
            r = subprocess.CompletedProcess(
                cmd,
                returncode=2,
                stdout="",
                stderr=(
                    'tshark: The file "corrupt.pcap" appears to be damaged or corrupt.\n'
                    "(pcap: File has 1742268728-byte packet, bigger than maximum of 262144)"
                ),
            )
            return r

        monkeypatch.setattr(probe_service_module.subprocess, "run", _fake_run)
        probes = probe_service_module.probe_service.extract_probes(pcap)
        assert probes == []

    def test_build_intelligence_empty(self):
        result = probe_service_module.probe_service._build_intelligence([], 0, 100)
        assert result["available"] is True
        assert result["summary"]["total_probes"] == 0
        assert result["clients"] == []
        assert result["ssids"] == []

    def test_build_intelligence_aggregates(self):
        probes = [
            {
                "client_mac": "aa:bb:cc:11:22:33",
                "ssid": "Net1",
                "timestamp": 1000.0,
                "signal": -40,
            },
            {
                "client_mac": "aa:bb:cc:11:22:33",
                "ssid": "Net2",
                "timestamp": 1001.0,
                "signal": -50,
            },
            {
                "client_mac": "dd:ee:ff:44:55:66",
                "ssid": "Net1",
                "timestamp": 1002.0,
                "signal": -60,
            },
            {
                "client_mac": "dd:ee:ff:44:55:66",
                "ssid": "",
                "timestamp": 1003.0,
                "signal": None,
            },
        ]
        result = probe_service_module.probe_service._build_intelligence(probes, 1, 100)
        assert result["summary"]["total_probes"] == 4
        assert result["summary"]["unique_clients"] == 2
        assert result["summary"]["unique_ssids"] == 2
        assert result["summary"]["broadcast_probes"] == 1

        # Client aa:bb:cc probed 2 SSIDs with 2 probes
        cl = next(
            c for c in result["clients"] if c["client_mac"] == "aa:bb:cc:11:22:33"
        )
        assert cl["probe_count"] == 2
        assert cl["unique_ssids"] == 2
        assert cl["avg_signal"] == -45  # avg(-40, -50)

        # SSID Net1 probed by 2 clients
        ss = next(s for s in result["ssids"] if s["ssid"] == "Net1")
        assert ss["client_count"] == 2

    def test_build_intelligence_respects_limit(self):
        probes = [
            {
                "client_mac": f"aa:bb:cc:dd:ee:{i:02x}",
                "ssid": f"Net{i}",
                "timestamp": 1000.0 + i,
                "signal": -40,
            }
            for i in range(10)
        ]
        result = probe_service_module.probe_service._build_intelligence(probes, 1, 3)
        assert len(result["clients"]) == 3
        assert len(result["ssids"]) == 3


# ---------------------------------------------------------------------------
# 4. GET /api/recon/probe-intel/status
# ---------------------------------------------------------------------------


class TestProbeIntelStatusEndpoint:
    def test_status_no_cache(self, client, patch_probe):
        resp = client.get("/api/recon/probe-intel/status")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["cached"] is False
        assert data["stale"] is False
        assert data["pcap_count"] == 0
        assert data["result"] is None

    def test_status_with_pcaps_no_cache(self, client, patch_probe):
        _write_pcap(patch_probe, "test.pcap")
        resp = client.get("/api/recon/probe-intel/status")
        data = resp.json()["data"]
        assert data["cached"] is False
        assert data["pcap_count"] == 1

    def test_status_returns_cached_after_scan(
        self, client, patch_probe, patch_tshark_output
    ):
        _write_pcap(patch_probe, "test.pcap")
        # Run a full analyse to populate cache
        probe_service_module.probe_service.analyse(limit=200)
        # Wait a moment and then do a analyse_with_progress to populate cache
        pcaps = probe_service_module.probe_service._find_pcaps()
        probe_service_module.probe_service.analyse_with_progress(pcaps, limit=200)

        resp = client.get("/api/recon/probe-intel/status")
        data = resp.json()["data"]
        assert data["cached"] is True
        assert data["stale"] is False
        assert data["result"] is not None
        assert data["result"]["summary"]["total_probes"] == 5

    def test_status_enriches_cached_result(
        self, client, patch_probe, patch_tshark_output, monkeypatch
    ):
        _write_pcap(patch_probe, "test.pcap")
        monkeypatch.setattr(
            probe_router_module,
            "load_real_data",
            lambda: {
                "aa:bb:cc:dd:ee:01": {
                    "ssid": "HomeNet",
                    "encryption": "WPA2",
                    "device_type": "router_ap",
                    "sources": ["wardrive"],
                },
            },
        )
        monkeypatch.setattr(
            probe_router_module.mac_lookup,
            "lookup",
            lambda value: (
                "Acme Wireless" if str(value).startswith("00:11:22") else "Unknown"
            ),
        )

        probe_service_module.probe_service.analyse(limit=200)
        resp = client.get("/api/recon/probe-intel/status")
        data = resp.json()["data"]

        assert data["cached"] is True
        assert data["result"]["ssids"][0]["name_shape"] is not None
        rich_client = next(
            c
            for c in data["result"]["clients"]
            if c["client_mac"] == "00:11:22:33:44:55"
        )
        assert rich_client["vendor"] == "Acme Wireless"

    def test_status_stale_after_new_pcap(
        self, client, patch_probe, patch_tshark_output
    ):
        _write_pcap(patch_probe, "test.pcap")
        pcaps = probe_service_module.probe_service._find_pcaps()
        probe_service_module.probe_service.analyse_with_progress(pcaps, limit=200)
        # Add new PCAP → signature changes → stale
        _write_pcap(patch_probe, "new_capture.pcap")
        resp = client.get("/api/recon/probe-intel/status")
        data = resp.json()["data"]
        assert data["cached"] is True
        assert data["stale"] is True

    def test_invalidate_cache(self, patch_probe, patch_tshark_output):
        _write_pcap(patch_probe, "test.pcap")
        pcaps = probe_service_module.probe_service._find_pcaps()
        probe_service_module.probe_service.analyse_with_progress(pcaps, limit=200)
        assert probe_service_module.probe_service._cache is not None
        probe_service_module.probe_service.invalidate_cache()
        assert probe_service_module.probe_service._cache is None
        assert probe_service_module.probe_service._cache_signature is None


# ---------------------------------------------------------------------------
# 5. POST /api/recon/probe-intel/scan
# ---------------------------------------------------------------------------


class TestProbeIntelScanEndpoint:
    def test_scan_no_pcaps(self, client, patch_probe):
        resp = client.post("/api/recon/probe-intel/scan")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["job_id"] is None
        assert data["pcap_count"] == 0

    def test_scan_starts_job(
        self, client, patch_probe, patch_tshark_output, monkeypatch
    ):
        _write_pcap(patch_probe, "test.pcap")
        # Mock start_multi_job to avoid real thread
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
            captured["meta"] = meta
            return "fake-job-id-123"

        monkeypatch.setattr(
            recon_jobs_module.job_manager, "start_multi_job", fake_start
        )

        resp = client.post("/api/recon/probe-intel/scan")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["job_id"] == "fake-job-id-123"
        assert data["pcap_count"] == 1
        assert captured["job_type"] == "probe_intel_scan"
        assert captured["total_steps"] == 1


# ---------------------------------------------------------------------------
# 6. analyse_with_progress
# ---------------------------------------------------------------------------


class TestProbeAnalyseWithProgress:
    def test_populates_cache(self, patch_probe, patch_tshark_output):
        _write_pcap(patch_probe, "test.pcap")
        pcaps = probe_service_module.probe_service._find_pcaps()
        result = probe_service_module.probe_service.analyse_with_progress(
            pcaps, limit=200
        )
        assert result["available"] is True
        assert result["summary"]["total_probes"] == 5
        assert probe_service_module.probe_service._cache is not None

    def test_emits_progress(self, patch_probe, patch_tshark_output):
        _write_pcap(patch_probe, "a.pcap")
        _write_pcap(patch_probe, "b.pcap")
        pcaps = probe_service_module.probe_service._find_pcaps()
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

        probe_service_module.probe_service.analyse_with_progress(
            pcaps,
            limit=200,
            emit=fake_emit,
            job=fake_job,
        )
        assert len(emissions) >= 2
        assert all(e[0] == "job_progress" for e in emissions)
        # Last emission should be 100%
        assert emissions[-1][1]["data"]["percentage"] == 100

    def test_no_tshark(self, patch_probe, monkeypatch):
        monkeypatch.setattr(
            probe_service_module.probe_service, "_check_tshark", lambda: None
        )
        result = probe_service_module.probe_service.analyse_with_progress([], limit=200)
        assert result["available"] is False

    def test_empty_pcaps(self, patch_probe, patch_tshark_output):
        result = probe_service_module.probe_service.analyse_with_progress([], limit=200)
        assert result["available"] is True
        assert result["summary"]["total_probes"] == 0
