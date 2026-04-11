"""Tests for WPS Attack (wps router + wps_service).

Covers:
  1. POST /api/wps/attack – validation and happy-path
  2. WpsService internals: start_attack, _parse_pin
"""

from __future__ import annotations

import pytest

from app.services import wps_service as wps_service_module
from app.services.wps_service import WpsService


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def wps_env(monkeypatch):
    """Patch config and WSL for isolation."""
    monkeypatch.setattr(
        wps_service_module.wps_service, "_get_config",
        lambda: {"reaver_path": "reaver", "bully_path": "bully"},
    )
    monkeypatch.setattr(
        wps_service_module.wps_service, "_should_use_wsl",
        lambda binary_path: False,
    )


@pytest.fixture()
def fake_job_start(monkeypatch):
    """Capture job_manager.start_job calls and return a fake job_id."""
    calls = []

    def _start_job(cmd_args, job_type=None, cwd=None, on_complete=None):
        calls.append({
            "cmd_args": cmd_args,
            "job_type": job_type,
            "cwd": cwd,
            "on_complete": on_complete,
        })
        return "fake-wps-job-id"

    monkeypatch.setattr(wps_service_module, "job_manager", type("FakeJM", (), {"start_job": staticmethod(_start_job)})())
    return calls


@pytest.fixture()
def fake_history(monkeypatch):
    """Stub history_service to avoid side-effects."""
    monkeypatch.setattr(
        wps_service_module, "history_service",
        type("FakeHS", (), {
            "add_entry": staticmethod(lambda *a, **kw: "fake-entry-id"),
            "update_entry": staticmethod(lambda *a, **kw: None),
        })(),
    )


# ---------------------------------------------------------------------------
# 1. POST /api/wps/attack – Router-level tests
# ---------------------------------------------------------------------------


class TestWpsAttackEndpoint:
    def test_missing_bssid(self, client):
        resp = client.post("/api/wps/attack", json={
            "bssid": "",
            "channel": "6",
            "interface": "wlan0mon",
        })
        assert resp.status_code == 400

    def test_missing_channel(self, client):
        resp = client.post("/api/wps/attack", json={
            "bssid": "AA:BB:CC:DD:EE:FF",
            "channel": "",
            "interface": "wlan0mon",
        })
        assert resp.status_code == 400

    def test_missing_interface(self, client):
        resp = client.post("/api/wps/attack", json={
            "bssid": "AA:BB:CC:DD:EE:FF",
            "channel": "6",
            "interface": "",
        })
        assert resp.status_code == 400

    def test_missing_fields_entirely(self, client):
        resp = client.post("/api/wps/attack", json={})
        assert resp.status_code == 422

    def test_success_reaver(self, client, wps_env, fake_job_start, fake_history):
        resp = client.post("/api/wps/attack", json={
            "bssid": "AA:BB:CC:DD:EE:FF",
            "channel": "6",
            "interface": "wlan0mon",
            "tool": "reaver",
        })
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["status"] == "started"
        assert data["job_id"] == "fake-wps-job-id"
        assert data["tool"] == "reaver"

    def test_success_bully(self, client, wps_env, fake_job_start, fake_history):
        resp = client.post("/api/wps/attack", json={
            "bssid": "AA:BB:CC:DD:EE:FF",
            "channel": "11",
            "interface": "wlan0mon",
            "tool": "bully",
        })
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["status"] == "started"
        assert data["tool"] == "bully"

    def test_pixie_dust(self, client, wps_env, fake_job_start, fake_history):
        resp = client.post("/api/wps/attack", json={
            "bssid": "AA:BB:CC:DD:EE:FF",
            "channel": "1",
            "interface": "wlan0mon",
            "pixie_dust": True,
        })
        assert resp.status_code == 200
        cmd = fake_job_start[0]["cmd_args"]
        assert "-K" in cmd

    def test_with_delay(self, client, wps_env, fake_job_start, fake_history):
        resp = client.post("/api/wps/attack", json={
            "bssid": "AA:BB:CC:DD:EE:FF",
            "channel": "6",
            "interface": "wlan0mon",
            "delay": 5,
        })
        assert resp.status_code == 200
        cmd = fake_job_start[0]["cmd_args"]
        assert "-d" in cmd
        assert "5" in cmd


# ---------------------------------------------------------------------------
# 2. WpsService internals
# ---------------------------------------------------------------------------


class TestWpsServiceStartAttack:
    def test_empty_bssid(self, wps_env):
        svc = wps_service_module.wps_service
        result = svc.start_attack("", "6", "wlan0mon")
        assert result["status"] == "error"
        assert "BSSID" in result["message"]

    def test_empty_channel(self, wps_env):
        svc = wps_service_module.wps_service
        result = svc.start_attack("AA:BB:CC:DD:EE:FF", "", "wlan0mon")
        assert result["status"] == "error"
        assert "Channel" in result["message"]

    def test_empty_interface(self, wps_env):
        svc = wps_service_module.wps_service
        result = svc.start_attack("AA:BB:CC:DD:EE:FF", "6", "")
        assert result["status"] == "error"
        assert "Interface" in result["message"]

    def test_unsupported_tool(self, wps_env):
        svc = wps_service_module.wps_service
        result = svc.start_attack("AA:BB:CC:DD:EE:FF", "6", "wlan0mon", tool="invalid")
        assert result["status"] == "error"
        assert "Unsupported" in result["message"]

    def test_reaver_command_structure(self, wps_env, fake_job_start, fake_history):
        svc = wps_service_module.wps_service
        result = svc.start_attack("AA:BB:CC:DD:EE:FF", "6", "wlan0mon", tool="reaver")
        assert result["status"] == "started"
        cmd = fake_job_start[0]["cmd_args"]
        assert cmd[0] == "reaver"
        assert "-i" in cmd
        assert "wlan0mon" in cmd
        assert "-b" in cmd
        assert "AA:BB:CC:DD:EE:FF" in cmd
        assert "-c" in cmd
        assert "6" in cmd
        assert "-vv" in cmd
        assert fake_job_start[0]["job_type"] == "wps"

    def test_bully_command_structure(self, wps_env, fake_job_start, fake_history):
        svc = wps_service_module.wps_service
        result = svc.start_attack("AA:BB:CC:DD:EE:FF", "11", "wlan0mon", tool="bully")
        assert result["status"] == "started"
        cmd = fake_job_start[0]["cmd_args"]
        assert cmd[0] == "bully"
        assert "-b" in cmd
        assert "-c" in cmd
        assert "wlan0mon" in cmd

    def test_reaver_pixie_dust_flag(self, wps_env, fake_job_start, fake_history):
        svc = wps_service_module.wps_service
        svc.start_attack("AA:BB:CC:DD:EE:FF", "6", "wlan0mon", tool="reaver", pixie_dust=True)
        cmd = fake_job_start[0]["cmd_args"]
        assert "-K" in cmd

    def test_bully_pixie_dust_flag(self, wps_env, fake_job_start, fake_history):
        svc = wps_service_module.wps_service
        svc.start_attack("AA:BB:CC:DD:EE:FF", "6", "wlan0mon", tool="bully", pixie_dust=True)
        cmd = fake_job_start[0]["cmd_args"]
        assert "-d" in cmd

    def test_reaver_delay(self, wps_env, fake_job_start, fake_history):
        svc = wps_service_module.wps_service
        svc.start_attack("AA:BB:CC:DD:EE:FF", "6", "wlan0mon", delay=3)
        cmd = fake_job_start[0]["cmd_args"]
        assert "-d" in cmd
        idx = cmd.index("-d")
        assert cmd[idx + 1] == "3"

    def test_bully_delay(self, wps_env, fake_job_start, fake_history):
        svc = wps_service_module.wps_service
        svc.start_attack("AA:BB:CC:DD:EE:FF", "6", "wlan0mon", tool="bully", delay=2)
        cmd = fake_job_start[0]["cmd_args"]
        assert "--pin-delay" in cmd
        idx = cmd.index("--pin-delay")
        assert cmd[idx + 1] == "2"

    def test_extra_args_sanitized(self, wps_env, fake_job_start, fake_history):
        svc = wps_service_module.wps_service
        svc.start_attack(
            "AA:BB:CC:DD:EE:FF", "6", "wlan0mon",
            extra_args=["--no-nacks", "; rm -rf /", "--timeout=30"]
        )
        cmd = fake_job_start[0]["cmd_args"]
        assert "--no-nacks" in cmd
        assert "--timeout=30" in cmd
        assert "; rm -rf /" not in cmd


class TestWpsServiceOnComplete:
    def test_on_complete_cracked(self, wps_env, fake_job_start, fake_history):
        svc = wps_service_module.wps_service
        svc.start_attack("AA:BB:CC:DD:EE:FF", "6", "wlan0mon")
        on_complete = fake_job_start[0]["on_complete"]
        job = {
            "return_code": 0,
            "logs": ["[+] WPS PIN: '12345678'"],
            "progress_data": {},
        }
        on_complete(job)
        assert job["progress_data"]["stage"] == "CRACKED"
        assert job["progress_data"]["pin"] == "12345678"

    def test_on_complete_success_no_pin(self, wps_env, fake_job_start, fake_history):
        svc = wps_service_module.wps_service
        svc.start_attack("AA:BB:CC:DD:EE:FF", "6", "wlan0mon")
        on_complete = fake_job_start[0]["on_complete"]
        job = {"return_code": 0, "logs": [], "progress_data": {}}
        on_complete(job)
        assert job["progress_data"]["stage"] == "COMPLETE"

    def test_on_complete_failed(self, wps_env, fake_job_start, fake_history):
        svc = wps_service_module.wps_service
        svc.start_attack("AA:BB:CC:DD:EE:FF", "6", "wlan0mon")
        on_complete = fake_job_start[0]["on_complete"]
        job = {"return_code": 1, "logs": [], "progress_data": {}}
        on_complete(job)
        assert job["progress_data"]["stage"] == "FAILED"


class TestWpsParsePin:
    def setup_method(self):
        self.svc = WpsService()

    def test_reaver_format(self):
        job = {"logs": ["[+] WPS PIN: '12345678'"]}
        assert self.svc._parse_pin(job) == "12345678"

    def test_reaver_format_no_quotes(self):
        job = {"logs": ["[+] WPS PIN: 12345678"]}
        assert self.svc._parse_pin(job) == "12345678"

    def test_pin_found_format(self):
        job = {"logs": ["Pin found: 87654321"]}
        assert self.svc._parse_pin(job) == "87654321"

    def test_bracket_pin_format(self):
        job = {"logs": ["[PIN] 11223344"]}
        assert self.svc._parse_pin(job) == "11223344"

    def test_no_pin(self):
        job = {"logs": ["[!] WPS transaction failed", "Timeout reached"]}
        assert self.svc._parse_pin(job) is None

    def test_empty_logs(self):
        job = {"logs": []}
        assert self.svc._parse_pin(job) is None

    def test_no_logs_key(self):
        job = {}
        assert self.svc._parse_pin(job) is None

    def test_four_digit_pin(self):
        job = {"logs": ["[+] WPS PIN: '1234'"]}
        assert self.svc._parse_pin(job) == "1234"
