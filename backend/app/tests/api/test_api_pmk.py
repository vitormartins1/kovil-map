"""Tests for PMK Database (pmk router + pmk_service).

Covers:
  1. GET /api/pmk/databases
  2. GET /api/pmk/databases/{db_name}/stats
  3. POST /api/pmk/build
  4. POST /api/pmk/attack
  5. DELETE /api/pmk/databases/{db_name}
  6. PmkService internals: list_databases, get_database_stats, build_database,
     attack_with_pmk, delete_database, _db_path, _check_key_found
"""

from __future__ import annotations

import os
import subprocess

import pytest

from app.services import pmk_service as pmk_service_module

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_pcap(tmp_path, name="capture.pcap"):
    p = tmp_path / name
    p.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    return str(p)


def _write_wordlist(tmp_path, name="wordlist.txt"):
    p = tmp_path / name
    p.write_text("password123\ntest1234\n", encoding="utf-8")
    return str(p)


def _write_db(tmp_path, name="pmk_test.db"):
    p = tmp_path / name
    p.write_bytes(b"SQLite format 3\x00" + b"\x00" * 80)
    return str(p)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def pmk_dir(tmp_path, monkeypatch):
    """Redirect PMK_DIR to tmp_path for isolation."""
    pmk_path = tmp_path / "airolib"
    pmk_path.mkdir()
    monkeypatch.setattr(pmk_service_module, "PMK_DIR", str(pmk_path))
    monkeypatch.setattr(
        pmk_service_module.pmk_service,
        "_get_config",
        lambda: {"airolib_path": "airolib-ng", "aircrack_path": "aircrack-ng"},
    )
    monkeypatch.setattr(
        pmk_service_module.pmk_service,
        "_should_use_wsl",
        lambda binary_path: False,
    )
    return pmk_path


@pytest.fixture()
def patch_pcap_resolve(monkeypatch, tmp_path):
    """Patch PCAP resolution for attack tests."""
    pcap = _write_pcap(tmp_path)
    monkeypatch.setattr(
        pmk_service_module.pmk_service,
        "_pcap_search_roots",
        lambda: (str(tmp_path),),
    )
    monkeypatch.setattr(
        pmk_service_module,
        "resolve_pcap_reference",
        lambda filename, capture_id=None, raw_item_id=None, search_roots=None: {
            "path": pcap,
            "filename": filename,
            "basename": "capture",
        },
    )
    return tmp_path


# ---------------------------------------------------------------------------
# 1. GET /api/pmk/databases
# ---------------------------------------------------------------------------


class TestListDatabases:
    def test_empty(self, client, pmk_dir):
        resp = client.get("/api/pmk/databases")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data == []

    def test_with_databases(self, client, pmk_dir):
        (pmk_dir / "test1.db").write_bytes(b"\x00" * 100)
        (pmk_dir / "test2.db").write_bytes(b"\x00" * 200)
        (pmk_dir / "readme.txt").write_text("ignore me")
        resp = client.get("/api/pmk/databases")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert len(data) == 2
        names = [d["name"] for d in data]
        assert "test1.db" in names
        assert "test2.db" in names
        assert all("size_bytes" in d for d in data)

    def test_no_dir(self, client, monkeypatch):
        monkeypatch.setattr(pmk_service_module, "PMK_DIR", "/nonexistent/path")
        resp = client.get("/api/pmk/databases")
        assert resp.status_code == 200
        assert resp.json()["data"] == []


# ---------------------------------------------------------------------------
# 2. GET /api/pmk/databases/{db_name}/stats
# ---------------------------------------------------------------------------


class TestDatabaseStats:
    def test_not_found(self, client, pmk_dir):
        resp = client.get("/api/pmk/databases/nonexistent.db/stats")
        assert resp.status_code == 400

    def test_success(self, client, pmk_dir, monkeypatch):
        db_file = pmk_dir / "mydb.db"
        db_file.write_bytes(b"\x00" * 50)

        monkeypatch.setattr(
            subprocess,
            "run",
            lambda cmd, capture_output=False, text=False, timeout=None: type(
                "FakeResult",
                (),
                {"stdout": "ESSID: 1\nPasswd: 100\nPMK: 50", "stderr": ""},
            )(),
        )
        resp = client.get("/api/pmk/databases/mydb.db/stats")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["name"] == "mydb.db"
        assert "stats_raw" in data

    def test_airolib_not_found(self, client, pmk_dir, monkeypatch):
        db_file = pmk_dir / "mydb.db"
        db_file.write_bytes(b"\x00" * 50)

        def _raise_not_found(*a, **kw):
            raise FileNotFoundError("airolib-ng not found")

        monkeypatch.setattr(subprocess, "run", _raise_not_found)
        resp = client.get("/api/pmk/databases/mydb.db/stats")
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# 3. POST /api/pmk/build
# ---------------------------------------------------------------------------


class TestBuildDatabase:
    def test_missing_essid(self, client, pmk_dir):
        resp = client.post("/api/pmk/build", json={"essid": "", "wordlist": "/w.txt"})
        assert resp.status_code == 400

    def test_missing_wordlist(self, client, pmk_dir):
        resp = client.post("/api/pmk/build", json={"essid": "TestNet", "wordlist": ""})
        assert resp.status_code == 400

    def test_wordlist_not_found(self, client, pmk_dir):
        resp = client.post(
            "/api/pmk/build",
            json={"essid": "TestNet", "wordlist": "/nonexistent/wordlist.txt"},
        )
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["status"] == "error"
        assert "not found" in data["message"].lower()

    def test_success(self, client, pmk_dir, tmp_path, monkeypatch):
        wl = _write_wordlist(tmp_path)
        started_jobs = []

        def fake_start_job(command, job_type="generic", cwd=None, on_complete=None):
            started_jobs.append(
                {
                    "command": command,
                    "job_type": job_type,
                    "cwd": cwd,
                }
            )
            return "fake-job-id"

        monkeypatch.setattr(
            pmk_service_module.job_manager,
            "start_job",
            fake_start_job,
        )
        monkeypatch.setattr(
            pmk_service_module.history_service,
            "add_entry",
            lambda *a, **kw: "fake-entry-id",
        )

        resp = client.post(
            "/api/pmk/build",
            json={"essid": "MyNetwork", "wordlist": wl},
        )
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["status"] == "started"
        assert data["job_id"] == "fake-job-id"
        assert "pmk_MyNetwork.db" in data["db_name"]
        assert len(started_jobs) == 1
        assert started_jobs[0]["job_type"] == "pmk"

    def test_custom_db_name(self, client, pmk_dir, tmp_path, monkeypatch):
        wl = _write_wordlist(tmp_path)
        monkeypatch.setattr(
            pmk_service_module.job_manager,
            "start_job",
            lambda *a, **kw: "fake-job-id",
        )
        monkeypatch.setattr(
            pmk_service_module.history_service,
            "add_entry",
            lambda *a, **kw: "fake-entry-id",
        )
        resp = client.post(
            "/api/pmk/build",
            json={"essid": "Net", "wordlist": wl, "db_name": "custom"},
        )
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert "custom.db" in data["db_name"]


# ---------------------------------------------------------------------------
# 4. POST /api/pmk/attack
# ---------------------------------------------------------------------------


class TestPmkAttack:
    def test_missing_fields(self, client, pmk_dir):
        resp = client.post(
            "/api/pmk/attack",
            json={"bssid": "AA:BB:CC:DD:EE:01", "db_name": "test.db"},
        )
        assert resp.status_code == 400

    def test_db_not_found(self, client, pmk_dir, patch_pcap_resolve):
        resp = client.post(
            "/api/pmk/attack",
            json={
                "filename": "capture.pcap",
                "bssid": "AA:BB:CC:DD:EE:01",
                "db_name": "nonexistent.db",
            },
        )
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["status"] == "error"

    def test_success(self, client, pmk_dir, patch_pcap_resolve, monkeypatch):
        _write_db(pmk_dir, "attack.db")
        started_jobs = []

        def fake_start_job(command, job_type="generic", cwd=None, on_complete=None):
            started_jobs.append({"command": command, "job_type": job_type})
            return "attack-job-id"

        monkeypatch.setattr(
            pmk_service_module.job_manager,
            "start_job",
            fake_start_job,
        )
        monkeypatch.setattr(
            pmk_service_module.history_service,
            "add_entry",
            lambda *a, **kw: "entry-id",
        )

        resp = client.post(
            "/api/pmk/attack",
            json={
                "filename": "capture.pcap",
                "bssid": "AA:BB:CC:DD:EE:01",
                "db_name": "attack.db",
            },
        )
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["status"] == "started"
        assert data["job_id"] == "attack-job-id"
        assert len(started_jobs) == 1
        assert started_jobs[0]["job_type"] == "aircrack"
        # Verify -r flag is in command
        cmd_str = " ".join(started_jobs[0]["command"])
        assert "-r" in cmd_str
        assert "attack.db" in cmd_str


# ---------------------------------------------------------------------------
# 5. DELETE /api/pmk/databases/{db_name}
# ---------------------------------------------------------------------------


class TestDeleteDatabase:
    def test_not_found(self, client, pmk_dir):
        resp = client.delete("/api/pmk/databases/nonexistent.db")
        assert resp.status_code == 400

    def test_success(self, client, pmk_dir):
        db_file = pmk_dir / "delete_me.db"
        db_file.write_bytes(b"\x00" * 10)
        assert db_file.exists()

        resp = client.delete("/api/pmk/databases/delete_me.db")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["deleted"] == "delete_me.db"
        assert not db_file.exists()


# ---------------------------------------------------------------------------
# 6. PmkService internals
# ---------------------------------------------------------------------------


class TestPmkServiceInternals:
    def test_db_path_sanitization(self, pmk_dir):
        svc = pmk_service_module.pmk_service
        path = svc._db_path("my net/work.db")
        assert ".." not in path
        assert "/" not in os.path.basename(path) or os.sep == "/"
        assert path.endswith(".db")

    def test_db_path_appends_extension(self, pmk_dir):
        svc = pmk_service_module.pmk_service
        path = svc._db_path("testname")
        assert path.endswith("testname.db")

    def test_db_path_does_not_double_extension(self, pmk_dir):
        svc = pmk_service_module.pmk_service
        path = svc._db_path("testname.db")
        assert path.endswith("testname.db")
        assert not path.endswith(".db.db")

    def test_build_database_empty_essid(self, pmk_dir):
        svc = pmk_service_module.pmk_service
        result = svc.build_database("   ", "/some/wordlist.txt")
        assert result["status"] == "error"

    def test_build_database_missing_wordlist(self, pmk_dir):
        svc = pmk_service_module.pmk_service
        result = svc.build_database("TestNet", "/nonexistent/wl.txt")
        assert result["status"] == "error"

    def test_check_key_found_from_file(self, pmk_dir, tmp_path):
        svc = pmk_service_module.pmk_service
        key_file = str(tmp_path / "test.key")
        with open(key_file, "w") as f:
            f.write("supersecret\n")

        # Need HANDSHAKES_DIR to be writable
        hs_dir = tmp_path / "handshakes"
        hs_dir.mkdir()
        import app.services.pmk_service as _mod

        original = _mod.HANDSHAKES_DIR
        _mod.HANDSHAKES_DIR = str(hs_dir)
        try:
            result = svc._check_key_found({"logs": []}, key_file, "test_network")
            assert result is True
            cracked_file = hs_dir / "test_network.pcap.cracked"
            assert cracked_file.exists()
            assert cracked_file.read_text().strip() == "supersecret"
            assert not os.path.exists(key_file)
        finally:
            _mod.HANDSHAKES_DIR = original

    def test_check_key_found_from_logs(self, pmk_dir, tmp_path):
        svc = pmk_service_module.pmk_service
        key_file = str(tmp_path / "nofile.key")

        hs_dir = tmp_path / "handshakes"
        hs_dir.mkdir()
        import app.services.pmk_service as _mod

        original = _mod.HANDSHAKES_DIR
        _mod.HANDSHAKES_DIR = str(hs_dir)
        try:
            job = {
                "logs": [
                    "Reading packets...",
                    "KEY FOUND! [ mypassword123 ]",
                    "Master Key: ...",
                ]
            }
            result = svc._check_key_found(job, key_file, "target")
            assert result is True
            cracked_file = hs_dir / "target.pcap.cracked"
            assert cracked_file.exists()
            assert cracked_file.read_text().strip() == "mypassword123"
        finally:
            _mod.HANDSHAKES_DIR = original

    def test_check_key_not_found(self, pmk_dir, tmp_path):
        svc = pmk_service_module.pmk_service
        key_file = str(tmp_path / "nofile.key")
        job = {"logs": ["Reading packets...", "No matching networks."]}
        result = svc._check_key_found(job, key_file, "target")
        assert result is False

    def test_list_databases_nonexistent_dir(self, monkeypatch):
        svc = pmk_service_module.pmk_service
        monkeypatch.setattr(pmk_service_module, "PMK_DIR", "/nonexistent")
        assert svc.list_databases() == []

    def test_get_database_stats_timeout(self, pmk_dir, monkeypatch):
        db_file = pmk_dir / "timeout.db"
        db_file.write_bytes(b"\x00" * 50)

        def _raise_timeout(*a, **kw):
            raise subprocess.TimeoutExpired(cmd="airolib-ng", timeout=15)

        monkeypatch.setattr(subprocess, "run", _raise_timeout)
        result = pmk_service_module.pmk_service.get_database_stats("timeout.db")
        assert "error" in result
        assert "timed out" in result["error"].lower()


class TestPmkAttackInternals:
    def test_attack_pcap_not_found(self, pmk_dir, monkeypatch):
        _write_db(pmk_dir, "attack.db")
        monkeypatch.setattr(
            pmk_service_module,
            "resolve_pcap_reference",
            lambda *a, **kw: None,
        )
        svc = pmk_service_module.pmk_service
        result = svc.attack_with_pmk("missing.pcap", "AA:BB:CC:DD:EE:01", "attack.db")
        assert result["status"] == "error"
        assert "not found" in result["message"].lower()

    def test_attack_db_not_found(self, pmk_dir):
        svc = pmk_service_module.pmk_service
        result = svc.attack_with_pmk(
            "capture.pcap", "AA:BB:CC:DD:EE:01", "nonexistent.db"
        )
        assert result["status"] == "error"

    def test_delete_nonexistent(self, pmk_dir):
        svc = pmk_service_module.pmk_service
        result = svc.delete_database("ghost.db")
        assert "error" in result
