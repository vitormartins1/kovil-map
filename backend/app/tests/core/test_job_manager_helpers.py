import asyncio
from datetime import datetime

import pytest

from app.core.job_manager import JobManager


@pytest.fixture
def manager():
    return JobManager()


def test_normalize_retention_value_defaults_on_invalid_env(manager):
    assert manager._normalize_retention_value("not-int", 10) == 10
    assert manager._normalize_retention_value("-5", 10) == 10
    assert manager._normalize_retention_value(None, 7) == 7


def test_parse_job_end_ts_handles_iso_date(manager):
    job = {"end_time": datetime.now().isoformat()}
    assert isinstance(manager._parse_job_end_ts(job), float)
    assert manager._parse_job_end_ts({"end_time": "not-a-date"}) is None
    assert manager._parse_job_end_ts({}) is None


def test_prune_jobs_removes_expired(monkeypatch):
    manager = JobManager()
    now = 1_000_000
    job_id = "old"
    manager.jobs[job_id] = {
        "status": "success",
        "end_time": (datetime.fromtimestamp(now - 10)).isoformat(),
    }
    manager.terminal_ttl_seconds = 5
    monkeypatch.setattr("app.core.job_manager.time.time", lambda: now)
    manager._prune_jobs()
    assert job_id not in manager.jobs


def test_prune_jobs_caps_by_max(monkeypatch):
    manager = JobManager()
    manager.terminal_ttl_seconds = 999
    now = 1_000_000
    manager.max_terminal_jobs = 1
    for idx in range(3):
        job_id = f"job-{idx}"
        manager.jobs[job_id] = {
            "status": "success",
            "end_time": (datetime.fromtimestamp(now - idx)).isoformat(),
        }
    monkeypatch.setattr("app.core.job_manager.time.time", lambda: now)
    manager._prune_jobs()
    assert len(manager.jobs) == 1


def test_decode_hashcat_hex_candidates_variants():
    manager = JobManager()
    text = "Result $HEX[70617373776f7264] done"
    assert "password" in manager._decode_hashcat_hex_candidates(text)
    malformed = "$HEX[abc]"  # odd number
    assert malformed in manager._decode_hashcat_hex_candidates(malformed)
    assert manager._decode_hashcat_hex_candidates("") == ""


def test_fire_and_forget_emit_logs(monkeypatch):
    jm = JobManager()
    called = []

    async def fake_callback(event_type, data):
        called.append((event_type, data))

    jm.event_callback = fake_callback
    loop = asyncio.new_event_loop()
    jm.main_loop = loop
    try:
        jm._fire_and_forget_emit("test", {"foo": "bar"})
        # Allow the future to execute
        loop.run_until_complete(asyncio.sleep(0))
    finally:
        loop.close()
    assert called == [("test", {"foo": "bar"})]
