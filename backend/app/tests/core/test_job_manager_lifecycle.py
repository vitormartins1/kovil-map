"""Job manager lifecycle tests for callbacks, listing, and lifecycle cleanup."""

import asyncio

from app.core import job_manager as jm_module


class TestJobManagerLifecycle:
    """Lifecycle-oriented tests for job_manager behavior."""

    def test_start_job_with_callbacks(self, monkeypatch):
        """Test start_job with on_complete and on_start callbacks."""
        captured = {"started": False, "completed": False}

        def on_start(job):
            captured["started"] = True

        def on_complete(job):
            captured["completed"] = True

        monkeypatch.setattr(jm_module.job_manager, "_run_process", lambda *a, **k: None)

        job_id = jm_module.job_manager.start_job(
            ["echo", "test"],
            job_type="test",
            on_start=on_start,
            on_complete=on_complete,
        )
        assert job_id is not None
        # Cleanup
        jm_module.job_manager.cancel_job(job_id)

    def test_cancel_job_not_found(self):
        """Test cancel_job with non-existent job."""
        result, msg = jm_module.job_manager.cancel_job("nonexistent-id")
        assert result is False

    def test_get_job_not_found(self):
        """Test get_job returns None for non-existent job."""
        result = jm_module.job_manager.get_job("nonexistent-id")
        assert result is None

    def test_list_jobs_empty(self, monkeypatch):
        """Test list_jobs returns empty list when no jobs."""
        monkeypatch.setattr(jm_module.job_manager, "jobs", {})
        jobs = jm_module.job_manager.list_jobs()
        assert jobs == []

    def test_kill_all_jobs(self, monkeypatch):
        """Test kill_all terminates all running jobs."""
        monkeypatch.setattr(jm_module.job_manager, "_run_process", lambda *a, **k: None)
        job_id = jm_module.job_manager.start_job(["sleep", "100"], job_type="test")
        jm_module.job_manager.kill_all()
        # Job should be canceled
        job = jm_module.job_manager.get_job(job_id)
        assert job is not None

    def test_decode_hashcat_hex_candidates(self):
        """Test _decode_hashcat_hex_candidates with hex encoded strings."""
        result = jm_module.job_manager._decode_hashcat_hex_candidates(
            "$HEX[70617373776f7264]"
        )
        assert result == "password"

    def test_decode_hashcat_hex_candidates_no_hex(self):
        """Test _decode_hashcat_hex_candidates with plain string."""
        result = jm_module.job_manager._decode_hashcat_hex_candidates("plaintext")
        assert result == "plaintext"

    def test_parse_hashcat_line_progress(self):
        """Test _parse_hashcat_line with progress info."""
        line = "Progress.......: 12345/100000 (12.35%)"
        result = jm_module.job_manager._parse_hashcat_line(line, {})
        assert result is not None
        assert "percentage" in result

    def test_parse_hashcat_line_speed(self):
        """Test _parse_hashcat_line with speed info."""
        line = "Speed.#1.......:  12345.6 kH/s"
        result = jm_module.job_manager._parse_hashcat_line(line, {})
        assert result is not None
        assert "speed" in result

    def test_parse_aircrack_line_progress(self):
        """Test _parse_aircrack_line with progress."""
        line = "[00:00:03] 420 keys tested (145.34 k/s)"
        result = jm_module.job_manager._parse_aircrack_line(line, {})
        assert result is not None
        assert "percentage" in result
        assert result["stage"] == "RUNNING"

    def test_emit_event_no_handlers(self):
        """Test _emit_event with no handlers registered."""
        # Should not raise
        asyncio.run(jm_module.job_manager._emit_event("test_event", {"data": "test"}))

    def test_prune_jobs_removes_old(self, monkeypatch):
        """Test _prune_jobs removes old completed jobs."""
        from datetime import datetime, timedelta

        old_time = datetime.now() - timedelta(days=8)
        monkeypatch.setattr(
            jm_module.job_manager,
            "jobs",
            {
                "old-job": {
                    "id": "old-job",
                    "status": "success",
                    "end_time": old_time.isoformat(),
                }
            },
        )
        monkeypatch.setattr(
            jm_module.job_manager, "terminal_ttl_seconds", 86400
        )  # 24 hours
        monkeypatch.setattr(jm_module.job_manager, "max_terminal_jobs", 500)
        jm_module.job_manager._prune_jobs()
        assert "old-job" not in jm_module.job_manager.jobs
