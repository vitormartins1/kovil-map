"""Tests for job manager parsers and multi-job control paths."""

from app.core import job_manager as jm_module


class TestJobManagerParsersAndMultiFlow:
    """Additional parser and multi-job scenarios for job_manager."""

    def test_start_multi_job(self, monkeypatch):
        """Test start_multi_job."""
        monkeypatch.setattr(
            jm_module.job_manager, "_run_multi_worker", lambda *a, **k: None
        )
        job_id = jm_module.job_manager.start_multi_job(
            lambda job, emit: None,
            job_type="conversion_multi",
            total_steps=5,
        )
        assert job_id is not None
        job = jm_module.job_manager.get_job(job_id)
        assert job["type"] == "conversion_multi"
        assert job["progress_data"]["total_steps"] == 5
        jm_module.job_manager.cancel_job(job_id)

    def test_parse_hashcat_line_status(self):
        """Test _parse_hashcat_line with status."""
        line = "Status...........: Running"
        result = jm_module.job_manager._parse_hashcat_line(line, {})
        assert result is not None
        assert result["stage"] == "RUNNING"

    def test_parse_hashcat_line_speed(self):
        """Test _parse_hashcat_line with speed."""
        line = "Speed.#1.........: 12345.6 kH/s"
        result = jm_module.job_manager._parse_hashcat_line(line, {})
        assert result is not None
        assert "12345.6 kH/s" in result["speed"]

    def test_parse_hashcat_line_candidates(self):
        """Test _parse_hashcat_line with candidates."""
        line = "Candidates.#1....: password -> secret"
        result = jm_module.job_manager._parse_hashcat_line(line, {})
        assert result is not None
        assert "extra" in result

    def test_parse_aircrack_line_key_found(self):
        """Test _parse_aircrack_line with key found."""
        line = "KEY FOUND! [password]"
        result = jm_module.job_manager._parse_aircrack_line(line, {})
        assert result is not None
        assert result["stage"] == "CRACKED"

    def test_parse_aircrack_line_exhausted(self):
        """Test _parse_aircrack_line with exhausted."""
        line = "Passphrase not in dictionary"
        result = jm_module.job_manager._parse_aircrack_line(line, {})
        assert result is not None
        assert result["stage"] == "EXHAUSTED"

    def test_cancel_job_from_queue(self, monkeypatch):
        """Test cancel_job removes job from queue."""
        monkeypatch.setattr(jm_module.job_manager, "_run_process", lambda *a, **k: None)
        monkeypatch.setattr(
            jm_module.job_manager, "_fire_and_forget_emit", lambda *a, **k: None
        )
        monkeypatch.setattr(jm_module.job_manager, "_prune_jobs", lambda: None)
        monkeypatch.setattr(jm_module.job_manager, "_check_queue_unsafe", lambda: None)

        job_id = jm_module.job_manager.start_job(["echo", "test"], job_type="cracking")
        result, msg = jm_module.job_manager.cancel_job(job_id)
        assert result is True

    def test_kill_all_no_processes(self):
        """Test kill_all with no active processes."""
        jm_module.job_manager.kill_all()
        assert len(jm_module.job_manager.active_processes) == 0
