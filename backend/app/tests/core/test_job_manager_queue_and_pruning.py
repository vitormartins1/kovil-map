from datetime import datetime, timedelta

from app.core.job_manager import JobManager


class _FakeChild:
    def kill(self):
        return None


class _FakeParent:
    def __init__(self, raise_on_kill=False):
        self.raise_on_kill = raise_on_kill

    def children(self, recursive=True):
        return [_FakeChild()]

    def kill(self):
        if self.raise_on_kill:
            raise RuntimeError("kill failed")
        return None


def test_cancel_job_from_queue():
    jm = JobManager()
    job_id = "job-1"
    jm.jobs[job_id] = {
        "id": job_id,
        "status": "queued",
        "logs": [],
        "progress_data": {},
    }
    jm.cracking_queue.append(job_id)

    success, message = jm.cancel_job(job_id)
    assert success is True
    assert "removed" in message.lower()
    assert jm.jobs[job_id]["status"] == "canceled"


def test_cancel_job_not_found():
    jm = JobManager()
    ok, msg = jm.cancel_job("missing")
    assert ok is False
    assert "not found" in msg.lower()


def test_cancel_job_active_process_ok_and_error(monkeypatch):
    jm = JobManager()
    job_id = "job-active"
    jm.jobs[job_id] = {
        "id": job_id,
        "status": "running",
        "logs": [],
        "progress_data": {},
    }
    jm.active_processes[job_id] = type("P", (), {"pid": 11})()

    monkeypatch.setattr(
        "app.core.job_manager.psutil.Process", lambda _pid: _FakeParent()
    )
    ok, msg = jm.cancel_job(job_id)
    assert ok is True
    assert "killed" in msg.lower()
    assert jm.jobs[job_id]["status"] == "canceled"

    jm.active_processes[job_id] = type("P", (), {"pid": 12})()
    monkeypatch.setattr(
        "app.core.job_manager.psutil.Process",
        lambda _pid: _FakeParent(raise_on_kill=True),
    )
    ok, msg = jm.cancel_job(job_id)
    assert ok is False
    assert "error killing" in msg.lower()


def test_get_job_strips_callbacks():
    jm = JobManager()
    job_id = "job-2"
    jm.jobs[job_id] = {
        "id": job_id,
        "status": "running",
        "logs": ["a", "b"],
        "progress_data": {},
        "on_complete": lambda *args, **kwargs: None,
        "on_start": lambda *args, **kwargs: None,
    }

    job = jm.get_job(job_id)
    assert "on_complete" not in job
    assert "on_start" not in job
    assert job["logs"] == ["a", "b"]


def test_get_job_none_and_log_truncation():
    jm = JobManager()
    assert jm.get_job("none") is None

    job_id = "job-log"
    jm.jobs[job_id] = {
        "id": job_id,
        "logs": [str(i) for i in range(30)],
        "progress_data": {},
    }
    job = jm.get_job(job_id)
    assert len(job["logs"]) == 20
    assert job["logs"][0] == "10"


def test_list_jobs():
    jm = JobManager()
    jm.jobs = {
        "a": {"id": "a", "logs": [], "progress_data": {}},
        "b": {"id": "b", "logs": [], "progress_data": {}},
    }
    jobs = jm.list_jobs()
    assert len(jobs) == 2


def test_kill_all_handles_exception(monkeypatch):
    jm = JobManager()
    jm.active_processes = {
        "a": type("P", (), {"pid": 21})(),
        "b": type("P", (), {"pid": 22})(),
    }

    def _fake_process(pid):
        return _FakeParent(raise_on_kill=(pid == 22))

    monkeypatch.setattr("app.core.job_manager.psutil.Process", _fake_process)
    jm.kill_all()
    assert jm.active_processes == {}


def test_prune_jobs_removes_expired_terminal_jobs():
    jm = JobManager()
    jm.max_terminal_jobs = 10
    jm.terminal_ttl_seconds = 1
    old_end = (datetime.now() - timedelta(seconds=10)).isoformat()

    jm.jobs = {
        "old-success": {
            "id": "old-success",
            "status": "success",
            "end_time": old_end,
            "logs": [],
            "progress_data": {},
        },
        "running": {
            "id": "running",
            "status": "running",
            "end_time": None,
            "logs": [],
            "progress_data": {},
        },
    }

    jm._prune_jobs()

    assert "old-success" not in jm.jobs
    assert "running" in jm.jobs


def test_prune_jobs_caps_terminal_jobs_count():
    jm = JobManager()
    jm.max_terminal_jobs = 2
    jm.terminal_ttl_seconds = 999999

    base = datetime.now()
    jm.jobs = {
        "j1": {
            "id": "j1",
            "status": "success",
            "end_time": (base - timedelta(seconds=30)).isoformat(),
            "logs": [],
            "progress_data": {},
        },
        "j2": {
            "id": "j2",
            "status": "failed",
            "end_time": (base - timedelta(seconds=20)).isoformat(),
            "logs": [],
            "progress_data": {},
        },
        "j3": {
            "id": "j3",
            "status": "canceled",
            "end_time": (base - timedelta(seconds=10)).isoformat(),
            "logs": [],
            "progress_data": {},
        },
    }

    jm._prune_jobs()

    assert "j1" not in jm.jobs
    assert "j2" in jm.jobs
    assert "j3" in jm.jobs
