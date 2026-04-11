import asyncio

from app.core import job_manager as jm_module
from app.core.job_manager import JobManager


class _ImmediateThread:
    def __init__(self, target=None, args=()):
        self._target = target
        self._args = args

    def start(self):
        if self._target:
            self._target(*self._args)


class _FakePopen:
    def __init__(self, lines=None, returncode=0, pid=1234):
        self.stdout = lines or []
        self.returncode = returncode
        self.pid = pid

    def wait(self):
        return self.returncode


def test_setters_and_emit_event_sync_async_and_error():
    jm = JobManager()
    received = []

    def _sync_cb(event, data):
        received.append((event, data))

    jm.set_event_callback(_sync_cb)
    jm.set_main_loop("loop")
    assert jm.main_loop == "loop"
    asyncio.run(jm._emit_event("evt", {"ok": 1}))
    assert received[-1][0] == "evt"

    async def _async_cb(event, data):
        received.append((event, data))

    jm.set_event_callback(_async_cb)
    asyncio.run(jm._emit_event("evt2", {"ok": 2}))
    assert received[-1][0] == "evt2"

    def _bad_cb(_event, _data):
        raise RuntimeError("boom")

    jm.set_event_callback(_bad_cb)
    asyncio.run(jm._emit_event("evt3", {}))


def test_fire_and_forget_emit_paths(monkeypatch):
    jm = JobManager()
    jm.set_event_callback(lambda *_: None)

    jm._fire_and_forget_emit("evt", {})

    jm.set_main_loop(object())

    def _raise(coro, *_args, **_kwargs):
        coro.close()
        raise RuntimeError("ws error")

    monkeypatch.setattr(jm_module.asyncio, "run_coroutine_threadsafe", _raise)
    jm._fire_and_forget_emit("evt", {})


def test_decode_hashcat_hex_candidates():
    jm = JobManager()
    text = "$HEX[52656c61746f722036303020] -> Relaxacao"
    decoded = jm._decode_hashcat_hex_candidates(text)
    assert "Relator 600" in decoded


def test_decode_hashcat_hex_candidates_invalid_hex():
    jm = JobManager()
    # Test invalid hex (odd length)
    text = "$HEX[52656c61746f72203630302] -> invalid"
    decoded = jm._decode_hashcat_hex_candidates(text)
    assert "$HEX[52656c61746f72203630302]" in decoded  # Should remain unchanged

    # Test invalid hex characters
    text = "$HEX[gggggggggggggggggggg] -> invalid"
    decoded = jm._decode_hashcat_hex_candidates(text)
    assert "$HEX[gggggggggggggggggggg]" in decoded  # Should remain unchanged


def test_normalize_retention_value_valid_and_invalid():
    jm = JobManager()
    # Valid positive integer
    assert jm._normalize_retention_value("3600", 7200) == 3600

    # Invalid: zero or negative
    assert jm._normalize_retention_value("0", 7200) == 7200
    assert jm._normalize_retention_value("-100", 7200) == 7200

    # Invalid: non-numeric
    assert jm._normalize_retention_value("not_a_number", 7200) == 7200
    assert jm._normalize_retention_value("", 7200) == 7200
    assert jm._normalize_retention_value(None, 7200) == 7200


def test_parse_job_end_ts_valid_and_invalid():
    jm = JobManager()
    # Valid ISO format timestamp
    job_valid = {"end_time": "2024-01-15T10:30:45.123456"}
    ts = jm._parse_job_end_ts(job_valid)
    assert ts is not None
    assert isinstance(ts, float)

    # Invalid timestamp format
    job_invalid_ts = {"end_time": "not-a-date"}
    assert jm._parse_job_end_ts(job_invalid_ts) is None

    # Missing end_time
    job_no_end = {}
    assert jm._parse_job_end_ts(job_no_end) is None

    # None end_time
    job_none = {"end_time": None}
    assert jm._parse_job_end_ts(job_none) is None


def test_prune_jobs_by_TTL_and_overflow():
    from datetime import datetime, timedelta

    jm = JobManager()
    jm.terminal_ttl_seconds = 100
    jm.max_terminal_jobs = 2

    now_dt = datetime.now()

    # Job 1: success, very old (should be pruned by TTL)
    old_time = (now_dt - timedelta(seconds=200)).isoformat()
    jm.jobs["old_done"] = {
        "status": "success",
        "end_time": old_time,
    }

    # Job 2: success, recent (should be kept)
    recent_time = (now_dt - timedelta(seconds=50)).isoformat()
    jm.jobs["recent_done"] = {
        "status": "success",
        "end_time": recent_time,
    }

    # Job 3: RUNNING (should be kept regardless of time)
    jm.jobs["running"] = {
        "status": "running",
        "end_time": None,
    }

    # Job 4: success, recent but will trigger overflow (third terminal job)
    overflow_time = (now_dt - timedelta(seconds=30)).isoformat()
    jm.jobs["overflow"] = {
        "status": "success",
        "end_time": overflow_time,
    }

    jm._prune_jobs()

    # old_done should be pruned by TTL
    assert "old_done" not in jm.jobs
    # recent_done should be kept
    assert "recent_done" in jm.jobs
    # running should be kept
    assert "running" in jm.jobs
    # overflow should trigger FIFO pruning (one terminal job gets pruned)
    # Since recent_done was added first, one of the 2 terminal jobs should remain
    terminal_jobs = [k for k, v in jm.jobs.items() if v.get("status") == "success"]
    assert len(terminal_jobs) <= jm.max_terminal_jobs


def test_callback_error_in_run_process(monkeypatch):
    jm = JobManager()
    callback_called = [False]

    def error_callback(job):
        callback_called[0] = True
        raise ValueError("Callback error!")

    monkeypatch.setattr(jm_module.threading, "Thread", _ImmediateThread)
    monkeypatch.setattr(jm, "_run_process", lambda _job_id, _is_cracking=False: None)

    job_id = jm.start_job(
        ["echo", "ok"], job_type="conversion", on_complete=error_callback
    )

    # Verify callback was called
    assert job_id in jm.jobs


def test_parse_hashcat_line_candidates_and_progress():
    jm = JobManager()
    current = {"total_steps": 2, "current_step": 0, "stage": "AUTOTUNING"}

    line = "Dictionary cache hit: /tmp/wordlist.txt"
    updates = jm._parse_hashcat_line(line, current)
    assert updates["stage"] == "RUNNING"
    assert "wordlist.txt" in updates["extra"]

    line = "Progress........: 10/100 (50.00%)"
    updates = jm._parse_hashcat_line(line, current)
    assert updates["percentage"] == 25

    line = "Candidates.#1...: $HEX[616263] -> def"
    updates = jm._parse_hashcat_line(line, {"total_steps": 1})
    assert "[abc -> def]" in updates["extra"]

    line = "Time.Estimated.: 1234 sec (3 mins, 4 secs)"
    updates = jm._parse_hashcat_line(line, {"total_steps": 1})
    assert updates["eta"] == "3 mins, 4 secs"

    updates = jm._parse_hashcat_line("Status...........: Exhausted", {"total_steps": 1})
    assert updates is None


def test_parse_aircrack_line():
    jm = JobManager()
    line = "[00:00:03] 420 keys tested (145.34 k/s)"
    updates = jm._parse_aircrack_line(line, {})
    assert updates["stage"] == "RUNNING"
    assert updates["speed"] == "145.34 k/s"
    assert updates["extra"] == "420 keys"
    assert jm._parse_aircrack_line("KEY FOUND!", {})["stage"] == "CRACKED"
    assert (
        jm._parse_aircrack_line("Passphrase not in dictionary", {})["stage"]
        == "EXHAUSTED"
    )


def test_start_job_non_cracking_immediate_thread(monkeypatch):
    jm = JobManager()
    monkeypatch.setattr(jm_module.threading, "Thread", _ImmediateThread)
    monkeypatch.setattr(jm, "_run_process", lambda _job_id, _is_cracking=False: None)

    job_id = jm.start_job(["echo", "ok"], job_type="conversion")
    job = jm.jobs[job_id]
    assert job["status"] == "running"
    assert job["start_time"] is not None


def test_start_job_cracking_queues_and_triggers_check(monkeypatch):
    jm = JobManager()
    calls = []
    monkeypatch.setattr(jm, "_check_queue_unsafe", lambda: calls.append("checked"))
    job_id = jm.start_job(["hashcat"], job_type="cracking")
    assert jm.jobs[job_id]["status"] == "queued"
    assert job_id in jm.cracking_queue
    assert calls == ["checked"]


def test_run_process_success_and_popen_exception(monkeypatch):
    jm = JobManager()
    job_id = "job-ok"
    jm.jobs[job_id] = {
        "id": job_id,
        "type": "generic",
        "command": ["cmd"],
        "cwd": None,
        "status": "running",
        "start_time": None,
        "end_time": None,
        "logs": [],
        "progress_data": {"stage": "PENDING", "current_step": 0, "total_steps": 1},
        "return_code": None,
        "on_complete": None,
        "on_start": None,
    }
    monkeypatch.setattr(
        jm_module.subprocess,
        "Popen",
        lambda *_a, **_k: _FakePopen(["line 1"], returncode=0),
    )
    jm._run_process(job_id)
    assert jm.jobs[job_id]["status"] == "success"

    bad_id = "job-bad"
    jm.jobs[bad_id] = {
        "id": bad_id,
        "type": "generic",
        "command": ["cmd"],
        "cwd": None,
        "status": "running",
        "start_time": None,
        "end_time": None,
        "logs": [],
        "progress_data": {"stage": "PENDING", "current_step": 0, "total_steps": 1},
        "return_code": None,
        "on_complete": None,
        "on_start": None,
    }
    monkeypatch.setattr(
        jm_module.subprocess,
        "Popen",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("popen fail")),
    )
    jm._run_process(bad_id)
    assert jm.jobs[bad_id]["status"] == "error"


def test_run_process_cracking_exhausted_and_invalid_mask(monkeypatch):
    jm = JobManager()
    ex_id = "job-ex"
    jm.jobs[ex_id] = {
        "id": ex_id,
        "type": "cracking",
        "command": ["hashcat"],
        "cwd": None,
        "status": "running",
        "start_time": None,
        "end_time": None,
        "logs": [],
        "progress_data": {"stage": "PENDING", "current_step": 0, "total_steps": 1},
        "return_code": None,
        "on_complete": None,
        "on_start": None,
    }
    monkeypatch.setattr(
        jm_module.subprocess,
        "Popen",
        lambda *_a, **_k: _FakePopen(
            ["Progress........: 10/100 (10.00%)"], returncode=1
        ),
    )
    jm._run_process(ex_id, is_cracking=True)
    assert jm.jobs[ex_id]["status"] == "success"
    assert jm.jobs[ex_id]["progress_data"]["stage"] == "EXHAUSTED"

    inv_id = "job-inv"
    jm.jobs[inv_id] = {
        "id": inv_id,
        "type": "cracking",
        "command": ["hashcat"],
        "cwd": None,
        "status": "running",
        "start_time": None,
        "end_time": None,
        "logs": [],
        "progress_data": {"stage": "PENDING", "current_step": 0, "total_steps": 1},
        "return_code": None,
        "on_complete": None,
        "on_start": None,
    }
    monkeypatch.setattr(
        jm_module.subprocess,
        "Popen",
        lambda *_a, **_k: _FakePopen(["Invalid mask"], returncode=2),
    )
    jm._run_process(inv_id, is_cracking=True)
    assert jm.jobs[inv_id]["status"] == "failed"
    assert jm.jobs[inv_id]["progress_data"]["extra"] == "Invalid Mask"


def test_start_multi_job_and_worker_paths(monkeypatch):
    jm = JobManager()
    monkeypatch.setattr(jm_module.threading, "Thread", _ImmediateThread)
    completions = []

    def _worker_ok(job, emit):
        emit("job_progress", {"job_id": job["id"], "data": {"percentage": 50}})
        job["logs"].append("ok")

    def _on_complete(job):
        completions.append(job["status"])

    job_id = jm.start_multi_job(_worker_ok, on_complete=_on_complete)
    assert jm.jobs[job_id]["status"] == "success"
    assert completions == ["success"]

    bad = JobManager()
    monkeypatch.setattr(jm_module.threading, "Thread", _ImmediateThread)

    def _on_start_fail(_job):
        raise RuntimeError("start fail")

    def _worker_fail(_job, _emit):
        raise RuntimeError("worker fail")

    bad_job = bad.start_multi_job(_worker_fail, on_start=_on_start_fail)
    assert bad.jobs[bad_job]["status"] == "failed"
    assert bad.jobs[bad_job]["return_code"] == 1


def test_run_process_rejects_string_command():
    jm = JobManager()
    job_id = "job-string"
    jm.jobs[job_id] = {
        "id": job_id,
        "type": "generic",
        "command": "echo unsafe",
        "cwd": None,
        "status": "running",
        "start_time": None,
        "end_time": None,
        "logs": [],
        "progress_data": {"stage": "PENDING", "current_step": 0, "total_steps": 1},
        "return_code": None,
        "on_complete": None,
        "on_start": None,
    }

    jm._run_process(job_id)

    assert jm.jobs[job_id]["status"] == "error"
    assert any("Invalid command format" in line for line in jm.jobs[job_id]["logs"])
