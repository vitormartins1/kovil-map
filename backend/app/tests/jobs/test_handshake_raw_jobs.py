from app.jobs import handshake_raw_jobs


def _make_job(meta=None):
    return {
        "id": "job-raw-all",
        "status": "running",
        "meta": meta or {},
        "progress_data": {
            "current_step": 0,
            "total_steps": 0,
            "percentage": 0,
            "stage": "RUNNING",
            "extra": "",
            "items": [],
        },
    }


def test_start_raw_prepare_all_job_delegates_to_job_manager(monkeypatch):
    captured = {}

    def _start_multi_job(worker, job_type, total_steps, meta):
        captured["worker"] = worker
        captured["job_type"] = job_type
        captured["total_steps"] = total_steps
        captured["meta"] = meta
        return "job-123"

    monkeypatch.setattr(
        handshake_raw_jobs.job_manager,
        "start_multi_job",
        _start_multi_job,
    )

    job_id = handshake_raw_jobs.start_raw_prepare_all_job(
        "AA:BB:CC:DD:EE:FF",
        force=True,
        source_files=None,
        ssid_hint="SSID",
        total_steps=3,
    )
    assert job_id == "job-123"
    assert captured["job_type"] == "raw_prepare_all"
    assert captured["total_steps"] == 3
    assert captured["meta"]["bssid"] == "AA:BB:CC:DD:EE:FF"
    assert captured["meta"]["force"] is True


def test_raw_prepare_all_worker_handles_partial_success(monkeypatch):
    emitted = []
    reloaded = {"count": 0}

    def _emit(event, payload):
        emitted.append((event, payload))

    def _prepare(_bssid, **kwargs):
        progress = kwargs.get("progress_callback")
        progress(
            {
                "index": 1,
                "total": 2,
                "source_file": "raw_1.pcap",
                "status": "success",
                "valid_lines": 2,
                "added_lines": 2,
            }
        )
        progress(
            {
                "index": 2,
                "total": 2,
                "source_file": "raw_2.pcap",
                "status": "error",
                "reason": "no_valid_hash_lines",
            }
        )
        return {
            "status": "success_partial",
            "message": "partial",
            "canonical_hash": "hidden_aabbccddeeff__wdrs__.22000",
            "processed": 2,
            "succeeded": 1,
            "failed": 1,
            "items": [
                {"source_file": "raw_1.pcap", "status": "success"},
                {"source_file": "raw_2.pcap", "status": "error"},
            ],
        }

    monkeypatch.setattr(
        handshake_raw_jobs.rawsniffer_service,
        "prepare_canonical_hash_for_bssid",
        _prepare,
    )
    monkeypatch.setattr(
        handshake_raw_jobs,
        "reload_data",
        lambda: reloaded.__setitem__("count", reloaded["count"] + 1),
    )

    job = _make_job({"bssid": "AA:BB:CC:DD:EE:FF", "force": False})
    handshake_raw_jobs._raw_prepare_all_worker(job, _emit)

    assert reloaded["count"] == 1
    assert job["progress_data"]["stage"] == "PARTIAL"
    assert job["progress_data"]["percentage"] == 100
    assert job["progress_data"]["canonical_hash"] == "hidden_aabbccddeeff__wdrs__.22000"
    assert job["meta"]["raw_prepare_summary"]["status"] == "success_partial"
    assert any(event == "job_progress" for event, _ in emitted)
    assert ("data_update", "map_data") in emitted


def test_raw_prepare_all_worker_marks_failure_when_nothing_generated(monkeypatch):
    monkeypatch.setattr(
        handshake_raw_jobs.rawsniffer_service,
        "prepare_canonical_hash_for_bssid",
        lambda _bssid, **_kwargs: {
            "status": "error",
            "message": "No valid hash lines",
            "processed": 1,
            "succeeded": 0,
            "failed": 1,
        },
    )

    job = _make_job({"bssid": "AA:BB:CC:DD:EE:FF"})
    handshake_raw_jobs._raw_prepare_all_worker(job, lambda *_args: None)

    assert job["status"] == "failed"
    assert job["progress_data"]["stage"] == "ERROR"
    assert job["meta"]["raw_prepare_summary"]["status"] == "error"


def test_raw_prepare_all_worker_handles_up_to_date_without_reload(monkeypatch):
    reloaded = {"count": 0}
    monkeypatch.setattr(
        handshake_raw_jobs.rawsniffer_service,
        "prepare_canonical_hash_for_bssid",
        lambda _bssid, **_kwargs: {
            "status": "up_to_date",
            "message": "already up to date",
            "processed": 0,
            "succeeded": 0,
            "failed": 0,
            "canonical_hash": "hidden_aabbccddeeff__wdrs__.22000",
        },
    )
    monkeypatch.setattr(
        handshake_raw_jobs,
        "reload_data",
        lambda: reloaded.__setitem__("count", reloaded["count"] + 1),
    )

    job = _make_job({"bssid": "AA:BB:CC:DD:EE:FF"})
    handshake_raw_jobs._raw_prepare_all_worker(job, lambda *_args: None)

    assert reloaded["count"] == 0
    assert job["status"] == "running"
    assert job["progress_data"]["stage"] == "UP TO DATE"
    assert job["progress_data"]["percentage"] == 100


def test_raw_prepare_all_worker_handles_data_update_emit_exception(monkeypatch):
    emitted = []
    exception_count = {"emit": 0, "fire_and_forget": 0}

    def _emit_failing(event, payload):
        if event == "data_update":
            exception_count["emit"] += 1
            raise RuntimeError("WebSocket disconnected")
        emitted.append((event, payload))

    def _fire_and_forget_failing(event, payload):
        exception_count["fire_and_forget"] += 1
        raise RuntimeError("Fire and forget failed")

    monkeypatch.setattr(
        handshake_raw_jobs.rawsniffer_service,
        "prepare_canonical_hash_for_bssid",
        lambda _bssid, **_kwargs: {
            "status": "success",
            "processed": 1,
            "succeeded": 1,
            "failed": 0,
        },
    )
    monkeypatch.setattr(handshake_raw_jobs, "reload_data", lambda: None)
    monkeypatch.setattr(
        handshake_raw_jobs.job_manager,
        "_fire_and_forget_emit",
        _fire_and_forget_failing,
    )

    job = _make_job({"bssid": "AA:BB:CC:DD:EE:FF"})
    handshake_raw_jobs._raw_prepare_all_worker(job, _emit_failing)

    assert exception_count["emit"] == 1
    assert exception_count["fire_and_forget"] == 1
    assert job["progress_data"]["stage"] == "COMPLETED"
    assert job["progress_data"]["percentage"] == 100


def test_raw_prepare_all_worker_handles_reload_data_exception(monkeypatch):
    def _raise_reload():
        raise RuntimeError("Data reload failed")

    monkeypatch.setattr(
        handshake_raw_jobs.rawsniffer_service,
        "prepare_canonical_hash_for_bssid",
        lambda _bssid, **_kwargs: {
            "status": "success",
            "processed": 1,
            "succeeded": 1,
            "failed": 0,
        },
    )
    monkeypatch.setattr(handshake_raw_jobs, "reload_data", _raise_reload)

    job = _make_job({"bssid": "AA:BB:CC:DD:EE:FF"})
    handshake_raw_jobs._raw_prepare_all_worker(job, lambda *_args: None)

    # Job should still complete successfully even if reload fails
    assert job["progress_data"]["stage"] == "COMPLETED"
    assert job["progress_data"]["percentage"] == 100


def test_start_raw_prepare_all_job_calculates_steps_from_source_files(monkeypatch):
    captured = {}

    def _start_multi_job(worker, job_type, total_steps, meta):
        captured["total_steps"] = total_steps
        captured["meta"] = meta
        return "job-123"

    monkeypatch.setattr(
        handshake_raw_jobs.job_manager,
        "start_multi_job",
        _start_multi_job,
    )

    handshake_raw_jobs.start_raw_prepare_all_job(
        "AA:BB:CC:DD:EE:FF",
        source_files=["raw1.pcap", "raw2.pcap", "raw3.pcap"],
    )

    assert captured["total_steps"] == 3
    assert captured["meta"]["source_files"] == ["raw1.pcap", "raw2.pcap", "raw3.pcap"]
