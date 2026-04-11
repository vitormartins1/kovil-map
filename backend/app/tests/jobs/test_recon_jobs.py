from app.jobs import recon_jobs


def test_probe_intel_worker_stores_result_and_passes_parameters(monkeypatch):
    captured = {}

    def _analyse_with_progress(pcaps, limit, emit, job):
        captured["pcaps"] = pcaps
        captured["limit"] = limit
        captured["emit"] = emit
        captured["job"] = job
        return {"status": "ok", "items": 2}

    monkeypatch.setattr(
        recon_jobs.probe_service,
        "analyse_with_progress",
        _analyse_with_progress,
    )

    job = {"meta": {"pcaps": ["a.pcap", "b.pcap"], "limit": 25}}

    def emit(*_args, **_kwargs):
        return None

    recon_jobs._probe_intel_worker(job, emit)

    assert captured["pcaps"] == ["a.pcap", "b.pcap"]
    assert captured["limit"] == 25
    assert captured["emit"] is emit
    assert captured["job"] is job
    assert job["meta"]["result"] == {"status": "ok", "items": 2}


def test_start_probe_intel_job_returns_none_when_pcaps_is_empty():
    assert recon_jobs.start_probe_intel_job([]) is None


def test_start_probe_intel_job_delegates_to_job_manager(monkeypatch):
    captured = {}

    def _start_multi_job(worker, job_type, total_steps, meta):
        captured["worker"] = worker
        captured["job_type"] = job_type
        captured["total_steps"] = total_steps
        captured["meta"] = meta
        return "probe-job-1"

    monkeypatch.setattr(recon_jobs.job_manager, "start_multi_job", _start_multi_job)

    job_id = recon_jobs.start_probe_intel_job(["1.pcap", "2.pcap"], limit=321)

    assert job_id == "probe-job-1"
    assert captured["worker"] is recon_jobs._probe_intel_worker
    assert captured["job_type"] == "probe_intel_scan"
    assert captured["total_steps"] == 2
    assert captured["meta"] == {"pcaps": ["1.pcap", "2.pcap"], "limit": 321}


def test_deep_analysis_worker_stores_result_and_passes_parameters(monkeypatch):
    captured = {}

    def _analyse_with_progress(pcaps, limit, emit, job):
        captured["pcaps"] = pcaps
        captured["limit"] = limit
        captured["emit"] = emit
        captured["job"] = job
        return {"status": "ok", "findings": 7}

    monkeypatch.setattr(
        recon_jobs.packet_analysis_service,
        "analyse_with_progress",
        _analyse_with_progress,
    )

    job = {"meta": {"pcaps": ["x.pcap"], "limit": 15}}

    def emit(*_args, **_kwargs):
        return None

    recon_jobs._deep_analysis_worker(job, emit)

    assert captured["pcaps"] == ["x.pcap"]
    assert captured["limit"] == 15
    assert captured["emit"] is emit
    assert captured["job"] is job
    assert job["meta"]["result"] == {"status": "ok", "findings": 7}


def test_start_deep_analysis_job_returns_none_when_pcaps_is_empty():
    assert recon_jobs.start_deep_analysis_job([]) is None


def test_start_deep_analysis_job_delegates_to_job_manager(monkeypatch):
    captured = {}

    def _start_multi_job(worker, job_type, total_steps, meta):
        captured["worker"] = worker
        captured["job_type"] = job_type
        captured["total_steps"] = total_steps
        captured["meta"] = meta
        return "deep-job-1"

    monkeypatch.setattr(recon_jobs.job_manager, "start_multi_job", _start_multi_job)

    job_id = recon_jobs.start_deep_analysis_job(
        ["a.pcap", "b.pcap", "c.pcap"], limit=123
    )

    assert job_id == "deep-job-1"
    assert captured["worker"] is recon_jobs._deep_analysis_worker
    assert captured["job_type"] == "deep_analysis_scan"
    assert captured["total_steps"] == 3
    assert captured["meta"] == {"pcaps": ["a.pcap", "b.pcap", "c.pcap"], "limit": 123}
