import os


from app.jobs import fingerprint_jobs, rawsniffer_jobs


def make_job(files):
    return {
        "id": "job123",
        "meta": {"files_to_process": files},
        "progress_data": {
            "current_step": 0,
            "percentage": 0,
            "stage": "PENDING",
            "extra": "",
            "items": [],
        },
    }


class DummyFingerprintService:
    def __init__(self, results):
        self.results = results

    def extract(self, filename, force):
        return self.results.get(filename, {"status": "error", "message": "missing"})


class DummyCrackService:
    def __init__(self, resp):
        self.resp = resp

    def convert_pcap_now(self, filename):
        return self.resp


def test_fingerprint_worker_handles_skip_and_success(tmp_path):
    handshakes = tmp_path / "handshakes"
    handshakes.mkdir()
    details = handshakes / "capture.details"
    details.write_text("cached")
    job = make_job(["capture.pcap", "fresh.pcap"])

    events = []

    service = DummyFingerprintService(
        {
            "fresh.pcap": {"status": "success", "details_count": 4},
        }
    )

    def emit(event, payload):
        events.append((event, payload))

    fingerprint_jobs._fingerprint_worker_impl(
        job,
        emit,
        fingerprint_service=service,
        reload_data=lambda: None,
        handshakes_dir=str(handshakes),
    )

    assert any(
        item.get("status") == "SKIPPED" for item in job["progress_data"]["items"]
    )
    assert any(item.get("details_count") == 4 for item in job["progress_data"]["items"])
    assert any(event == "job_progress" for event, _ in events)


def test_rawsniffer_worker_enrichment_paths(monkeypatch):
    job = make_job(["capture.pcap"])
    events = []

    def emit(event, payload):
        events.append(payload)

    metadata_response = {
        "status": "success",
        "cached": False,
        "data": {"stats": {"networks_count": 1, "beacon_frames": 2, "eapol_frames": 1}},
    }

    monkeypatch.setattr(
        rawsniffer_jobs,
        "rawsniffer_service",
        type("Stub", (), {"extract_metadata": lambda *a, **k: metadata_response})(),
    )
    monkeypatch.setattr(
        rawsniffer_jobs,
        "crack_service",
        DummyCrackService({"status": "success", "output_file": "raw.22000"}),
    )

    rawsniffer_jobs._rawsniffer_worker_impl(
        job,
        emit,
        crack_service=rawsniffer_jobs.crack_service,
        reload_data=lambda: None,
        needs_hash_enrichment=lambda filename: True,
    )

    assert job["progress_data"]["enrichment"]["attempted"] == 1
    assert job["progress_data"]["enrichment"]["success"] == 1


def test_rawsniffer_worker_failure(monkeypatch):
    job = make_job(["missing.pcap"])
    events = []

    def emit(event, payload):
        events.append(payload)

    monkeypatch.setattr(
        rawsniffer_jobs,
        "rawsniffer_service",
        type(
            "Stub",
            (),
            {"extract_metadata": lambda *a, **k: {"status": "error", "message": "bad"}},
        )(),
    )

    rawsniffer_jobs._rawsniffer_worker_impl(
        job,
        emit,
        crack_service=rawsniffer_jobs.crack_service,
        reload_data=lambda: None,
        needs_hash_enrichment=lambda _: False,
    )
    assert job["progress_data"]["items"][0]["status"] == "FAILED"


def test_needs_hash_enrichment(tmp_path, monkeypatch):
    bruce = tmp_path / "bruce"
    handshakes = tmp_path / "handshakes"
    bruce.mkdir()
    handshakes.mkdir()
    pcap = bruce / "capture.pcap"
    pcap.write_text("x", encoding="utf-8")
    hash_path = handshakes / "capture.22000"
    hash_path.write_text("", encoding="utf-8")
    monkeypatch.setattr(rawsniffer_jobs, "BRUCE_PCAP_DIR", str(bruce))
    monkeypatch.setattr(rawsniffer_jobs, "HANDSHAKES_DIR", str(handshakes))

    assert rawsniffer_jobs._needs_hash_enrichment(str(pcap)) is True
    hash_path.unlink()
    assert rawsniffer_jobs._needs_hash_enrichment(str(pcap)) is True


def test_fingerprint_worker_failed_and_exception_paths(tmp_path, monkeypatch):
    handshakes = tmp_path / "handshakes"
    handshakes.mkdir()
    calls = []

    class FailingFingerprintService:
        def extract(self, filename, force):
            if filename == "raise.pcap":
                raise RuntimeError("boom")
            return {"status": "error", "message": "no details"}

    def emit(event, payload):
        if event == "data_update":
            raise RuntimeError("emit down")
        calls.append((event, payload))

    fallback = []
    monkeypatch.setattr(
        fingerprint_jobs.job_manager,
        "_fire_and_forget_emit",
        lambda event, payload: fallback.append((event, payload)),
    )

    job = {
        "id": "job-x",
        "meta": {"files_to_process": ["fail.pcap", "raise.pcap"]},
        "progress_data": {
            "current_step": 0,
            "percentage": 0,
            "stage": "PENDING",
            "extra": "",
            "items": [],
        },
    }
    fingerprint_jobs._fingerprint_worker_impl(
        job,
        emit,
        fingerprint_service=FailingFingerprintService(),
        reload_data=lambda: None,
        handshakes_dir=str(handshakes),
    )
    statuses = [item["status"] for item in job["progress_data"]["items"]]
    assert statuses == ["FAILED", "FAILED"]
    assert fallback == [("data_update", "map_data")]


def test_fingerprint_worker_reload_data_exception_is_ignored(tmp_path):
    handshakes = tmp_path / "handshakes"
    handshakes.mkdir()
    job = make_job(["ok.pcap"])

    class SuccessService:
        def extract(self, *_args, **_kwargs):
            return {"status": "success", "details_count": 1}

    events = []
    fingerprint_jobs._fingerprint_worker_impl(
        job,
        lambda event, payload: events.append((event, payload)),
        fingerprint_service=SuccessService(),
        reload_data=lambda: (_ for _ in ()).throw(RuntimeError("reload failed")),
        handshakes_dir=str(handshakes),
    )
    assert any(item["status"] == "SUCCESS" for item in job["progress_data"]["items"])


def test_fingerprint_worker_wrapper_delegates(monkeypatch):
    captured = {}

    def fake_impl(job, emit, **kwargs):
        captured["job"] = job
        captured["emit"] = emit
        captured["kwargs"] = kwargs
        return "ok"

    monkeypatch.setattr(fingerprint_jobs, "_fingerprint_worker_impl", fake_impl)
    result = fingerprint_jobs._fingerprint_worker({"id": "1"}, lambda *_: None)
    assert result == "ok"
    assert "fingerprint_service" in captured["kwargs"]
    assert "reload_data" in captured["kwargs"]
    assert "handshakes_dir" in captured["kwargs"]


def test_needs_hash_enrichment_additional_paths(tmp_path, monkeypatch):
    bruce = tmp_path / "bruce"
    handshakes = tmp_path / "handshakes"
    bruce.mkdir()
    handshakes.mkdir()
    pcap = bruce / "capture.pcap"
    hash_file = handshakes / "capture.22000"

    monkeypatch.setattr(rawsniffer_jobs, "BRUCE_PCAP_DIR", str(bruce))
    monkeypatch.setattr(rawsniffer_jobs, "HANDSHAKES_DIR", str(handshakes))

    assert rawsniffer_jobs._needs_hash_enrichment("capture.pcap") is False

    pcap.write_text("x", encoding="utf-8")
    hash_file.write_text("hash", encoding="utf-8")
    os.utime(pcap, (10, 10))
    os.utime(hash_file, (20, 20))
    assert rawsniffer_jobs._needs_hash_enrichment("capture.pcap") is False

    monkeypatch.setattr(
        rawsniffer_jobs.os.path,
        "getsize",
        lambda _path: (_ for _ in ()).throw(OSError("boom")),
    )
    assert rawsniffer_jobs._needs_hash_enrichment("capture.pcap") is True


def test_rawsniffer_worker_enrichment_failed_and_skipped(monkeypatch, tmp_path):
    monkeypatch.setattr(rawsniffer_jobs, "HANDSHAKES_DIR", str(tmp_path))

    responses = {
        "needs_fail.pcap": {
            "status": "success",
            "cached": False,
            "data": {"stats": {"eapol_frames": 1}},
        },
        "up_to_date.pcap": {
            "status": "success",
            "cached": False,
            "data": {"stats": {"eapol_frames": 1}},
        },
        "no_eapol.pcap": {
            "status": "success",
            "cached": False,
            "data": {"stats": {"eapol_frames": 0}},
        },
    }
    monkeypatch.setattr(
        rawsniffer_jobs,
        "rawsniffer_service",
        type(
            "Stub",
            (),
            {
                "extract_metadata": lambda _self, filename, force=False: responses[
                    filename
                ]
            },
        )(),
    )
    monkeypatch.setattr(
        rawsniffer_jobs,
        "crack_service",
        DummyCrackService({"status": "error", "message": "convert fail"}),
    )
    job = make_job(["needs_fail.pcap", "up_to_date.pcap", "no_eapol.pcap"])
    rawsniffer_jobs._rawsniffer_worker_impl(
        job,
        lambda *_args, **_kwargs: None,
        crack_service=rawsniffer_jobs.crack_service,
        reload_data=lambda: None,
        needs_hash_enrichment=lambda filename: filename == "needs_fail.pcap",
    )
    enrichment = job["progress_data"]["enrichment"]
    assert enrichment["attempted"] == 1
    assert enrichment["failed"] == 1
    assert enrichment["skipped"] == 2


def test_rawsniffer_worker_exception_and_fallback_emit(monkeypatch):
    job = make_job(["broken.pcap"])
    fallback = []

    monkeypatch.setattr(
        rawsniffer_jobs,
        "rawsniffer_service",
        type(
            "Stub",
            (),
            {
                "extract_metadata": lambda *_args, **_kwargs: (_ for _ in ()).throw(
                    RuntimeError("broken")
                )
            },
        )(),
    )
    monkeypatch.setattr(
        rawsniffer_jobs.job_manager,
        "_fire_and_forget_emit",
        lambda event, payload: fallback.append((event, payload)),
    )

    def emit(event, payload):
        if event == "data_update":
            raise RuntimeError("ws down")
        return None

    rawsniffer_jobs._rawsniffer_worker_impl(
        job,
        emit,
        crack_service=rawsniffer_jobs.crack_service,
        reload_data=lambda: None,
        needs_hash_enrichment=lambda _: False,
    )
    assert job["progress_data"]["items"][0]["status"] == "FAILED"
    assert fallback == [("data_update", "map_data")]


def test_rawsniffer_worker_wrapper_and_start_job(monkeypatch):
    captured = {}

    def fake_impl(job, emit, **kwargs):
        captured["kwargs"] = kwargs
        return "ok"

    monkeypatch.setattr(rawsniffer_jobs, "_rawsniffer_worker_impl", fake_impl)
    result = rawsniffer_jobs._rawsniffer_worker({"id": "1"}, lambda *_: None)
    assert result == "ok"
    assert "crack_service" in captured["kwargs"]
    assert "reload_data" in captured["kwargs"]
    assert "needs_hash_enrichment" in captured["kwargs"]

    assert rawsniffer_jobs.start_rawsniffer_job([], force=False) is None
    monkeypatch.setattr(
        rawsniffer_jobs.job_manager,
        "start_multi_job",
        lambda worker, job_type, total_steps, meta: "job-raw",
    )
    assert rawsniffer_jobs.start_rawsniffer_job(["a.pcap"], force=True) == "job-raw"
