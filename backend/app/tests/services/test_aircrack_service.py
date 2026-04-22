from app.services import aircrack_service as ac_module


def test_aircrack_process_success_writes_cracked(tmp_path, monkeypatch):
    monkeypatch.setattr(ac_module, "HANDSHAKES_DIR", str(tmp_path))

    key_file = tmp_path / "test.key"
    key_file.write_text("password123")

    service = ac_module.AircrackService()
    job = {"id": "1", "logs": []}
    found = service.process_success(job, str(key_file), "sample")

    cracked_path = tmp_path / "sample.pcap.cracked"
    assert found is True
    assert cracked_path.exists()
    assert cracked_path.read_text() == "password123"


def test_aircrack_run_attack_requires_wordlist(tmp_path, monkeypatch):
    monkeypatch.setattr(ac_module, "HANDSHAKES_DIR", str(tmp_path))
    service = ac_module.AircrackService()
    monkeypatch.setattr(
        service, "_get_config", lambda: {"aircrack_path": "aircrack-ng"}
    )

    result = service.run_attack("any.pcap", "AA:BB:CC:DD:EE:FF", wordlist_path=None)
    assert result["status"] == "error"
    assert "wordlist" in result["message"].lower()


def test_aircrack_run_attack_missing_pcap(tmp_path, monkeypatch):
    monkeypatch.setattr(ac_module, "HANDSHAKES_DIR", str(tmp_path))
    service = ac_module.AircrackService()
    monkeypatch.setattr(
        service, "_get_config", lambda: {"aircrack_path": "aircrack-ng"}
    )

    result = service.run_attack(
        "missing.pcap", "AA:BB:CC:DD:EE:FF", wordlist_path="/tmp/wl.txt"
    )
    assert result["status"] == "error"
    assert "PCAP file not found" in result["message"]


def test_aircrack_run_attack_uses_capture_id_resolution(tmp_path, monkeypatch):
    hand_dir = tmp_path / "handshakes"
    hand_dir.mkdir()
    external_dir = tmp_path / "external"
    external_dir.mkdir()
    external_pcap = external_dir / "Alias.pcap"
    external_pcap.write_text("pcap", encoding="utf-8")

    monkeypatch.setattr(ac_module, "HANDSHAKES_DIR", str(hand_dir))
    service = ac_module.AircrackService()
    monkeypatch.setattr(
        service, "_get_config", lambda: {"aircrack_path": "aircrack-ng"}
    )
    monkeypatch.setattr(service, "_should_use_wsl", lambda _bin: False)
    monkeypatch.setattr(
        ac_module,
        "resolve_pcap_reference",
        lambda filename, capture_id=None, raw_item_id=None, search_roots=None: {
            "path": str(external_pcap),
            "filename": "Alias.pcap",
            "capture_id": capture_id,
            "raw_item_id": raw_item_id,
            "basename": "Alias",
        },
    )
    monkeypatch.setattr(
        ac_module.history_service, "add_entry", lambda *a, **k: "entry-cap"
    )
    monkeypatch.setattr(ac_module.history_service, "update_entry", lambda *a, **k: None)

    captured = {}

    def _fake_start_job(command, **kwargs):
        captured["command"] = command
        return "job-cap"

    monkeypatch.setattr(ac_module.job_manager, "start_job", _fake_start_job)

    result = service.run_attack(
        None,
        "AA:BB:CC:DD:EE:FF",
        wordlist_path="/tmp/wl.txt",
        capture_id="cap-123",
    )
    assert result == {"status": "started", "job_id": "job-cap"}
    assert str(external_pcap) in captured["command"]
    assert str(external_dir / "Alias.key") in captured["command"]


def test_aircrack_run_attack_uses_raw_item_id_resolution(tmp_path, monkeypatch):
    hand_dir = tmp_path / "handshakes"
    hand_dir.mkdir()
    external_dir = tmp_path / "raw"
    external_dir.mkdir()
    external_pcap = external_dir / "raw_1.pcap"
    external_pcap.write_text("pcap", encoding="utf-8")

    monkeypatch.setattr(ac_module, "HANDSHAKES_DIR", str(hand_dir))
    service = ac_module.AircrackService()
    monkeypatch.setattr(
        service, "_get_config", lambda: {"aircrack_path": "aircrack-ng"}
    )
    monkeypatch.setattr(service, "_should_use_wsl", lambda _bin: False)
    monkeypatch.setattr(
        ac_module,
        "resolve_pcap_reference",
        lambda filename, capture_id=None, raw_item_id=None, search_roots=None: {
            "path": str(external_pcap),
            "filename": "raw_1.pcap",
            "capture_id": capture_id,
            "raw_item_id": raw_item_id,
            "basename": "raw_1",
        },
    )
    monkeypatch.setattr(
        ac_module.history_service, "add_entry", lambda *a, **k: "entry-raw"
    )
    monkeypatch.setattr(ac_module.history_service, "update_entry", lambda *a, **k: None)

    captured = {}

    def _fake_start_job(command, **kwargs):
        captured["command"] = command
        return "job-raw"

    monkeypatch.setattr(ac_module.job_manager, "start_job", _fake_start_job)

    result = service.run_attack(
        None,
        "AA:BB:CC:DD:EE:FF",
        wordlist_path="/tmp/wl.txt",
        raw_item_id="raw::pcap::abc123",
    )
    assert result == {"status": "started", "job_id": "job-raw"}
    assert str(external_pcap) in captured["command"]
    assert str(hand_dir / "raw_1.key") in captured["command"]


def test_aircrack_run_attack_starts_job_and_on_complete_success(tmp_path, monkeypatch):
    monkeypatch.setattr(ac_module, "HANDSHAKES_DIR", str(tmp_path))
    pcap_name = "sample.pcap"
    (tmp_path / pcap_name).write_text("pcap", encoding="utf-8")
    key_path = tmp_path / "sample.key"
    key_path.write_text("superpass", encoding="utf-8")

    service = ac_module.AircrackService()
    monkeypatch.setattr(
        service, "_get_config", lambda: {"aircrack_path": "aircrack-ng"}
    )
    monkeypatch.setattr(service, "_should_use_wsl", lambda _bin: False)

    update_calls = []
    monkeypatch.setattr(
        ac_module.history_service, "add_entry", lambda *a, **k: "entry-1"
    )
    monkeypatch.setattr(
        ac_module.history_service,
        "update_entry",
        lambda *a, **k: update_calls.append((a, k)),
    )
    monkeypatch.setattr("app.services.data_loader.reload_data", lambda: None)

    captured = {}

    def _fake_start_job(
        command, job_type="generic", cwd=None, on_complete=None, on_start=None
    ):
        captured["command"] = command
        captured["job_type"] = job_type
        captured["cwd"] = cwd
        captured["on_complete"] = on_complete
        captured["on_start"] = on_start
        return "job-123"

    monkeypatch.setattr(ac_module.job_manager, "start_job", _fake_start_job)

    result = service.run_attack(
        pcap_name, "AA:BB:CC:DD:EE:FF", wordlist_path="/tmp/wl.txt"
    )
    assert result == {"status": "started", "job_id": "job-123"}
    assert captured["job_type"] == "aircrack"
    assert captured["command"][0] == "aircrack-ng"
    assert "-w" in captured["command"]

    # Simula finalizacao do job e valida fluxo CRACKED
    job = {"id": "job-123", "logs": [], "progress_data": {"stage": "RUNNING"}}
    captured["on_complete"](job)
    assert job["progress_data"]["stage"] == "CRACKED"
    assert (tmp_path / "sample.pcap.cracked").exists()
    assert len(update_calls) == 1
    assert update_calls[0][0][2] == "CRACKED"


def test_aircrack_run_attack_on_complete_exhausted(tmp_path, monkeypatch):
    monkeypatch.setattr(ac_module, "HANDSHAKES_DIR", str(tmp_path))
    pcap_name = "sample2.pcap"
    (tmp_path / pcap_name).write_text("pcap", encoding="utf-8")

    service = ac_module.AircrackService()
    monkeypatch.setattr(
        service, "_get_config", lambda: {"aircrack_path": "aircrack-ng"}
    )
    monkeypatch.setattr(service, "_should_use_wsl", lambda _bin: False)

    updates = []
    monkeypatch.setattr(
        ac_module.history_service, "add_entry", lambda *a, **k: "entry-2"
    )
    monkeypatch.setattr(
        ac_module.history_service, "update_entry", lambda *a, **k: updates.append(a)
    )

    captured = {}

    def _fake_start_job(
        command, job_type="generic", cwd=None, on_complete=None, on_start=None
    ):
        captured["on_complete"] = on_complete
        return "job-999"

    monkeypatch.setattr(ac_module.job_manager, "start_job", _fake_start_job)
    service.run_attack(pcap_name, "AA:BB:CC:DD:EE:00", wordlist_path="/tmp/wl.txt")

    job = {"id": "job-999", "logs": ["no key"], "progress_data": {"stage": "RUNNING"}}
    captured["on_complete"](job)
    assert job["progress_data"]["stage"] == "EXHAUSTED"
    assert updates and updates[-1][2] == "EXHAUSTED"


def test_aircrack_process_success_parses_key_from_logs(tmp_path, monkeypatch):
    monkeypatch.setattr(ac_module, "HANDSHAKES_DIR", str(tmp_path))
    service = ac_module.AircrackService()
    job = {"id": "j1", "logs": ["something", "KEY FOUND! [ p4ssw0rd ]"]}

    found = service.process_success(job, str(tmp_path / "missing.key"), "logparse")
    assert found is True
    cracked_path = tmp_path / "logparse.pcap.cracked"
    assert cracked_path.exists()
    assert cracked_path.read_text(encoding="utf-8") == "p4ssw0rd"


def test_aircrack_run_attack_wsl_mode_builds_wsl_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(ac_module, "HANDSHAKES_DIR", str(tmp_path))
    pcap_name = "sample_wsl.pcap"
    (tmp_path / pcap_name).write_text("pcap", encoding="utf-8")
    service = ac_module.AircrackService()

    monkeypatch.setattr(
        service,
        "_get_config",
        lambda: {"aircrack_path": "/usr/bin/aircrack-ng"},
    )
    monkeypatch.setattr(service, "_should_use_wsl", lambda _bin: True)
    monkeypatch.setattr(service, "_to_wsl_path", lambda p: f"/mnt/{p}")
    monkeypatch.setattr(
        ac_module.history_service, "add_entry", lambda *a, **k: "entry-wsl"
    )
    monkeypatch.setattr(ac_module.history_service, "update_entry", lambda *a, **k: None)
    monkeypatch.setattr("app.services.data_loader.reload_data", lambda: None)

    captured = {}

    def _start_job(command, **kwargs):
        captured["command"] = command
        job = {"id": "jwsl", "logs": [], "progress_data": {"stage": "RUNNING"}}
        kwargs["on_complete"](job)
        return "jwsl"

    monkeypatch.setattr(ac_module.job_manager, "start_job", _start_job)
    result = service.run_attack(
        pcap_name, "AA:BB:CC:DD:EE:11", wordlist_path="/tmp/wl.txt"
    )

    assert result == {"status": "started", "job_id": "jwsl"}
    assert captured["command"][0] == "wsl"
    assert "/mnt/" in " ".join(captured["command"])


def test_aircrack_process_success_empty_key_and_no_log_match(tmp_path, monkeypatch):
    monkeypatch.setattr(ac_module, "HANDSHAKES_DIR", str(tmp_path))
    service = ac_module.AircrackService()

    empty_key = tmp_path / "empty.key"
    empty_key.write_text("", encoding="utf-8")
    found_empty = service.process_success(
        {"id": "j-empty", "logs": []}, str(empty_key), "empty"
    )
    assert found_empty is False

    found_no_match = service.process_success(
        {"id": "j-no-log", "logs": ["no key here"]},
        str(tmp_path / "missing.key"),
        "nolog",
    )
    assert found_no_match is False


def test_aircrack_error_paths_in_run_attack_and_process_success(tmp_path, monkeypatch):
    monkeypatch.setattr(ac_module, "HANDSHAKES_DIR", str(tmp_path))
    pcap_name = "err.pcap"
    (tmp_path / pcap_name).write_text("pcap", encoding="utf-8")
    service = ac_module.AircrackService()

    monkeypatch.setattr(
        service, "_get_config", lambda: {"aircrack_path": "aircrack-ng"}
    )
    monkeypatch.setattr(service, "_should_use_wsl", lambda _bin: False)
    monkeypatch.setattr(
        ac_module.history_service,
        "add_entry",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("history down")),
    )

    result = service.run_attack(
        pcap_name, "AA:BB:CC:DD:EE:22", wordlist_path="/tmp/wl.txt"
    )
    assert result["status"] == "error"
    assert "history down" in result["message"]

    key_file = tmp_path / "any.key"
    key_file.write_text("pw", encoding="utf-8")
    import builtins

    real_open = builtins.open
    monkeypatch.setattr(
        "builtins.open",
        lambda path, mode="r", *a, **k: (
            (_ for _ in ()).throw(OSError("open fail"))
            if str(path).endswith("any.key")
            else real_open(path, mode, *a, **k)
        ),
    )
    found = service.process_success({"id": "j-err", "logs": []}, str(key_file), "x")
    assert found is False


def test_aircrack_run_attack_reads_m5evil_pcap(tmp_path, monkeypatch):
    monkeypatch.setattr(ac_module, "HANDSHAKES_DIR", str(tmp_path / "handshakes"))
    monkeypatch.setattr(ac_module, "BRUCE_HANDSHAKES_DIR", str(tmp_path / "bruce-hand"))
    monkeypatch.setattr(ac_module, "BRUCE_PCAP_DIR", str(tmp_path / "bruce"))
    m5evil_dir = tmp_path / "m5evil"
    m5evil_dir.mkdir()
    pcap_name = "HS_AABBCCDDEEFF.pcap"
    (m5evil_dir / pcap_name).write_text("pcap", encoding="utf-8")
    monkeypatch.setattr(ac_module, "M5EVIL_HANDSHAKES_DIR", str(m5evil_dir))

    service = ac_module.AircrackService()
    monkeypatch.setattr(
        service, "_get_config", lambda: {"aircrack_path": "aircrack-ng"}
    )
    monkeypatch.setattr(service, "_should_use_wsl", lambda _bin: False)
    monkeypatch.setattr(
        ac_module.history_service, "add_entry", lambda *a, **k: "entry-m5evil"
    )

    captured = {}

    def _start_job(command, **kwargs):
        captured["command"] = command
        return "job-m5evil"

    monkeypatch.setattr(ac_module.job_manager, "start_job", _start_job)

    result = service.run_attack(
        pcap_name, "AA:BB:CC:DD:EE:FF", wordlist_path="/tmp/wl.txt"
    )

    assert result == {"status": "started", "job_id": "job-m5evil"}
    assert str(m5evil_dir / pcap_name) in captured["command"]
