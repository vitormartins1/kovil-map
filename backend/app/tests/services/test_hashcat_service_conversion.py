import json

from app.services import hashcat_service as hs_module


def test_get_available_rules_from_hashcat_dir(tmp_path, monkeypatch):
    """Test get_available_rules reads from hashcat rules directory."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "best64.rule").write_text("r1", encoding="utf-8")
    (rules_dir / "custom.rule").write_text("r2", encoding="utf-8")

    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda _self: {
            "hashcat_path": str(tmp_path / "hashcat"),
            "custom_rules_path": "",
        },
    )

    service = hs_module.HashcatService()
    rules = service.get_available_rules()
    names = [r["name"] for r in rules]
    assert "best64.rule" in names
    assert "custom.rule" in names


def test_get_available_rules_from_custom_rules_dir(tmp_path, monkeypatch):
    """Test get_available_rules reads from custom rules directory."""
    custom_rules = tmp_path / "custom_rules"
    custom_rules.mkdir()
    (custom_rules / "my-rule.rule").write_text("r1", encoding="utf-8")

    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda _self: {
            "hashcat_path": "hashcat",
            "custom_rules_path": str(custom_rules),
        },
    )

    service = hs_module.HashcatService()
    rules = service.get_available_rules()
    names = [r["name"] for r in rules]
    assert "my-rule.rule" in names


def test_get_available_masks_from_hashcat_dir(tmp_path, monkeypatch):
    """Test get_available_masks reads from hashcat masks directory."""
    masks_dir = tmp_path / "masks"
    masks_dir.mkdir()
    (masks_dir / "8char.hcmask").write_text("?d?d?d?d?d?d?d?d", encoding="utf-8")

    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda _self: {
            "hashcat_path": str(tmp_path / "hashcat"),
            "custom_masks_path": "",
        },
    )

    service = hs_module.HashcatService()
    masks = service.get_available_masks()
    names = [m["name"] for m in masks]
    assert "8char.hcmask" in names


def test_get_available_masks_from_custom_dir(tmp_path, monkeypatch):
    """Test get_available_masks reads from custom masks directory."""
    custom_masks = tmp_path / "custom_masks"
    custom_masks.mkdir()
    (custom_masks / "wifi.hcmask").write_text("?d?d?d?d?d?d?d?d", encoding="utf-8")

    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda _self: {
            "hashcat_path": "hashcat",
            "custom_masks_path": str(custom_masks),
        },
    )

    service = hs_module.HashcatService()
    masks = service.get_available_masks()
    names = [m["name"] for m in masks]
    assert "wifi.hcmask" in names


def test_get_devices_parses_output(monkeypatch):
    """Test get_devices parses hashcat -I output."""
    mock_output = """
Backend Device ID #1:
  Type...........: GPU
  Name...........: NVIDIA GeForce RTX 3080
"""

    class _Result:
        returncode = 0
        stdout = mock_output
        stderr = ""

    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda _self: {"hashcat_path": "hashcat"},
    )
    monkeypatch.setattr(
        hs_module.BaseService, "_should_use_wsl", lambda *_a, **_k: False
    )
    monkeypatch.setattr(hs_module.subprocess, "run", lambda *_a, **_k: _Result())

    service = hs_module.HashcatService()
    devices = service.get_devices()
    assert len(devices) == 1
    assert devices[0]["name"] == "NVIDIA GeForce RTX 3080"
    assert devices[0]["type"] == "GPU"


def test_get_devices_handles_exception(monkeypatch):
    """Test get_devices handles subprocess exception."""
    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda _self: {"hashcat_path": "hashcat"},
    )
    monkeypatch.setattr(
        hs_module.BaseService, "_should_use_wsl", lambda *_a, **_k: False
    )
    monkeypatch.setattr(
        hs_module.subprocess,
        "run",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("command not found")),
    )

    service = hs_module.HashcatService()
    devices = service.get_devices()
    assert devices == []


def test_normalize_association_seed():
    """Test _normalize_association_seed normalizes values."""
    service = hs_module.HashcatService()
    assert service._normalize_association_seed("hello  world") == "hello world"
    assert service._normalize_association_seed("  test  ") == "test"
    assert service._normalize_association_seed(None) == ""
    assert service._normalize_association_seed("") == ""


def test_extract_essids_from_hash_lines():
    """Test _extract_essids_from_hash_lines extracts SSIDs."""
    service = hs_module.HashcatService()
    lines = [
        "WPA*02*deadbeef*aabbccddeeff*001122334455*4d7957694669*00",
        "invalid line",
    ]
    essids = service._extract_essids_from_hash_lines(lines)
    assert "MyWiFi" in essids


def test_association_variant_candidates():
    """Test _association_variant_candidates generates variants."""
    service = hs_module.HashcatService()
    candidates = service._association_variant_candidates("TestNet")
    assert "TestNet" in candidates
    assert "testnet" in candidates
    assert "TESTNET" in candidates
    assert any("123" in c for c in candidates)


def test_build_association_candidates_v2_empty_hash(tmp_path, monkeypatch):
    """Test _build_association_candidates_v2 with empty hash file."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    hash_file = tmp_path / "empty.22000"
    hash_file.write_text("", encoding="utf-8")

    service = hs_module.HashcatService()
    result = service._build_association_candidates_v2(str(hash_file))
    assert result["status"] == "error"
    assert "empty" in result["message"].lower()


def test_build_association_candidates_v2_no_seeds(tmp_path, monkeypatch):
    """Test _build_association_candidates_v2 with no SSID or hints."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    hash_file = tmp_path / "noseed.22000"
    hash_file.write_text("invalid-hash-line\n", encoding="utf-8")

    service = hs_module.HashcatService()
    result = service._build_association_candidates_v2(
        str(hash_file), mode="association"
    )
    assert result["status"] == "error"
    assert "requires SSID" in result["message"]


def test_convert_pcap_now_file_not_found(tmp_path, monkeypatch):
    """Test convert_pcap_now when PCAP file is not found."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda _self: {"hcxpcapngtool_path": "hcx"},
    )
    monkeypatch.setattr(
        hs_module.BaseService, "_should_use_wsl", lambda *_a, **_k: False
    )

    service = hs_module.HashcatService()
    result = service.convert_pcap_now("nonexistent.pcap")
    assert result["status"] == "error"
    assert "not found" in result["message"].lower()


def test_convert_pcap_now_fails_with_error(tmp_path, monkeypatch):
    """Test convert_pcap_now handles conversion failure."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    pcap = tmp_path / "test.pcap"
    pcap.write_text("pcap", encoding="utf-8")

    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda _self: {"hcxpcapngtool_path": "hcx"},
    )
    monkeypatch.setattr(
        hs_module.BaseService, "_should_use_wsl", lambda *_a, **_k: False
    )

    class _Result:
        returncode = 1
        stderr = "conversion failed"
        stdout = ""

    monkeypatch.setattr(hs_module.subprocess, "run", lambda *_a, **_k: _Result())

    service = hs_module.HashcatService()
    result = service.convert_pcap_now("test.pcap")
    assert result["status"] == "error"
    assert "failed" in result["message"].lower()


def test_run_attack_with_device_all(tmp_path, monkeypatch):
    """Test run_attack with device_id='all'."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda _self: {
            "hashcat_path": "hashcat",
            "hashcat_potfile": False,
            "attack_mode": "straight",
            "workload_profile": "3",
        },
    )
    monkeypatch.setattr(
        hs_module.BaseService, "_should_use_wsl", lambda *_a, **_k: False
    )
    monkeypatch.setattr(
        hs_module.HashcatService, "process_cracked_file", lambda *_a, **_k: None
    )
    monkeypatch.setattr(
        hs_module.history_service, "update_entry", lambda *_a, **_k: None
    )

    captured = {"params": None}

    def _add_entry(_f, _tool, _cmd, params, **_kwargs):
        captured["params"] = params
        return "e1"

    monkeypatch.setattr(hs_module.history_service, "add_entry", _add_entry)
    monkeypatch.setattr(hs_module.job_manager, "start_job", lambda *_a, **_k: "j1")

    hash_file = tmp_path / "h.22000"
    hash_file.write_text("hash\n", encoding="utf-8")

    service = hs_module.HashcatService()
    out = service.run_attack("h.22000", wordlist="wl.txt", device_id="all")
    assert out["status"] == "started"
    assert captured["params"]["device"] == "Auto / All"


def test_run_attack_with_potfile_enabled(tmp_path, monkeypatch):
    """Test run_attack with potfile enabled."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda _self: {
            "hashcat_path": "hashcat",
            "hashcat_potfile": True,
            "attack_mode": "straight",
            "workload_profile": "3",
        },
    )
    monkeypatch.setattr(
        hs_module.BaseService, "_should_use_wsl", lambda *_a, **_k: False
    )
    monkeypatch.setattr(
        hs_module.HashcatService, "process_cracked_file", lambda *_a, **_k: None
    )
    monkeypatch.setattr(
        hs_module.history_service, "update_entry", lambda *_a, **_k: None
    )

    captured = {"cmd": None}

    def _add_entry(_f, _tool, _cmd, params, **_kwargs):
        return "e1"

    def _start_job(command, **_kwargs):
        captured["cmd"] = command
        return "j1"

    monkeypatch.setattr(hs_module.history_service, "add_entry", _add_entry)
    monkeypatch.setattr(hs_module.job_manager, "start_job", _start_job)

    hash_file = tmp_path / "h.22000"
    hash_file.write_text("hash\n", encoding="utf-8")

    service = hs_module.HashcatService()
    out = service.run_attack("h.22000", wordlist="wl.txt")
    assert out["status"] == "started"
    assert "--potfile-disable" not in captured["cmd"]


def test_run_attack_with_increment(tmp_path, monkeypatch):
    """Test run_attack with increment enabled for mask mode."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda _self: {
            "hashcat_path": "hashcat",
            "hashcat_potfile": False,
            "attack_mode": "mask",
            "workload_profile": "3",
        },
    )
    monkeypatch.setattr(
        hs_module.BaseService, "_should_use_wsl", lambda *_a, **_k: False
    )
    monkeypatch.setattr(
        hs_module.HashcatService, "process_cracked_file", lambda *_a, **_k: None
    )
    monkeypatch.setattr(
        hs_module.history_service, "update_entry", lambda *_a, **_k: None
    )

    captured = {"cmd": None}

    def _add_entry(_f, _tool, _cmd, params, **_kwargs):
        return "e1"

    def _start_job(command, **_kwargs):
        captured["cmd"] = command
        return "j1"

    monkeypatch.setattr(hs_module.history_service, "add_entry", _add_entry)
    monkeypatch.setattr(hs_module.job_manager, "start_job", _start_job)

    hash_file = tmp_path / "h.22000"
    hash_file.write_text("hash\n", encoding="utf-8")

    service = hs_module.HashcatService()
    out = service.run_attack(
        "h.22000",
        attack_mode="mask",
        custom_mask="?d?d?d?d",
        enable_increment=True,
        increment_min=2,
        increment_max=8,
    )
    assert out["status"] == "started"
    assert "--increment" in captured["cmd"]
    assert "--increment-min" in captured["cmd"]
    assert "--increment-max" in captured["cmd"]


def test_convert_multi_pcap_single_file(tmp_path, monkeypatch):
    """Test convert_multi_pcap with a single file."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    pcap = tmp_path / "single_aabbccddeeff.pcap"
    pcap.write_text("pcap", encoding="utf-8")

    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda _self: {"hcxpcapngtool_path": "hcx"},
    )
    monkeypatch.setattr(
        hs_module.BaseService, "_should_use_wsl", lambda *_a, **_k: False
    )

    class _Result:
        returncode = 0
        stderr = ""
        stdout = ""

    monkeypatch.setattr(hs_module.subprocess, "run", lambda *_a, **_k: _Result())

    def _start_multi_job(worker, **kwargs):
        job = {
            "id": "m1",
            "status": "running",
            "logs": [],
            "progress_data": {"current_step": 0, "percentage": 0},
        }
        worker(job, lambda *_a, **_k: None)
        return "m1"

    monkeypatch.setattr(hs_module.job_manager, "start_multi_job", _start_multi_job)

    service = hs_module.HashcatService()
    result = service.convert_multi_pcap(["single_aabbccddeeff.pcap"])
    assert result["status"] == "started"
    assert result["output_file"].startswith("batch_")


def test_process_cracked_file_batch_with_manifest(tmp_path, monkeypatch):
    """Test process_cracked_file with batch manifest."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))

    digest = "00112233445566778899aabbccddeeff"
    sta = "010203040506"
    h = f"WPA*02*{digest}*aabbccddeeff*{sta}*4d7957694669"

    cracked = tmp_path / "batch.cracked"
    cracked.write_text(f"{h}:foundpass\n", encoding="utf-8")

    manifest = {
        "items": [
            {
                "filename": "target.pcap",
                "mac": "aabbccddeeff",
                "ssid": "MyWiFi",
                "hashes": [h],
            }
        ]
    }
    (tmp_path / "batch.22000.batch.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )

    service = hs_module.HashcatService()
    service.process_cracked_file(
        {"id": "1", "command": ["hashcat", "-o", str(cracked)], "logs": []}
    )

    assert (tmp_path / "target.pcap.cracked").exists()
    assert (tmp_path / "target.pcap.cracked").read_text(encoding="utf-8") == "foundpass"


def test_process_cracked_file_batch_essid_match(tmp_path, monkeypatch):
    """Test process_cracked_file batch matches by SSID when unique."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))

    digest = "00112233445566778899aabbccddeeff"
    sta = "010203040506"
    essid_hex = "536f6c6f4e6574"  # SoloNet
    h = f"WPA*02*{digest}*deadbeefdead*{sta}*{essid_hex}"

    cracked = tmp_path / "batch2.cracked"
    cracked.write_text(f"{h}:solenet_pass\n", encoding="utf-8")

    manifest = {
        "items": [
            {
                "filename": "solo.pcap",
                "mac": "deadbeefdead",
                "ssid": "SoloNet",
                "hashes": [],
            }
        ]
    }
    (tmp_path / "batch2.22000.batch.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )

    service = hs_module.HashcatService()
    service.process_cracked_file(
        {"id": "2", "command": ["hashcat", "-o", str(cracked)], "logs": []}
    )

    assert (tmp_path / "solo.pcap.cracked").exists()
    assert (tmp_path / "solo.pcap.cracked").read_text(
        encoding="utf-8"
    ) == "solenet_pass"


def test_process_cracked_file_batch_unmapped_warning(tmp_path, monkeypatch):
    """Test process_cracked_file warns for unmapped batch hashes."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))

    digest = "ffeeddccbbaa99887766554433221100"
    sta = "010203040506"
    h = f"WPA*02*{digest}*cccccccccccc*{sta}*4d7957694669"

    cracked = tmp_path / "batch3.cracked"
    cracked.write_text(f"{h}:orphan_pass\n", encoding="utf-8")

    manifest = {
        "items": [
            {
                "filename": "other.pcap",
                "mac": "aaaaaaaaaaaa",
                "ssid": "OtherNet",
                "hashes": [],
            }
        ]
    }
    (tmp_path / "batch3.22000.batch.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )

    service = hs_module.HashcatService()
    service.process_cracked_file(
        {"id": "3", "command": ["hashcat", "-o", str(cracked)], "logs": []}
    )

    assert not (tmp_path / "other.pcap.cracked").exists()


def test_generate_funny_multi_name(tmp_path, monkeypatch):
    """Test _generate_funny_multi_name generates unique names."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))

    service = hs_module.HashcatService()
    name1 = service._generate_funny_multi_name()
    assert name1.startswith("batch_")
    assert name1.endswith(".22000")


def test_generate_funny_multi_name_collision(tmp_path, monkeypatch):
    """Test _generate_funny_multi_name falls back on collision."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))

    service = hs_module.HashcatService()
    name = service._generate_funny_multi_name()
    (tmp_path / name).write_text("exists", encoding="utf-8")

    name2 = service._generate_funny_multi_name()
    assert name2 != name
    assert name2.startswith("batch_")


def test_association_preview_sample_size(tmp_path, monkeypatch):
    """Test preview_association_candidates respects sample size."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    hash_file = tmp_path / "preview.22000"
    hash_file.write_text(
        "WPA*02*deadbeef*aabbccddeeff*001122334455*4d7957694669*00\n",
        encoding="utf-8",
    )

    service = hs_module.HashcatService()
    out = service.preview_association_candidates("preview.22000")
    assert out["status"] == "success"
    assert len(out["sample_candidates"]) <= service.ASSOCIATION_PREVIEW_SAMPLE


def test_association_candidate_cap(tmp_path, monkeypatch):
    """Test association candidates respect cap."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    hash_file = tmp_path / "cap.22000"
    hash_file.write_text(
        "WPA*02*deadbeef*aabbccddeeff*001122334455*4d7957694669*00\n",
        encoding="utf-8",
    )

    service = hs_module.HashcatService()
    result = service._build_association_candidates_v2(
        str(hash_file), mode="association"
    )
    assert result["status"] == "success"
    assert result["candidate_count"] <= result["cap"]


def test_run_attack_digits_mode(tmp_path, monkeypatch):
    """Test run_attack with digits mode."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda _self: {
            "hashcat_path": "hashcat",
            "hashcat_potfile": False,
            "attack_mode": "digits",
            "workload_profile": "3",
        },
    )
    monkeypatch.setattr(
        hs_module.BaseService, "_should_use_wsl", lambda *_a, **_k: False
    )
    monkeypatch.setattr(
        hs_module.HashcatService, "process_cracked_file", lambda *_a, **_k: None
    )
    monkeypatch.setattr(
        hs_module.history_service, "update_entry", lambda *_a, **_k: None
    )

    captured = {"cmd": None}

    def _add_entry(_f, _tool, _cmd, params, **_kwargs):
        return "e1"

    def _start_job(command, **_kwargs):
        captured["cmd"] = command
        return "j1"

    monkeypatch.setattr(hs_module.history_service, "add_entry", _add_entry)
    monkeypatch.setattr(hs_module.job_manager, "start_job", _start_job)

    hash_file = tmp_path / "h.22000"
    hash_file.write_text("hash\n", encoding="utf-8")

    service = hs_module.HashcatService()
    out = service.run_attack("h.22000", attack_mode="digits")
    assert out["status"] == "started"
    assert "-a" in captured["cmd"]
    assert "3" in captured["cmd"]


def test_convert_pcap_job_start(tmp_path, monkeypatch):
    """Test convert_pcap starts job correctly."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    pcap = tmp_path / "convert.pcap"
    pcap.write_text("pcap", encoding="utf-8")

    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda _self: {"hcxpcapngtool_path": "hcx"},
    )
    monkeypatch.setattr(
        hs_module.BaseService, "_should_use_wsl", lambda *_a, **_k: False
    )
    monkeypatch.setattr(hs_module.history_service, "add_entry", lambda *_a, **_k: "e1")

    captured = {"on_complete": None, "on_start": None}

    def _start_job(command, **kwargs):
        captured["on_complete"] = kwargs.get("on_complete")
        captured["on_start"] = kwargs.get("on_start")
        return "j1"

    monkeypatch.setattr(hs_module.job_manager, "start_job", _start_job)

    service = hs_module.HashcatService()
    result = service.convert_pcap("convert.pcap")
    assert result["status"] == "started"
    assert result["job_id"] == "j1"
    assert captured["on_complete"] is not None
    assert captured["on_start"] is not None
