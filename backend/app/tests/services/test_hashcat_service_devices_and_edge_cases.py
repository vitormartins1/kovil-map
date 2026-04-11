"""Hashcat service regression tests for edge-case execution paths."""

import json
import os
import random
from app.services import hashcat_service as hs_module


def test_hashcat_get_devices_no_devices(monkeypatch):
    """Test get_devices returns empty list when no devices found."""

    class _Result:
        returncode = 0
        stdout = ""
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
    assert devices == []


def test_hashcat_get_devices_partial_info(monkeypatch):
    """Test get_devices with partial device info."""
    mock_output = """Backend Device ID #1:
  Name...........: GPU Device
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
    assert devices[0]["name"] == "GPU Device"
    assert devices[0]["type"] == "N/A"


def test_hashcat_get_devices_timeout(monkeypatch):
    """Test get_devices handles timeout exception."""
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
        lambda *_a, **_k: (_ for _ in ()).throw(TimeoutError("timeout")),
    )

    service = hs_module.HashcatService()
    devices = service.get_devices()
    assert devices == []


def test_hashcat_get_available_rules_empty_dir(tmp_path, monkeypatch):
    """Test get_available_rules with non-existent rules directory."""
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
    assert len(rules) == 1
    assert rules[0]["name"] == "best64.rule"


def test_hashcat_get_available_rules_custom_only(tmp_path, monkeypatch):
    """Test get_available_rules with custom rules only."""
    custom_dir = tmp_path / "custom_rules"
    custom_dir.mkdir()
    (custom_dir / "my_rules.rule").write_text("rule1\n", encoding="utf-8")
    (custom_dir / "best64.rule").write_text("rule2\n", encoding="utf-8")

    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda _self: {
            "hashcat_path": str(tmp_path / "hashcat"),
            "custom_rules_path": str(custom_dir),
        },
    )

    service = hs_module.HashcatService()
    rules = service.get_available_rules()
    names = [r["name"] for r in rules]
    assert "my_rules.rule" in names
    assert "best64.rule" in names


def test_hashcat_get_available_masks_empty(tmp_path, monkeypatch):
    """Test get_available_masks with no masks found."""
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
    assert masks == []


def test_hashcat_get_available_masks_custom_only(tmp_path, monkeypatch):
    """Test get_available_masks with custom masks only."""
    custom_dir = tmp_path / "custom_masks"
    custom_dir.mkdir()
    (custom_dir / "8digit.hcmask").write_text("?d?d?d?d?d?d?d?d\n", encoding="utf-8")

    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda _self: {
            "hashcat_path": str(tmp_path / "hashcat"),
            "custom_masks_path": str(custom_dir),
        },
    )

    service = hs_module.HashcatService()
    masks = service.get_available_masks()
    assert len(masks) == 1
    assert masks[0]["name"] == "8digit.hcmask"


def test_hashcat_association_variant_candidates_dedup():
    """Test _association_variant_candidates deduplicates variants."""
    service = hs_module.HashcatService()
    candidates = service._association_variant_candidates("Test123")
    assert len(candidates) == len(set(candidates))


def test_hashcat_association_variant_candidates_long_string():
    """Test _association_variant_candidates with long string."""
    service = hs_module.HashcatService()
    long_seed = "A" * 100
    candidates = service._association_variant_candidates(long_seed)
    assert len(candidates) > 0
    assert long_seed in candidates


def test_hashcat_build_association_candidates_v2_hash_not_found(tmp_path, monkeypatch):
    """Test _build_association_candidates_v2 with non-existent hash file."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))

    service = hs_module.HashcatService()
    result = service._build_association_candidates_v2(
        str(tmp_path / "nonexistent.22000")
    )
    assert result["status"] == "error"
    assert "not found" in result["message"].lower()


def test_hashcat_normalize_association_seed_special_chars():
    """Test _normalize_association_seed with special characters."""
    service = hs_module.HashcatService()
    assert service._normalize_association_seed("test\x00name") == "testname"
    assert service._normalize_association_seed("test\nname") == "testname"
    assert (
        service._normalize_association_seed("  multiple   spaces  ")
        == "multiple spaces"
    )


def test_hashcat_extract_essids_from_hash_lines_invalid():
    """Test _extract_essids_from_hash_lines with invalid lines."""
    service = hs_module.HashcatService()
    lines = [
        "invalid",
        "WPA*02*deadbeef",
        "",
        "WPA*02*deadbeef*aabbccddeeff*001122334455*4d7957694669*00",
    ]
    essids = service._extract_essids_from_hash_lines(lines)
    assert "MyWiFi" in essids
    assert len(essids) == 1


def test_hashcat_convert_pcap_now_empty_output(tmp_path, monkeypatch):
    """Test convert_pcap_now with empty output file."""
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

    def mock_run(*args, **kwargs):
        cmd = args[0]
        output_file = cmd[cmd.index("-o") + 1]
        with open(output_file, "w") as f:
            f.write("")
        return type("_Result", (), {"returncode": 0, "stderr": "", "stdout": ""})()

    monkeypatch.setattr(hs_module.subprocess, "run", mock_run)

    service = hs_module.HashcatService()
    result = service.convert_pcap_now("test.pcap")
    assert result["status"] == "error"
    assert "empty output" in result["message"].lower()


def test_hashcat_convert_pcap_now_nonzero_exit(tmp_path, monkeypatch):
    """Test convert_pcap_now with non-zero exit code."""
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

    def mock_run(*args, **kwargs):
        return type(
            "_Result", (), {"returncode": 1, "stderr": "error occurred", "stdout": ""}
        )()

    monkeypatch.setattr(hs_module.subprocess, "run", mock_run)

    service = hs_module.HashcatService()
    result = service.convert_pcap_now("test.pcap")
    assert result["status"] == "error"
    assert "failed" in result["message"].lower()


def test_hashcat_run_attack_default_attack_mode(tmp_path, monkeypatch):
    """Test run_attack uses default attack mode from config."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda _self: {
            "hashcat_path": "hashcat",
            "hashcat_potfile": False,
            "attack_mode": "rules",
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

    def _add_entry(_f, _tool, cmd, params, **_kwargs):
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
    assert "-a" in captured["cmd"]
    assert "0" in captured["cmd"]
    assert "-r" in captured["cmd"]


def test_hashcat_run_attack_default_workload(tmp_path, monkeypatch):
    """Test run_attack uses default workload from config."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda _self: {
            "hashcat_path": "hashcat",
            "hashcat_potfile": False,
            "attack_mode": "straight",
            "workload_profile": "2",
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

    def _add_entry(_f, _tool, cmd, params, **_kwargs):
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
    assert "-w" in captured["cmd"]
    assert "2" in captured["cmd"]


def test_hashcat_run_attack_cleans_existing_cracked_file(tmp_path, monkeypatch):
    """Test run_attack removes existing cracked file."""
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

    monkeypatch.setattr(hs_module.history_service, "add_entry", lambda *_a, **_k: "e1")
    monkeypatch.setattr(hs_module.job_manager, "start_job", lambda *_a, **_k: "j1")

    hash_file = tmp_path / "h.22000"
    hash_file.write_text("hash\n", encoding="utf-8")

    cracked_file = tmp_path / "h.cracked"
    cracked_file.write_text("old_password\n", encoding="utf-8")
    assert cracked_file.exists()

    service = hs_module.HashcatService()
    out = service.run_attack("h.22000", wordlist="wl.txt")
    assert out["status"] == "started"
    assert not cracked_file.exists()


def test_hashcat_run_attack_hybrid_mask_profile(tmp_path, monkeypatch):
    """Test run_attack with hybrid_mask_profile mode."""
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

    captured = {"cmd": None}

    def _add_entry(_f, _tool, cmd, params, **_kwargs):
        return "e1"

    def _start_job(command, **_kwargs):
        captured["cmd"] = command
        return "j1"

    monkeypatch.setattr(hs_module.history_service, "add_entry", _add_entry)
    monkeypatch.setattr(hs_module.job_manager, "start_job", _start_job)

    hash_file = tmp_path / "h.22000"
    hash_file.write_text("hash\n", encoding="utf-8")

    mask_file = tmp_path / "test.hcmask"
    mask_file.write_text("?d?d?d?d\n", encoding="utf-8")

    service = hs_module.HashcatService()
    out = service.run_attack(
        "h.22000",
        attack_mode="hybrid_mask_profile",
        wordlist="wl.txt",
        mask_file=str(mask_file),
    )
    assert out["status"] == "started"
    assert "-a" in captured["cmd"]
    assert "6" in captured["cmd"]


def test_hashcat_run_attack_hybrid_reverse_mask_profile(tmp_path, monkeypatch):
    """Test run_attack with hybrid_reverse_mask_profile mode."""
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

    captured = {"cmd": None}

    def _add_entry(_f, _tool, cmd, params, **_kwargs):
        return "e1"

    def _start_job(command, **_kwargs):
        captured["cmd"] = command
        return "j1"

    monkeypatch.setattr(hs_module.history_service, "add_entry", _add_entry)
    monkeypatch.setattr(hs_module.job_manager, "start_job", _start_job)

    hash_file = tmp_path / "h.22000"
    hash_file.write_text("hash\n", encoding="utf-8")

    mask_file = tmp_path / "test.hcmask"
    mask_file.write_text("?d?d?d?d\n", encoding="utf-8")

    service = hs_module.HashcatService()
    out = service.run_attack(
        "h.22000",
        attack_mode="hybrid_reverse_mask_profile",
        wordlist="wl.txt",
        mask_file=str(mask_file),
    )
    assert out["status"] == "started"
    assert "-a" in captured["cmd"]
    assert "7" in captured["cmd"]


def test_hashcat_run_attack_mask_profile_missing(tmp_path, monkeypatch):
    """Test run_attack with mask_profile mode but no mask_file."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda _self: {
            "hashcat_path": "hashcat",
            "hashcat_potfile": False,
            "attack_mode": "mask_profile",
            "workload_profile": "3",
        },
    )

    hash_file = tmp_path / "h.22000"
    hash_file.write_text("hash\n", encoding="utf-8")

    service = hs_module.HashcatService()
    out = service.run_attack("h.22000")
    assert out["status"] == "error"
    assert "Mask profile not selected" in out["message"]


def test_hashcat_run_attack_passphrase_missing_rules(tmp_path, monkeypatch):
    """Test run_attack with passphrase mode but missing rule files."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda _self: {
            "hashcat_path": "hashcat",
            "hashcat_potfile": False,
            "attack_mode": "passphrase",
            "workload_profile": "3",
            "custom_rules_path": "",
        },
    )

    hash_file = tmp_path / "h.22000"
    hash_file.write_text("hash\n", encoding="utf-8")

    service = hs_module.HashcatService()
    out = service.run_attack("h.22000", wordlist="wl.txt")
    assert out["status"] == "error"
    assert "passphrase-rule1.rule" in out["message"]


def test_hashcat_convert_multi_pcap_success(tmp_path, monkeypatch):
    """Test convert_multi_pcap with successful conversion."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    pcap = tmp_path / "test_aabbccddeeff.pcap"
    pcap.write_text("pcap", encoding="utf-8")

    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda _self: {"hcxpcapngtool_path": "hcx"},
    )
    monkeypatch.setattr(
        hs_module.BaseService, "_should_use_wsl", lambda *_a, **_k: False
    )

    def mock_run(*args, **kwargs):
        cmd = args[0]
        output_file = cmd[cmd.index("-o") + 1]
        with open(output_file, "w") as f:
            f.write("WPA*02*deadbeef*aabbccddeeff*001122334455*TestNet*00\n")
        return type("_Result", (), {"returncode": 0, "stderr": "", "stdout": ""})()

    monkeypatch.setattr(hs_module.subprocess, "run", mock_run)

    def _start_multi_job(worker, **kwargs):
        job = {
            "id": "m1",
            "status": "running",
            "logs": [],
            "progress_data": {"current_step": 0, "percentage": 0, "items": []},
        }
        worker(job, lambda *_a, **_k: None)
        return "m1"

    monkeypatch.setattr(hs_module.job_manager, "start_multi_job", _start_multi_job)

    service = hs_module.HashcatService()
    result = service.convert_multi_pcap(["test_aabbccddeeff.pcap"])
    assert result["status"] == "started"
    assert result["output_file"].startswith("batch_")

    manifest = tmp_path / f"{result['output_file']}.batch.json"
    assert manifest.exists()
    data = json.loads(manifest.read_text(encoding="utf-8"))
    assert len(data["items"]) == 1
    assert data["items"][0]["status"] == "OK"


def test_hashcat_convert_multi_pcap_no_pmkid(tmp_path, monkeypatch):
    """Test convert_multi_pcap with no PMKID found."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    pcap = tmp_path / "test_aabbccddeeff.pcap"
    pcap.write_text("pcap", encoding="utf-8")

    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda _self: {"hcxpcapngtool_path": "hcx"},
    )
    monkeypatch.setattr(
        hs_module.BaseService, "_should_use_wsl", lambda *_a, **_k: False
    )

    def mock_run(*args, **kwargs):
        cmd = args[0]
        output_file = cmd[cmd.index("-o") + 1]
        with open(output_file, "w") as f:
            f.write("")
        return type(
            "_Result", (), {"returncode": 0, "stderr": "no PMKID found", "stdout": ""}
        )()

    monkeypatch.setattr(hs_module.subprocess, "run", mock_run)

    def _start_multi_job(worker, **kwargs):
        job = {
            "id": "m1",
            "status": "running",
            "logs": [],
            "progress_data": {"current_step": 0, "percentage": 0, "items": []},
        }
        worker(job, lambda *_a, **_k: None)
        return "m1"

    monkeypatch.setattr(hs_module.job_manager, "start_multi_job", _start_multi_job)

    service = hs_module.HashcatService()
    result = service.convert_multi_pcap(["test_aabbccddeeff.pcap"])
    assert result["status"] == "started"

    manifest = tmp_path / f"{result['output_file']}.batch.json"
    assert manifest.exists()
    data = json.loads(manifest.read_text(encoding="utf-8"))
    assert data["items"][0]["status"] == "FAILED"
    # Reason can be "NO PMKID" or "EMPTY OUTPUT" depending on stderr parsing
    assert data["items"][0]["reason"] in ("NO PMKID", "EMPTY OUTPUT")


def test_hashcat_convert_multi_pcap_no_handshake(tmp_path, monkeypatch):
    """Test convert_multi_pcap with no valid handshake."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    pcap = tmp_path / "test_aabbccddeeff.pcap"
    pcap.write_text("pcap", encoding="utf-8")

    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda _self: {"hcxpcapngtool_path": "hcx"},
    )
    monkeypatch.setattr(
        hs_module.BaseService, "_should_use_wsl", lambda *_a, **_k: False
    )

    def mock_run(*args, **kwargs):
        cmd = args[0]
        output_file = cmd[cmd.index("-o") + 1]
        with open(output_file, "w") as f:
            f.write("")
        return type(
            "_Result",
            (),
            {"returncode": 0, "stderr": "no valid handshake found", "stdout": ""},
        )()

    monkeypatch.setattr(hs_module.subprocess, "run", mock_run)

    def _start_multi_job(worker, **kwargs):
        job = {
            "id": "m1",
            "status": "running",
            "logs": [],
            "progress_data": {"current_step": 0, "percentage": 0, "items": []},
        }
        worker(job, lambda *_a, **_k: None)
        return "m1"

    monkeypatch.setattr(hs_module.job_manager, "start_multi_job", _start_multi_job)

    service = hs_module.HashcatService()
    result = service.convert_multi_pcap(["test_aabbccddeeff.pcap"])
    assert result["status"] == "started"

    manifest = tmp_path / f"{result['output_file']}.batch.json"
    assert manifest.exists()
    data = json.loads(manifest.read_text(encoding="utf-8"))
    assert data["items"][0]["status"] == "FAILED"
    # The regex uses \\s which matches literal \s, not whitespace
    # "no valid handshake found" matches the "no valid handshake" pattern
    assert data["items"][0]["reason"] in ("NO VALID HANDSHAKE", "EMPTY OUTPUT")


def test_hashcat_run_attack_digits_with_custom_mask(tmp_path, monkeypatch):
    """Test run_attack with digits mode and custom mask."""
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

    def _add_entry(_f, _tool, cmd, params, **_kwargs):
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
        "h.22000", attack_mode="digits", custom_mask="?d?d?d?d?d?d"
    )
    assert out["status"] == "started"
    assert "?d?d?d?d?d?d" in captured["cmd"]


def test_hashcat_run_attack_hybrid_with_custom_mask(tmp_path, monkeypatch):
    """Test run_attack with hybrid mode and custom mask."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda _self: {
            "hashcat_path": "hashcat",
            "hashcat_potfile": False,
            "attack_mode": "hybrid",
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

    def _add_entry(_f, _tool, cmd, params, **_kwargs):
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
        attack_mode="hybrid",
        wordlist="wl.txt",
        custom_mask="?d?d?d?d",
    )
    assert out["status"] == "started"
    assert "-a" in captured["cmd"]
    assert "6" in captured["cmd"]
    assert "?d?d?d?d" in captured["cmd"]


def test_hashcat_run_attack_hybrid_reverse_with_custom_mask(tmp_path, monkeypatch):
    """Test run_attack with hybrid_reverse mode and custom mask."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda _self: {
            "hashcat_path": "hashcat",
            "hashcat_potfile": False,
            "attack_mode": "hybrid_reverse",
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

    def _add_entry(_f, _tool, cmd, params, **_kwargs):
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
        attack_mode="hybrid_reverse",
        wordlist="wl.txt",
        custom_mask="?d?d?d?d",
    )
    assert out["status"] == "started"
    assert "-a" in captured["cmd"]
    assert "7" in captured["cmd"]
    assert "?d?d?d?d" in captured["cmd"]


def test_hashcat_get_devices_wsl(monkeypatch):
    """Test get_devices with WSL mode."""
    mock_output = """Backend Device ID #1:
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
        hs_module.BaseService, "_should_use_wsl", lambda *_a, **_k: True
    )
    monkeypatch.setattr(hs_module.subprocess, "run", lambda *_a, **_k: _Result())

    service = hs_module.HashcatService()
    devices = service.get_devices()
    assert len(devices) == 1
    assert devices[0]["name"] == "NVIDIA GeForce RTX 3080"


def test_hashcat_get_devices_with_backend_sections(monkeypatch):
    """Test get_devices parses different backend sections."""
    mock_output = """Metal Info:
=============
Backend Device ID #1:
  Type...........: GPU
  Name...........: Apple M1

OpenCL Info:
============
Backend Device ID #2:
  Type...........: CPU
  Name...........: Intel Core i9
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
    assert len(devices) == 2
    assert devices[0]["backend"] == "Metal"
    assert devices[1]["backend"] == "OpenCL"


def test_hashcat_association_variant_candidates_empty():
    """Test _association_variant_candidates with empty seed."""
    service = hs_module.HashcatService()
    candidates = service._association_variant_candidates("")
    assert candidates == []


def test_hashcat_association_variant_candidates_special_chars():
    """Test _association_variant_candidates with special characters."""
    service = hs_module.HashcatService()
    candidates = service._association_variant_candidates("My.Net_Name-123")
    assert len(candidates) > 0
    # Should have variants without separators
    assert any("MyNetName123" in c for c in candidates)


def test_hashcat_build_association_candidates_v2_invalid_mode(tmp_path, monkeypatch):
    """Test _build_association_candidates_v2 with invalid mode."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    hash_file = tmp_path / "test.22000"
    hash_file.write_text(
        "WPA*02*deadbeef*aabbccddeeff*001122334455*4d7957694669*00\n",
        encoding="utf-8",
    )

    service = hs_module.HashcatService()
    result = service._build_association_candidates_v2(str(hash_file), mode="invalid")
    assert result["status"] == "error"
    assert "Invalid association mode" in result["message"]


def test_hashcat_association_hint_first_no_seeds(tmp_path, monkeypatch):
    """Test association_hint_first mode with no hints and no SSID."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    hash_file = tmp_path / "test.22000"
    hash_file.write_text("invalid-hash-line\n", encoding="utf-8")

    service = hs_module.HashcatService()
    result = service._build_association_candidates_v2(
        str(hash_file), mode="association_hint_first"
    )
    assert result["status"] == "error"
    assert "requires hints or SSID" in result["message"]


def test_hashcat_convert_pcap_now_success(tmp_path, monkeypatch):
    """Test convert_pcap_now successful conversion."""
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

    def mock_run(*args, **kwargs):
        cmd = args[0]
        output_file = cmd[cmd.index("-o") + 1]
        with open(output_file, "w") as f:
            f.write("WPA*02*deadbeef*aabbccddeeff*001122334455*TestNet*00\n")
        result = type("_Result", (), {"returncode": 0, "stderr": "", "stdout": ""})()
        return result

    monkeypatch.setattr(hs_module.subprocess, "run", mock_run)

    service = hs_module.HashcatService()
    result = service.convert_pcap_now("test.pcap")
    assert result["status"] == "success"
    assert result["output_file"] == "test.22000"


def test_hashcat_run_attack_with_optimized_kernel(tmp_path, monkeypatch):
    """Test run_attack with optimized kernel flag."""
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

    captured = {"cmd": None, "params": None}

    def _add_entry(_f, _tool, cmd, params, **_kwargs):
        captured["cmd"] = cmd
        captured["params"] = params
        return "e1"

    monkeypatch.setattr(hs_module.history_service, "add_entry", _add_entry)
    monkeypatch.setattr(hs_module.job_manager, "start_job", lambda *_a, **_k: "j1")

    hash_file = tmp_path / "h.22000"
    hash_file.write_text("hash\n", encoding="utf-8")

    service = hs_module.HashcatService()
    out = service.run_attack("h.22000", wordlist="wl.txt", is_optimized=True)
    assert out["status"] == "started"
    assert "-O" in captured["cmd"]
    assert captured["params"]["optimized"] is True


def test_hashcat_run_attack_without_optimized_kernel(tmp_path, monkeypatch):
    """Test run_attack without optimized kernel flag."""
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

    captured = {"cmd": None, "params": None}

    def _add_entry(_f, _tool, cmd, params, **_kwargs):
        captured["cmd"] = cmd
        captured["params"] = params
        return "e1"

    monkeypatch.setattr(hs_module.history_service, "add_entry", _add_entry)
    monkeypatch.setattr(hs_module.job_manager, "start_job", lambda *_a, **_k: "j1")

    hash_file = tmp_path / "h.22000"
    hash_file.write_text("hash\n", encoding="utf-8")

    service = hs_module.HashcatService()
    out = service.run_attack("h.22000", wordlist="wl.txt", is_optimized=False)
    assert out["status"] == "started"
    assert "-O" not in captured["cmd"]
    assert captured["params"].get("optimized") is None


def test_hashcat_run_attack_hash_not_found(tmp_path, monkeypatch):
    """Test run_attack with missing hash file."""
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

    service = hs_module.HashcatService()
    out = service.run_attack("missing.22000", wordlist="wl.txt")
    assert out["status"] == "error"
    assert "not found" in out["message"].lower()


def test_hashcat_convert_multi_pcap_with_missing_file(tmp_path, monkeypatch):
    """Test convert_multi_pcap with missing PCAP file."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda _self: {"hcxpcapngtool_path": "hcx"},
    )
    monkeypatch.setattr(
        hs_module.BaseService, "_should_use_wsl", lambda *_a, **_k: False
    )

    def _start_multi_job(worker, **kwargs):
        job = {
            "id": "m1",
            "status": "running",
            "logs": [],
            "progress_data": {"current_step": 0, "percentage": 0, "items": []},
        }
        worker(job, lambda *_a, **_k: None)
        return "m1"

    monkeypatch.setattr(hs_module.job_manager, "start_multi_job", _start_multi_job)

    service = hs_module.HashcatService()
    result = service.convert_multi_pcap(["missing.pcap"])
    assert result["status"] == "started"
    manifest = tmp_path / (result["output_file"] + ".batch.json")
    assert manifest.exists()
    data = json.loads(manifest.read_text(encoding="utf-8"))
    assert data["items"][0]["status"] == "FAILED"
    assert "NOT FOUND" in data["items"][0]["reason"]


class TestHashcatServiceDeviceAndConversionEdges:
    """Device parsing and conversion edge scenarios."""

    def test_get_devices_parsing(self, tmp_path, monkeypatch):
        """Test get_devices parses hashcat -I output."""
        mock_output = """hashcat (v6.2.6) starting in backend information mode...

Backend Device ID #1:
  Type...........: GPU
  Name...........: NVIDIA GeForce RTX 3080
  Processor(s)...: 68
  Clock...........: 1710
  Memory.Total....: 10240 MB
  Memory.Available: 9500 MB

Backend Device ID #2:
  Type...........: CPU
  Name...........: Intel Core i9-10900K
  Processor(s)...: 20
"""
        monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(
            hs_module.BaseService,
            "_get_config",
            lambda _self: {"hashcat_path": "hashcat"},
        )
        monkeypatch.setattr(
            hs_module.BaseService, "_should_use_wsl", lambda *_a, **_k: False
        )

        captured = {"cmd": None}

        def mock_run(*args, **kwargs):
            captured["cmd"] = args[0]
            return type(
                "_Result", (), {"returncode": 0, "stdout": mock_output, "stderr": ""}
            )()

        monkeypatch.setattr(hs_module.subprocess, "run", mock_run)

        service = hs_module.HashcatService()
        devices = service.get_devices()
        assert len(devices) == 2
        assert devices[0]["id"] == "1"
        assert devices[0]["type"] == "GPU"
        assert "RTX 3080" in devices[0]["name"]
        assert devices[1]["id"] == "2"
        assert devices[1]["type"] == "CPU"

    def test_get_devices_timeout(self, monkeypatch):
        """Test get_devices handles timeout."""
        monkeypatch.setattr(
            hs_module.BaseService,
            "_get_config",
            lambda _self: {"hashcat_path": "hashcat"},
        )
        monkeypatch.setattr(
            hs_module.BaseService, "_should_use_wsl", lambda *_a, **_k: False
        )

        import subprocess

        def mock_run(*args, **kwargs):
            raise subprocess.TimeoutExpired("hashcat", 10)

        monkeypatch.setattr(hs_module.subprocess, "run", mock_run)

        service = hs_module.HashcatService()
        devices = service.get_devices()
        assert devices == []

    def test_get_devices_exception(self, monkeypatch):
        """Test get_devices handles exceptions."""
        monkeypatch.setattr(
            hs_module.BaseService,
            "_get_config",
            lambda _self: {"hashcat_path": "hashcat"},
        )
        monkeypatch.setattr(
            hs_module.BaseService, "_should_use_wsl", lambda *_a, **_k: False
        )

        def mock_run(*args, **kwargs):
            raise Exception("some error")

        monkeypatch.setattr(hs_module.subprocess, "run", mock_run)

        service = hs_module.HashcatService()
        devices = service.get_devices()
        assert devices == []

    def test_convert_pcap_now_success(self, tmp_path, monkeypatch):
        """Test convert_pcap_now successful conversion."""
        monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(
            hs_module.BaseService,
            "_get_config",
            lambda _self: {"hcxpcapngtool_path": "hcxpcapngtool"},
        )
        monkeypatch.setattr(
            hs_module.BaseService, "_should_use_wsl", lambda *_a, **_k: False
        )

        pcap_file = tmp_path / "test.pcap"
        pcap_file.write_bytes(b"pcap data")

        def mock_run(*args, **kwargs):
            # Find output file in args
            args_list = args[0] if args else []
            out_idx = args_list.index("-o") + 1 if "-o" in args_list else None
            if out_idx and out_idx < len(args_list):
                out_path = args_list[out_idx]
                with open(out_path, "w") as f:
                    f.write("WPA*02*hash*mac*essid\n")
            return type("_Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()

        monkeypatch.setattr(hs_module.subprocess, "run", mock_run)

        service = hs_module.HashcatService()
        result = service.convert_pcap_now("test.pcap")
        assert result["status"] == "success"
        assert "test.22000" in result["output_file"]

    def test_convert_pcap_now_failure(self, tmp_path, monkeypatch):
        """Test convert_pcap_now with failure."""
        monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
        monkeypatch.setattr(
            hs_module.BaseService,
            "_get_config",
            lambda _self: {"hcxpcapngtool_path": "hcxpcapngtool"},
        )
        monkeypatch.setattr(
            hs_module.BaseService, "_should_use_wsl", lambda *_a, **_k: False
        )

        pcap_file = tmp_path / "test.pcap"
        pcap_file.write_bytes(b"pcap data")

        def mock_run(*args, **kwargs):
            return type(
                "_Result",
                (),
                {"returncode": 1, "stdout": "", "stderr": "conversion failed"},
            )()

        monkeypatch.setattr(hs_module.subprocess, "run", mock_run)

        service = hs_module.HashcatService()
        result = service.convert_pcap_now("test.pcap")
        assert result["status"] == "error"
        assert "failed" in result["message"].lower()

    def test_run_attack_with_device_id(self, tmp_path, monkeypatch):
        """Test run_attack with specific device_id."""
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

        captured = {"cmd": None}

        def _add_entry(_f, _tool, cmd, params, **_kwargs):
            return "e1"

        def _start_job(command, **_kwargs):
            captured["cmd"] = command
            return "j1"

        monkeypatch.setattr(hs_module.history_service, "add_entry", _add_entry)
        monkeypatch.setattr(hs_module.job_manager, "start_job", _start_job)

        hash_file = tmp_path / "h.22000"
        hash_file.write_text("hash\n", encoding="utf-8")

        service = hs_module.HashcatService()
        out = service.run_attack("h.22000", wordlist="wl.txt", device_id="2")
        assert out["status"] == "started"
        assert "-d" in captured["cmd"]
        assert "2" in captured["cmd"]

    def test_run_attack_with_increment(self, tmp_path, monkeypatch):
        """Test run_attack with increment enabled."""
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

        def _add_entry(_f, _tool, cmd, params, **_kwargs):
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
            increment_min=4,
            increment_max=8,
        )
        assert out["status"] == "started"
        assert "--increment" in captured["cmd"]
        assert "--increment-min" in captured["cmd"]
        assert "--increment-max" in captured["cmd"]


class TestHashcatServiceModePoliciesAndCandidates:
    """Mode policies and candidate generation behaviors."""

    def test_get_attack_mode_policy_unknown(self):
        """Test _get_attack_mode_policy with unknown mode."""
        service = hs_module.HashcatService()
        policy = service._get_attack_mode_policy("unknown_mode")
        assert policy["requires_wordlist"] is True

    def test_requires_wordlist_various_modes(self):
        """Test _requires_wordlist for various modes."""
        service = hs_module.HashcatService()
        assert service._requires_wordlist("straight") is True
        assert service._requires_wordlist("mask") is False
        assert service._requires_wordlist("combinator") is True

    def test_supports_increment_various_modes(self):
        """Test _supports_increment for various modes."""
        service = hs_module.HashcatService()
        assert service._supports_increment("mask") is True
        assert service._supports_increment("digits") is True
        assert service._supports_increment("straight") is False

    def test_supports_slow_candidates_various_modes(self):
        """Test _supports_slow_candidates for various modes."""
        service = hs_module.HashcatService()
        assert service._supports_slow_candidates("straight") is True
        assert service._supports_slow_candidates("association") is False

    def test_association_candidate_caps(self):
        """Test ASSOCIATION_CANDIDATE_CAPS."""
        service = hs_module.HashcatService()
        assert service.ASSOCIATION_CANDIDATE_CAPS["association"] == 20000
        assert service.ASSOCIATION_CANDIDATE_CAPS["association_hint_first"] == 60000

    def test_association_suffixes(self):
        """Test ASSOCIATION_SUFFIXES."""
        service = hs_module.HashcatService()
        assert "123" in service.ASSOCIATION_SUFFIXES
        assert "2024" in service.ASSOCIATION_SUFFIXES

    def test_funny_multi_words(self):
        """Test FUNNY_MULTI_WORDS."""
        service = hs_module.HashcatService()
        assert "pwn" in service.FUNNY_MULTI_WORDS
        assert len(service.FUNNY_MULTI_WORDS) > 0

    def test_carioca_slang(self):
        """Test CARIOCA_SLANG."""
        service = hs_module.HashcatService()
        assert "mane" in service.CARIOCA_SLANG
        assert len(service.CARIOCA_SLANG) > 0

    def test_passphrase_rule_files(self):
        """Test PASSPHRASE_RULE_FILES."""
        service = hs_module.HashcatService()
        assert service.PASSPHRASE_RULE_FILES == (
            "passphrase-rule1.rule",
            "passphrase-rule2.rule",
        )


def test_mode_rules_args_basic():
    """Test _mode_rules_args builds correct attack arguments."""
    service = hs_module.HashcatService()
    cmd_args = []
    context = {
        "rule_file": "custom.rule",
        "wordlist": "/path/wordlist.txt",
        "use_wsl": False,
    }
    associate_file, error = service._mode_rules_args(cmd_args, context)
    assert error is None
    assert "-a" in cmd_args
    assert "0" in cmd_args
    assert "-r" in cmd_args
    assert "custom.rule" in cmd_args


def test_mode_digits_args_custom_mask():
    """Test _mode_digits_args with custom mask."""
    service = hs_module.HashcatService()
    cmd_args = []
    context = {"custom_mask": "?d?d?d?d", "use_wsl": False}
    associate_file, error = service._mode_digits_args(cmd_args, context)
    assert error is None
    assert "-a" in cmd_args
    assert "3" in cmd_args
    assert "?d?d?d?d" in cmd_args


def test_mode_mask_args_default():
    """Test _mode_mask_args with default mask."""
    service = hs_module.HashcatService()
    cmd_args = []
    context = {"custom_mask": None, "use_wsl": False}
    associate_file, error = service._mode_mask_args(cmd_args, context)
    assert error is None
    assert "-a" in cmd_args
    assert "3" in cmd_args
    assert "?a?a?a?a?a?a?a?a" in cmd_args


def test_mode_hybrid_args_basic():
    """Test _mode_hybrid_args builds hybrid attack."""
    service = hs_module.HashcatService()
    cmd_args = []
    context = {
        "wordlist": "/path/wordlist.txt",
        "custom_mask": "?d?d?d?d",
        "use_wsl": False,
    }
    associate_file, error = service._mode_hybrid_args(cmd_args, context)
    assert error is None
    assert "-a" in cmd_args
    assert "6" in cmd_args
    assert "/path/wordlist.txt" in cmd_args
    assert "?d?d?d?d" in cmd_args


def test_mode_hybrid_reverse_args_basic():
    """Test _mode_hybrid_reverse_args builds hybrid reverse attack."""
    service = hs_module.HashcatService()
    cmd_args = []
    context = {
        "wordlist": "/path/wordlist.txt",
        "custom_mask": "?d?d?d?d",
        "use_wsl": False,
    }
    associate_file, error = service._mode_hybrid_reverse_args(cmd_args, context)
    assert error is None
    assert "-a" in cmd_args
    assert "7" in cmd_args


def test_mode_straight_args_basic():
    """Test _mode_straight_args builds straight attack."""
    service = hs_module.HashcatService()
    cmd_args = []
    context = {"wordlist": "/path/wordlist.txt", "use_wsl": False}
    associate_file, error = service._mode_straight_args(cmd_args, context)
    assert error is None
    assert "-a" in cmd_args
    assert "0" in cmd_args
    assert "/path/wordlist.txt" in cmd_args


def test_mode_combinator_args_basic():
    """Test _mode_combinator_args builds combinator attack."""
    service = hs_module.HashcatService()
    cmd_args = []
    context = {
        "wordlist": "/path/wordlist1.txt",
        "wordlist_2": "/path/wordlist2.txt",
        "use_wsl": False,
    }
    associate_file, error = service._mode_combinator_args(cmd_args, context)
    assert error is None
    assert "-a" in cmd_args
    assert "1" in cmd_args
    assert "/path/wordlist1.txt" in cmd_args
    assert "/path/wordlist2.txt" in cmd_args


def test_append_mode_specific_args_straight():
    """Test _append_mode_specific_args routes to straight mode."""
    service = hs_module.HashcatService()
    cmd_args = []
    context = {"wordlist": "/path/wordlist.txt", "use_wsl": False}
    associate_file, error = service._append_mode_specific_args(
        cmd_args, "straight", context
    )
    assert error is None
    assert "-a" in cmd_args
    assert "0" in cmd_args


def test_append_mode_specific_args_unknown_defaults_straight():
    """Test _append_mode_specific_args defaults to straight mode."""
    service = hs_module.HashcatService()
    cmd_args = []
    context = {"wordlist": "/path/wordlist.txt", "use_wsl": False}
    associate_file, error = service._append_mode_specific_args(
        cmd_args, "unknown_mode", context
    )
    assert error is None
    assert "-a" in cmd_args
    assert "0" in cmd_args


def test_mode_association_args_success(tmp_path, monkeypatch):
    """Test _mode_association_args with successful candidate build."""
    service = hs_module.HashcatService()
    cmd_args = []
    context = {
        "hash_path": str(tmp_path / "test.22000"),
        "association_hint": "hint",
        "association_hints": ["hint1", "hint2"],
        "use_wsl": False,
    }

    # Mock successful build
    monkeypatch.setattr(
        service,
        "_build_association_candidates_v2",
        lambda *args, **kwargs: {"status": "success", "candidates": ["pass1", "pass2"]},
    )
    monkeypatch.setattr(
        service,
        "_write_association_candidates_file",
        lambda *args: str(tmp_path / "candidates.txt"),
    )

    result_file, error = service._mode_association_args(cmd_args, context)
    assert error is None
    assert result_file == str(tmp_path / "candidates.txt")
    assert cmd_args == ["-a", "0", str(tmp_path / "candidates.txt")]
    assert context["association_preview"] == {
        "status": "success",
        "candidates": ["pass1", "pass2"],
    }


def test_mode_association_args_build_failure(tmp_path, monkeypatch):
    """Test _mode_association_args with failed candidate build."""
    service = hs_module.HashcatService()
    cmd_args = []
    context = {
        "hash_path": str(tmp_path / "test.22000"),
        "association_hint": "hint",
        "association_hints": ["hint1", "hint2"],
        "use_wsl": False,
    }

    # Mock failed build
    monkeypatch.setattr(
        service,
        "_build_association_candidates_v2",
        lambda *args, **kwargs: {"status": "error", "message": "Build failed"},
    )

    result_file, error = service._mode_association_args(cmd_args, context)
    assert result_file is None
    assert error == "Build failed"
    assert cmd_args == ["-a", "0"]


def test_mode_association_hint_first_args_success(tmp_path, monkeypatch):
    """Test _mode_association_hint_first_args with successful candidate build."""
    service = hs_module.HashcatService()
    cmd_args = []
    context = {
        "hash_path": str(tmp_path / "test.22000"),
        "association_hint": "hint",
        "association_hints": ["hint1", "hint2"],
        "use_wsl": False,
    }

    # Mock successful build
    monkeypatch.setattr(
        service,
        "_build_association_candidates_v2",
        lambda *args, **kwargs: {"status": "success", "candidates": ["pass1", "pass2"]},
    )
    monkeypatch.setattr(
        service,
        "_write_association_candidates_file",
        lambda *args: str(tmp_path / "candidates.txt"),
    )

    result_file, error = service._mode_association_hint_first_args(cmd_args, context)
    assert error is None
    assert result_file == str(tmp_path / "candidates.txt")
    assert cmd_args == ["-a", "0", str(tmp_path / "candidates.txt")]
    assert context["association_preview"] == {
        "status": "success",
        "candidates": ["pass1", "pass2"],
    }


def test_mode_association_hint_first_args_build_failure(tmp_path, monkeypatch):
    """Test _mode_association_hint_first_args with failed candidate build."""
    service = hs_module.HashcatService()
    cmd_args = []
    context = {
        "hash_path": str(tmp_path / "test.22000"),
        "association_hint": "hint",
        "association_hints": ["hint1", "hint2"],
        "use_wsl": False,
    }

    # Mock failed build
    monkeypatch.setattr(
        service,
        "_build_association_candidates_v2",
        lambda *args, **kwargs: {"status": "error", "message": "Build failed"},
    )

    result_file, error = service._mode_association_hint_first_args(cmd_args, context)
    assert result_file is None
    assert error == "Build failed"
    assert cmd_args == ["-a", "0"]


def test_mode_association_hint_rule_args_success(tmp_path, monkeypatch):
    """Test _mode_association_hint_rule_args with successful candidate build."""
    service = hs_module.HashcatService()
    cmd_args = []
    context = {
        "hash_path": str(tmp_path / "test.22000"),
        "association_hint": "hint",
        "association_hints": ["hint1", "hint2"],
        "rule_file": "custom.rule",
        "use_wsl": False,
    }

    # Mock successful build
    monkeypatch.setattr(
        service,
        "_build_association_candidates_v2",
        lambda *args, **kwargs: {"status": "success", "candidates": ["pass1", "pass2"]},
    )
    monkeypatch.setattr(
        service,
        "_write_association_candidates_file",
        lambda *args: str(tmp_path / "candidates.txt"),
    )

    result_file, error = service._mode_association_hint_rule_args(cmd_args, context)
    assert error is None
    assert result_file == str(tmp_path / "candidates.txt")
    assert cmd_args == [
        "-a",
        "0",
        "-r",
        "custom.rule",
        str(tmp_path / "candidates.txt"),
    ]
    assert context["association_preview"] == {
        "status": "success",
        "candidates": ["pass1", "pass2"],
    }


def test_mode_association_hint_rule_args_default_rule(tmp_path, monkeypatch):
    """Test _mode_association_hint_rule_args with default rule file."""
    service = hs_module.HashcatService()
    cmd_args = []
    context = {
        "hash_path": str(tmp_path / "test.22000"),
        "association_hint": "hint",
        "association_hints": ["hint1", "hint2"],
        "use_wsl": False,
    }

    # Mock successful build
    monkeypatch.setattr(
        service,
        "_build_association_candidates_v2",
        lambda *args, **kwargs: {"status": "success", "candidates": ["pass1", "pass2"]},
    )
    monkeypatch.setattr(
        service,
        "_write_association_candidates_file",
        lambda *args: str(tmp_path / "candidates.txt"),
    )

    result_file, error = service._mode_association_hint_rule_args(cmd_args, context)
    assert error is None
    assert result_file == str(tmp_path / "candidates.txt")
    assert cmd_args == [
        "-a",
        "0",
        "-r",
        "rules/best64.rule",
        str(tmp_path / "candidates.txt"),
    ]
    assert context["association_preview"] == {
        "status": "success",
        "candidates": ["pass1", "pass2"],
    }


def test_mode_association_hint_rule_args_build_failure(tmp_path, monkeypatch):
    """Test _mode_association_hint_rule_args with failed candidate build."""
    service = hs_module.HashcatService()
    cmd_args = []
    context = {
        "hash_path": str(tmp_path / "test.22000"),
        "association_hint": "hint",
        "association_hints": ["hint1", "hint2"],
        "rule_file": "custom.rule",
        "use_wsl": False,
    }

    # Mock failed build
    monkeypatch.setattr(
        service,
        "_build_association_candidates_v2",
        lambda *args, **kwargs: {"status": "error", "message": "Build failed"},
    )

    result_file, error = service._mode_association_hint_rule_args(cmd_args, context)
    assert result_file is None
    assert error == "Build failed"
    assert cmd_args == ["-a", "0"]


def test_mode_association_args_with_wsl(tmp_path, monkeypatch):
    """Test _mode_association_args with WSL path conversion."""
    service = hs_module.HashcatService()
    cmd_args = []
    context = {
        "hash_path": str(tmp_path / "test.22000"),
        "association_hint": "hint",
        "association_hints": ["hint1", "hint2"],
        "use_wsl": True,
    }

    # Mock successful build
    monkeypatch.setattr(
        service,
        "_build_association_candidates_v2",
        lambda *args, **kwargs: {"status": "success", "candidates": ["pass1", "pass2"]},
    )
    monkeypatch.setattr(
        service,
        "_write_association_candidates_file",
        lambda *args: "/mnt/c/path/candidates.txt",
    )
    monkeypatch.setattr(service, "_to_wsl_path", lambda path: f"/wsl{path}")

    result_file, error = service._mode_association_args(cmd_args, context)
    assert error is None
    assert result_file == "/mnt/c/path/candidates.txt"
    assert cmd_args == ["-a", "0", "/wsl/mnt/c/path/candidates.txt"]


def test_mode_passphrase_args_success(tmp_path, monkeypatch):
    """Test _mode_passphrase_args with successful rule resolution."""
    service = hs_module.HashcatService()
    cmd_args = []
    context = {
        "wordlist": str(tmp_path / "wordlist.txt"),
        "rule_file": "custom.rule",
        "hashcat_bin": "hashcat",
        "custom_rules_dir": str(tmp_path / "rules"),
        "use_wsl": False,
    }

    # Mock successful rule resolution
    monkeypatch.setattr(
        service,
        "_resolve_passphrase_rule_paths",
        lambda *args: ("rule1.rule", "rule2.rule", None),
    )

    result_file, error = service._mode_passphrase_args(cmd_args, context)
    assert error is None
    assert result_file is None
    assert cmd_args == [
        "-a",
        "0",
        "-r",
        "rule1.rule",
        "-r",
        "rule2.rule",
        str(tmp_path / "wordlist.txt"),
    ]
    assert context["passphrase_rule_1"] == "rule1.rule"
    assert context["passphrase_rule_2"] == "rule2.rule"


def test_mode_passphrase_args_rule_resolution_failure(tmp_path, monkeypatch):
    """Test _mode_passphrase_args with rule resolution failure."""
    service = hs_module.HashcatService()
    cmd_args = []
    context = {
        "wordlist": str(tmp_path / "wordlist.txt"),
        "rule_file": "custom.rule",
        "hashcat_bin": "hashcat",
        "custom_rules_dir": str(tmp_path / "rules"),
        "use_wsl": False,
    }

    # Mock failed rule resolution
    monkeypatch.setattr(
        service,
        "_resolve_passphrase_rule_paths",
        lambda *args: (None, None, "Rule resolution failed"),
    )

    result_file, error = service._mode_passphrase_args(cmd_args, context)
    assert result_file is None
    assert error == "Rule resolution failed"
    assert cmd_args == ["-a", "0"]


def test_mode_passphrase_args_with_wsl(tmp_path, monkeypatch):
    """Test _mode_passphrase_args with WSL path conversion."""
    service = hs_module.HashcatService()
    cmd_args = []
    context = {
        "wordlist": "/mnt/c/wordlist.txt",
        "rule_file": "custom.rule",
        "hashcat_bin": "hashcat",
        "custom_rules_dir": "/mnt/c/rules",
        "use_wsl": True,
    }

    # Mock successful rule resolution
    monkeypatch.setattr(
        service,
        "_resolve_passphrase_rule_paths",
        lambda *args: ("/mnt/c/rule1.rule", "/mnt/c/rule2.rule", None),
    )
    monkeypatch.setattr(service, "_to_wsl_path", lambda path: f"/wsl{path}")

    result_file, error = service._mode_passphrase_args(cmd_args, context)
    assert error is None
    assert result_file is None
    assert cmd_args == [
        "-a",
        "0",
        "-r",
        "/wsl/mnt/c/rule1.rule",
        "-r",
        "/wsl/mnt/c/rule2.rule",
        "/wsl/mnt/c/wordlist.txt",
    ]


def test_mode_combinator_passphrase_args_success(tmp_path, monkeypatch):
    """Test _mode_combinator_passphrase_args with successful rule resolution."""
    service = hs_module.HashcatService()
    cmd_args = []
    context = {
        "wordlist": str(tmp_path / "wordlist1.txt"),
        "wordlist_2": str(tmp_path / "wordlist2.txt"),
        "rule_file": "custom.rule",
        "hashcat_bin": "hashcat",
        "custom_rules_dir": str(tmp_path / "rules"),
        "use_wsl": False,
    }

    # Mock successful rule resolution
    monkeypatch.setattr(
        service,
        "_resolve_passphrase_rule_paths",
        lambda *args: ("rule1.rule", "rule2.rule", None),
    )

    result_file, error = service._mode_combinator_passphrase_args(cmd_args, context)
    assert error is None
    assert result_file is None
    assert cmd_args == [
        "-a",
        "1",
        str(tmp_path / "wordlist1.txt"),
        str(tmp_path / "wordlist2.txt"),
        "-r",
        "rule1.rule",
        "-r",
        "rule2.rule",
    ]
    assert context["passphrase_rule_1"] == "rule1.rule"
    assert context["passphrase_rule_2"] == "rule2.rule"


def test_mode_combinator_passphrase_args_missing_wordlist2(tmp_path, monkeypatch):
    """Test _mode_combinator_passphrase_args with missing second wordlist."""
    service = hs_module.HashcatService()
    cmd_args = []
    context = {
        "wordlist": str(tmp_path / "wordlist1.txt"),
        "wordlist_2": None,
        "rule_file": "custom.rule",
        "hashcat_bin": "hashcat",
        "custom_rules_dir": str(tmp_path / "rules"),
        "use_wsl": False,
    }

    result_file, error = service._mode_combinator_passphrase_args(cmd_args, context)
    assert result_file is None
    assert error == "Second wordlist is required for combinator passphrase mode"
    assert cmd_args == ["-a", "1"]


def test_mode_combinator_passphrase_args_rule_resolution_failure(tmp_path, monkeypatch):
    """Test _mode_combinator_passphrase_args with rule resolution failure."""
    service = hs_module.HashcatService()
    cmd_args = []
    context = {
        "wordlist": str(tmp_path / "wordlist1.txt"),
        "wordlist_2": str(tmp_path / "wordlist2.txt"),
        "rule_file": "custom.rule",
        "hashcat_bin": "hashcat",
        "custom_rules_dir": str(tmp_path / "rules"),
        "use_wsl": False,
    }

    # Mock failed rule resolution
    monkeypatch.setattr(
        service,
        "_resolve_passphrase_rule_paths",
        lambda *args: (None, None, "Rule resolution failed"),
    )

    result_file, error = service._mode_combinator_passphrase_args(cmd_args, context)
    assert result_file is None
    assert error == "Rule resolution failed"
    assert cmd_args == ["-a", "1"]


def test_mode_combinator_passphrase_args_with_wsl(tmp_path, monkeypatch):
    """Test _mode_combinator_passphrase_args with WSL path conversion."""
    service = hs_module.HashcatService()
    cmd_args = []
    context = {
        "wordlist": "/mnt/c/wordlist1.txt",
        "wordlist_2": "/mnt/c/wordlist2.txt",
        "rule_file": "custom.rule",
        "hashcat_bin": "hashcat",
        "custom_rules_dir": "/mnt/c/rules",
        "use_wsl": True,
    }

    # Mock successful rule resolution
    monkeypatch.setattr(
        service,
        "_resolve_passphrase_rule_paths",
        lambda *args: ("/mnt/c/rule1.rule", "/mnt/c/rule2.rule", None),
    )
    monkeypatch.setattr(service, "_to_wsl_path", lambda path: f"/wsl{path}")

    result_file, error = service._mode_combinator_passphrase_args(cmd_args, context)
    assert error is None
    assert result_file is None
    assert cmd_args == [
        "-a",
        "1",
        "/wsl/mnt/c/wordlist1.txt",
        "/wsl/mnt/c/wordlist2.txt",
        "-r",
        "/wsl/mnt/c/rule1.rule",
        "-r",
        "/wsl/mnt/c/rule2.rule",
    ]


def test_mode_mask_profile_args_success(tmp_path, monkeypatch):
    """Test _mode_mask_profile_args with existing mask file."""
    service = hs_module.HashcatService()
    mask_file = tmp_path / "profile.hcmask"
    mask_file.write_text("mask content")
    cmd_args = []
    context = {"mask_file": str(mask_file), "use_wsl": False}

    result_file, error = service._mode_mask_profile_args(cmd_args, context)
    assert error is None
    assert result_file is None
    assert cmd_args == ["-a", "3", str(mask_file)]


def test_mode_mask_profile_args_missing_file(tmp_path, monkeypatch):
    """Test _mode_mask_profile_args with non-existent mask file."""
    service = hs_module.HashcatService()
    cmd_args = []
    context = {"mask_file": str(tmp_path / "missing.hcmask"), "use_wsl": False}

    result_file, error = service._mode_mask_profile_args(cmd_args, context)
    assert result_file is None
    assert error == f"Mask profile not found: {tmp_path / 'missing.hcmask'}"
    assert cmd_args == ["-a", "3"]


def test_mode_mask_profile_args_no_file_selected(tmp_path, monkeypatch):
    """Test _mode_mask_profile_args with no mask file selected."""
    service = hs_module.HashcatService()
    cmd_args = []
    context = {"mask_file": None, "use_wsl": False}

    result_file, error = service._mode_mask_profile_args(cmd_args, context)
    assert result_file is None
    assert error == "Mask profile not selected"
    assert cmd_args == ["-a", "3"]


def test_mode_mask_profile_args_with_wsl(tmp_path, monkeypatch):
    """Test _mode_mask_profile_args with WSL path conversion."""
    service = hs_module.HashcatService()
    mask_file = tmp_path / "profile.hcmask"
    mask_file.write_text("mask content")
    cmd_args = []
    context = {"mask_file": str(mask_file), "use_wsl": True}

    monkeypatch.setattr(service, "_to_wsl_path", lambda path: f"/wsl{path}")

    result_file, error = service._mode_mask_profile_args(cmd_args, context)
    assert error is None
    assert result_file is None
    assert cmd_args == ["-a", "3", f"/wsl{str(mask_file)}"]


def test_mode_hybrid_mask_profile_args_success(tmp_path, monkeypatch):
    """Test _mode_hybrid_mask_profile_args with existing mask file."""
    service = hs_module.HashcatService()
    mask_file = tmp_path / "profile.hcmask"
    mask_file.write_text("mask content")
    cmd_args = []
    context = {
        "wordlist": str(tmp_path / "wordlist.txt"),
        "mask_file": str(mask_file),
        "use_wsl": False,
    }

    result_file, error = service._mode_hybrid_mask_profile_args(cmd_args, context)
    assert error is None
    assert result_file is None
    assert cmd_args == ["-a", "6", str(tmp_path / "wordlist.txt"), str(mask_file)]


def test_mode_hybrid_mask_profile_args_missing_file(tmp_path, monkeypatch):
    """Test _mode_hybrid_mask_profile_args with non-existent mask file."""
    service = hs_module.HashcatService()
    cmd_args = []
    context = {
        "wordlist": str(tmp_path / "wordlist.txt"),
        "mask_file": str(tmp_path / "missing.hcmask"),
        "use_wsl": False,
    }

    result_file, error = service._mode_hybrid_mask_profile_args(cmd_args, context)
    assert result_file is None
    assert error == f"Mask profile not found: {tmp_path / 'missing.hcmask'}"
    assert cmd_args == ["-a", "6"]


def test_mode_hybrid_mask_profile_args_no_file_selected(tmp_path, monkeypatch):
    """Test _mode_hybrid_mask_profile_args with no mask file selected."""
    service = hs_module.HashcatService()
    cmd_args = []
    context = {
        "wordlist": str(tmp_path / "wordlist.txt"),
        "mask_file": None,
        "use_wsl": False,
    }

    result_file, error = service._mode_hybrid_mask_profile_args(cmd_args, context)
    assert result_file is None
    assert error == "Mask profile not selected"
    assert cmd_args == ["-a", "6"]


def test_mode_hybrid_mask_profile_args_with_wsl(tmp_path, monkeypatch):
    """Test _mode_hybrid_mask_profile_args with WSL path conversion."""
    service = hs_module.HashcatService()
    mask_file = tmp_path / "profile.hcmask"
    mask_file.write_text("mask content")
    cmd_args = []
    context = {
        "wordlist": "/mnt/c/wordlist.txt",
        "mask_file": str(mask_file),
        "use_wsl": True,
    }

    monkeypatch.setattr(service, "_to_wsl_path", lambda path: f"/wsl{path}")

    result_file, error = service._mode_hybrid_mask_profile_args(cmd_args, context)
    assert error is None
    assert result_file is None
    assert cmd_args == ["-a", "6", "/wsl/mnt/c/wordlist.txt", f"/wsl{str(mask_file)}"]


def test_mode_hybrid_reverse_mask_profile_args_success(tmp_path, monkeypatch):
    """Test _mode_hybrid_reverse_mask_profile_args with existing mask file."""
    service = hs_module.HashcatService()
    mask_file = tmp_path / "profile.hcmask"
    mask_file.write_text("mask content")
    cmd_args = []
    context = {
        "wordlist": str(tmp_path / "wordlist.txt"),
        "mask_file": str(mask_file),
        "use_wsl": False,
    }

    result_file, error = service._mode_hybrid_reverse_mask_profile_args(
        cmd_args, context
    )
    assert error is None
    assert result_file is None
    assert cmd_args == ["-a", "7", str(mask_file), str(tmp_path / "wordlist.txt")]


def test_mode_hybrid_reverse_mask_profile_args_missing_file(tmp_path, monkeypatch):
    """Test _mode_hybrid_reverse_mask_profile_args with non-existent mask file."""
    service = hs_module.HashcatService()
    cmd_args = []
    context = {
        "wordlist": str(tmp_path / "wordlist.txt"),
        "mask_file": str(tmp_path / "missing.hcmask"),
        "use_wsl": False,
    }

    result_file, error = service._mode_hybrid_reverse_mask_profile_args(
        cmd_args, context
    )
    assert result_file is None
    assert error == f"Mask profile not found: {tmp_path / 'missing.hcmask'}"
    assert cmd_args == ["-a", "7"]


def test_mode_hybrid_reverse_mask_profile_args_no_file_selected(tmp_path, monkeypatch):
    """Test _mode_hybrid_reverse_mask_profile_args with no mask file selected."""
    service = hs_module.HashcatService()
    cmd_args = []
    context = {
        "wordlist": str(tmp_path / "wordlist.txt"),
        "mask_file": None,
        "use_wsl": False,
    }

    result_file, error = service._mode_hybrid_reverse_mask_profile_args(
        cmd_args, context
    )
    assert result_file is None
    assert error == "Mask profile not selected"
    assert cmd_args == ["-a", "7"]


def test_mode_hybrid_reverse_mask_profile_args_with_wsl(tmp_path, monkeypatch):
    """Test _mode_hybrid_reverse_mask_profile_args with WSL path conversion."""
    service = hs_module.HashcatService()
    mask_file = tmp_path / "profile.hcmask"
    mask_file.write_text("mask content")
    cmd_args = []
    context = {
        "wordlist": "/mnt/c/wordlist.txt",
        "mask_file": str(mask_file),
        "use_wsl": True,
    }

    monkeypatch.setattr(service, "_to_wsl_path", lambda path: f"/wsl{path}")

    result_file, error = service._mode_hybrid_reverse_mask_profile_args(
        cmd_args, context
    )
    assert error is None
    assert result_file is None
    assert cmd_args == ["-a", "7", f"/wsl{str(mask_file)}", "/wsl/mnt/c/wordlist.txt"]


def test_mode_straight_args_with_wsl(tmp_path, monkeypatch):
    """Test _mode_straight_args with WSL path conversion."""
    service = hs_module.HashcatService()
    cmd_args = []
    context = {"wordlist": "/mnt/c/wordlist.txt", "use_wsl": True}

    monkeypatch.setattr(service, "_to_wsl_path", lambda path: f"/wsl{path}")

    result_file, error = service._mode_straight_args(cmd_args, context)
    assert error is None
    assert result_file is None
    assert cmd_args == ["-a", "0", "/wsl/mnt/c/wordlist.txt"]


def test_generate_funny_multi_name(tmp_path, monkeypatch):
    """Test _generate_funny_multi_name generates unique batch names."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    service = hs_module.HashcatService()

    name = service._generate_funny_multi_name()
    assert name.startswith("batch_")
    assert name.endswith(".22000")
    assert "_" in name  # Should have multiple parts


def test_generate_funny_multi_name_fallback(tmp_path, monkeypatch):
    """Test _generate_funny_multi_name fallback when collisions occur."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    service = hs_module.HashcatService()

    # Mock os.path.exists to always return True (collision)
    monkeypatch.setattr(os.path, "exists", lambda path: True)

    # Mock datetime.now to return a mock datetime object
    class MockDatetime:
        @staticmethod
        def now():
            class MockDt:
                def strftime(self, fmt):
                    return "20231201_120000"

            return MockDt()

    monkeypatch.setattr(hs_module, "datetime", MockDatetime)

    # Mock random
    monkeypatch.setattr(random, "randint", lambda a, b: 1234)

    name = service._generate_funny_multi_name()
    assert name == "batch_20231201_120000_1234.22000"
