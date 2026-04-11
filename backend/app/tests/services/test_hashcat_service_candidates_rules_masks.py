from app.services import hashcat_service as hs_module


def test_generate_funny_multi_name_no_collision(tmp_path, monkeypatch):
    """Test _generate_funny_multi_name with no collision."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))

    service = hs_module.HashcatService()
    name = service._generate_funny_multi_name()
    assert name.endswith(".22000")
    assert name.startswith("batch_")


def test_generate_funny_multi_name_with_collision(tmp_path, monkeypatch):
    """Test _generate_funny_multi_name with collision."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(
        hs_module.random,
        "choice",
        lambda seq: seq[0],
    )
    monkeypatch.setattr(
        hs_module.random,
        "sample",
        lambda seq, _count: list(seq),
    )
    monkeypatch.setattr(hs_module.random, "randint", lambda *_args, **_kwargs: 42)
    monkeypatch.setattr(hs_module.os.path, "exists", lambda _path: True)

    service = hs_module.HashcatService()
    name = service._generate_funny_multi_name()
    assert name.startswith("batch_")
    assert name.endswith(".22000")


def test_association_candidate_cap_applied(tmp_path, monkeypatch):
    """Test association candidates are capped."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    hash_file = tmp_path / "cap.22000"
    # Create hash with long SSID to generate many candidates
    hash_file.write_text(
        "WPA*02*deadbeef*aabbccddeeff*001122334455*"
        + "4142434445464748494a4b4c4d4e4f50"
        + "*00\n",
        encoding="utf-8",
    )

    service = hs_module.HashcatService()
    result = service._build_association_candidates_v2(str(hash_file))
    assert result["status"] == "success"
    assert result["candidate_count"] <= result["cap"]


def test_association_variant_candidates_with_suffixes():
    """Test _association_variant_candidates adds suffixes."""
    service = hs_module.HashcatService()
    candidates = service._association_variant_candidates("TestNet")
    assert "TestNet123" in candidates
    assert "TestNet2024" in candidates
    assert "TestNet2025" in candidates
    assert "TestNet2026" in candidates


def test_association_variant_candidates_case_variants():
    """Test _association_variant_candidates generates case variants."""
    service = hs_module.HashcatService()
    candidates = service._association_variant_candidates("TestNet")
    assert "testnet" in candidates
    assert "TESTNET" in candidates
    assert "TestNet" in candidates


def test_association_variant_candidates_separator_stripping():
    """Test _association_variant_candidates strips separators."""
    service = hs_module.HashcatService()
    candidates = service._association_variant_candidates("Test-Net_Name.123")
    assert "TestNetName123" in candidates
    assert "testnetname123" in candidates


def test_normalize_association_seed_empty():
    """Test _normalize_association_seed with empty string."""
    service = hs_module.HashcatService()
    assert service._normalize_association_seed("") == ""


def test_normalize_association_seed_whitespace_only():
    """Test _normalize_association_seed with whitespace only."""
    service = hs_module.HashcatService()
    assert service._normalize_association_seed("   ") == ""


def test_normalize_association_seed_multiple_spaces():
    """Test _normalize_association_seed collapses multiple spaces."""
    service = hs_module.HashcatService()
    assert service._normalize_association_seed("a  b   c") == "a b c"


def test_extract_essids_from_hash_lines_hex_decode():
    """Test _extract_essids_from_hash_lines decodes hex SSIDs."""
    service = hs_module.HashcatService()
    lines = [
        "WPA*02*deadbeef*aabbccddeeff*001122334455*48656c6c6f*00",  # "Hello" in hex
    ]
    essids = service._extract_essids_from_hash_lines(lines)
    assert "Hello" in essids


def test_extract_essids_from_hash_lines_skips_invalid():
    """Test _extract_essids_from_hash_lines skips invalid lines."""
    service = hs_module.HashcatService()
    lines = [
        "not a hash",
        "WPA*01*short",
        "WPA*02*deadbeef*aabbccddeeff*001122334455*57696669*00",  # "Wifi"
    ]
    essids = service._extract_essids_from_hash_lines(lines)
    assert len(essids) == 1
    assert essids[0] == "Wifi"


def test_get_attack_mode_policy_known_modes():
    """Test _get_attack_mode_policy for known modes."""
    service = hs_module.HashcatService()
    assert service._get_attack_mode_policy("straight")["requires_wordlist"] is True
    assert service._get_attack_mode_policy("mask")["requires_wordlist"] is False
    assert service._get_attack_mode_policy("combinator")["requires_wordlist"] is True


def test_get_attack_mode_policy_unknown_mode():
    """Test _get_attack_mode_policy falls back to straight for unknown."""
    service = hs_module.HashcatService()
    policy = service._get_attack_mode_policy("unknown_mode")
    assert policy["requires_wordlist"] is True


def test_requires_wordlist_various_modes():
    """Test _requires_wordlist for various attack modes."""
    service = hs_module.HashcatService()
    assert service._requires_wordlist("straight") is True
    assert service._requires_wordlist("rules") is True
    assert service._requires_wordlist("mask") is False
    assert service._requires_wordlist("digits") is False
    assert service._requires_wordlist("association") is False
    assert service._requires_wordlist("hybrid") is True


def test_supports_increment_various_modes():
    """Test _supports_increment for various attack modes."""
    service = hs_module.HashcatService()
    assert service._supports_increment("mask") is True
    assert service._supports_increment("digits") is True
    assert service._supports_increment("straight") is False
    assert service._supports_increment("rules") is False
    assert service._supports_increment("combinator") is False


def test_supports_slow_candidates_various_modes():
    """Test _supports_slow_candidates for various attack modes."""
    service = hs_module.HashcatService()
    assert service._supports_slow_candidates("straight") is True
    assert service._supports_slow_candidates("rules") is True
    assert service._supports_slow_candidates("combinator") is True
    assert service._supports_slow_candidates("association") is False
    assert service._supports_slow_candidates("mask") is False


def test_convert_pcap_now_wsl_mode(tmp_path, monkeypatch):
    """Test convert_pcap_now with WSL mode."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    pcap = tmp_path / "test.pcap"
    pcap.write_text("pcap", encoding="utf-8")

    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda _self: {"hcxpcapngtool_path": "hcx"},
    )
    monkeypatch.setattr(
        hs_module.BaseService, "_should_use_wsl", lambda *_a, **_k: True
    )

    # Make _to_wsl_path return the actual local path so mock can write to it
    def _fake_wsl_path(_self, p):
        return str(p)

    monkeypatch.setattr(hs_module.BaseService, "_to_wsl_path", _fake_wsl_path)

    captured = {"cmd": None}

    def mock_run(*args, **kwargs):
        captured["cmd"] = args[0]
        cmd = args[0]
        output_file = cmd[cmd.index("-o") + 1]
        with open(output_file, "w") as f:
            f.write("WPA*02*deadbeef*aabbccddeeff*001122334455*TestNet*00\n")
        return type("_Result", (), {"returncode": 0, "stderr": "", "stdout": ""})()

    monkeypatch.setattr(hs_module.subprocess, "run", mock_run)

    service = hs_module.HashcatService()
    result = service.convert_pcap_now("test.pcap")
    assert result["status"] == "success"
    assert captured["cmd"][0] == "wsl"


def test_convert_pcap_now_absolute_hcx_path(tmp_path, monkeypatch):
    """Test convert_pcap_now with absolute hcx path sets cwd."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    pcap = tmp_path / "test.pcap"
    pcap.write_text("pcap", encoding="utf-8")

    hcx_dir = tmp_path / "tools"
    hcx_dir.mkdir()
    hcx_bin = hcx_dir / "hcxpcapngtool"
    hcx_bin.write_text("fake", encoding="utf-8")

    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda _self: {"hcxpcapngtool_path": str(hcx_bin)},
    )
    monkeypatch.setattr(
        hs_module.BaseService, "_should_use_wsl", lambda *_a, **_k: False
    )

    captured = {"cwd": None}

    def mock_run(*args, **kwargs):
        captured["cwd"] = kwargs.get("cwd")
        cmd = args[0]
        output_file = cmd[cmd.index("-o") + 1]
        with open(output_file, "w") as f:
            f.write("WPA*02*deadbeef*aabbccddeeff*001122334455*TestNet*00\n")
        return type("_Result", (), {"returncode": 0, "stderr": "", "stdout": ""})()

    monkeypatch.setattr(hs_module.subprocess, "run", mock_run)

    service = hs_module.HashcatService()
    result = service.convert_pcap_now("test.pcap")
    assert result["status"] == "success"
    assert captured["cwd"] == str(hcx_dir)


def test_run_attack_with_wordlist_2(tmp_path, monkeypatch):
    """Test run_attack with wordlist_2 parameter."""
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

    def _add_entry(_f, _tool, cmd, params, **_kwargs):
        captured["params"] = params
        return "e1"

    monkeypatch.setattr(hs_module.history_service, "add_entry", _add_entry)
    monkeypatch.setattr(hs_module.job_manager, "start_job", lambda *_a, **_k: "j1")

    hash_file = tmp_path / "h.22000"
    hash_file.write_text("hash\n", encoding="utf-8")

    service = hs_module.HashcatService()
    out = service.run_attack(
        "h.22000",
        attack_mode="combinator",
        wordlist="wl1.txt",
        wordlist_2="wl2.txt",
    )
    assert out["status"] == "started"
    assert captured["params"]["wordlist"] == "wl1.txt"
    assert captured["params"]["wordlist_2"] == "wl2.txt"


def test_run_attack_with_rule_file(tmp_path, monkeypatch):
    """Test run_attack with rule_file parameter."""
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

    def _add_entry(_f, _tool, cmd, params, **_kwargs):
        captured["params"] = params
        return "e1"

    monkeypatch.setattr(hs_module.history_service, "add_entry", _add_entry)
    monkeypatch.setattr(hs_module.job_manager, "start_job", lambda *_a, **_k: "j1")

    hash_file = tmp_path / "h.22000"
    hash_file.write_text("hash\n", encoding="utf-8")

    service = hs_module.HashcatService()
    out = service.run_attack(
        "h.22000",
        attack_mode="rules",
        wordlist="wl.txt",
        rule_file="custom.rule",
    )
    assert out["status"] == "started"
    assert captured["params"]["rule"] == "custom.rule"


def test_run_attack_with_device_id(tmp_path, monkeypatch):
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


def test_run_attack_removes_old_cracked_file(tmp_path, monkeypatch):
    """Test run_attack removes existing cracked file before starting."""
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

    service = hs_module.HashcatService()
    out = service.run_attack("h.22000", wordlist="wl.txt")
    assert out["status"] == "started"
    assert not cracked_file.exists()


def test_run_attack_output_format_args(tmp_path, monkeypatch):
    """Test run_attack includes outfile-format and autohex-disable."""
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
    out = service.run_attack("h.22000", wordlist="wl.txt")
    assert out["status"] == "started"
    assert "--outfile-format" in captured["cmd"]
    assert "--outfile-autohex-disable" in captured["cmd"]


def test_run_attack_status_timer_args(tmp_path, monkeypatch):
    """Test run_attack includes status and status-timer args."""
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
    out = service.run_attack("h.22000", wordlist="wl.txt")
    assert out["status"] == "started"
    assert "--status" in captured["cmd"]
    assert "--status-timer" in captured["cmd"]
    assert "--force" in captured["cmd"]
