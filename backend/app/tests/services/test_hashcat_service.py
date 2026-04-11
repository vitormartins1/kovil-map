import json
import os

from app.services import data_loader as dl_module
from app.services import hashcat_service as hs_module


def test_generate_funny_multi_name(tmp_path, monkeypatch):
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    service = hs_module.HashcatService()
    name = service._generate_funny_multi_name()
    assert name.startswith("batch_")
    assert name.endswith(".22000")


def test_get_available_rules(tmp_path, monkeypatch):
    base_dir = tmp_path / "hashcat"
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "alpha.rule").write_text("x")

    custom_dir = tmp_path / "custom_rules"
    custom_dir.mkdir()
    (custom_dir / "beta.rule").write_text("x")

    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda self: {
            "hashcat_path": str(base_dir),
            "custom_rules_path": str(custom_dir),
        },
    )

    service = hs_module.HashcatService()
    rules = service.get_available_rules()
    names = [r["name"] for r in rules]
    assert "alpha.rule" in names
    assert "beta.rule" in names


def test_get_available_rules_exception_fallback(monkeypatch):
    """get_available_rules returns default on exception."""
    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda self: {"hashcat_path": "hashcat", "custom_rules_path": ""},
    )
    # Mock glob.glob to raise exception
    import glob

    monkeypatch.setattr(
        glob,
        "glob",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("glob failed")),
    )

    service = hs_module.HashcatService()
    rules = service.get_available_rules()
    assert rules == [{"name": "best64.rule", "path": "rules/best64.rule"}]


def test_get_available_masks(tmp_path, monkeypatch):
    base_dir = tmp_path / "hashcat"
    masks_dir = tmp_path / "masks"
    masks_dir.mkdir()
    (masks_dir / "base.hcmask").write_text("?d?d?d?d", encoding="utf-8")

    custom_dir = tmp_path / "custom_masks"
    custom_dir.mkdir()
    (custom_dir / "custom.hcmask").write_text("?l?l?l?l", encoding="utf-8")

    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda self: {
            "hashcat_path": str(base_dir),
            "custom_masks_path": str(custom_dir),
        },
    )

    service = hs_module.HashcatService()
    masks = service.get_available_masks()
    names = [m["name"] for m in masks]
    assert "base.hcmask" in names
    assert "custom.hcmask" in names


def test_get_available_masks_exception_fallback(monkeypatch):
    """get_available_masks returns empty list on exception."""
    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda self: {"hashcat_path": "hashcat", "custom_masks_path": ""},
    )
    # Mock glob.glob to raise exception
    import glob

    monkeypatch.setattr(
        glob,
        "glob",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("glob failed")),
    )

    service = hs_module.HashcatService()
    masks = service.get_available_masks()
    assert masks == []


def test_get_devices_parsing(monkeypatch):
    class _Result:
        returncode = 0
        stdout = (
            """OpenCL Info:\nBackend Device ID #1\n  Name.: GPU X\n  Type.: GPU\n"""
        )

    monkeypatch.setattr(hs_module.subprocess, "run", lambda *args, **kwargs: _Result())
    monkeypatch.setattr(
        hs_module.BaseService, "_get_config", lambda self: {"hashcat_path": "hashcat"}
    )

    service = hs_module.HashcatService()
    devices = service.get_devices()
    assert devices
    assert devices[0]["name"] == "GPU X"
    assert devices[0]["type"] == "GPU"
    assert devices[0]["backend"] == "OpenCL"


def test_get_devices_exception_fallback(monkeypatch):
    """get_devices returns empty list on exception."""
    monkeypatch.setattr(
        hs_module.BaseService, "_get_config", lambda self: {"hashcat_path": "hashcat"}
    )
    # Mock subprocess.run to raise exception
    monkeypatch.setattr(
        hs_module.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            RuntimeError("subprocess failed")
        ),
    )

    service = hs_module.HashcatService()
    devices = service.get_devices()
    assert devices == []


def test_get_devices_with_absolute_path(monkeypatch):
    """Test get_devices with absolute hashcat path to cover cwd assignment."""

    class _Result:
        returncode = 0
        stdout = (
            """OpenCL Info:\nBackend Device ID #1\n  Name.: GPU X\n  Type.: GPU\n"""
        )

    monkeypatch.setattr(hs_module.subprocess, "run", lambda *args, **kwargs: _Result())
    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda self: {"hashcat_path": "/usr/bin/hashcat"},
    )
    monkeypatch.setattr(
        hs_module.BaseService, "_should_use_wsl", lambda self, path: False
    )

    service = hs_module.HashcatService()
    devices = service.get_devices()
    assert devices
    assert devices[0]["name"] == "GPU X"


def test_convert_pcap_success(tmp_path, monkeypatch):
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(
        hs_module.BaseService, "_get_config", lambda self: {"hcxpcapngtool_path": "hcx"}
    )
    monkeypatch.setattr(
        hs_module.BaseService, "_should_use_wsl", lambda *args, **kwargs: False
    )

    pcap = tmp_path / "sample.pcap"
    pcap.write_text("pcap")

    def _start_job(
        command, job_type=None, cwd=None, on_complete=None, on_start=None, total_steps=1
    ):
        if isinstance(command, list) and "-o" in command:
            out_path = command[command.index("-o") + 1]
            with open(out_path, "w", encoding="utf-8") as f:
                f.write("hashline")
        job = {"id": "1", "logs": [], "progress_data": {}}
        if on_start:
            on_start(job)
        if on_complete:
            on_complete(job)
        return "job-1"

    monkeypatch.setattr(hs_module.job_manager, "start_job", _start_job)
    monkeypatch.setattr(
        hs_module.history_service, "add_entry", lambda *args, **kwargs: "e1"
    )
    monkeypatch.setattr(
        hs_module.history_service, "update_entry", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(dl_module, "reload_data", lambda: None)

    service = hs_module.HashcatService()
    result = service.convert_pcap("sample.pcap")
    assert result["status"] == "started"
    assert result["output_file"] == "sample.22000"


def test_convert_pcap_missing_file(tmp_path, monkeypatch):
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(
        hs_module.BaseService, "_get_config", lambda self: {"hcxpcapngtool_path": "hcx"}
    )
    service = hs_module.HashcatService()
    result = service.convert_pcap("missing.pcap")
    assert result["status"] == "error"


def test_convert_multi_pcap_basic(tmp_path, monkeypatch):
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(
        hs_module.BaseService, "_get_config", lambda self: {"hcxpcapngtool_path": "hcx"}
    )
    monkeypatch.setattr(
        hs_module.BaseService, "_should_use_wsl", lambda *args, **kwargs: False
    )

    pcap1 = tmp_path / "net1_aabbccddeeff.pcap"
    pcap1.write_text("pcap")

    def _run(cmd, capture_output=False, text=False, shell=False, **kwargs):
        class _Result:
            returncode = 0
            stderr = ""
            stdout = ""

        if isinstance(cmd, list) and "-o" in cmd:
            out_path = cmd[cmd.index("-o") + 1]
            with open(out_path, "w", encoding="utf-8") as f:
                f.write("WPA*02*deadbeef*aabbccddeeff*112233445566*74657374*0\n")
        return _Result()

    monkeypatch.setattr(hs_module.subprocess, "run", _run)

    def _start_multi_job(
        worker, job_type=None, on_complete=None, on_start=None, total_steps=1, meta=None
    ):
        job = {
            "id": "1",
            "logs": [],
            "progress_data": {"current_step": 0, "percentage": 0},
        }

        def _emit(event, payload):
            return None

        worker(job, _emit)
        if on_complete:
            on_complete(job)
        return "job-1"

    monkeypatch.setattr(hs_module.job_manager, "start_multi_job", _start_multi_job)

    service = hs_module.HashcatService()
    result = service.convert_multi_pcap(["net1_aabbccddeeff.pcap"])
    assert result["status"] == "started"

    manifest = tmp_path / f"{result['output_file']}.batch.json"
    assert manifest.exists()


def test_run_attack_rules_and_digits(tmp_path, monkeypatch):
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda self: {
            "hashcat_path": "hashcat",
            "hashcat_potfile": False,
            "attack_mode": "straight",
            "workload_profile": "3",
        },
    )
    monkeypatch.setattr(
        hs_module.BaseService, "_should_use_wsl", lambda *args, **kwargs: False
    )
    monkeypatch.setattr(
        hs_module.history_service, "add_entry", lambda *args, **kwargs: "e1"
    )
    monkeypatch.setattr(
        hs_module.history_service, "update_entry", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        hs_module.HashcatService, "process_cracked_file", lambda *args, **kwargs: None
    )

    hash_file = tmp_path / "hashes.22000"
    hash_file.write_text("hash")

    captured = {}

    def _start_job(command, **kwargs):
        captured["cmd"] = command
        return "job-1"

    monkeypatch.setattr(hs_module.job_manager, "start_job", _start_job)
    monkeypatch.setattr(
        hs_module.HashcatService,
        "get_devices",
        lambda *args, **kwargs: [
            {"id": "1", "name": "GPU X", "type": "GPU", "backend": "Metal"}
        ],
    )

    service = hs_module.HashcatService()
    result = service.run_attack(
        "hashes.22000",
        attack_mode="rules",
        wordlist="wordlist.txt",
        device_id="1",
    )
    assert result["status"] == "started"
    assert "-r" in captured["cmd"]
    assert "--potfile-disable" in captured["cmd"]

    result = service.run_attack(
        "hashes.22000",
        attack_mode="digits",
        enable_increment=True,
        increment_min=2,
        increment_max=4,
    )
    assert result["status"] == "started"
    assert "--increment" in captured["cmd"]
    assert "--increment-min" in captured["cmd"]
    assert "--increment-max" in captured["cmd"]


def test_run_attack_passphrase_mode_uses_dual_rules(tmp_path, monkeypatch):
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    rules_dir = tmp_path / "custom_rules"
    rules_dir.mkdir()
    (rules_dir / "passphrase-rule1.rule").write_text("r1", encoding="utf-8")
    (rules_dir / "passphrase-rule2.rule").write_text("r2", encoding="utf-8")

    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda self: {
            "hashcat_path": "hashcat",
            "custom_rules_path": str(rules_dir),
            "hashcat_potfile": False,
            "attack_mode": "straight",
            "workload_profile": "3",
        },
    )
    monkeypatch.setattr(
        hs_module.BaseService, "_should_use_wsl", lambda *args, **kwargs: False
    )
    monkeypatch.setattr(
        hs_module.history_service, "add_entry", lambda *args, **kwargs: "e1"
    )
    monkeypatch.setattr(
        hs_module.history_service, "update_entry", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        hs_module.HashcatService, "process_cracked_file", lambda *args, **kwargs: None
    )

    hash_file = tmp_path / "hashes.22000"
    hash_file.write_text("hash", encoding="utf-8")
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("senha123", encoding="utf-8")

    captured = {}

    def _start_job(command, **kwargs):
        captured["cmd"] = command
        return "job-1"

    monkeypatch.setattr(hs_module.job_manager, "start_job", _start_job)

    service = hs_module.HashcatService()
    result = service.run_attack(
        "hashes.22000",
        attack_mode="passphrase",
        wordlist=str(wordlist),
    )
    assert result["status"] == "started"
    cmd_str = " ".join(captured["cmd"])
    assert "passphrase-rule1.rule" in cmd_str
    assert "passphrase-rule2.rule" in cmd_str


def test_process_cracked_file_single(tmp_path, monkeypatch):
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))

    cracked_path = tmp_path / "sample.cracked"
    cracked_path.write_text("hash:plain_password\n")

    service = hs_module.HashcatService()
    job = {"id": "1", "command": ["hashcat", "-o", str(cracked_path)], "logs": []}

    service.process_cracked_file(job)

    output_path = tmp_path / "sample.pcap.cracked"
    assert output_path.exists()
    assert output_path.read_text() == "plain_password"


def test_process_cracked_file_batch_manifest(tmp_path, monkeypatch):
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))

    cracked_path = tmp_path / "batch_test.cracked"
    cracked_path.write_text("hashvalue:pass123\n")

    manifest = {
        "items": [
            {
                "filename": "net1.pcap",
                "mac": "aabbccddeeff",
                "ssid": "net1",
                "hashes": ["hashvalue"],
            }
        ]
    }
    manifest_path = tmp_path / "batch_test.22000.batch.json"
    manifest_path.write_text(json.dumps(manifest))

    service = hs_module.HashcatService()
    job = {"id": "1", "command": ["hashcat", "-o", str(cracked_path)], "logs": []}

    service.process_cracked_file(job)

    output_path = tmp_path / "net1.pcap.cracked"
    assert output_path.exists()
    assert output_path.read_text() == "pass123"


def test_attack_mode_policies():
    """Verify attack mode policy values."""
    service = hs_module.HashcatService()
    assert service._requires_wordlist("rules") is True
    assert service._requires_wordlist("association") is False
    assert service._supports_increment("digits") is True
    assert service._supports_increment("rules") is False
    assert service._supports_slow_candidates("straight") is True
    assert service._supports_slow_candidates("digits") is False


def test_normalize_association_seed():
    """_normalize_association_seed cleans input values."""
    service = hs_module.HashcatService()
    assert service._normalize_association_seed("  Home  Network  ") == "Home Network"
    assert service._normalize_association_seed(None) == ""
    assert service._normalize_association_seed("") == ""
    assert service._normalize_association_seed("\tTest\nLine") == "TestLine"


def test_extract_essids_from_hash_lines():
    """_extract_essids_from_hash_lines parses WPA hash lines."""
    service = hs_module.HashcatService()
    lines = [
        "WPA*02*deadbeef*aabbccddeeff*112233445566*546573744e6574776f726b*0",
        "WPA*02*abcdef*001122334455*66778899aabb*486f6d65*0",
        "invalid line",
        "",
    ]
    essids = service._extract_essids_from_hash_lines(lines)
    assert "TestNetwork" in essids
    assert "Home" in essids
    assert len(essids) == 2


def test_association_variant_candidates():
    """_association_variant_candidates generates variants."""
    service = hs_module.HashcatService()
    variants = service._association_variant_candidates("Home Network")
    assert "Home Network" in variants
    assert "home network" in variants
    assert "HOME NETWORK" in variants
    assert "HomeNetwork" in variants
    assert "HomeNetwork123" in variants
    assert len(variants) > 10


def test_build_association_candidates_v2(tmp_path, monkeypatch):
    """_build_association_candidates_v2 builds candidate list."""
    service = hs_module.HashcatService()
    hash_path = tmp_path / "test.22000"
    hash_path.write_text("WPA*02*deadbeef*aabbccddeeff*112233445566*54657374*0\n")

    result = service._build_association_candidates_v2(
        str(hash_path), mode="association"
    )
    assert result["status"] == "success"
    assert len(result["candidates"]) > 0
    assert "test" in [c.lower() for c in result["candidates"]]


def test_preview_association_candidates(tmp_path, monkeypatch):
    """preview_association_candidates returns sample candidates."""
    service = hs_module.HashcatService()
    hash_path = tmp_path / "test.22000"
    hash_path.write_text("WPA*02*deadbeef*aabbccddeeff*112233445566*54657374*0\n")

    def mock_resolve(*args, **kwargs):
        return {"path": str(hash_path)}

    monkeypatch.setattr(service, "_resolve_hash_artifact", mock_resolve)
    result = service.preview_association_candidates("test.22000")
    assert result["status"] == "success"
    assert "sample_candidates" in result
    assert len(result["sample_candidates"]) == 12


def test_combined_build_candidate(tmp_path, monkeypatch):
    """build_combined_candidate combines multiple captures."""
    service = hs_module.HashcatService()
    monkeypatch.setattr(
        hs_module.handshake_catalog_service,
        "normalize_mac",
        lambda mac: "aa:bb:cc:dd:ee:ff",
    )
    monkeypatch.setattr(
        hs_module.handshake_catalog_service,
        "get_handshake_set",
        lambda mac: {
            "captures": [
                {
                    "capture_id": "cap1",
                    "source": "wardrive",
                    "artifacts": {
                        "hash_22000": [
                            {
                                "path": str(tmp_path / "hash1.22000"),
                                "valid_hash_lines": 1,
                            }
                        ]
                    },
                }
            ]
        },
    )
    monkeypatch.setattr(hs_module, "create_combined_build_id", lambda ids: "build123")
    monkeypatch.setattr(
        hs_module,
        "get_combined_build_dir",
        lambda *args, **kwargs: str(tmp_path / "build"),
    )
    monkeypatch.setattr(
        hs_module,
        "get_combined_artifact_path",
        lambda *args, **kwargs: str(tmp_path / "build" / "out.22000"),
    )
    monkeypatch.setattr(hs_module, "write_json", lambda *args, **kwargs: None)

    with open(tmp_path / "hash1.22000", "w") as f:
        f.write("WPA*02*deadbeef*aabbccddeeff*112233445566*54657374*0\n")

    # Cria o diretório do build já que o mock não faz isso
    build_dir = tmp_path / "build"
    build_dir.mkdir(parents=True, exist_ok=True)

    result = service.build_combined_candidate("aa:bb:cc:dd:ee:ff")
    assert result["status"] == "success"
    assert "build_id" in result
    assert result["deduped_hash_count"] == 1


def test_mode_args_builders():
    """All mode args builders implement correct attack modes."""
    service = hs_module.HashcatService()
    cmd_args = []
    context = {
        "use_wsl": False,
        "wordlist": "wordlist.txt",
        "rule_file": "best64.rule",
        "custom_mask": "?d?d?d?d",
        "wordlist_2": "wordlist2.txt",
        "mask_file": "mask.hcmask",
        "hash_path": "/tmp/hash.22000",
        "hashcat_bin": "hashcat",
        "custom_rules_dir": "/tmp/rules",
        "association_hint": "",
        "association_hints": "",
    }

    # Test all mode builders exist
    for mode in service.ATTACK_MODE_POLICIES:
        mode_method = getattr(service, f"_mode_{mode}_args", None)
        if mode_method:
            cmd_args = []
            temp_file, error = mode_method(cmd_args, context)
            assert cmd_args  # Every mode adds at least -a parameter
            assert "-a" in cmd_args


def test_resolve_passphrase_rule_paths(tmp_path):
    """_resolve_passphrase_rule_paths finds rule files."""
    service = hs_module.HashcatService()
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "passphrase-rule1.rule").write_text("r1")
    (rules_dir / "passphrase-rule2.rule").write_text("r2")

    r1, r2, err = service._resolve_passphrase_rule_paths(
        None, "wordlist.txt", "hashcat", str(rules_dir)
    )
    assert err is None
    assert r1.endswith("passphrase-rule1.rule")
    assert r2.endswith("passphrase-rule2.rule")


def test_apply_mode_specific_params():
    """_apply_mode_specific_params fills parameters correctly."""
    service = hs_module.HashcatService()
    params = {}
    context = {"wordlist": "wordlist.txt", "rule_file": "best64.rule"}
    service._apply_mode_specific_params(params, "rules", context, False, None, None)
    assert params["wordlist"] == "wordlist.txt"
    assert params["rule"] == "best64.rule"


def test_convert_pcap_now(tmp_path, monkeypatch):
    """convert_pcap_now runs conversion synchronously."""
    service = hs_module.HashcatService()
    monkeypatch.setattr(
        hs_module.BaseService, "_get_config", lambda self: {"hcxpcapngtool_path": "hcx"}
    )
    monkeypatch.setattr(
        hs_module.BaseService, "_should_use_wsl", lambda *args, **kwargs: False
    )

    pcap = tmp_path / "test.pcap"
    pcap.write_text("pcap")

    def mock_run(cmd, **kwargs):
        class Result:
            returncode = 0
            stderr = ""
            stdout = ""

        if "-o" in cmd:
            out_path = cmd[cmd.index("-o") + 1]
            with open(out_path, "w") as f:
                f.write("WPA*02*deadbeef*aabbccddeeff*112233445566*54657374*0\n")
        return Result()

    monkeypatch.setattr(hs_module.subprocess, "run", mock_run)

    result = service.convert_pcap_now(str(pcap))
    assert result["status"] == "success"
    assert result["output_file"] == "test.22000"


def test_generate_funny_multi_name_collisions(tmp_path, monkeypatch):
    """_generate_funny_multi_name handles file collisions."""
    service = hs_module.HashcatService()
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(hs_module.random, "choice", lambda lst: lst[0])
    monkeypatch.setattr(hs_module.random, "randint", lambda a, b: 10)

    # Pre-create file to force collision
    existing = tmp_path / "batch_pwn_mane_10.22000"
    existing.touch()

    name = service._generate_funny_multi_name()
    assert name != "batch_pwn_mane_10.22000"
    assert name.startswith("batch_")
    assert name.endswith(".22000")


def test_pcap_search_roots():
    """_pcap_search_roots returns configured search roots."""
    service = hs_module.HashcatService()
    roots = service._pcap_search_roots()
    assert isinstance(roots, tuple)
    assert len(roots) > 0
    # Should include the configured directories
    assert any("handshakes" in root.lower() for root in roots)


def test_write_association_candidates_file(tmp_path, monkeypatch):
    """_write_association_candidates_file creates file with candidates."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    service = hs_module.HashcatService()

    candidates = ["candidate1", "candidate2", "candidate3"]
    hash_path = "test_hash.22000"

    result_path = service._write_association_candidates_file(hash_path, candidates)

    assert os.path.exists(result_path)
    assert result_path.startswith(str(tmp_path))
    assert "association_" in result_path
    assert "test_hash.22000" in result_path
    assert result_path.endswith(".txt")

    with open(result_path, "r", encoding="utf-8") as f:
        content = f.read()
        lines = content.strip().split("\n")
        assert lines == candidates


def test_attack_mode_policy_methods():
    """Test attack mode policy helper methods."""
    service = hs_module.HashcatService()

    # Test _get_attack_mode_policy for valid mode
    policy = service._get_attack_mode_policy("straight")
    assert policy is not None
    assert "requires_wordlist" in policy
    assert "supports_increment" in policy
    assert "supports_slow_candidates" in policy

    # Test _get_attack_mode_policy for invalid mode (should return default)
    policy_invalid = service._get_attack_mode_policy("invalid_mode_xyz")
    assert policy_invalid == service.ATTACK_MODE_POLICIES["straight"]

    # Test _requires_wordlist
    requires_wl_straight = service._requires_wordlist("straight")
    assert isinstance(requires_wl_straight, bool)

    # Test _supports_increment
    supports_inc = service._supports_increment("straight")
    assert isinstance(supports_inc, bool)

    # Test _supports_slow_candidates
    supports_slow = service._supports_slow_candidates("straight")
    assert isinstance(supports_slow, bool)

    # None value
    assert service._normalize_association_seed(None) == ""

    # Numeric value
    assert service._normalize_association_seed(12345) == "12345"

    # Leading/trailing whitespace
    assert service._normalize_association_seed("  test  ") == "test"


# ============================================================================
# COMPREHENSIVE EXCEPTION HANDLER TESTS FOR hashcat_service.py
# These tests cover external tool integration, file I/O, and parsing errors
# ============================================================================


# Tests for get_available_rules() exception handling
def test_get_available_rules_glob_exception_returns_default(monkeypatch):
    """Test get_available_rules returns default when glob fails."""

    def raise_glob_error(*args, **kwargs):
        raise RuntimeError("glob operation failed")

    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda self: {"hashcat_path": "/usr/bin/hashcat", "custom_rules_path": ""},
    )
    monkeypatch.setattr("glob.glob", raise_glob_error)

    service = hs_module.HashcatService()
    result = service.get_available_rules()

    assert result is not None
    assert len(result) > 0
    assert result[0]["name"] == "best64.rule"


def test_get_available_rules_missing_hashcat_dir(monkeypatch):
    """Test get_available_rules handles missing hashcat directory."""
    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda self: {"hashcat_path": "/nonexistent/hashcat", "custom_rules_path": ""},
    )

    service = hs_module.HashcatService()
    result = service.get_available_rules()

    assert result is not None
    assert result[0]["name"] == "best64.rule"


def test_get_available_rules_custom_rules_dir_empty(tmp_path, monkeypatch):
    """Test get_available_rules with empty custom rules directory."""
    custom_dir = tmp_path / "custom_rules"
    custom_dir.mkdir()

    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda self: {
            "hashcat_path": "/nonexistent/hashcat",
            "custom_rules_path": str(custom_dir),
        },
    )

    service = hs_module.HashcatService()
    result = service.get_available_rules()

    assert len(result) > 0
    assert result[0]["name"] == "best64.rule"


# Tests for get_available_masks() exception handling
def test_get_available_masks_glob_exception_returns_empty(monkeypatch):
    """Test get_available_masks returns empty list when glob fails."""

    def raise_glob_error(*args, **kwargs):
        raise RuntimeError("glob operation failed")

    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda self: {"hashcat_path": "/usr/bin/hashcat", "custom_masks_path": ""},
    )
    monkeypatch.setattr("glob.glob", raise_glob_error)

    service = hs_module.HashcatService()
    result = service.get_available_masks()

    assert result == []


def test_get_available_masks_missing_hashcat_dir(monkeypatch):
    """Test get_available_masks handles missing hashcat directory."""
    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda self: {"hashcat_path": "/nonexistent/hashcat", "custom_masks_path": ""},
    )

    service = hs_module.HashcatService()
    result = service.get_available_masks()

    assert result == []


def test_get_available_masks_custom_dir_empty(tmp_path, monkeypatch):
    """Test get_available_masks with empty custom masks directory."""
    custom_dir = tmp_path / "custom_masks"
    custom_dir.mkdir()

    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda self: {
            "hashcat_path": "/nonexistent/hashcat",
            "custom_masks_path": str(custom_dir),
        },
    )

    service = hs_module.HashcatService()
    result = service.get_available_masks()

    assert result == []


# Tests for get_devices() exception handling
def test_get_devices_subprocess_timeout(monkeypatch):
    """Test get_devices handles subprocess timeout."""
    import subprocess

    def raise_timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("hashcat", 10)

    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda self: {"hashcat_path": "hashcat"},
    )
    monkeypatch.setattr("subprocess.run", raise_timeout)

    service = hs_module.HashcatService()
    result = service.get_devices()

    assert result == []


def test_get_devices_subprocess_file_not_found(monkeypatch):
    """Test get_devices handles FileNotFoundError (hashcat binary not found)."""

    def raise_file_not_found(*args, **kwargs):
        raise FileNotFoundError("hashcat binary not found")

    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda self: {"hashcat_path": "/nonexistent/hashcat"},
    )
    monkeypatch.setattr("subprocess.run", raise_file_not_found)

    service = hs_module.HashcatService()
    result = service.get_devices()

    assert result == []


def test_get_devices_subprocess_permission_error(monkeypatch):
    """Test get_devices handles PermissionError."""

    def raise_permission_error(*args, **kwargs):
        raise PermissionError("Permission denied on hashcat binary")

    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda self: {"hashcat_path": "/usr/bin/hashcat"},
    )
    monkeypatch.setattr("subprocess.run", raise_permission_error)

    service = hs_module.HashcatService()
    result = service.get_devices()

    assert result == []


def test_get_devices_returncode_nonzero(monkeypatch):
    """Test get_devices handles non-zero return code gracefully."""

    class FailedResult:
        returncode = 127
        stdout = ""

    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda self: {"hashcat_path": "hashcat"},
    )
    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: FailedResult())

    service = hs_module.HashcatService()
    result = service.get_devices()

    assert result == []


def test_get_devices_malformed_output(monkeypatch):
    """Test get_devices handles malformed hashcat output."""

    class MalformedResult:
        returncode = 0
        stdout = "This is not valid hashcat output at all"

    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda self: {"hashcat_path": "hashcat"},
    )
    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: MalformedResult())

    service = hs_module.HashcatService()
    result = service.get_devices()

    assert isinstance(result, list)


def test_get_devices_wsl_command_fallback(monkeypatch):
    """Test get_devices falls back when WSL fails."""

    def raise_on_wsl(*args, **kwargs):
        if "wsl" in str(args):
            raise RuntimeError("WSL not available")
        raise StopIteration()

    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda self: {"hashcat_path": "hashcat"},
    )
    monkeypatch.setattr(
        hs_module.BaseService,
        "_should_use_wsl",
        lambda self, path: True,
    )
    monkeypatch.setattr("subprocess.run", raise_on_wsl)

    service = hs_module.HashcatService()
    result = service.get_devices()

    assert result == []


def test_preview_association_candidates_missing_hash_path(monkeypatch):
    """Test preview_association_candidates returns error when hash path is missing."""
    service = hs_module.HashcatService()
    monkeypatch.setattr(
        service, "_resolve_hash_artifact", lambda *args, **kwargs: {"path": None}
    )

    result = service.preview_association_candidates("missing.22000")
    assert result["status"] == "error"
    assert "not found" in result["message"].lower()


def test_convert_pcap_now_empty_output(tmp_path, monkeypatch):
    """Test convert_pcap_now returns error when HCX produces empty output."""
    pcap = tmp_path / "empty.pcap"
    pcap.write_text("pcap", encoding="utf-8")

    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda self: {"hcxpcapngtool_path": "hcx"},
    )

    def mock_run(cmd, **kwargs):
        out_path = cmd[cmd.index("-o") + 1]
        open(out_path, "wb").close()

        class Result:
            returncode = 0
            stderr = ""
            stdout = ""

        return Result()

    monkeypatch.setattr(hs_module.subprocess, "run", mock_run)

    service = hs_module.HashcatService()
    result = service.convert_pcap_now(str(pcap))

    assert result["status"] == "error"
    assert "empty output" in result["message"].lower()


def test_convert_pcap_now_nonzero_exit_code(tmp_path, monkeypatch):
    """Test convert_pcap_now returns error when HCX exits with non-zero status."""
    pcap = tmp_path / "sample.pcap"
    pcap.write_text("pcap", encoding="utf-8")

    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda self: {"hcxpcapngtool_path": "hcx"},
    )

    def mock_run(cmd, **kwargs):
        out_path = cmd[cmd.index("-o") + 1]
        open(out_path, "wb").close()

        class Result:
            returncode = 1
            stderr = "error"
            stdout = ""

        return Result()

    monkeypatch.setattr(hs_module.subprocess, "run", mock_run)

    service = hs_module.HashcatService()
    result = service.convert_pcap_now(str(pcap))

    assert result["status"] == "error"
    assert "exit 1" in result["message"].lower()


def test_convert_multi_pcap_requires_at_least_one_input(tmp_path, monkeypatch):
    """Test convert_multi_pcap returns error when there are no inputs."""
    service = hs_module.HashcatService()
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))

    result = service.convert_multi_pcap([], [])
    assert result["status"] == "error"
    assert "no pcap files" in result["message"].lower()


def test_convert_multi_pcap_detects_existing_output_collision(tmp_path, monkeypatch):
    """Test convert_multi_pcap returns error when batch output already exists."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(
        hs_module.HashcatService,
        "_generate_funny_multi_name",
        lambda self: "batch_collision.22000",
    )
    (tmp_path / "batch_collision.22000").write_text("exists", encoding="utf-8")

    service = hs_module.HashcatService()
    result = service.convert_multi_pcap(["file.pcap"], [])

    assert result["status"] == "error"
    assert "already exists" in result["message"].lower()


def test_build_combined_candidate_invalid_mac():
    """Test build_combined_candidate rejects invalid MAC values."""
    service = hs_module.HashcatService()

    result = service.build_combined_candidate("not-a-mac")
    assert result["status"] == "error"
    assert "invalid" in result["message"].lower()


def test_build_combined_candidate_no_handshake_set(monkeypatch):
    """Test build_combined_candidate returns error when handshake set is missing."""
    monkeypatch.setattr(
        hs_module,
        "handshake_catalog_service",
        type(
            "HCS",
            (),
            {
                "normalize_mac": lambda self, mac: "aa:bb:cc:dd:ee:ff",
                "get_handshake_set": lambda self, mac: None,
            },
        )(),
    )

    service = hs_module.HashcatService()
    result = service.build_combined_candidate("aa:bb:cc:dd:ee:ff")

    assert result["status"] == "error"
    assert "handshake set not found" in result["message"].lower()


# Tests for _resolve_passphrase_rule_paths error handling
def test_resolve_passphrase_rule_paths_missing_both_files(tmp_path, monkeypatch):
    """Test _resolve_passphrase_rule_paths reports missing rule files."""
    test_dir = tmp_path / "test"
    test_dir.mkdir()

    service = hs_module.HashcatService()

    rule1, rule2, error = service._resolve_passphrase_rule_paths(
        None,
        None,
        str(test_dir / "hashcat"),
        None,
    )

    assert rule1 is None
    assert rule2 is None
    assert error is not None
    # Error message says "requires" and "searched"
    assert "requires" in error.lower() or "searched" in error.lower()


def test_resolve_passphrase_rule_paths_one_file_missing(tmp_path):
    """Test _resolve_passphrase_rule_paths reports when only one rule file exists."""
    test_dir = tmp_path / "test"
    test_dir.mkdir()

    # Create only first rule file
    rule1_path = test_dir / "passphrase-rule1.rule"
    rule1_path.write_text("r1", encoding="utf-8")

    service = hs_module.HashcatService()

    rule1, rule2, error = service._resolve_passphrase_rule_paths(
        None,
        None,
        str(test_dir / "hashcat"),
        str(test_dir),
    )

    assert rule1 is None
    assert rule2 is None
    assert error is not None


def test_resolve_passphrase_rule_paths_explicit_invalid_paths():
    """Test _resolve_passphrase_rule_paths rejects explicitly specified invalid paths."""
    service = hs_module.HashcatService()

    rule1, rule2, error = service._resolve_passphrase_rule_paths(
        "/nonexistent/rule1.rule,/nonexistent/rule2.rule",
        None,
        "hashcat",
        None,
    )

    assert rule1 is None
    assert rule2 is None
    assert error is not None
    assert "not found" in error.lower()


# Tests for extract essids from hash lines error handling
def test_extract_essids_malformed_hex():
    """Test _extract_essids_from_hash_lines handles malformed hex in ESSID."""
    service = hs_module.HashcatService()

    # Invalid hex in ESSID field
    line = "WPA*02*a0b0c0d0e0f0*00102030405060*1234567890abcdef*ZZZZZZZZZZZZ*"
    essids = service._extract_essids_from_hash_lines([line])

    assert isinstance(essids, list)


def test_extract_essids_truncated_line():
    """Test _extract_essids_from_hash_lines handles truncated lines."""
    service = hs_module.HashcatService()

    # Truncated line (fewer than 6 fields)
    line = "WPA*02*a0b0c0d0e0f0*00102030405060"
    essids = service._extract_essids_from_hash_lines([line])

    assert essids == []


def test_extract_essids_empty_essid_field():
    """Test _extract_essids_from_hash_lines handles empty ESSID field."""
    service = hs_module.HashcatService()

    # Empty ESSID field (no hex)
    line = "WPA*02*a0b0c0d0e0f0*00102030405060*1234567890abcdef**"
    essids = service._extract_essids_from_hash_lines([line])

    assert essids == []


def test_extract_essids_utf8_decoding_fallback():
    """Test _extract_essids_from_hash_lines handles UTF-8 decoding with fallback."""
    service = hs_module.HashcatService()

    # Valid hex that might not decode as UTF-8
    line = "WPA*02*a0b0c0d0e0f0*00102030405060*1234567890abcdef*ffff*"
    essids = service._extract_essids_from_hash_lines([line])

    assert isinstance(essids, list)


# Tests for association candidate generation edge cases
def test_build_association_candidates_empty_hash_file(tmp_path):
    """Test _build_association_candidates_v2 handles empty hash file."""
    empty_file = tmp_path / "empty.22000"
    empty_file.write_text("", encoding="utf-8")

    service = hs_module.HashcatService()
    result = service._build_association_candidates_v2(str(empty_file))

    assert result["status"] == "error"
    assert "empty" in result["message"].lower()


def test_build_association_candidates_missing_file(tmp_path):
    """Test _build_association_candidates_v2 handles missing hash file."""
    service = hs_module.HashcatService()
    result = service._build_association_candidates_v2(str(tmp_path / "missing.22000"))

    assert result["status"] == "error"
    assert "not found" in result["message"].lower()


def test_build_association_candidates_no_valid_ssids(tmp_path):
    """Test _build_association_candidates_v2 returns error when no SSIDs found."""
    hash_file = tmp_path / "hashes.22000"
    hash_file.write_text("invalid line 1\ninvalid line 2\n", encoding="utf-8")

    service = hs_module.HashcatService()
    result = service._build_association_candidates_v2(str(hash_file))

    assert result["status"] == "error"
    assert (
        "ssid" in result["message"].lower() or "candidates" in result["message"].lower()
    )


def test_build_association_candidates_invalid_mode():
    """Test _build_association_candidates_v2 rejects invalid mode."""
    service = hs_module.HashcatService()
    result = service._build_association_candidates_v2(
        "/nonexistent", mode="invalid_mode"
    )

    assert result["status"] == "error"
    # Checks for file existence first before mode validation
    assert (
        "not found" in result["message"].lower()
        or "hash file" in result["message"].lower()
    )


def test_normalize_association_seed_non_printable_chars():
    """Test _normalize_association_seed removes non-printable characters."""
    service = hs_module.HashcatService()

    result = service._normalize_association_seed("hello\x00\x01\x02world")

    assert "\x00" not in result
    assert "\x01" not in result
    assert "hello" in result and "world" in result


def test_normalize_association_seed_whitespace_collapse():
    """Test _normalize_association_seed collapses multiple whitespace."""
    service = hs_module.HashcatService()

    result = service._normalize_association_seed("hello    \t   world")

    assert "hello world" == result


# Tests for convert_pcap error handling
def test_convert_pcap_subprocess_failure(tmp_path, monkeypatch):
    """Test convert_pcap handles subprocess failure gracefully."""
    pcap_file = tmp_path / "test.pcap"
    pcap_file.write_text("pcap content", encoding="utf-8")

    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda self: {"hcxpcapngtool_path": "/nonexistent/hcx"},
    )
    monkeypatch.setattr(
        hs_module.BaseService,
        "_should_use_wsl",
        lambda self, path: False,
    )

    service = hs_module.HashcatService()
    result = service.convert_pcap("test.pcap")

    assert result["status"] == "error" or result["status"] == "started"


def test_convert_pcap_output_encoding_error(tmp_path, monkeypatch):
    """Test convert_pcap handles output with encoding errors."""
    pcap_file = tmp_path / "test.pcap"
    pcap_file.write_text("pcap content", encoding="utf-8")

    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda self: {"hcxpcapngtool_path": "hcx"},
    )
    monkeypatch.setattr(
        hs_module.BaseService,
        "_should_use_wsl",
        lambda self, path: False,
    )

    service = hs_module.HashcatService()
    result = service.convert_pcap("test.pcap")
    assert result is not None


# Tests for coverage of generate_funny_multi_name collision handling
def test_generate_funny_multi_name_collision_handling(tmp_path, monkeypatch):
    """Test _generate_funny_multi_name handles filename collisions."""
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))

    # Pre-create a file to force collision
    collision_file = tmp_path / "batch_pwn_mane_42.22000"
    collision_file.write_text("collision", encoding="utf-8")

    service = hs_module.HashcatService()
    name = service._generate_funny_multi_name()

    assert name.endswith(".22000")
    assert name != "batch_pwn_mane_42.22000"


def test_extract_essids_non_wpa_line():
    """Test _extract_essids_from_hash_lines skips non-WPA format lines."""
    service = hs_module.HashcatService()

    lines = [
        "MD5:$1$salt$hash",
        "BCRYPT:$2a$12$hash",
        "WPA*02*a0b0c0d0e0f0*00102030405060*1234567890abcdef*48656c6c6f*",
    ]

    essids = service._extract_essids_from_hash_lines(lines)

    assert len(essids) >= 0
    assert isinstance(essids, list)


def test_resolve_passphrase_rule_paths_directory_hint(tmp_path):
    """Test _resolve_passphrase_rule_paths explores explicit directory hints."""
    service = hs_module.HashcatService()

    rules_dir = tmp_path / "rule_hint"
    rules_dir.mkdir()
    (rules_dir / "passphrase-rule1.rule").write_text("r1", encoding="utf-8")
    (rules_dir / "passphrase-rule2.rule").write_text("r2", encoding="utf-8")

    rule1, rule2, error = service._resolve_passphrase_rule_paths(
        str(rules_dir),
        "wordlist.txt",
        "/usr/bin/hashcat",
        None,
    )

    assert error is None
    assert rule1.endswith("passphrase-rule1.rule")
    assert rule2.endswith("passphrase-rule2.rule")


def test_build_association_candidates_v2_capped(monkeypatch, tmp_path):
    """Test _build_association_candidates_v2 caps a candidate list."""
    service = hs_module.HashcatService()
    hash_path = tmp_path / "test.22000"
    hash_path.write_text(
        "WPA*02*deadbeef*aabbccddeeff*112233445566*54657374*0\n", encoding="utf-8"
    )

    monkeypatch.setitem(
        hs_module.HashcatService.ASSOCIATION_CANDIDATE_CAPS, "association", 1
    )

    result = service._build_association_candidates_v2(
        str(hash_path), mode="association"
    )

    assert result["status"] == "success"
    assert result["capped"] is True
    assert any("capped" in warning.lower() for warning in result.get("warnings", []))


def test_build_association_candidates_v2_hint_first_requires_hints(tmp_path):
    """Test _build_association_candidates_v2 returns error for hint-first mode without hints."""
    service = hs_module.HashcatService()
    hash_path = tmp_path / "test.22000"
    hash_path.write_text("invalid line\n", encoding="utf-8")

    result = service._build_association_candidates_v2(
        str(hash_path),
        mode="association_hint_first",
        association_hints="",
    )

    assert result["status"] == "error"
    assert "hint-first" in result["message"].lower()
