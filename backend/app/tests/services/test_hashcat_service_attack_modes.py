import builtins
import json
import os
import pytest

from app.services import hashcat_service as hs_module


def test_run_attack_missing_wordlist(tmp_path, monkeypatch):
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda self: {
            "hashcat_path": "hashcat",
            "attack_mode": "straight",
            "workload_profile": "3",
        },
    )

    hash_file = tmp_path / "hashes.22000"
    hash_file.write_text("hash")

    service = hs_module.HashcatService()
    result = service.run_attack("hashes.22000")
    assert result["status"] == "error"


@pytest.mark.parametrize(
    "attack_mode,context_overrides,expected",
    [
        ("straight", {}, {"wordlist": "wl.txt"}),
        ("rules", {}, {"wordlist": "wl.txt", "rule": "rules/best64.rule"}),
        (
            "passphrase",
            {},
            {"wordlist": "wl.txt", "rule_1": "rule1.rule", "rule_2": "rule2.rule"},
        ),
        ("combinator", {}, {"wordlist": "wl.txt", "wordlist_2": "wl.txt"}),
        (
            "combinator_passphrase",
            {"wordlist_2": "wl2.txt"},
            {
                "wordlist": "wl.txt",
                "wordlist_2": "wl2.txt",
                "rule_1": "rule1.rule",
                "rule_2": "rule2.rule",
            },
        ),
        (
            "association",
            {},
            {"association_hint": "hint-single"},
        ),
        (
            "association_hint_first",
            {},
            {"association_hints": "hint-a\nhint-b"},
        ),
        (
            "association_hint_rule",
            {},
            {"association_hints": "hint-a\nhint-b", "rule": "rules/best64.rule"},
        ),
        ("mask_profile", {}, {"mask_file": "/tmp/profile.hcmask"}),
        ("hybrid", {}, {"wordlist": "wl.txt", "mask": "?d?d?d?d"}),
        ("hybrid_reverse", {}, {"wordlist": "wl.txt", "mask": "?d?d?d?d"}),
        (
            "hybrid_mask_profile",
            {},
            {"wordlist": "wl.txt", "mask_file": "/tmp/profile.hcmask"},
        ),
        (
            "hybrid_reverse_mask_profile",
            {},
            {"wordlist": "wl.txt", "mask_file": "/tmp/profile.hcmask"},
        ),
    ],
)
def test_apply_mode_specific_params_dispatch(attack_mode, context_overrides, expected):
    service = hs_module.HashcatService()
    params = {}
    context = {
        "wordlist": "wl.txt",
        "rule_file": None,
        "passphrase_rule_1": "rule1.rule",
        "passphrase_rule_2": "rule2.rule",
        "wordlist_2": None,
        "custom_mask": "?d?d?d?d",
        "association_hint": "hint-single",
        "association_hints": "hint-a\nhint-b",
        "mask_file": "/tmp/profile.hcmask",
    }
    context.update(context_overrides)

    service._apply_mode_specific_params(
        params,
        attack_mode,
        context,
        enable_increment=True,
        increment_min=2,
        increment_max=8,
    )

    for key, value in expected.items():
        assert params[key] == value


def test_apply_mode_specific_params_mask_increment_enabled_and_disabled():
    service = hs_module.HashcatService()
    context = {
        "wordlist": "wl.txt",
        "rule_file": None,
        "passphrase_rule_1": "rule1.rule",
        "passphrase_rule_2": "rule2.rule",
        "wordlist_2": None,
        "custom_mask": "?d?d?d?d",
        "association_hint": None,
        "association_hints": None,
        "mask_file": None,
    }

    params_enabled = {}
    service._apply_mode_specific_params(
        params_enabled,
        "mask",
        context,
        enable_increment=True,
        increment_min=3,
        increment_max=7,
    )
    assert params_enabled["mask"] == "?d?d?d?d"
    assert params_enabled["increment"] is True
    assert params_enabled["increment_min"] == 3
    assert params_enabled["increment_max"] == 7

    params_disabled = {}
    service._apply_mode_specific_params(
        params_disabled,
        "digits",
        context,
        enable_increment=False,
        increment_min=3,
        increment_max=7,
    )
    assert params_disabled["mask"] == "?d?d?d?d"
    assert "increment" not in params_disabled
    assert "increment_min" not in params_disabled
    assert "increment_max" not in params_disabled


def test_attack_mode_policy_helpers():
    service = hs_module.HashcatService()

    assert service._requires_wordlist("straight") is True
    assert service._requires_wordlist("mask_profile") is False
    assert service._requires_wordlist("hybrid_mask_profile") is True

    assert service._supports_increment("mask") is True
    assert service._supports_increment("hybrid") is False

    assert service._supports_slow_candidates("rules") is True
    assert service._supports_slow_candidates("association") is False
    assert service._supports_slow_candidates("combinator_passphrase") is True

    # Unknown mode falls back to straight policy.
    assert service._requires_wordlist("unknown_mode") is True
    assert service._supports_increment("unknown_mode") is False
    assert service._supports_slow_candidates("unknown_mode") is True


def test_run_attack_disables_slow_for_incompatible_mode_association(
    tmp_path, monkeypatch
):
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

    def _start_job(command, **kwargs):
        kwargs["on_complete"]({"id": "j1", "status": "failed", "logs": []})
        return "j1"

    monkeypatch.setattr(hs_module.history_service, "add_entry", _add_entry)
    monkeypatch.setattr(hs_module.job_manager, "start_job", _start_job)

    hash_file = tmp_path / "h.22000"
    hash_file.write_text("invalid-hash-line\n", encoding="utf-8")

    service = hs_module.HashcatService()
    out = service.run_attack(
        "h.22000",
        attack_mode="association",
        association_hint="hint",
        is_slow=True,
    )
    assert out["status"] == "started"
    assert "-S" not in captured["cmd"]
    assert "slow" not in captured["params"]


def test_run_attack_disables_optimized_for_association_modes(tmp_path, monkeypatch):
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
    hash_file.write_text("invalid-hash-line\n", encoding="utf-8")

    service = hs_module.HashcatService()
    out = service.run_attack(
        "h.22000",
        attack_mode="association",
        association_hint="myhint",
        is_optimized=True,
    )
    assert out["status"] == "started"
    assert "-O" not in captured["cmd"]
    assert "optimized" not in captured["params"]


def test_run_attack_keeps_slow_for_compatible_mode_rules(tmp_path, monkeypatch):
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
    out = service.run_attack(
        "h.22000",
        attack_mode="rules",
        wordlist="wl.txt",
        is_slow=True,
    )
    assert out["status"] == "started"
    assert "-S" in captured["cmd"]
    assert captured["params"]["slow"] is True


def test_run_attack_combinator_and_hybrid(tmp_path, monkeypatch):
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda self: {
            "hashcat_path": "hashcat",
            "hashcat_potfile": True,
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
    mask_profile = tmp_path / "wifi.hcmask"
    mask_profile.write_text("?d?d?d?d\n", encoding="utf-8")

    captured = {}

    def _start_job(command, **kwargs):
        captured["cmd"] = command
        return "job-1"

    monkeypatch.setattr(hs_module.job_manager, "start_job", _start_job)

    service = hs_module.HashcatService()
    result = service.run_attack(
        "hashes.22000",
        attack_mode="combinator",
        wordlist="wl1.txt",
        wordlist_2="wl2.txt",
    )
    assert result["status"] == "started"
    assert "-a" in captured["cmd"]
    assert "1" in captured["cmd"]

    result = service.run_attack(
        "hashes.22000",
        attack_mode="hybrid",
        wordlist="wl1.txt",
        custom_mask="?d?d",
    )
    assert result["status"] == "started"
    assert "6" in captured["cmd"]

    result = service.run_attack(
        "hashes.22000",
        attack_mode="hybrid_reverse",
        wordlist="wl1.txt",
        custom_mask="?d?d",
    )
    assert result["status"] == "started"
    assert "7" in captured["cmd"]

    result = service.run_attack(
        "hashes.22000",
        attack_mode="hybrid_mask_profile",
        wordlist="wl1.txt",
        mask_file=str(mask_profile),
    )
    assert result["status"] == "started"
    assert "6" in captured["cmd"]
    assert str(mask_profile) in captured["cmd"]

    result = service.run_attack(
        "hashes.22000",
        attack_mode="hybrid_reverse_mask_profile",
        wordlist="wl1.txt",
        mask_file=str(mask_profile),
    )
    assert result["status"] == "started"
    assert "7" in captured["cmd"]
    assert str(mask_profile) in captured["cmd"]


def test_run_attack_combinator_passphrase_requires_second_wordlist(
    tmp_path, monkeypatch
):
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

    hash_file = tmp_path / "h.22000"
    hash_file.write_text("hash", encoding="utf-8")
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("secret", encoding="utf-8")

    service = hs_module.HashcatService()
    out = service.run_attack(
        "h.22000",
        attack_mode="combinator_passphrase",
        wordlist=str(wordlist),
        wordlist_2=None,
    )
    assert out["status"] == "error"
    assert (
        "Second wordlist is required for combinator passphrase mode" in out["message"]
    )


def test_run_attack_combinator_passphrase_adds_dual_rules(tmp_path, monkeypatch):
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
    monkeypatch.setattr(hs_module.history_service, "add_entry", lambda *_a, **_k: "e1")
    monkeypatch.setattr(
        hs_module.history_service, "update_entry", lambda *_a, **_k: None
    )

    hash_file = tmp_path / "h.22000"
    hash_file.write_text("hash", encoding="utf-8")
    wl1 = tmp_path / "wl1.txt"
    wl2 = tmp_path / "wl2.txt"
    wl1.write_text("one", encoding="utf-8")
    wl2.write_text("two", encoding="utf-8")
    rule1 = tmp_path / "passphrase-rule1.rule"
    rule2 = tmp_path / "passphrase-rule2.rule"
    rule1.write_text("r1", encoding="utf-8")
    rule2.write_text("r2", encoding="utf-8")

    captured = {}

    def _start_job(command, **_kwargs):
        captured["cmd"] = command
        return "j1"

    monkeypatch.setattr(hs_module.job_manager, "start_job", _start_job)

    service = hs_module.HashcatService()
    out = service.run_attack(
        "h.22000",
        attack_mode="combinator_passphrase",
        wordlist=str(wl1),
        wordlist_2=str(wl2),
    )
    assert out["status"] == "started"
    cmd = captured["cmd"]
    assert "-a" in cmd and "1" in cmd
    assert str(wl1) in cmd
    assert str(wl2) in cmd
    assert str(rule1) in cmd
    assert str(rule2) in cmd


def test_run_attack_passphrase_mode_requires_rule_files(tmp_path, monkeypatch):
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda self: {
            "hashcat_path": "hashcat",
            "custom_rules_path": str(tmp_path / "no_rules_here"),
            "hashcat_potfile": False,
            "attack_mode": "straight",
            "workload_profile": "3",
        },
    )
    monkeypatch.setattr(
        hs_module.BaseService, "_should_use_wsl", lambda *args, **kwargs: False
    )

    hash_file = tmp_path / "hashes.22000"
    hash_file.write_text("hash", encoding="utf-8")
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("senha123", encoding="utf-8")

    service = hs_module.HashcatService()
    result = service.run_attack(
        "hashes.22000",
        attack_mode="passphrase",
        wordlist=str(wordlist),
    )
    assert result["status"] == "error"
    assert "passphrase-rule1.rule" in result["message"]


def test_resolve_passphrase_rule_paths_explicit_pair_and_missing(tmp_path):
    service = hs_module.HashcatService()
    rule1 = tmp_path / "passphrase-rule1.rule"
    rule2 = tmp_path / "passphrase-rule2.rule"
    rule1.write_text("r1", encoding="utf-8")
    rule2.write_text("r2", encoding="utf-8")

    p1, p2, err = service._resolve_passphrase_rule_paths(
        f"{rule1};{rule2}", None, "hashcat", ""
    )
    assert err is None
    assert p1 == str(rule1)
    assert p2 == str(rule2)

    p1, p2, err = service._resolve_passphrase_rule_paths(
        f"{rule1};{tmp_path / 'missing.rule'}", None, "hashcat", ""
    )
    assert p1 is None
    assert p2 is None
    assert "Passphrase rules not found" in err


def test_resolve_passphrase_rule_paths_with_single_hint_file(tmp_path):
    service = hs_module.HashcatService()
    rules_dir = tmp_path / "rules_custom"
    rules_dir.mkdir()
    rule1 = rules_dir / "passphrase-rule1.rule"
    rule2 = rules_dir / "passphrase-rule2.rule"
    rule1.write_text("r1", encoding="utf-8")
    rule2.write_text("r2", encoding="utf-8")

    p1, p2, err = service._resolve_passphrase_rule_paths(
        str(rule1), None, "hashcat", ""
    )
    assert err is None
    assert p1 == str(rule1)
    assert p2 == str(rule2)


def test_resolve_passphrase_rule_paths_from_absolute_hashcat_rules_dir(tmp_path):
    service = hs_module.HashcatService()
    hashcat_bin = tmp_path / "hc" / "hashcat"
    rules_dir = hashcat_bin.parent / "rules"
    rules_dir.mkdir(parents=True)
    rule1 = rules_dir / "passphrase-rule1.rule"
    rule2 = rules_dir / "passphrase-rule2.rule"
    rule1.write_text("r1", encoding="utf-8")
    rule2.write_text("r2", encoding="utf-8")

    p1, p2, err = service._resolve_passphrase_rule_paths(
        None, None, str(hashcat_bin), ""
    )
    assert err is None
    assert p1 == str(rule1)
    assert p2 == str(rule2)


def test_run_attack_passphrase_explicit_rule_order_and_params(tmp_path, monkeypatch):
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

    hash_file = tmp_path / "h.22000"
    hash_file.write_text("hash", encoding="utf-8")
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("senha", encoding="utf-8")
    rule1 = tmp_path / "passphrase-rule1.rule"
    rule2 = tmp_path / "passphrase-rule2.rule"
    rule1.write_text("r1", encoding="utf-8")
    rule2.write_text("r2", encoding="utf-8")

    captured = {"params": None, "cmd": None}

    def _add_entry(_f, _tool, _cmd, params, **_kwargs):
        captured["params"] = params
        return "e1"

    def _start_job(command, **_kwargs):
        captured["cmd"] = command
        return "j1"

    monkeypatch.setattr(hs_module.history_service, "add_entry", _add_entry)
    monkeypatch.setattr(hs_module.job_manager, "start_job", _start_job)

    service = hs_module.HashcatService()
    result = service.run_attack(
        "h.22000",
        attack_mode="passphrase",
        wordlist=str(wordlist),
        rule_file=f"{rule2};{rule1}",
    )
    assert result["status"] == "started"
    cmd = captured["cmd"]
    first_r = cmd.index("-r")
    second_r = cmd.index("-r", first_r + 1)
    assert cmd[first_r + 1] == str(rule2)
    assert cmd[second_r + 1] == str(rule1)
    assert captured["params"]["rule_1"] == str(rule2)
    assert captured["params"]["rule_2"] == str(rule1)


def test_run_attack_passphrase_wsl_converts_rule_paths(tmp_path, monkeypatch):
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
        hs_module.BaseService, "_should_use_wsl", lambda *_a, **_k: True
    )
    monkeypatch.setattr(
        hs_module.BaseService,
        "_to_wsl_path",
        lambda _self, p: f"/wsl/{os.path.basename(str(p))}",
    )
    monkeypatch.setattr(
        hs_module.HashcatService, "process_cracked_file", lambda *_a, **_k: None
    )
    monkeypatch.setattr(hs_module.history_service, "add_entry", lambda *_a, **_k: "e1")
    monkeypatch.setattr(
        hs_module.history_service, "update_entry", lambda *_a, **_k: None
    )

    hash_file = tmp_path / "h.22000"
    hash_file.write_text("hash", encoding="utf-8")
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("senha", encoding="utf-8")
    rule1 = tmp_path / "passphrase-rule1.rule"
    rule2 = tmp_path / "passphrase-rule2.rule"
    rule1.write_text("r1", encoding="utf-8")
    rule2.write_text("r2", encoding="utf-8")

    captured = {}

    def _start_job(command, **_kwargs):
        captured["cmd"] = command
        return "j1"

    monkeypatch.setattr(hs_module.job_manager, "start_job", _start_job)

    service = hs_module.HashcatService()
    result = service.run_attack(
        "h.22000",
        attack_mode="passphrase",
        wordlist=str(wordlist),
        rule_file=f"{rule1};{rule2}",
    )
    assert result["status"] == "started"
    cmd = captured["cmd"]
    assert cmd[0] == "wsl"
    assert "/wsl/passphrase-rule1.rule" in cmd
    assert "/wsl/passphrase-rule2.rule" in cmd
    assert "/wsl/wl.txt" in cmd


def test_get_available_masks_error_fallback(monkeypatch):
    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda _self: (_ for _ in ()).throw(RuntimeError("bad config")),
    )
    service = hs_module.HashcatService()
    assert service.get_available_masks() == []


def test_run_attack_association_uses_essid_from_hash(tmp_path, monkeypatch):
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
    monkeypatch.setattr(hs_module.history_service, "add_entry", lambda *_a, **_k: "e1")
    monkeypatch.setattr(
        hs_module.history_service, "update_entry", lambda *_a, **_k: None
    )

    hash_file = tmp_path / "h.22000"
    hash_file.write_text(
        "WPA*02*deadbeef*aabbccddeeff*001122334455*4d7957694669*00\n",
        encoding="utf-8",
    )
    captured = {}

    def _start_job(command, **kwargs):
        captured["cmd"] = command
        kwargs["on_complete"]({"id": "j1", "status": "failed", "logs": []})
        return "j1"

    monkeypatch.setattr(hs_module.job_manager, "start_job", _start_job)

    service = hs_module.HashcatService()
    out = service.run_attack("h.22000", attack_mode="association")
    assert out["status"] == "started"
    cmd = captured["cmd"]
    assoc_file = cmd[cmd.index("-a") + 2]
    assert os.path.basename(assoc_file).startswith("association_h.22000_")
    assert not os.path.exists(assoc_file)


def test_run_attack_association_uses_hint_fallback(tmp_path, monkeypatch):
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
    monkeypatch.setattr(hs_module.history_service, "add_entry", lambda *_a, **_k: "e1")
    monkeypatch.setattr(
        hs_module.history_service, "update_entry", lambda *_a, **_k: None
    )

    hash_file = tmp_path / "h.22000"
    hash_file.write_text("invalid-hash-line\n", encoding="utf-8")
    captured = {}

    def _start_job(command, **kwargs):
        captured["cmd"] = command
        kwargs["on_complete"]({"id": "j1", "status": "failed", "logs": []})
        return "j1"

    monkeypatch.setattr(hs_module.job_manager, "start_job", _start_job)

    service = hs_module.HashcatService()
    out = service.run_attack(
        "h.22000", attack_mode="association", association_hint="default_hint_123"
    )
    assert out["status"] == "started"
    cmd = captured["cmd"]
    assoc_file = cmd[cmd.index("-a") + 2]
    assert not os.path.exists(assoc_file)


def test_run_attack_association_errors_when_missing_ssid_and_hint(
    tmp_path, monkeypatch
):
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

    hash_file = tmp_path / "h.22000"
    hash_file.write_text("invalid-hash-line\n", encoding="utf-8")

    service = hs_module.HashcatService()
    out = service.run_attack("h.22000", attack_mode="association")
    assert out["status"] == "error"
    assert "requires SSID in hash or fallback hint" in out["message"]


def test_run_attack_association_wsl_converts_candidates_path(tmp_path, monkeypatch):
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
        hs_module.BaseService, "_should_use_wsl", lambda *_a, **_k: True
    )
    monkeypatch.setattr(
        hs_module.BaseService,
        "_to_wsl_path",
        lambda _self, p: f"/wsl/{os.path.basename(str(p))}",
    )
    monkeypatch.setattr(
        hs_module.HashcatService, "process_cracked_file", lambda *_a, **_k: None
    )
    monkeypatch.setattr(hs_module.history_service, "add_entry", lambda *_a, **_k: "e1")
    monkeypatch.setattr(
        hs_module.history_service, "update_entry", lambda *_a, **_k: None
    )

    hash_file = tmp_path / "h.22000"
    hash_file.write_text(
        "WPA*02*deadbeef*aabbccddeeff*001122334455*4d7957694669*00\n",
        encoding="utf-8",
    )

    captured = {}

    def _start_job(command, **kwargs):
        captured["cmd"] = command
        kwargs["on_complete"]({"id": "j1", "status": "failed", "logs": []})
        return "j1"

    monkeypatch.setattr(hs_module.job_manager, "start_job", _start_job)

    service = hs_module.HashcatService()
    out = service.run_attack("h.22000", attack_mode="association")
    assert out["status"] == "started"
    assert captured["cmd"][0] == "wsl"
    assert any(part.startswith("/wsl/association_h.22000_") for part in captured["cmd"])


def test_run_attack_association_hint_first_uses_multiple_hints(tmp_path, monkeypatch):
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

    captured = {"params": None, "assoc_lines": None, "assoc_file_deleted": None}

    def _add_entry(_f, _tool, _cmd, params, **_kwargs):
        captured["params"] = params
        return "e1"

    def _start_job(command, **kwargs):
        captured["cmd"] = command
        assoc_file = command[command.index("-a") + 2]
        with open(assoc_file, "r", encoding="utf-8") as f:
            captured["assoc_lines"] = [
                line.strip() for line in f.readlines() if line.strip()
            ]
        kwargs["on_complete"]({"id": "j1", "status": "failed", "logs": []})
        captured["assoc_file_deleted"] = not os.path.exists(assoc_file)
        return "j1"

    monkeypatch.setattr(hs_module.history_service, "add_entry", _add_entry)
    monkeypatch.setattr(hs_module.job_manager, "start_job", _start_job)

    hash_file = tmp_path / "h.22000"
    hash_file.write_text(
        "WPA*02*deadbeef*aabbccddeeff*001122334455*4d7957694669*00\ninvalid-hash\n",
        encoding="utf-8",
    )

    service = hs_module.HashcatService()
    out = service.run_attack(
        "h.22000",
        attack_mode="association_hint_first",
        association_hints="\n \nprimary_hint\nsecondary_hint\n",
    )
    assert out["status"] == "started"
    assert "primary_hint" in captured["assoc_lines"]
    assert "secondary_hint" in captured["assoc_lines"]
    # v2 mode also adds transformed variants; ensure generation is not single-hint replication.
    assert len(captured["assoc_lines"]) > 2
    assert (
        captured["params"]["association_hints"] == "\n \nprimary_hint\nsecondary_hint\n"
    )
    assert captured["assoc_file_deleted"] is True


def test_run_attack_association_hint_first_requires_hint(tmp_path, monkeypatch):
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

    hash_file = tmp_path / "h.22000"
    hash_file.write_text("invalid-hash-line\n", encoding="utf-8")

    service = hs_module.HashcatService()
    out = service.run_attack(
        "h.22000", attack_mode="association_hint_first", association_hints=" \n "
    )
    assert out["status"] == "error"
    assert "requires hints or SSID" in out["message"]


def test_run_attack_association_hint_rule_applies_rule(tmp_path, monkeypatch):
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

    hash_file = tmp_path / "h.22000"
    hash_file.write_text(
        "WPA*02*deadbeef*aabbccddeeff*001122334455*4d7957694669*00\n",
        encoding="utf-8",
    )

    captured = {"params": None, "cmd": None}

    def _add_entry(_f, _tool, cmd, params, **_kwargs):
        captured["params"] = params
        captured["cmd"] = cmd
        return "e1"

    def _start_job(command, **_kwargs):
        return "j1"

    monkeypatch.setattr(hs_module.history_service, "add_entry", _add_entry)
    monkeypatch.setattr(hs_module.job_manager, "start_job", _start_job)

    service = hs_module.HashcatService()
    out = service.run_attack(
        "h.22000",
        attack_mode="association_hint_rule",
        association_hints="primary_hint\nsecondary_hint\n",
    )
    assert out["status"] == "started"
    assert captured["params"]["association_hints"] == "primary_hint\nsecondary_hint\n"
    assert captured["params"]["rule"] == "rules/best64.rule"
    assert "-r" in captured["cmd"]


def test_run_attack_association_hint_rule_custom_rule(tmp_path, monkeypatch):
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

    hash_file = tmp_path / "h.22000"
    hash_file.write_text("hash\n", encoding="utf-8")
    rule_file = tmp_path / "custom.rule"
    rule_file.write_text("rule1\n", encoding="utf-8")

    captured = {"params": None}

    def _add_entry(_f, _tool, _cmd, params, **_kwargs):
        captured["params"] = params
        return "e1"

    def _start_job(command, **_kwargs):
        return "j1"

    monkeypatch.setattr(hs_module.history_service, "add_entry", _add_entry)
    monkeypatch.setattr(hs_module.job_manager, "start_job", _start_job)

    service = hs_module.HashcatService()
    out = service.run_attack(
        "h.22000",
        attack_mode="association_hint_rule",
        association_hints="hint\n",
        rule_file=str(rule_file),
    )
    assert out["status"] == "started"
    assert captured["params"]["rule"] == str(rule_file)


def test_run_attack_association_hint_rule_requires_hint(tmp_path, monkeypatch):
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

    hash_file = tmp_path / "h.22000"
    hash_file.write_text("invalid-hash-line\n", encoding="utf-8")

    service = hs_module.HashcatService()
    out = service.run_attack(
        "h.22000",
        attack_mode="association_hint_rule",
        association_hints=" \n ",
    )
    assert out["status"] == "error"
    assert "requires hints or SSID" in out["message"]


def test_preview_association_candidates_returns_summary(tmp_path, monkeypatch):
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    hash_file = tmp_path / "preview.22000"
    hash_file.write_text(
        "WPA*02*deadbeef*aabbccddeeff*001122334455*4d7957694669*00\n",
        encoding="utf-8",
    )

    service = hs_module.HashcatService()
    out = service.preview_association_candidates(
        "preview.22000",
        mode="association_hint_first",
        association_hints="primary\nsecondary\n",
    )
    assert out["status"] == "success"
    assert out["candidate_count"] > 0
    assert "sample_candidates" in out
    assert out["sources"]["hint_count"] == 2


def test_preview_association_candidates_rejects_invalid_mode(tmp_path, monkeypatch):
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    hash_file = tmp_path / "preview.22000"
    hash_file.write_text("hash\n", encoding="utf-8")

    service = hs_module.HashcatService()
    out = service.preview_association_candidates(
        "preview.22000",
        mode="invalid_mode",
    )
    assert out["status"] == "error"
    assert "Invalid association mode" in out["message"]


def test_run_attack_association_hint_first_wsl_converts_candidates_path(
    tmp_path, monkeypatch
):
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
        hs_module.BaseService, "_should_use_wsl", lambda *_a, **_k: True
    )
    monkeypatch.setattr(
        hs_module.BaseService,
        "_to_wsl_path",
        lambda _self, p: f"/wsl/{os.path.basename(str(p))}",
    )
    monkeypatch.setattr(
        hs_module.HashcatService, "process_cracked_file", lambda *_a, **_k: None
    )
    monkeypatch.setattr(hs_module.history_service, "add_entry", lambda *_a, **_k: "e1")
    monkeypatch.setattr(
        hs_module.history_service, "update_entry", lambda *_a, **_k: None
    )

    hash_file = tmp_path / "h.22000"
    hash_file.write_text("invalid-hash-line\n", encoding="utf-8")
    captured = {}

    def _start_job(command, **kwargs):
        captured["cmd"] = command
        kwargs["on_complete"]({"id": "j1", "status": "failed", "logs": []})
        return "j1"

    monkeypatch.setattr(hs_module.job_manager, "start_job", _start_job)

    service = hs_module.HashcatService()
    out = service.run_attack(
        "h.22000",
        attack_mode="association_hint_first",
        association_hints="hint_from_user",
    )
    assert out["status"] == "started"
    assert captured["cmd"][0] == "wsl"
    assert any(part.startswith("/wsl/association_h.22000_") for part in captured["cmd"])


def test_run_attack_mask_profile_success_and_error_paths(tmp_path, monkeypatch):
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
    monkeypatch.setattr(hs_module.history_service, "add_entry", lambda *_a, **_k: "e1")
    monkeypatch.setattr(
        hs_module.history_service, "update_entry", lambda *_a, **_k: None
    )

    hash_file = tmp_path / "h.22000"
    hash_file.write_text("hash\n", encoding="utf-8")

    service = hs_module.HashcatService()
    err_missing = service.run_attack("h.22000", attack_mode="mask_profile")
    assert err_missing["status"] == "error"
    assert "Mask profile not selected" in err_missing["message"]

    err_not_found = service.run_attack(
        "h.22000",
        attack_mode="mask_profile",
        mask_file=str(tmp_path / "missing.hcmask"),
    )
    assert err_not_found["status"] == "error"
    assert "Mask profile not found" in err_not_found["message"]

    mask_file = tmp_path / "profile.hcmask"
    mask_file.write_text("?d?d?d?d\n", encoding="utf-8")
    captured = {}

    def _start_job(command, **kwargs):
        captured["cmd"] = command
        return "j1"

    monkeypatch.setattr(hs_module.job_manager, "start_job", _start_job)

    ok = service.run_attack(
        "h.22000",
        attack_mode="mask_profile",
        mask_file=str(mask_file),
    )
    assert ok["status"] == "started"
    assert str(mask_file) in captured["cmd"]


def test_convert_multi_pcap_empty_list():
    service = hs_module.HashcatService()
    result = service.convert_multi_pcap([])
    assert result["status"] == "error"


def test_get_available_rules_fallback_and_get_devices_error(monkeypatch):
    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda _self: (_ for _ in ()).throw(RuntimeError("bad config")),
    )
    service = hs_module.HashcatService()
    rules = service.get_available_rules()
    assert rules[0]["name"] == "best64.rule"

    class _Bad:
        returncode = 1
        stdout = ""

    monkeypatch.setattr(
        hs_module.BaseService, "_get_config", lambda _self: {"hashcat_path": "hashcat"}
    )
    monkeypatch.setattr(hs_module.subprocess, "run", lambda *_a, **_k: _Bad())
    assert service.get_devices() == []
    monkeypatch.setattr(
        hs_module.subprocess,
        "run",
        lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("run fail")),
    )
    assert service.get_devices() == []


def test_convert_pcap_wsl_and_empty_output_marks_failed(tmp_path, monkeypatch):
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    pcap = tmp_path / "x.pcap"
    pcap.write_text("pcap", encoding="utf-8")
    monkeypatch.setattr(
        hs_module.BaseService,
        "_get_config",
        lambda _self: {"hcxpcapngtool_path": "hcx"},
    )
    monkeypatch.setattr(
        hs_module.BaseService, "_should_use_wsl", lambda *_a, **_k: True
    )
    monkeypatch.setattr(
        hs_module.BaseService, "_to_wsl_path", lambda *_a, **_k: "/mnt/c/x"
    )

    updates = []
    monkeypatch.setattr(hs_module.history_service, "add_entry", lambda *_a, **_k: "e1")
    monkeypatch.setattr(
        hs_module.history_service,
        "update_entry",
        lambda *a, **k: updates.append((a, k)),
    )

    def _start_job(command, **kwargs):
        job = {"id": "j1", "logs": ["error: missing handshake"], "progress_data": {}}
        kwargs["on_start"](job)
        kwargs["on_complete"](job)
        return "j1"

    monkeypatch.setattr(hs_module.job_manager, "start_job", _start_job)
    service = hs_module.HashcatService()
    result = service.convert_pcap("x.pcap")
    assert result["status"] == "started"
    assert updates
    statuses = [args[2] for args, _ in updates if len(args) >= 3]
    assert "FAILED" in statuses


def test_convert_multi_collisions_and_worker_reasons(tmp_path, monkeypatch):
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
    monkeypatch.setattr(
        service, "_generate_funny_multi_name", lambda: "batch_fixed.22000"
    )

    (tmp_path / "batch_fixed.22000").write_text("exists", encoding="utf-8")
    assert service.convert_multi_pcap(["a.pcap"])["status"] == "error"
    (tmp_path / "batch_fixed.22000").unlink()
    (tmp_path / "batch_fixed.22000.batch.json").write_text("{}", encoding="utf-8")
    assert service.convert_multi_pcap(["a.pcap"])["status"] == "error"
    (tmp_path / "batch_fixed.22000.batch.json").unlink()

    pcap = tmp_path / "ok_aabbccddeeff.pcap"
    pcap.write_text("pcap", encoding="utf-8")

    class _Result:
        def __init__(self, returncode, stderr):
            self.returncode = returncode
            self.stderr = stderr
            self.stdout = ""

    calls = {"n": 0}

    def _run(cmd, **_kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return _Result(1, "no PMKID")
        return _Result(0, "")

    monkeypatch.setattr(hs_module.subprocess, "run", _run)

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
    out = service.convert_multi_pcap(["missing.pcap", "ok_aabbccddeeff.pcap"])
    assert out["status"] == "started"
    manifest = tmp_path / "batch_fixed.22000.batch.json"
    data = __import__("json").loads(manifest.read_text(encoding="utf-8"))
    reasons = [item.get("reason") for item in data["items"]]
    assert "PCAP NOT FOUND" in reasons
    assert "NO PMKID" in reasons or "CONVERSION FAILED" in reasons


def test_run_attack_hash_missing_and_on_complete_status_paths(tmp_path, monkeypatch):
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
    service = hs_module.HashcatService()
    assert service.run_attack("missing.22000", wordlist="wl.txt")["status"] == "error"

    hash_file = tmp_path / "h.22000"
    hash_file.write_text("hash", encoding="utf-8")
    monkeypatch.setattr(hs_module.history_service, "add_entry", lambda *_a, **_k: "e1")
    updates = []
    monkeypatch.setattr(
        hs_module.history_service, "update_entry", lambda *a, **_k: updates.append(a)
    )
    monkeypatch.setattr(
        hs_module.HashcatService, "process_cracked_file", lambda *_a, **_k: None
    )
    monkeypatch.setattr("app.services.data_loader.reload_data", lambda: {})
    monkeypatch.setattr(
        hs_module.job_manager, "_fire_and_forget_emit", lambda *_a, **_k: None
    )

    def _start_job(command, **kwargs):
        out = command[command.index("-o") + 1]
        job = {
            "id": "j",
            "status": "failed",
            "return_code": 2,
            "logs": ["Invalid mask"],
            "progress_data": {"stage": "ERROR", "extra": "Invalid Mask"},
        }
        kwargs["on_start"](job)
        kwargs["on_complete"](job)
        job["status"] = "canceled"
        kwargs["on_complete"](job)
        job["status"] = "success"
        with open(out, "w", encoding="utf-8") as f:
            f.write("h:pass")
        kwargs["on_complete"](job)
        __import__("os").remove(out)
        kwargs["on_complete"](job)
        return "j"

    monkeypatch.setattr(hs_module.job_manager, "start_job", _start_job)
    result = service.run_attack(
        "h.22000",
        attack_mode="mask",
        custom_mask="?d?d",
        enable_increment=True,
        increment_min=1,
        increment_max=2,
    )
    assert result["status"] == "started"
    statuses = [a[2] for a in updates if len(a) >= 3]
    assert "FAILED" in statuses
    assert "CANCELED" in statuses
    assert "CRACKED" in statuses
    assert "EXHAUSTED" in statuses


def test_process_cracked_file_edge_cases(tmp_path, monkeypatch):
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    service = hs_module.HashcatService()
    service.process_cracked_file({"id": "1", "command": ["hashcat"], "logs": []})

    service.process_cracked_file(
        {
            "id": "2",
            "command": ["hashcat", "-o", str(tmp_path / "none.cracked")],
            "logs": [],
        }
    )

    empty = tmp_path / "empty.cracked"
    empty.write_text("", encoding="utf-8")
    service.process_cracked_file(
        {"id": "3", "command": ["hashcat", "-o", str(empty)], "logs": []}
    )

    bad_manifest = tmp_path / "sample.22000.batch.json"
    bad_manifest.write_text("{", encoding="utf-8")
    cracked = tmp_path / "sample.cracked"
    cracked.write_text("hash:plain\n", encoding="utf-8")
    service.process_cracked_file(
        {"id": "4", "command": ["hashcat", "-o", str(cracked)], "logs": []}
    )
    assert (tmp_path / "sample.pcap.cracked").exists()


def test_process_cracked_file_string_command_and_hex_plain_decode(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    service = hs_module.HashcatService()

    cracked = tmp_path / "string_cmd.cracked"
    h = (
        "WPA*02*00112233445566778899aabbccddeeff*"
        "a1b2c3d4e5f6*112233445566*546573745f4e6574"
    )
    cracked.write_text(f"{h}::706173735f66726f6d5f686578\n", encoding="utf-8")

    service.process_cracked_file(
        {
            "id": "5",
            "command": f'hashcat -m 22000 -o "{cracked}" hashes.22000',
            "logs": [],
        }
    )

    out = tmp_path / "string_cmd.pcap.cracked"
    assert out.exists()
    assert out.read_text(encoding="utf-8") == "pass_from_hex"


def test_process_cracked_file_batch_manifest_mapping_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    service = hs_module.HashcatService()

    digest_1 = "00112233445566778899aabbccddeeff"
    digest_2 = "8899aabbccddeeff0011223344556677"
    digest_3 = "102132435465768798a9babcbddcedfe"
    digest_4 = "ffeeddccbbaa99887766554433221100"
    bssid_mac = "abcabcabcabc"
    bssid_dup = "bbbbbbbbbbbb"
    sta = "010203040506"
    essid_hash_hex = "486173684e6574"  # HashNet
    essid_solo_hex = "536f6c6f"  # Solo
    essid_dup_hex = "4475704e6574"  # DupNet
    essid_key_hex = "4e6574204f6e65"  # Net One

    hash_1 = f"WPA*02*{digest_1}*aaaaaaaaaaaa*{sta}*{essid_hash_hex}"
    hash_mac = f"WPA*02*{digest_2}*{bssid_mac}*{sta}*48696464656e"
    hash_unique = f"WPA*02*{digest_3}*cccccccccccc*{sta}*{essid_solo_hex}"
    hash_dup = f"WPA*02*{digest_4}*{bssid_dup}*{sta}*{essid_dup_hex}"
    hash_no_filename = f"WPA*02*{digest_4}*dddddddddddd*{sta}*4e6f46696c65"

    cracked = tmp_path / "batch_complex.cracked"
    cracked.write_text(
        "\n".join(
            [
                f"{hash_1}:plain_hash",
                f"{digest_2}:{bssid_mac}:{sta}:Net One::706173735f6b6579",
                f"{hash_mac}:pass_mac",
                f"{hash_unique}:pass_unique",
                f"{hash_dup}:pass_dup",
                f"{hash_no_filename}:pass_nofile",
                "ffff:eeee:dddd:ssid:pwd",
                "invalid_line_without_delimiter",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    manifest = {
        "items": [
            {
                "filename": "item_hash.pcap",
                "mac": "aaaaaaaaaaaa",
                "ssid": "HashNet",
                "hashes": [hash_1],
            },
            {
                "filename": "item_key.pcap",
                "mac": bssid_mac,
                "ssid": "Net One",
                "hash_keys": [f"{digest_2}:{bssid_mac}:{sta}:{essid_key_hex}"],
            },
            {"filename": "item_mac.pcap", "mac": bssid_mac, "ssid": "MacNet"},
            {"filename": "item_unique.pcap", "mac": "111111111111", "ssid": "Solo"},
            {"filename": "item_dup_a.pcap", "mac": "aaaaaaaaaaab", "ssid": "DupNet"},
            {"filename": "item_dup_b.pcap", "mac": bssid_dup, "ssid": "DupNet"},
            {
                "filename": "",
                "mac": "dddddddddddd",
                "ssid": "NoFile",
                "hashes": [hash_no_filename],
            },
        ]
    }
    (tmp_path / "batch_complex.22000.batch.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )

    service.process_cracked_file(
        {"id": "6", "command": ["hashcat", "-o", str(cracked)], "logs": []}
    )

    assert (tmp_path / "item_hash.pcap.cracked").read_text(
        encoding="utf-8"
    ) == "plain_hash"
    assert (tmp_path / "item_key.pcap.cracked").read_text(
        encoding="utf-8"
    ) == "pass_key"
    assert (tmp_path / "item_mac.pcap.cracked").read_text(
        encoding="utf-8"
    ) == "pass_mac"
    assert (tmp_path / "item_unique.pcap.cracked").read_text(
        encoding="utf-8"
    ) == "pass_unique"
    assert (tmp_path / "item_dup_b.pcap.cracked").read_text(
        encoding="utf-8"
    ) == "pass_dup"
    assert not (tmp_path / "NoFile.pcap.cracked").exists()


def test_process_cracked_file_handles_write_failures_in_batch_mapping(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(tmp_path))
    service = hs_module.HashcatService()

    digest = "0123456789abcdeffedcba9876543210"
    sta = "112233445566"
    h = f"WPA*02*{digest}*cafebabecafe*{sta}*4661696c4e6574"
    cracked = tmp_path / "batch_write_error.cracked"
    cracked.write_text(f"{h}:pass\n", encoding="utf-8")
    (tmp_path / "batch_write_error.22000.batch.json").write_text(
        json.dumps(
            {
                "items": [
                    {
                        "filename": "fail_write.pcap",
                        "mac": "cafebabecafe",
                        "ssid": "FailNet",
                        "hashes": [h],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    real_open = builtins.open

    def _open_with_fail(path, mode="r", *args, **kwargs):
        if str(path).endswith("fail_write.pcap.cracked") and "w" in mode:
            raise OSError("disk full")
        return real_open(path, mode, *args, **kwargs)

    monkeypatch.setattr("builtins.open", _open_with_fail)
    service.process_cracked_file(
        {"id": "7", "command": ["hashcat", "-o", str(cracked)], "logs": []}
    )

    assert not (tmp_path / "fail_write.pcap.cracked").exists()
