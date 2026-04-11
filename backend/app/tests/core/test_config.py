import json

from app.core import config


def test_load_config_defaults_when_missing(tmp_path, monkeypatch):
    cfg_path = tmp_path / "config.json"
    monkeypatch.setattr(config, "CONFIG_FILE", str(cfg_path))

    loaded = config.load_config()
    assert loaded["pwn_host"] == config.DEFAULT_CONFIG["pwn_host"]


def test_load_config_merges_and_strips_wordlist_path(tmp_path, monkeypatch):
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps({"pwn_host": "1.2.3.4", "wordlist_path": "old"}))
    monkeypatch.setattr(config, "CONFIG_FILE", str(cfg_path))

    loaded = config.load_config()
    assert loaded["pwn_host"] == "1.2.3.4"
    assert "wordlist_path" not in loaded
    assert loaded["custom_wordlists_path"] == "old"


def test_save_config_writes_and_strips_wordlist_path(tmp_path, monkeypatch):
    cfg_path = tmp_path / "config.json"
    monkeypatch.setattr(config, "CONFIG_FILE", str(cfg_path))

    saved = config.save_config({"pwn_host": "9.9.9.9", "wordlist_path": "old"})
    assert saved["pwn_host"] == "9.9.9.9"
    assert "wordlist_path" not in saved

    on_disk = json.loads(cfg_path.read_text())
    assert on_disk["pwn_host"] == "9.9.9.9"
    assert "wordlist_path" not in on_disk


def test_load_config_normalizes_types_and_filters_unknown_keys(tmp_path, monkeypatch):
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(
        json.dumps(
            {
                "pwn_port": "2022",
                "use_wsl": "true",
                "hashcat_slow": "0",
                "workload_profile": 4,
                "map_tile": "invalid-tile",
                "hashcat_device_default": "01",
                "ui_hud_density": "invalid-density",
                "ui_sidebar_preset": "giant",
                "ui_font_scale": "130",
                "ui_cracking_accordion_mode": "stacked",
                "ui_wardrive_replay_speed_default": "9",
                "ui_wardrive_replay_follow_zoom_default": "999",
                "ui_wardrive_replay_timing_mode_default": "time_warp",
                "ui_wardrive_sessions_sort_by": "alphabetical",
                "ui_wardrive_sessions_sort_direction": "sideways",
                "ui_wardrive_route_accent_color": "ultraviolet",
                "ui_wardrive_primary_zone_accent_color": "moss",
                "ui_wardrive_secondary_accent_color": "lavender",
                "__unknown__": "drop-me",
            }
        )
    )
    monkeypatch.setattr(config, "CONFIG_FILE", str(cfg_path))

    loaded = config.load_config()
    assert loaded["pwn_port"] == 2022
    assert loaded["use_wsl"] is True
    assert loaded["hashcat_slow"] is False
    assert loaded["workload_profile"] == "4"
    assert loaded["map_tile"] == config.DEFAULT_CONFIG["map_tile"]
    assert loaded["hashcat_device_default"] == "01"
    assert loaded["ui_hud_density"] == config.DEFAULT_CONFIG["ui_hud_density"]
    assert loaded["ui_sidebar_preset"] == config.DEFAULT_CONFIG["ui_sidebar_preset"]
    assert loaded["ui_font_scale"] == config.DEFAULT_CONFIG["ui_font_scale"]
    assert (
        loaded["ui_cracking_accordion_mode"]
        == config.DEFAULT_CONFIG["ui_cracking_accordion_mode"]
    )
    assert (
        loaded["ui_wardrive_replay_speed_default"]
        == config.DEFAULT_CONFIG["ui_wardrive_replay_speed_default"]
    )
    assert (
        loaded["ui_wardrive_replay_follow_zoom_default"]
        == config.DEFAULT_CONFIG["ui_wardrive_replay_follow_zoom_default"]
    )
    assert (
        loaded["ui_wardrive_replay_timing_mode_default"]
        == config.DEFAULT_CONFIG["ui_wardrive_replay_timing_mode_default"]
    )
    assert (
        loaded["ui_wardrive_sessions_sort_by"]
        == config.DEFAULT_CONFIG["ui_wardrive_sessions_sort_by"]
    )
    assert (
        loaded["ui_wardrive_sessions_sort_direction"]
        == config.DEFAULT_CONFIG["ui_wardrive_sessions_sort_direction"]
    )
    assert (
        loaded["ui_wardrive_route_accent_color"]
        == config.DEFAULT_CONFIG["ui_wardrive_route_accent_color"]
    )
    assert (
        loaded["ui_wardrive_primary_zone_accent_color"]
        == config.DEFAULT_CONFIG["ui_wardrive_primary_zone_accent_color"]
    )
    assert (
        loaded["ui_wardrive_secondary_accent_color"]
        == config.DEFAULT_CONFIG["ui_wardrive_secondary_accent_color"]
    )
    assert "__unknown__" not in loaded


def test_save_config_normalizes_enums_and_paths(tmp_path, monkeypatch):
    cfg_path = tmp_path / "config.json"
    monkeypatch.setattr(config, "CONFIG_FILE", str(cfg_path))

    saved = config.save_config(
        {
            "map_cluster_mode": "adaptive",
            "ui_theme": "green",
            "ui_icon_open": "fa-wifi",
            "ui_icon_wardrive": "fa-satellite-dish",
            "ui_wardrive_color": "teal",
            "ui_wardrive_style": "pulse",
            "ui_hud_density": "comfortable",
            "ui_sidebar_preset": "wide",
            "ui_font_scale": "110",
            "ui_cracking_accordion_mode": "single",
            "ui_wardrive_replay_speed_default": "0.1",
            "ui_wardrive_replay_autoplay": True,
            "ui_wardrive_replay_auto_focus": False,
            "ui_wardrive_replay_follow_camera_default": True,
            "ui_wardrive_replay_follow_zoom_default": "19",
            "ui_wardrive_replay_timing_mode_default": "compress_idle",
            "ui_wardrive_sessions_sort_by": "distance",
            "ui_wardrive_sessions_sort_direction": "asc",
            "ui_wardrive_merge_confirmation": False,
            "ui_wardrive_route_accent_color": "orange",
            "ui_wardrive_primary_zone_accent_color": "purple",
            "ui_wardrive_secondary_accent_color": "white",
            "custom_rules_path": "  /tmp/rules  ",
            "hashcat_device_default": "all",
            "pwn_port": "not-int",
            "m5_sync_enabled": "true",
            "m5_host": " 192.168.4.1 ",
            "m5_port": "2022",
            "m5_web_protocol": "https",
            "m5_admin_base_path": " /evil-menu/ ",
            "m5_web_user": " admin ",
            "m5_web_password": " secret ",
            "m5_remote_root": " /sdcard/evil ",
            "m5_handshake_remote_path": " handshake ",
            "m5_wardrive_remote_path": " wardriving ",
        }
    )
    assert saved["map_cluster_mode"] == "performance"
    assert saved["ui_theme"] == "green"
    assert saved["ui_icon_open"] == "fa-wifi"
    assert saved["ui_icon_wardrive"] == "fa-satellite-dish"
    assert saved["ui_wardrive_color"] == "teal"
    assert saved["ui_wardrive_style"] == "pulse"
    assert saved["ui_hud_density"] == "comfortable"
    assert saved["ui_sidebar_preset"] == "wide"
    assert saved["ui_font_scale"] == "110"
    assert saved["ui_cracking_accordion_mode"] == "single"
    assert saved["ui_wardrive_replay_speed_default"] == "0.1"
    assert saved["ui_wardrive_replay_autoplay"] is True
    assert saved["ui_wardrive_replay_auto_focus"] is False
    assert saved["ui_wardrive_replay_follow_camera_default"] is True
    assert saved["ui_wardrive_replay_follow_zoom_default"] == "19"
    assert saved["ui_wardrive_replay_timing_mode_default"] == "compress_idle"
    assert saved["ui_wardrive_sessions_sort_by"] == "distance"
    assert saved["ui_wardrive_sessions_sort_direction"] == "asc"
    assert saved["ui_wardrive_merge_confirmation"] is False
    assert saved["ui_wardrive_route_accent_color"] == "orange"
    assert saved["ui_wardrive_primary_zone_accent_color"] == "purple"
    assert saved["ui_wardrive_secondary_accent_color"] == "white"
    assert saved["custom_rules_path"] == "/tmp/rules"
    assert saved["hashcat_device_default"] == "all"
    assert saved["pwn_port"] == config.DEFAULT_CONFIG["pwn_port"]
    assert saved["m5_sync_enabled"] is True
    assert saved["m5_host"] == "192.168.4.1"
    assert saved["m5_port"] == 2022
    assert saved["m5_web_protocol"] == "https"
    assert saved["m5_admin_base_path"] == "/evil-menu"
    assert saved["m5_web_user"] == "admin"
    assert saved["m5_web_password"] == "secret"
    assert saved["m5_handshake_remote_path"] == "evil/handshake"
    assert saved["m5_wardrive_remote_path"] == "evil/wardriving"


def test_sanitize_config_for_client_hides_password():
    sanitized = config.sanitize_config_for_client(
        {
            "pwn_host": "10.0.0.5",
            "pwn_pass": "secret",
            "m5_host": "192.168.4.1",
            "m5_user": "root",
            "m5_web_password": "test",
            "m5_remote_root": "/sdcard/evil",
        }
    )

    assert sanitized["pwn_host"] == "10.0.0.5"
    assert sanitized["pwn_pass_configured"] is True
    assert "pwn_pass" not in sanitized
    assert sanitized["m5_host"] == "192.168.4.1"
    assert sanitized["m5_web_password_configured"] is True
    assert "m5_user" not in sanitized
    assert "m5_remote_root" not in sanitized
    assert "m5_pass" not in sanitized
    assert "m5_transport" not in sanitized
    assert "m5_web_base_path" not in sanitized


def test_sanitize_config_for_client_without_passwords():
    sanitized = config.sanitize_config_for_client(
        {
            "pwn_host": "10.0.0.5",
            "m5_host": "192.168.4.1",
        }
    )

    assert sanitized["pwn_pass_configured"] is False
    assert sanitized["m5_web_password_configured"] is False


def test_normalize_bool_edge_cases():
    assert config._normalize_bool(True, False) is True
    assert config._normalize_bool(False, True) is False
    assert config._normalize_bool(1, False) is True
    assert config._normalize_bool(0, True) is False
    assert config._normalize_bool("true", False) is True
    assert config._normalize_bool("FALSE", True) is False
    assert config._normalize_bool("YES", False) is True
    assert config._normalize_bool("no", True) is False
    assert config._normalize_bool("ON", False) is True
    assert config._normalize_bool("off", True) is False
    assert config._normalize_bool("invalid", True) is True
    assert config._normalize_bool(None, False) is False


def test_normalize_int_bounds():
    assert config._normalize_int(123, 100, 1, 200) == 123
    assert config._normalize_int(0, 100, 1, 200) == 100
    assert config._normalize_int(300, 100, 1, 200) == 100
    assert config._normalize_int("not-int", 42) == 42
    assert config._normalize_int(None, 42) == 42


def test_normalize_choice_case_insensitive():
    assert (
        config._normalize_choice("PURPLE", "cyan", config._ALLOWED_UI_THEMES) == "cyan"
    )
    assert (
        config._normalize_choice("green", "cyan", config._ALLOWED_UI_THEMES) == "green"
    )


def test_normalize_m5_web_path_cleanup():
    assert config._normalize_m5_web_path("//evil//test//", "/") == "evil/test"
    assert (
        config._normalize_m5_web_path("/sdcard/evil/handshakes", "/")
        == "evil/handshakes"
    )
    assert config._normalize_m5_web_path("   /   ", "/") == "/"
    assert config._normalize_m5_web_path("", "/test") == "/test"


def test_normalize_m5_admin_base_path():
    assert config._normalize_m5_admin_base_path("evil-menu", "/") == "/evil-menu"
    assert config._normalize_m5_admin_base_path("/evil-menu/", "/") == "/evil-menu"
    assert config._normalize_m5_admin_base_path("/", "/") == "/"


def test_derive_legacy_m5_web_path():
    # Without legacy root
    assert (
        config._derive_legacy_m5_web_path("", "handshakes", "default") == "handshakes"
    )

    # With legacy root containing evil
    assert (
        config._derive_legacy_m5_web_path("/sdcard/evil/", "handshakes", "default")
        == "evil/handshakes"
    )
    assert config._derive_legacy_m5_web_path("/evil/test", "", "default") == "default"


def test_normalize_device_default():
    assert config._normalize_device_default("all", "all") == "all"
    assert config._normalize_device_default("0", "all") == "0"
    assert config._normalize_device_default("123", "all") == "123"
    assert config._normalize_device_default("invalid", "all") == "all"
    assert config._normalize_device_default("", "all") == "all"


def test_normalize_config_force_sync_alias(monkeypatch, tmp_path):
    cfg_path = tmp_path / "config.json"
    monkeypatch.setattr(config, "CONFIG_FILE", str(cfg_path))

    cfg_path.write_text(json.dumps({"force_sync": True}))
    loaded = config.load_config()
    assert loaded["pwn_force_sync"] is True
    assert loaded["force_sync"] is True


def test_load_config_invalid_json_falls_back_defaults(tmp_path, monkeypatch):
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text("invalid json content")
    monkeypatch.setattr(config, "CONFIG_FILE", str(cfg_path))

    loaded = config.load_config()
    assert loaded == config.DEFAULT_CONFIG
