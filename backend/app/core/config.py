import json
import os
import sys

# Detecta se está rodando como executável (PyInstaller) ou script
if getattr(sys, "frozen", False):
    # Se for executável, o diretório base é onde o .exe está
    BASE_DIR = os.path.dirname(sys.executable)
else:
    # Se for script, é o diretório raiz do backend (dois níveis acima de app/core)
    # app/core/config.py -> app/core -> app -> backend
    BASE_DIR = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )

DATA_DIR = os.path.join(BASE_DIR, "data")
HANDSHAKES_DIR = os.path.join(DATA_DIR, "handshakes")
WARDRIVE_DIR = os.path.join(DATA_DIR, "wardrive")
MAPS_DIR = os.path.join(DATA_DIR, "maps")
BRUCE_PCAP_DIR = os.path.join(DATA_DIR, "BrucePCAP")
BRUCE_HANDSHAKES_DIR = os.path.join(BRUCE_PCAP_DIR, "handshakes")
BRUCE_RAWSNIFFER_DIR = os.path.join(BRUCE_PCAP_DIR, "rawsniffer")
BRUCE_WARDRIVE_DIR = os.path.join(DATA_DIR, "wardrive")

# Fixed remote paths on the current Bruce WebUI filesystem
BRUCE_HANDSHAKE_REMOTE_PATH = "/BrucePCAP/handshakes"
BRUCE_RAWSNIFFER_REMOTE_PATH = "/BrucePCAP"
BRUCE_WARDRIVE_REMOTE_PATH = "/BruceWardriving"
M5EVIL_DIR = os.path.join(DATA_DIR, "m5evil")
M5EVIL_HANDSHAKES_DIR = os.path.join(M5EVIL_DIR, "handshakes")
M5EVIL_RAWSNIFFER_DIR = os.path.join(M5EVIL_DIR, "rawsniffer")
M5EVIL_MASTERSNIFFER_DIR = os.path.join(M5EVIL_DIR, "mastersniffer")
PEERS_DIR = os.path.join(DATA_DIR, "peers")
PMK_DIR = os.path.join(DATA_DIR, "airolib")
CONFIG_FILE = os.path.join(BASE_DIR, "config.json")

# Garante diretórios
os.makedirs(HANDSHAKES_DIR, exist_ok=True)
os.makedirs(WARDRIVE_DIR, exist_ok=True)
os.makedirs(MAPS_DIR, exist_ok=True)
os.makedirs(BRUCE_PCAP_DIR, exist_ok=True)
os.makedirs(BRUCE_HANDSHAKES_DIR, exist_ok=True)
os.makedirs(BRUCE_RAWSNIFFER_DIR, exist_ok=True)
os.makedirs(M5EVIL_DIR, exist_ok=True)
os.makedirs(M5EVIL_HANDSHAKES_DIR, exist_ok=True)
os.makedirs(M5EVIL_RAWSNIFFER_DIR, exist_ok=True)
os.makedirs(M5EVIL_MASTERSNIFFER_DIR, exist_ok=True)
os.makedirs(PEERS_DIR, exist_ok=True)
os.makedirs(PMK_DIR, exist_ok=True)

_ALLOWED_ATTACK_MODES = {
    "straight",
    "rules",
    "passphrase",
    "association",
    "association_hint_first",
    "association_hint_rule",
    "combinator",
    "combinator_passphrase",
    "digits",
    "mask",
    "mask_profile",
    "hybrid",
    "hybrid_reverse",
    "hybrid_mask_profile",
    "hybrid_reverse_mask_profile",
}
_ALLOWED_WORKLOADS = {"1", "2", "3", "4"}
_ALLOWED_MAP_TILES = {
    "carto_dark",
    "carto_dark_nolabels",
    "osm",
    "opentopomap",
    "esri_sat",
    "carto_light",
}
_ALLOWED_CLUSTER_MODES = {
    "performance",
    "ultra",
    "spread",
    "tight",
}
_ALLOWED_UI_VISUAL_THEMES = {"cyberpunk", "professional", "synthwave", "military"}
_ALLOWED_UI_THEMES = {
    "cyan", "purple", "green", "pink", "orange",
    "steel", "slate", "forest", "amber", "rose",
    "sunset", "vapor", "miami", "retro", "plasma",
    "tactical", "desert", "nightvision", "command", "stealth",
}
_ALLOWED_PWNED_ICONS = {"fa-skull", "fa-ghost", "fa-gem"}
_ALLOWED_LOCKED_ICONS = {"fa-shield-halved", "fa-lock", "fa-house-lock", "fa-vault"}
_ALLOWED_OPEN_ICONS = {"fa-bolt", "fa-wifi", "fa-unlock", "fa-signal"}
_ALLOWED_WARDRIVE_ICONS = {
    "fa-tower-broadcast",
    "fa-satellite-dish",
    "fa-location-crosshairs",
    "fa-signal",
}
_ALLOWED_WARDRIVE_COLORS = {
    "teal",
    "cyan",
    "purple",
    "yellow",
    "green",
    "orange",
}
_ALLOWED_WARDRIVE_STYLES = {"icon", "badge", "pulse"}
_ALLOWED_UI_HUD_DENSITY = {"compact", "balanced", "comfortable"}
_ALLOWED_UI_SIDEBAR_PRESETS = {"narrow", "standard", "wide"}
_ALLOWED_UI_FONT_SCALE = {"90", "100", "110"}
_ALLOWED_UI_CRACKING_ACCORDION_MODES = {"multi", "single"}
_ALLOWED_M5_WEB_PROTOCOLS = {"http", "https"}
_ALLOWED_UI_WARDRIVE_REPLAY_SPEEDS = {
    "0.05",
    "0.1",
    "0.25",
    "0.5",
    "1",
    "1.5",
    "2",
    "2.5",
    "4",
    "8",
}
_ALLOWED_UI_WARDRIVE_REPLAY_TIMING_MODES = {
    "real_time",
    "compress_idle",
    "uniform_path",
}
_ALLOWED_UI_WARDRIVE_REPLAY_FOLLOW_ZOOMS = {"current", "13", "15", "17", "19"}
_ALLOWED_UI_WARDRIVE_SESSION_SORT = {"none", "date", "duration", "distance", "nets"}
_ALLOWED_SORT_DIRECTIONS = {"asc", "desc"}
_ALLOWED_UI_WARDRIVE_ACCENT_COLORS = {
    "theme",
    "teal",
    "cyan",
    "purple",
    "yellow",
    "green",
    "orange",
    "pink",
    "amber",
    "red",
    "white",
}

# Valores padrão
DEFAULT_CONFIG = {
    "pwn_sync_enabled": True,
    "pwn_host": "10.0.0.2",
    "pwn_port": 22,
    "pwn_user": "pi",
    "pwn_pass": "raspberry",
    "remote_path": "/home/pi/handshakes",
    "pwn_force_sync": False,
    "m5_sync_enabled": False,
    "m5_force_sync": False,
    "m5_host": "192.168.4.1",
    "m5_port": 80,
    "m5_web_protocol": "http",
    "m5_admin_base_path": "/evil-menu",
    "m5_web_user": "evil",
    "m5_web_password": "test",
    "m5_handshake_remote_path": "evil/handshakes",
    "m5_wardrive_remote_path": "evil/wardriving",
    "bruce_sync_enabled": False,
    "bruce_force_sync": False,
    "bruce_host": "bruce.local",
    "bruce_port": 80,
    "bruce_web_protocol": "http",
    "bruce_web_user": "admin",
    "bruce_web_password": "bruce",
    "hashcat_path": "hashcat",
    "hcxpcapngtool_path": "hcxpcapngtool",
    "aircrack_path": "aircrack-ng",
    "airolib_path": "airolib-ng",
    "reaver_path": "reaver",
    "bully_path": "bully",
    "tshark_path": "tshark",
    "custom_wordlists_path": "",
    "custom_rules_path": "",
    "custom_masks_path": "",
    "ssh_known_hosts_path": "",
    "use_wsl": False,
    "attack_mode": "straight",
    "workload_profile": "3",
    "hashcat_optimized": False,  # Default -O
    "hashcat_slow": False,  # Default -S
    "hashcat_potfile": False,  # Default Potfile (False = --potfile-disable)
    "hashcat_device_default": "all",
    "map_tile": "carto_dark",
    "map_cluster_mode": "performance",
    "force_sync": False,
    "rawsniffer_include_raw_only_networks": False,
    "ui_hide_passwords": False,
    "ui_visual_theme": "professional",
    "ui_theme": "slate",
    "ui_icon_pwned": "fa-skull",
    "ui_icon_locked": "fa-shield-halved",
    "ui_icon_open": "fa-bolt",
    "ui_icon_wardrive": "fa-tower-broadcast",
    "ui_wardrive_color": "teal",
    "ui_wardrive_style": "icon",
    "ui_hud_density": "balanced",
    "ui_sidebar_preset": "standard",
    "ui_font_scale": "100",
    "ui_cracking_accordion_mode": "multi",
    "ui_wardrive_replay_speed_default": "1",
    "ui_wardrive_replay_autoplay": False,
    "ui_wardrive_replay_auto_focus": True,
    "ui_wardrive_replay_follow_camera_default": False,
    "ui_wardrive_replay_follow_zoom_default": "current",
    "ui_wardrive_replay_timing_mode_default": "real_time",
    "ui_wardrive_sessions_sort_by": "none",
    "ui_wardrive_sessions_sort_direction": "desc",
    "ui_wardrive_merge_confirmation": True,
    "ui_wardrive_route_accent_color": "theme",
    "ui_wardrive_primary_zone_accent_color": "theme",
    "ui_wardrive_secondary_accent_color": "amber",
}

SENSITIVE_CLIENT_CONFIG_KEYS = {"pwn_pass", "m5_web_password", "bruce_web_password"}


def _normalize_bool(value, default):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    return default


def _normalize_int(value, default, minimum=None, maximum=None):
    try:
        normalized = int(value)
    except (TypeError, ValueError):
        return default
    if minimum is not None and normalized < minimum:
        return default
    if maximum is not None and normalized > maximum:
        return default
    return normalized


def _normalize_string(value, default):
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def _normalize_choice(value, default, allowed_values):
    normalized = _normalize_string(value, default)
    if normalized in allowed_values:
        return normalized
    return default


def _normalize_m5_web_path(value, default):
    normalized = _normalize_string(value, default).replace("\\", "/")
    normalized = normalized.strip()
    if not normalized:
        return default
    while "//" in normalized:
        normalized = normalized.replace("//", "/")
    if normalized != "/" and normalized.endswith("/"):
        normalized = normalized.rstrip("/")
    if normalized.startswith("/sdcard/"):
        normalized = normalized[len("/sdcard/") :]
    return normalized.strip("/") if normalized != "/" else "/"


def _normalize_m5_admin_base_path(value, default):
    normalized = _normalize_m5_web_path(value, default)
    if normalized == "/":
        return normalized
    return f"/{normalized.strip('/')}"


def _derive_legacy_m5_web_path(root_value, child_value, fallback):
    child = _normalize_string(child_value, "").replace("\\", "/").strip()
    if child.startswith("/sdcard/"):
        return _normalize_m5_web_path(child, fallback)

    root = _normalize_string(root_value, "").replace("\\", "/").strip()
    legacy_prefix = ""
    if root:
        parts = [part for part in root.split("/") if part]
        if "evil" in parts:
            legacy_prefix = "/".join(parts[parts.index("evil") :])

    if not child:
        return fallback
    child = child.strip("/")
    if (
        legacy_prefix
        and not child.startswith(f"{legacy_prefix}/")
        and child != legacy_prefix
    ):
        child = f"{legacy_prefix}/{child}"
    return _normalize_m5_web_path(child, fallback)


def _normalize_workload(value, default):
    normalized = _normalize_string(value, default)
    if normalized in _ALLOWED_WORKLOADS:
        return normalized
    return default


def _normalize_device_default(value, default):
    normalized = _normalize_string(value, default)
    if not normalized:
        return default
    if normalized.lower() == "all":
        return "all"
    if normalized.isdigit():
        return normalized
    return default


def normalize_config(raw_config):
    data = raw_config if isinstance(raw_config, dict) else {}
    migrated = dict(data)

    legacy_wordlist = migrated.pop("wordlist_path", None)
    if (
        isinstance(legacy_wordlist, str)
        and legacy_wordlist.strip()
        and not migrated.get("custom_wordlists_path")
    ):
        migrated["custom_wordlists_path"] = legacy_wordlist

    normalized = dict(DEFAULT_CONFIG)

    normalized["pwn_host"] = _normalize_string(
        migrated.get("pwn_host"), DEFAULT_CONFIG["pwn_host"]
    )
    normalized["pwn_sync_enabled"] = _normalize_bool(
        migrated.get("pwn_sync_enabled"), DEFAULT_CONFIG["pwn_sync_enabled"]
    )
    normalized["pwn_port"] = _normalize_int(
        migrated.get("pwn_port"), DEFAULT_CONFIG["pwn_port"], minimum=1, maximum=65535
    )
    normalized["pwn_user"] = _normalize_string(
        migrated.get("pwn_user"), DEFAULT_CONFIG["pwn_user"]
    )
    normalized["pwn_pass"] = _normalize_string(
        migrated.get("pwn_pass"), DEFAULT_CONFIG["pwn_pass"]
    )
    normalized["remote_path"] = _normalize_string(
        migrated.get("remote_path"), DEFAULT_CONFIG["remote_path"]
    )
    normalized["pwn_force_sync"] = _normalize_bool(
        migrated.get("pwn_force_sync", migrated.get("force_sync")),
        DEFAULT_CONFIG["pwn_force_sync"],
    )
    normalized["m5_sync_enabled"] = _normalize_bool(
        migrated.get("m5_sync_enabled"), DEFAULT_CONFIG["m5_sync_enabled"]
    )
    normalized["m5_force_sync"] = _normalize_bool(
        migrated.get("m5_force_sync"), DEFAULT_CONFIG["m5_force_sync"]
    )
    normalized["m5_host"] = _normalize_string(
        migrated.get("m5_host"), DEFAULT_CONFIG["m5_host"]
    )
    normalized["m5_port"] = _normalize_int(
        migrated.get("m5_port"), DEFAULT_CONFIG["m5_port"], minimum=1, maximum=65535
    )
    normalized["m5_web_protocol"] = _normalize_choice(
        _normalize_string(
            migrated.get("m5_web_protocol"), DEFAULT_CONFIG["m5_web_protocol"]
        ).lower(),
        DEFAULT_CONFIG["m5_web_protocol"],
        _ALLOWED_M5_WEB_PROTOCOLS,
    )
    normalized["m5_admin_base_path"] = _normalize_m5_admin_base_path(
        migrated.get("m5_admin_base_path", migrated.get("m5_web_base_path")),
        DEFAULT_CONFIG["m5_admin_base_path"],
    )
    normalized["m5_web_user"] = _normalize_string(
        migrated.get("m5_web_user", migrated.get("m5_user")),
        DEFAULT_CONFIG["m5_web_user"],
    )
    normalized["m5_web_password"] = _normalize_string(
        migrated.get("m5_web_password", migrated.get("m5_pass")),
        DEFAULT_CONFIG["m5_web_password"],
    )
    normalized["m5_handshake_remote_path"] = _derive_legacy_m5_web_path(
        migrated.get("m5_remote_root"),
        migrated.get("m5_handshake_remote_path"),
        DEFAULT_CONFIG["m5_handshake_remote_path"],
    )
    normalized["m5_wardrive_remote_path"] = _derive_legacy_m5_web_path(
        migrated.get("m5_remote_root"),
        migrated.get("m5_wardrive_remote_path"),
        DEFAULT_CONFIG["m5_wardrive_remote_path"],
    )
    normalized["bruce_sync_enabled"] = _normalize_bool(
        migrated.get("bruce_sync_enabled"), DEFAULT_CONFIG["bruce_sync_enabled"]
    )
    normalized["bruce_force_sync"] = _normalize_bool(
        migrated.get("bruce_force_sync"), DEFAULT_CONFIG["bruce_force_sync"]
    )
    normalized["bruce_host"] = _normalize_string(
        migrated.get("bruce_host"), DEFAULT_CONFIG["bruce_host"]
    )
    normalized["bruce_port"] = _normalize_int(
        migrated.get("bruce_port"), DEFAULT_CONFIG["bruce_port"], minimum=1, maximum=65535
    )
    normalized["bruce_web_protocol"] = _normalize_choice(
        _normalize_string(
            migrated.get("bruce_web_protocol"), DEFAULT_CONFIG["bruce_web_protocol"]
        ).lower(),
        DEFAULT_CONFIG["bruce_web_protocol"],
        _ALLOWED_M5_WEB_PROTOCOLS,
    )
    normalized["bruce_web_user"] = _normalize_string(
        migrated.get("bruce_web_user"), DEFAULT_CONFIG["bruce_web_user"]
    )
    normalized["bruce_web_password"] = _normalize_string(
        migrated.get("bruce_web_password"), DEFAULT_CONFIG["bruce_web_password"]
    )
    normalized["hashcat_path"] = _normalize_string(
        migrated.get("hashcat_path"), DEFAULT_CONFIG["hashcat_path"]
    )
    normalized["hcxpcapngtool_path"] = _normalize_string(
        migrated.get("hcxpcapngtool_path"), DEFAULT_CONFIG["hcxpcapngtool_path"]
    )
    normalized["aircrack_path"] = _normalize_string(
        migrated.get("aircrack_path"), DEFAULT_CONFIG["aircrack_path"]
    )
    normalized["airolib_path"] = _normalize_string(
        migrated.get("airolib_path"), DEFAULT_CONFIG["airolib_path"]
    )
    normalized["reaver_path"] = _normalize_string(
        migrated.get("reaver_path"), DEFAULT_CONFIG["reaver_path"]
    )
    normalized["bully_path"] = _normalize_string(
        migrated.get("bully_path"), DEFAULT_CONFIG["bully_path"]
    )
    normalized["tshark_path"] = _normalize_string(
        migrated.get("tshark_path"), DEFAULT_CONFIG["tshark_path"]
    )
    normalized["custom_wordlists_path"] = _normalize_string(
        migrated.get("custom_wordlists_path"), DEFAULT_CONFIG["custom_wordlists_path"]
    )
    normalized["custom_rules_path"] = _normalize_string(
        migrated.get("custom_rules_path"), DEFAULT_CONFIG["custom_rules_path"]
    )
    normalized["custom_masks_path"] = _normalize_string(
        migrated.get("custom_masks_path"), DEFAULT_CONFIG["custom_masks_path"]
    )
    normalized["ssh_known_hosts_path"] = _normalize_string(
        migrated.get("ssh_known_hosts_path"), DEFAULT_CONFIG["ssh_known_hosts_path"]
    )

    normalized["use_wsl"] = _normalize_bool(
        migrated.get("use_wsl"), DEFAULT_CONFIG["use_wsl"]
    )
    normalized["attack_mode"] = _normalize_choice(
        migrated.get("attack_mode"),
        DEFAULT_CONFIG["attack_mode"],
        _ALLOWED_ATTACK_MODES,
    )
    normalized["workload_profile"] = _normalize_workload(
        migrated.get("workload_profile"), DEFAULT_CONFIG["workload_profile"]
    )
    normalized["hashcat_optimized"] = _normalize_bool(
        migrated.get("hashcat_optimized"), DEFAULT_CONFIG["hashcat_optimized"]
    )
    normalized["hashcat_slow"] = _normalize_bool(
        migrated.get("hashcat_slow"), DEFAULT_CONFIG["hashcat_slow"]
    )
    normalized["hashcat_potfile"] = _normalize_bool(
        migrated.get("hashcat_potfile"), DEFAULT_CONFIG["hashcat_potfile"]
    )
    normalized["hashcat_device_default"] = _normalize_device_default(
        migrated.get("hashcat_device_default"), DEFAULT_CONFIG["hashcat_device_default"]
    )
    normalized["map_tile"] = _normalize_choice(
        migrated.get("map_tile"), DEFAULT_CONFIG["map_tile"], _ALLOWED_MAP_TILES
    )
    normalized["map_cluster_mode"] = _normalize_choice(
        migrated.get("map_cluster_mode"),
        DEFAULT_CONFIG["map_cluster_mode"],
        _ALLOWED_CLUSTER_MODES,
    )
    normalized["force_sync"] = normalized["pwn_force_sync"]
    normalized["rawsniffer_include_raw_only_networks"] = _normalize_bool(
        migrated.get("rawsniffer_include_raw_only_networks"),
        DEFAULT_CONFIG["rawsniffer_include_raw_only_networks"],
    )
    normalized["ui_hide_passwords"] = _normalize_bool(
        migrated.get("ui_hide_passwords"), DEFAULT_CONFIG["ui_hide_passwords"]
    )
    normalized["ui_visual_theme"] = _normalize_choice(
        migrated.get("ui_visual_theme"),
        DEFAULT_CONFIG["ui_visual_theme"],
        _ALLOWED_UI_VISUAL_THEMES,
    )
    normalized["ui_theme"] = _normalize_choice(
        migrated.get("ui_theme"), DEFAULT_CONFIG["ui_theme"], _ALLOWED_UI_THEMES
    )
    normalized["ui_icon_pwned"] = _normalize_choice(
        migrated.get("ui_icon_pwned"),
        DEFAULT_CONFIG["ui_icon_pwned"],
        _ALLOWED_PWNED_ICONS,
    )
    normalized["ui_icon_locked"] = _normalize_choice(
        migrated.get("ui_icon_locked"),
        DEFAULT_CONFIG["ui_icon_locked"],
        _ALLOWED_LOCKED_ICONS,
    )
    normalized["ui_icon_open"] = _normalize_choice(
        migrated.get("ui_icon_open"),
        DEFAULT_CONFIG["ui_icon_open"],
        _ALLOWED_OPEN_ICONS,
    )
    normalized["ui_icon_wardrive"] = _normalize_choice(
        migrated.get("ui_icon_wardrive"),
        DEFAULT_CONFIG["ui_icon_wardrive"],
        _ALLOWED_WARDRIVE_ICONS,
    )
    normalized["ui_wardrive_color"] = _normalize_choice(
        migrated.get("ui_wardrive_color"),
        DEFAULT_CONFIG["ui_wardrive_color"],
        _ALLOWED_WARDRIVE_COLORS,
    )
    normalized["ui_wardrive_style"] = _normalize_choice(
        migrated.get("ui_wardrive_style"),
        DEFAULT_CONFIG["ui_wardrive_style"],
        _ALLOWED_WARDRIVE_STYLES,
    )
    normalized["ui_hud_density"] = _normalize_choice(
        migrated.get("ui_hud_density"),
        DEFAULT_CONFIG["ui_hud_density"],
        _ALLOWED_UI_HUD_DENSITY,
    )
    normalized["ui_sidebar_preset"] = _normalize_choice(
        migrated.get("ui_sidebar_preset"),
        DEFAULT_CONFIG["ui_sidebar_preset"],
        _ALLOWED_UI_SIDEBAR_PRESETS,
    )
    normalized["ui_font_scale"] = _normalize_choice(
        migrated.get("ui_font_scale"),
        DEFAULT_CONFIG["ui_font_scale"],
        _ALLOWED_UI_FONT_SCALE,
    )
    normalized["ui_cracking_accordion_mode"] = _normalize_choice(
        migrated.get("ui_cracking_accordion_mode"),
        DEFAULT_CONFIG["ui_cracking_accordion_mode"],
        _ALLOWED_UI_CRACKING_ACCORDION_MODES,
    )
    normalized["ui_wardrive_replay_speed_default"] = _normalize_choice(
        migrated.get("ui_wardrive_replay_speed_default"),
        DEFAULT_CONFIG["ui_wardrive_replay_speed_default"],
        _ALLOWED_UI_WARDRIVE_REPLAY_SPEEDS,
    )
    normalized["ui_wardrive_replay_autoplay"] = _normalize_bool(
        migrated.get("ui_wardrive_replay_autoplay"),
        DEFAULT_CONFIG["ui_wardrive_replay_autoplay"],
    )
    normalized["ui_wardrive_replay_auto_focus"] = _normalize_bool(
        migrated.get("ui_wardrive_replay_auto_focus"),
        DEFAULT_CONFIG["ui_wardrive_replay_auto_focus"],
    )
    normalized["ui_wardrive_replay_follow_camera_default"] = _normalize_bool(
        migrated.get("ui_wardrive_replay_follow_camera_default"),
        DEFAULT_CONFIG["ui_wardrive_replay_follow_camera_default"],
    )
    normalized["ui_wardrive_replay_follow_zoom_default"] = _normalize_choice(
        migrated.get("ui_wardrive_replay_follow_zoom_default"),
        DEFAULT_CONFIG["ui_wardrive_replay_follow_zoom_default"],
        _ALLOWED_UI_WARDRIVE_REPLAY_FOLLOW_ZOOMS,
    )
    normalized["ui_wardrive_replay_timing_mode_default"] = _normalize_choice(
        migrated.get("ui_wardrive_replay_timing_mode_default"),
        DEFAULT_CONFIG["ui_wardrive_replay_timing_mode_default"],
        _ALLOWED_UI_WARDRIVE_REPLAY_TIMING_MODES,
    )
    normalized["ui_wardrive_sessions_sort_by"] = _normalize_choice(
        migrated.get("ui_wardrive_sessions_sort_by"),
        DEFAULT_CONFIG["ui_wardrive_sessions_sort_by"],
        _ALLOWED_UI_WARDRIVE_SESSION_SORT,
    )
    normalized["ui_wardrive_sessions_sort_direction"] = _normalize_choice(
        migrated.get("ui_wardrive_sessions_sort_direction"),
        DEFAULT_CONFIG["ui_wardrive_sessions_sort_direction"],
        _ALLOWED_SORT_DIRECTIONS,
    )
    normalized["ui_wardrive_merge_confirmation"] = _normalize_bool(
        migrated.get("ui_wardrive_merge_confirmation"),
        DEFAULT_CONFIG["ui_wardrive_merge_confirmation"],
    )
    normalized["ui_wardrive_route_accent_color"] = _normalize_choice(
        migrated.get("ui_wardrive_route_accent_color"),
        DEFAULT_CONFIG["ui_wardrive_route_accent_color"],
        _ALLOWED_UI_WARDRIVE_ACCENT_COLORS,
    )
    normalized["ui_wardrive_primary_zone_accent_color"] = _normalize_choice(
        migrated.get("ui_wardrive_primary_zone_accent_color"),
        DEFAULT_CONFIG["ui_wardrive_primary_zone_accent_color"],
        _ALLOWED_UI_WARDRIVE_ACCENT_COLORS,
    )
    normalized["ui_wardrive_secondary_accent_color"] = _normalize_choice(
        migrated.get("ui_wardrive_secondary_accent_color"),
        DEFAULT_CONFIG["ui_wardrive_secondary_accent_color"],
        _ALLOWED_UI_WARDRIVE_ACCENT_COLORS,
    )
    return normalized


def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                return normalize_config(data)
        except Exception:
            pass
    return dict(DEFAULT_CONFIG)


def save_config(new_config):
    current = load_config()
    incoming = new_config if isinstance(new_config, dict) else {}
    updated = normalize_config({**current, **incoming})
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(updated, f, indent=4)
    return updated


def sanitize_config_for_client(raw_config=None):
    config = dict(raw_config if isinstance(raw_config, dict) else load_config())
    secret = str(config.pop("pwn_pass", "") or "").strip()
    config["pwn_pass_configured"] = bool(secret)
    m5_secret = str(config.pop("m5_web_password", "") or "").strip()
    config["m5_web_password_configured"] = bool(m5_secret)
    bruce_secret = str(config.pop("bruce_web_password", "") or "").strip()
    config["bruce_web_password_configured"] = bool(bruce_secret)
    config.pop("m5_user", None)
    config.pop("m5_pass", None)
    config.pop("m5_transport", None)
    config.pop("m5_remote_root", None)
    config.pop("m5_web_base_path", None)
    return config


# Carrega config inicial para uso global
_conf = load_config()
PWNAGOTCHI_HOST = _conf.get("pwn_host", DEFAULT_CONFIG["pwn_host"])
PWNAGOTCHI_PORT = _conf.get("pwn_port", DEFAULT_CONFIG["pwn_port"])
PWNAGOTCHI_USER = _conf.get("pwn_user", DEFAULT_CONFIG["pwn_user"])
PWNAGOTCHI_PASS = _conf.get("pwn_pass", DEFAULT_CONFIG["pwn_pass"])
REMOTE_HANDSHAKES_DIR = _conf.get("remote_path", DEFAULT_CONFIG["remote_path"])
HASHCAT_PATH = _conf.get("hashcat_path", DEFAULT_CONFIG["hashcat_path"])
HCX_PATH = _conf.get("hcxpcapngtool_path", DEFAULT_CONFIG["hcxpcapngtool_path"])
AIRCRACK_PATH = _conf.get("aircrack_path", DEFAULT_CONFIG["aircrack_path"])
AIROLIB_PATH = _conf.get("airolib_path", DEFAULT_CONFIG["airolib_path"])
REAVER_PATH = _conf.get("reaver_path", DEFAULT_CONFIG["reaver_path"])
BULLY_PATH = _conf.get("bully_path", DEFAULT_CONFIG["bully_path"])
CUSTOM_WORDLISTS_PATH = _conf.get(
    "custom_wordlists_path", DEFAULT_CONFIG["custom_wordlists_path"]
)
TSHARK_PATH = _conf.get("tshark_path", DEFAULT_CONFIG["tshark_path"])
USE_WSL = _conf.get("use_wsl", DEFAULT_CONFIG["use_wsl"])
ATTACK_MODE = _conf.get("attack_mode", DEFAULT_CONFIG["attack_mode"])
WORKLOAD_PROFILE = _conf.get("workload_profile", DEFAULT_CONFIG["workload_profile"])
MAP_TILE = _conf.get("map_tile", DEFAULT_CONFIG["map_tile"])
MAP_CLUSTER_MODE = _conf.get("map_cluster_mode", DEFAULT_CONFIG["map_cluster_mode"])
