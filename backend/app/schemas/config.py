from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

AttackMode = Literal[
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
]

WorkloadProfile = Literal["1", "2", "3", "4"]
MapTile = Literal[
    "carto_dark",
    "carto_dark_nolabels",
    "osm",
    "opentopomap",
    "esri_sat",
    "carto_light",
]
MapClusterMode = Literal[
    "performance",
    "ultra",
    "spread",
    "tight",
]
UIVisualTheme = Literal["cyberpunk", "professional", "synthwave", "military"]
UITheme = Literal[
    "cyan", "purple", "green", "pink", "orange",
    "steel", "slate", "forest", "amber", "rose",
    "sunset", "vapor", "miami", "retro", "plasma",
    "tactical", "desert", "nightvision", "command", "stealth",
]
M5WebProtocol = Literal["http", "https"]
UIPwnedIcon = Literal["fa-skull", "fa-ghost", "fa-gem"]
UILockedIcon = Literal["fa-shield-halved", "fa-lock", "fa-house-lock", "fa-vault"]
UIOpenIcon = Literal["fa-bolt", "fa-wifi", "fa-unlock", "fa-signal"]
UIWardriveIcon = Literal[
    "fa-tower-broadcast",
    "fa-satellite-dish",
    "fa-location-crosshairs",
    "fa-signal",
]
UIWardriveColor = Literal["teal", "cyan", "purple", "yellow", "green", "orange"]
UIWardriveStyle = Literal["icon", "badge", "pulse"]
UIHudDensity = Literal["compact", "balanced", "comfortable"]
UISidebarPreset = Literal["narrow", "standard", "wide"]
UIFontScale = Literal["90", "100", "110"]
UICrackingAccordionMode = Literal["multi", "single"]
UIWardriveReplaySpeed = Literal[
    "0.05", "0.1", "0.25", "0.5", "1", "1.5", "2", "2.5", "4", "8"
]
UIWardriveReplayTimingMode = Literal["real_time", "compress_idle", "uniform_path"]
UIWardriveReplayFollowZoom = Literal["current", "13", "15", "17", "19"]
UIWardriveSessionSortBy = Literal["none", "date", "duration", "distance", "nets"]
UISortDirection = Literal["asc", "desc"]
UIWardriveAccentColor = Literal[
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
]


class ConfigUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    pwn_sync_enabled: Optional[bool] = None
    pwn_host: Optional[str] = None
    pwn_port: Optional[int] = Field(default=None, ge=1, le=65535)
    pwn_user: Optional[str] = None
    pwn_pass: Optional[str] = None
    remote_path: Optional[str] = None
    pwn_force_sync: Optional[bool] = None
    m5_sync_enabled: Optional[bool] = None
    m5_force_sync: Optional[bool] = None
    m5_host: Optional[str] = None
    m5_port: Optional[int] = Field(default=None, ge=1, le=65535)
    m5_web_protocol: Optional[M5WebProtocol] = None
    m5_admin_base_path: Optional[str] = None
    m5_web_user: Optional[str] = None
    m5_web_password: Optional[str] = None
    m5_handshake_remote_path: Optional[str] = None
    m5_wardrive_remote_path: Optional[str] = None
    bruce_sync_enabled: Optional[bool] = None
    bruce_force_sync: Optional[bool] = None
    bruce_host: Optional[str] = None
    bruce_port: Optional[int] = Field(default=None, ge=1, le=65535)
    bruce_web_protocol: Optional[M5WebProtocol] = None
    bruce_web_user: Optional[str] = None
    bruce_web_password: Optional[str] = None

    hashcat_path: Optional[str] = None
    hcxpcapngtool_path: Optional[str] = None
    aircrack_path: Optional[str] = None
    tshark_path: Optional[str] = None

    custom_wordlists_path: Optional[str] = None
    custom_rules_path: Optional[str] = None
    custom_masks_path: Optional[str] = None
    ssh_known_hosts_path: Optional[str] = None

    use_wsl: Optional[bool] = None
    attack_mode: Optional[AttackMode] = None
    workload_profile: Optional[WorkloadProfile] = None
    hashcat_optimized: Optional[bool] = None
    hashcat_slow: Optional[bool] = None
    hashcat_potfile: Optional[bool] = None
    hashcat_device_default: Optional[str] = Field(default=None, pattern=r"^(all|\d+)$")

    map_tile: Optional[MapTile] = None
    map_cluster_mode: Optional[MapClusterMode] = None
    force_sync: Optional[bool] = None
    rawsniffer_include_raw_only_networks: Optional[bool] = None

    ui_hide_passwords: Optional[bool] = None
    ui_visual_theme: Optional[UIVisualTheme] = None
    ui_theme: Optional[UITheme] = None
    ui_icon_pwned: Optional[UIPwnedIcon] = None
    ui_icon_locked: Optional[UILockedIcon] = None
    ui_icon_open: Optional[UIOpenIcon] = None
    ui_icon_wardrive: Optional[UIWardriveIcon] = None
    ui_wardrive_color: Optional[UIWardriveColor] = None
    ui_wardrive_style: Optional[UIWardriveStyle] = None
    ui_hud_density: Optional[UIHudDensity] = None
    ui_sidebar_preset: Optional[UISidebarPreset] = None
    ui_font_scale: Optional[UIFontScale] = None
    ui_cracking_accordion_mode: Optional[UICrackingAccordionMode] = None
    ui_wardrive_replay_speed_default: Optional[UIWardriveReplaySpeed] = None
    ui_wardrive_replay_autoplay: Optional[bool] = None
    ui_wardrive_replay_auto_focus: Optional[bool] = None
    ui_wardrive_replay_follow_camera_default: Optional[bool] = None
    ui_wardrive_replay_follow_zoom_default: Optional[UIWardriveReplayFollowZoom] = None
    ui_wardrive_replay_timing_mode_default: Optional[UIWardriveReplayTimingMode] = None
    ui_wardrive_sessions_sort_by: Optional[UIWardriveSessionSortBy] = None
    ui_wardrive_sessions_sort_direction: Optional[UISortDirection] = None
    ui_wardrive_merge_confirmation: Optional[bool] = None
    ui_wardrive_route_accent_color: Optional[UIWardriveAccentColor] = None
    ui_wardrive_primary_zone_accent_color: Optional[UIWardriveAccentColor] = None
    ui_wardrive_secondary_accent_color: Optional[UIWardriveAccentColor] = None
