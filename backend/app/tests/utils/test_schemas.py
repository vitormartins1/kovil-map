import pytest
from pydantic import ValidationError

from app.schemas.config import ConfigUpdateRequest
from app.schemas.sync import SyncRequest, SyncTrustHostKeyRequest
from app.schemas.zones import ZonesRequest
from app.schemas.jobs import HashcatJobRequest, HashcatAssociationPreviewRequest


def test_sync_request_defaults():
    req = SyncRequest()
    assert req.force is False


def test_sync_trust_host_key_request_defaults():
    req = SyncTrustHostKeyRequest()
    assert req.host is None
    assert req.port is None
    assert req.replace is False
    assert req.target is None


def test_zones_request_defaults():
    req = ZonesRequest()
    assert req.points == []
    assert req.eps_m == 200
    assert req.min_samples == 3


def test_hashcat_job_request_minimal():
    req = HashcatJobRequest(filename="example.22000")
    assert req.filename == "example.22000"
    assert req.is_optimized is False
    assert req.is_slow is False
    assert req.mask_file is None
    assert req.association_hint is None
    assert req.association_hints is None


def test_hashcat_association_preview_request_defaults():
    req = HashcatAssociationPreviewRequest(filename="example.22000")
    assert req.filename == "example.22000"
    assert req.mode == "association"
    assert req.association_hint is None
    assert req.association_hints is None


def test_config_update_request_accepts_known_fields():
    req = ConfigUpdateRequest(
        pwn_port=2222,
        m5_sync_enabled=True,
        m5_port=2022,
        m5_web_protocol="https",
        m5_admin_base_path="/evil-menu",
        m5_web_user="evil",
        m5_web_password="test",
        map_cluster_mode="tight",
        hashcat_device_default="01",
        ui_hud_density="comfortable",
        ui_sidebar_preset="wide",
        ui_font_scale="110",
        ui_cracking_accordion_mode="single",
        ui_cracking_attack_panel_mode="single",
        ui_wardrive_replay_speed_default="0.1",
        ui_wardrive_replay_follow_camera_default=True,
        ui_wardrive_replay_follow_zoom_default="19",
        ui_wardrive_replay_timing_mode_default="compress_idle",
        ui_wardrive_sessions_sort_by="distance",
        ui_wardrive_sessions_sort_direction="asc",
        ui_wardrive_route_accent_color="theme",
        ui_wardrive_primary_zone_accent_color="purple",
        ui_wardrive_secondary_accent_color="amber",
    )
    assert req.pwn_port == 2222
    assert req.m5_sync_enabled is True
    assert req.m5_port == 2022
    assert req.m5_web_protocol == "https"
    assert req.m5_admin_base_path == "/evil-menu"
    assert req.m5_web_user == "evil"
    assert req.m5_web_password == "test"
    assert req.map_cluster_mode == "tight"
    assert req.hashcat_device_default == "01"
    assert req.ui_hud_density == "comfortable"
    assert req.ui_sidebar_preset == "wide"
    assert req.ui_font_scale == "110"
    assert req.ui_cracking_accordion_mode == "single"
    assert req.ui_cracking_attack_panel_mode == "single"
    assert req.ui_wardrive_replay_speed_default == "0.1"
    assert req.ui_wardrive_replay_follow_camera_default is True
    assert req.ui_wardrive_replay_follow_zoom_default == "19"
    assert req.ui_wardrive_replay_timing_mode_default == "compress_idle"
    assert req.ui_wardrive_sessions_sort_by == "distance"
    assert req.ui_wardrive_sessions_sort_direction == "asc"
    assert req.ui_wardrive_route_accent_color == "theme"
    assert req.ui_wardrive_primary_zone_accent_color == "purple"
    assert req.ui_wardrive_secondary_accent_color == "amber"


def test_config_update_request_rejects_unknown_fields():
    with pytest.raises(ValidationError):
        ConfigUpdateRequest(unknown_field=True)


def test_config_update_request_rejects_invalid_layout_values():
    with pytest.raises(ValidationError):
        ConfigUpdateRequest(ui_hud_density="ultra")
    with pytest.raises(ValidationError):
        ConfigUpdateRequest(ui_cracking_attack_panel_mode="stacked")
