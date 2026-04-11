from typing import Optional

from pydantic import BaseModel, Field


class SyncRequest(BaseModel):
    force: bool = False
    pwn_force_sync: Optional[bool] = None
    m5_force_sync: Optional[bool] = None
    bruce_force_sync: Optional[bool] = None
    pwn_handshakes_process_id: Optional[str] = None
    m5_handshakes_process_id: Optional[str] = None
    m5_rawsniffer_process_id: Optional[str] = None
    m5_mastersniffer_process_id: Optional[str] = None
    m5_wardrive_process_id: Optional[str] = None
    bruce_handshakes_process_id: Optional[str] = None
    bruce_rawsniffer_process_id: Optional[str] = None
    bruce_wardrive_process_id: Optional[str] = None


class SyncTrustHostKeyRequest(BaseModel):
    host: Optional[str] = None
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    replace: bool = False
    target: Optional[str] = None


class PwnagotchiProbeRequest(BaseModel):
    pwn_host: Optional[str] = None
    pwn_port: Optional[int] = Field(default=None, ge=1, le=65535)
    pwn_user: Optional[str] = None
    pwn_pass: Optional[str] = None
    remote_path: Optional[str] = None


class M5EvilProbeRequest(BaseModel):
    m5_sync_enabled: Optional[bool] = None
    m5_host: Optional[str] = None
    m5_port: Optional[int] = Field(default=None, ge=1, le=65535)
    m5_web_protocol: Optional[str] = None
    m5_admin_base_path: Optional[str] = None
    m5_web_user: Optional[str] = None
    m5_web_password: Optional[str] = None
    m5_handshake_remote_path: Optional[str] = None
    m5_wardrive_remote_path: Optional[str] = None


class BruceProbeRequest(BaseModel):
    bruce_sync_enabled: Optional[bool] = None
    bruce_host: Optional[str] = None
    bruce_port: Optional[int] = Field(default=None, ge=1, le=65535)
    bruce_web_protocol: Optional[str] = None
    bruce_web_user: Optional[str] = None
    bruce_web_password: Optional[str] = None
