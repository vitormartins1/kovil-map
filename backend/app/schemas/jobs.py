from pydantic import BaseModel
from typing import Optional


class HashcatJobRequest(BaseModel):
    filename: str
    capture_id: Optional[str] = None
    combined_build_id: Optional[str] = None
    mac: Optional[str] = None
    attack_mode: Optional[str] = None
    workload_profile: Optional[str] = None
    wordlist: Optional[str] = None
    rule_file: Optional[str] = None
    custom_mask: Optional[str] = None
    is_optimized: bool = False
    is_slow: bool = False
    device_id: Optional[str] = None
    enable_potfile: bool = False
    wordlist_2: Optional[str] = None
    enable_increment: bool = False
    increment_min: Optional[int] = None
    increment_max: Optional[int] = None
    mask_file: Optional[str] = None
    association_hint: Optional[str] = None
    association_hints: Optional[str] = None
    skip_quality_gate: bool = False


class HashcatAssociationPreviewRequest(BaseModel):
    filename: str
    capture_id: Optional[str] = None
    combined_build_id: Optional[str] = None
    mac: Optional[str] = None
    mode: Optional[str] = "association"
    association_hint: Optional[str] = None
    association_hints: Optional[str] = None


class AircrackJobRequest(BaseModel):
    filename: Optional[str] = None
    capture_id: Optional[str] = None
    raw_item_id: Optional[str] = None
    bssid: str
    wordlist: str


class PmkBuildRequest(BaseModel):
    essid: str
    wordlist: str
    db_name: Optional[str] = None


class PmkAttackRequest(BaseModel):
    filename: Optional[str] = None
    capture_id: Optional[str] = None
    raw_item_id: Optional[str] = None
    bssid: str
    db_name: str


class WpsAttackRequest(BaseModel):
    bssid: str
    channel: str
    interface: str
    tool: str = "reaver"
    pixie_dust: bool = False
    delay: Optional[int] = None


class RawSnifferExtractRequest(BaseModel):
    filename: Optional[str] = None
    force: bool = False
    only_pending: bool = False


class JobPatchRequest(BaseModel):
    status: str
