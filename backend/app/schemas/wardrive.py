from pydantic import BaseModel, ConfigDict, Field
from typing import List, Literal, Optional


class WardriveZonesRequest(BaseModel):
    region_id: str = Field(..., min_length=1)
    eps_m: float = 200
    min_samples: int = 3
    time_window: str = "all"
    source: str = "all"
    session_ids: Optional[List[str]] = None
    comparison_mode: Literal["standard", "focus_active"] = "standard"
    active_session_id: Optional[str] = None


class WardriveRefreshRequest(BaseModel):
    reload_data: bool = True
    reload_maps: bool = False


class WardriveSessionTagRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    session_id: str = Field(..., min_length=1)
    transport_mode: Optional[str] = None


class WardriveSessionTracksRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    session_ids: List[str] = Field(default_factory=list)


class WardriveSessionMergeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    session_ids: List[str] = Field(default_factory=list)
