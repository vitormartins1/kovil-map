from pydantic import BaseModel, Field


class ZonesRequest(BaseModel):
    points: list = Field(default_factory=list)
    eps_m: float = 200
    min_samples: int = 3


class ToConquerZonesRequest(BaseModel):
    conquered_points: list = Field(default_factory=list)
    to_conquer_points: list = Field(default_factory=list)
    eps_m: float = 200
    min_samples: int = 3
    acc_segments: int = 8
    min_zone_points: int = 2
