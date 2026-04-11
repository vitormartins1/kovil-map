from fastapi import APIRouter, Body
from app.schemas.zones import ZonesRequest, ToConquerZonesRequest
from app.services.to_conquer_service import (
    build_conquered_zones,
    build_to_conquer_zones,
)
from app.utils.responses import ok, fail

router = APIRouter()


@router.post("/api/zones", tags=["Zones"])
def get_zones(payload: ZonesRequest = Body(...)):
    points = payload.points or []
    try:
        eps_m = float(payload.eps_m)
        min_samples = int(payload.min_samples)
    except (TypeError, ValueError):
        fail("Invalid eps_m or min_samples")

    sanitized = []
    for p in points:
        if not isinstance(p, dict):
            continue
        lat = p.get("lat")
        lng = p.get("lng")
        acc = p.get("acc", 0)
        if lat is None or lng is None:
            continue
        try:
            lat = float(lat)
            lng = float(lng)
            acc = float(acc) if acc is not None else 0.0
        except (TypeError, ValueError):
            continue
        sanitized.append({"lat": lat, "lng": lng, "acc": acc})

    zones = build_conquered_zones(sanitized, eps_m=eps_m, min_samples=min_samples)
    return ok({"params": {"eps_m": eps_m, "min_samples": min_samples}, "zones": zones})


@router.post("/api/zones/to-conquer", tags=["Zones"])
def get_to_conquer_zones(payload: ToConquerZonesRequest = Body(...)):
    conquered_points = payload.conquered_points or []
    to_conquer_points = payload.to_conquer_points or []
    try:
        eps_m = float(payload.eps_m)
        min_samples = int(payload.min_samples)
        acc_segments = int(payload.acc_segments)
        min_zone_points = int(payload.min_zone_points)
    except (TypeError, ValueError):
        fail("Invalid params")

    def sanitize(points):
        sanitized = []
        for p in points:
            if not isinstance(p, dict):
                continue
            lat = p.get("lat")
            lng = p.get("lng")
            acc = p.get("acc", 0)
            if lat is None or lng is None:
                continue
            try:
                lat = float(lat)
                lng = float(lng)
                acc = float(acc) if acc is not None else 0.0
            except (TypeError, ValueError):
                continue
            sanitized.append({"lat": lat, "lng": lng, "acc": acc})
        return sanitized

    conquered = sanitize(conquered_points)
    to_conquer = sanitize(to_conquer_points)

    zones = build_to_conquer_zones(
        conquered,
        to_conquer,
        eps_m=eps_m,
        min_samples=min_samples,
        acc_segments=acc_segments,
        min_zone_points=min_zone_points,
    )
    return ok(
        {
            "params": {
                "eps_m": eps_m,
                "min_samples": min_samples,
                "acc_segments": acc_segments,
                "min_zone_points": min_zone_points,
            },
            "zones": zones,
        }
    )
