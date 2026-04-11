from fastapi import APIRouter, Body, Query

from app.api.ws.handlers import manager
from app.schemas.wardrive import (
    WardriveRefreshRequest,
    WardriveSessionMergeRequest,
    WardriveSessionTracksRequest,
    WardriveSessionTagRequest,
    WardriveZonesRequest,
)
from app.services.wardrive_regions_service import wardrive_regions_service
from app.utils.responses import fail, ok

router = APIRouter()

_ALLOWED_TIME_WINDOWS = {"all", "24h"}
_ALLOWED_SOURCES = {"all", "pwn", "bruce", "ward", "raw"}


def _validate_time_window(value: str) -> str:
    normalized = str(value or "all").strip().lower()
    if normalized not in _ALLOWED_TIME_WINDOWS:
        fail("Invalid time_window. Allowed: all, 24h")
    return normalized


def _validate_source(value: str) -> str:
    normalized = str(value or "all").strip().lower()
    if normalized not in _ALLOWED_SOURCES:
        fail("Invalid source. Allowed: all, pwn, bruce, ward, raw")
    return normalized


def _parse_session_ids(value: str | None) -> list[str]:
    if value is None:
        return []
    return [item.strip() for item in str(value).split(",") if item.strip()]


@router.get("/api/wardrive/hierarchy", tags=["WarDrive"])
def get_wardrive_hierarchy(
    time_window: str = Query(default="all"),
    source: str = Query(default="all"),
    session_ids: str | None = Query(default=None),
):
    normalized_time = _validate_time_window(time_window)
    normalized_source = _validate_source(source)
    parsed_session_ids = _parse_session_ids(session_ids)

    try:
        payload = wardrive_regions_service.get_hierarchy(
            time_window=normalized_time,
            source=normalized_source,
            session_ids=parsed_session_ids,
        )
    except ValueError as exc:
        fail(str(exc))
    return ok(payload)


@router.get("/api/wardrive/inventory", tags=["WarDrive"])
def get_wardrive_inventory():
    return ok(wardrive_regions_service.get_maps_inventory())


@router.get("/api/wardrive/sessions", tags=["WarDrive"])
def get_wardrive_sessions(
    time_window: str = Query(default="all"),
):
    normalized_time = _validate_time_window(time_window)
    return ok(wardrive_regions_service.get_sessions(time_window=normalized_time))


@router.post("/api/wardrive/sessions/tag", tags=["WarDrive"])
def set_wardrive_session_tag(payload: WardriveSessionTagRequest = Body(...)):
    try:
        data = wardrive_regions_service.set_session_tag(
            session_id=payload.session_id,
            transport_mode=payload.transport_mode,
        )
    except ValueError as exc:
        fail(str(exc))
    return ok(data)


@router.post("/api/wardrive/sessions/tracks", tags=["WarDrive"])
def get_wardrive_session_tracks(payload: WardriveSessionTracksRequest = Body(...)):
    try:
        data = wardrive_regions_service.get_session_tracks(
            session_ids=payload.session_ids
        )
    except ValueError as exc:
        fail(str(exc))
    return ok(data)


@router.post("/api/wardrive/sessions/merge", tags=["WarDrive"])
async def merge_wardrive_sessions_route(
    payload: WardriveSessionMergeRequest = Body(...),
):
    try:
        data = wardrive_regions_service.merge_sessions(session_ids=payload.session_ids)
    except ValueError as exc:
        fail(str(exc))
    await manager.broadcast({"type": "data_update", "payload": "map_data"})
    return ok(data)


@router.post("/api/wardrive/refresh", tags=["WarDrive"])
def refresh_wardrive_runtime(payload: WardriveRefreshRequest = Body(...)):
    result = wardrive_regions_service.refresh_runtime(
        reload_data_enabled=bool(payload.reload_data),
        reload_maps=bool(payload.reload_maps),
    )
    return ok(result)


@router.post("/api/wardrive/zones", tags=["WarDrive"])
def get_wardrive_zones(payload: WardriveZonesRequest = Body(...)):
    normalized_time = _validate_time_window(payload.time_window)
    normalized_source = _validate_source(payload.source)
    normalized_session_ids = [
        str(item or "").strip()
        for item in (payload.session_ids or [])
        if str(item or "").strip()
    ]
    normalized_active_session_id = str(payload.active_session_id or "").strip() or None

    try:
        eps_m = float(payload.eps_m)
        min_samples = int(payload.min_samples)
    except (TypeError, ValueError):
        fail("Invalid eps_m or min_samples")

    if eps_m <= 0:
        fail("eps_m must be greater than 0")
    if min_samples < 1:
        fail("min_samples must be greater than or equal to 1")

    try:
        data = wardrive_regions_service.get_region_zones(
            region_id=payload.region_id,
            eps_m=eps_m,
            min_samples=min_samples,
            time_window=normalized_time,
            source=normalized_source,
            session_ids=normalized_session_ids,
            comparison_mode=payload.comparison_mode,
            active_session_id=normalized_active_session_id,
        )
    except ValueError as exc:
        message = str(exc)
        if "region_id not found" in message:
            fail(message, status_code=404)
        fail(message)

    return ok(data)
