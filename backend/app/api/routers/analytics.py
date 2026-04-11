from fastapi import APIRouter, Query

from app.services.analytics_service import analytics_service
from app.utils.responses import fail, ok

router = APIRouter()


def _validate_metric(metric: str) -> str:
    value = str(metric or "opportunity").strip().lower()
    allowed = {"density", "opportunity", "eapol", "beacon", "probe"}
    if value not in allowed:
        fail(f"Invalid metric '{metric}'. Allowed: {', '.join(sorted(allowed))}")
    return value


def _validate_time_window(time_window: str) -> str:
    value = str(time_window or "all").strip().lower()
    allowed = {"all", "24h"}
    if value not in allowed:
        fail(f"Invalid time_window '{time_window}'. Allowed: all, 24h")
    return value


def _validate_source(source: str) -> str:
    value = str(source or "all").strip().lower()
    allowed = {"all", "pwn", "bruce", "ward", "raw"}
    if value not in allowed:
        fail(f"Invalid source '{source}'. Allowed: {', '.join(sorted(allowed))}")
    return value


def _validate_security(security: str) -> str:
    value = str(security or "all").strip().lower()
    allowed = {"all", "locked", "open", "cracked"}
    if value not in allowed:
        fail(f"Invalid security '{security}'. Allowed: {', '.join(sorted(allowed))}")
    return value


def _validate_device_type(device_type: str) -> str:
    value = str(device_type or "all").strip().lower()
    allowed = {
        "all",
        "router_ap",
        "phone_hotspot",
        "camera_ap",
        "printer_ap",
        "iot_ap",
        "unknown",
    }
    if value not in allowed:
        fail(
            f"Invalid device_type '{device_type}'. Allowed: {', '.join(sorted(allowed))}"
        )
    return value


@router.get("/api/analytics/heatmap", tags=["Analytics"])
def get_analytics_heatmap(
    metric: str = Query(default="opportunity"),
    time_window: str = Query(default="all"),
    source: str = Query(default="all"),
    security: str = Query(default="all"),
    device_type: str = Query(default="all"),
    channel: int | None = Query(default=None),
    cell_size_m: int = Query(default=120),
):
    metric_v = _validate_metric(metric)
    time_v = _validate_time_window(time_window)
    source_v = _validate_source(source)
    security_v = _validate_security(security)
    device_type_v = _validate_device_type(device_type)

    if channel is not None and channel <= 0:
        fail("channel must be greater than 0")
    if cell_size_m < 50 or cell_size_m > 300:
        fail("cell_size_m must be between 50 and 300")

    return ok(
        analytics_service.get_heatmap(
            metric=metric_v,
            time_window=time_v,
            source=source_v,
            security=security_v,
            device_type=device_type_v,
            channel=channel,
            cell_size_m=cell_size_m,
        )
    )


@router.get("/api/analytics/channel-summary", tags=["Analytics"])
def get_analytics_channel_summary(
    metric: str = Query(default="opportunity"),
    time_window: str = Query(default="all"),
    source: str = Query(default="all"),
    security: str = Query(default="all"),
    device_type: str = Query(default="all"),
    channel: int | None = Query(default=None),
):
    metric_v = _validate_metric(metric)
    time_v = _validate_time_window(time_window)
    source_v = _validate_source(source)
    security_v = _validate_security(security)
    device_type_v = _validate_device_type(device_type)

    if channel is not None and channel <= 0:
        fail("channel must be greater than 0")

    return ok(
        analytics_service.get_channel_summary(
            metric=metric_v,
            time_window=time_v,
            source=source_v,
            security=security_v,
            device_type=device_type_v,
            channel=channel,
        )
    )


@router.get("/api/analytics/hotspots", tags=["Analytics"])
def get_analytics_hotspots(
    metric: str = Query(default="opportunity"),
    time_window: str = Query(default="all"),
    source: str = Query(default="all"),
    security: str = Query(default="all"),
    device_type: str = Query(default="all"),
    channel: int | None = Query(default=None),
    cell_size_m: int = Query(default=120),
    limit: int = Query(default=12),
):
    metric_v = _validate_metric(metric)
    time_v = _validate_time_window(time_window)
    source_v = _validate_source(source)
    security_v = _validate_security(security)
    device_type_v = _validate_device_type(device_type)

    if channel is not None and channel <= 0:
        fail("channel must be greater than 0")
    if cell_size_m < 50 or cell_size_m > 300:
        fail("cell_size_m must be between 50 and 300")
    if limit < 1 or limit > 50:
        fail("limit must be between 1 and 50")

    return ok(
        analytics_service.get_hotspots(
            metric=metric_v,
            time_window=time_v,
            source=source_v,
            security=security_v,
            device_type=device_type_v,
            channel=channel,
            cell_size_m=cell_size_m,
            limit=limit,
        )
    )
