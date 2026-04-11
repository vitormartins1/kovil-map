from fastapi import APIRouter, Body
from app.services.wps_service import wps_service
from app.schemas.jobs import WpsAttackRequest
from app.utils.responses import ok, fail

router = APIRouter()


@router.post("/api/wps/attack", tags=["WPS"])
def wps_attack(payload: WpsAttackRequest = Body(...)):
    if not payload.bssid or not payload.bssid.strip():
        fail("BSSID is required")
    if not payload.channel:
        fail("Channel is required")
    if not payload.interface or not payload.interface.strip():
        fail("Interface is required")
    return ok(
        wps_service.start_attack(
            bssid=payload.bssid,
            channel=payload.channel,
            interface=payload.interface,
            tool=payload.tool,
            pixie_dust=payload.pixie_dust,
            delay=payload.delay,
        )
    )
