from fastapi import APIRouter, Body
from app.services.crack_service import crack_service
from app.schemas.jobs import AircrackJobRequest
from app.utils.responses import ok, fail
from app.utils.validators import validate_safe_filename

router = APIRouter()


@router.post("/api/aircrack/jobs", tags=["Aircrack"])
def start_aircrack(payload: AircrackJobRequest = Body(...)):
    filename = payload.filename
    if filename:
        validate_safe_filename(filename)
    if not filename and not payload.capture_id and not payload.raw_item_id:
        fail("filename, capture_id or raw_item_id required")
    if not payload.bssid:
        fail("BSSID required")
    return ok(
        crack_service.run_aircrack_attack(
            filename,
            payload.bssid,
            payload.wordlist,
            capture_id=payload.capture_id,
            raw_item_id=payload.raw_item_id,
        )
    )
