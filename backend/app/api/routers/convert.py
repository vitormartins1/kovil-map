from fastapi import APIRouter, Body
from app.services.crack_service import crack_service
from app.schemas.convert import ConvertRequest, ConvertMultiRequest
from app.utils.responses import ok, fail
from app.utils.validators import validate_safe_filename

router = APIRouter()


@router.post("/api/convert/hcx", tags=["Convert"])
def convert_pcap(payload: ConvertRequest = Body(...)):
    filename = payload.filename
    if filename:
        validate_safe_filename(filename)
    if not filename and not payload.capture_id and not payload.raw_item_id:
        fail("filename, capture_id or raw_item_id is required")
    return ok(
        crack_service.convert_pcap(
            filename,
            capture_id=payload.capture_id,
            raw_item_id=payload.raw_item_id,
        )
    )


@router.post("/api/convert/hcx/batch", tags=["Convert"])
def convert_pcap_multi(payload: ConvertMultiRequest = Body(...)):
    filenames = payload.filenames or []
    capture_ids = payload.capture_ids or []
    if (not isinstance(filenames, list) or not filenames) and (
        not isinstance(capture_ids, list) or not capture_ids
    ):
        fail("filenames or capture_ids list is required")
    for name in filenames:
        validate_safe_filename(name)
    return ok(crack_service.convert_pcap_multi(filenames, capture_ids=capture_ids))
