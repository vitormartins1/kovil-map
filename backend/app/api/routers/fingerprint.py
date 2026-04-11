import glob
import json
import logging
import os
from fastapi import APIRouter, Body, Query

from app.core.config import HANDSHAKES_DIR
from app.services.fingerprint_service import fingerprint_service
from app.services.rawsniffer_service import rawsniffer_service
from app.utils.handshake_artifacts import resolve_artifact_path
from app.utils.responses import ok, fail
from app.utils.validators import validate_safe_filename

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/api/fingerprint/extract", tags=["Fingerprint"])
def extract_fingerprint(payload: dict = Body(...)):
    filename = payload.get("filename")
    capture_id = payload.get("capture_id")
    raw_item_id = payload.get("raw_item_id")
    bssid = payload.get("bssid")
    force = bool(payload.get("force", False))

    if filename:
        validate_safe_filename(filename)
    if not filename and not capture_id and not raw_item_id:
        fail("filename, capture_id or raw_item_id required", status_code=400)
    try:
        result = fingerprint_service.extract(
            filename or "",
            force,
            capture_id=capture_id,
            raw_item_id=raw_item_id,
            bssid=bssid,
        )
    except TypeError:
        if capture_id or raw_item_id:
            raise
        result = fingerprint_service.extract(filename or "", force)
    if result.get("status") != "success":
        fail(result.get("message", "Failed to extract details"), status_code=400)
    return ok(result)


@router.get("/api/fingerprint/details", tags=["Fingerprint"])
def get_fingerprint_details(
    filename: str | None = Query(default=None),
    mac: str | None = Query(default=None),
    capture_id: str | None = Query(default=None),
):
    target_path = None

    if filename:
        validate_safe_filename(filename)
        if not filename.endswith(".details"):
            filename = f"{filename}.details" if "." not in filename else filename
        candidate = resolve_artifact_path(
            filename,
            handshakes_dir=HANDSHAKES_DIR,
            capture_id=capture_id,
        )
        if candidate and os.path.exists(candidate):
            target_path = candidate
    elif mac:
        mac_clean = mac.replace(":", "").lower()
        pattern = os.path.join(HANDSHAKES_DIR, f"*{mac_clean}*.details")
        matches = glob.glob(pattern)
        if matches:
            target_path = matches[0]

    if not target_path or not os.path.exists(target_path):
        fail("Details file not found", status_code=404)

    try:
        with open(target_path, "r", encoding="utf-8") as f:
            content = json.load(f)

        raw_sniffer = {"present": False}
        try:
            bssid = None
            if isinstance(content, dict):
                bssid = content.get("bssid")
            if not bssid and mac:
                bssid = mac
            raw_sniffer = rawsniffer_service.get_aggregated_metadata_for_bssid(bssid)
        except Exception as exc:
            logger.warning("Failed to attach raw sniffer metadata: %s", exc)
            raw_sniffer = {"present": False}

        if isinstance(content, dict):
            content = dict(content)
            content["raw_sniffer"] = raw_sniffer
        return ok(content)
    except Exception as e:
        fail(str(e), status_code=500)
