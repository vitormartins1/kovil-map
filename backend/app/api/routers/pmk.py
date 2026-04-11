from fastapi import APIRouter, Body, Query
from app.services.pmk_service import pmk_service
from app.schemas.jobs import PmkBuildRequest, PmkAttackRequest
from app.utils.responses import ok, fail
from app.utils.validators import validate_safe_filename

router = APIRouter()


@router.get("/api/pmk/databases", tags=["PMK"])
def list_databases():
    return ok(pmk_service.list_databases())


@router.get("/api/pmk/databases/{db_name}/stats", tags=["PMK"])
def database_stats(db_name: str):
    validate_safe_filename(db_name)
    result = pmk_service.get_database_stats(db_name)
    if "error" in result:
        fail(result["error"])
    return ok(result)


@router.post("/api/pmk/build", tags=["PMK"])
def build_database(payload: PmkBuildRequest = Body(...)):
    if not payload.essid or not payload.essid.strip():
        fail("ESSID is required")
    if not payload.wordlist:
        fail("Wordlist path is required")
    return ok(
        pmk_service.build_database(
            payload.essid,
            payload.wordlist,
            db_name=payload.db_name,
        )
    )


@router.post("/api/pmk/attack", tags=["PMK"])
def attack_with_pmk(payload: PmkAttackRequest = Body(...)):
    filename = payload.filename
    if filename:
        validate_safe_filename(filename)
    if not filename and not payload.capture_id and not payload.raw_item_id:
        fail("filename, capture_id or raw_item_id required")
    if not payload.bssid:
        fail("BSSID required")
    validate_safe_filename(payload.db_name)
    return ok(
        pmk_service.attack_with_pmk(
            filename,
            payload.bssid,
            payload.db_name,
            capture_id=payload.capture_id,
            raw_item_id=payload.raw_item_id,
        )
    )


@router.delete("/api/pmk/databases/{db_name}", tags=["PMK"])
def delete_database(db_name: str):
    validate_safe_filename(db_name)
    result = pmk_service.delete_database(db_name)
    if "error" in result:
        fail(result["error"])
    return ok(result)
