from fastapi import APIRouter, Query

from app.services.insights_service import insights_service
from app.utils.responses import fail, ok
from app.utils.validators import validate_safe_filename

router = APIRouter()


@router.get("/api/insights/score", tags=["Insights"])
def get_attack_score(
    mac: str | None = Query(default=None),
    filename: str | None = Query(default=None),
    capture_id: str | None = Query(default=None),
    combined_build_id: str | None = Query(default=None),
):
    if not mac and not filename:
        fail("Provide mac or filename")
    if filename:
        validate_safe_filename(filename)
    return ok(
        insights_service.get_attack_score(
            mac=mac,
            filename=filename,
            capture_id=capture_id,
            combined_build_id=combined_build_id,
        )
    )


@router.get("/api/insights/attack-recommendation", tags=["Insights"])
def get_attack_recommendation(
    mac: str | None = Query(default=None),
    filename: str | None = Query(default=None),
    capture_id: str | None = Query(default=None),
    combined_build_id: str | None = Query(default=None),
):
    if not mac and not filename:
        fail("Provide mac or filename")
    if filename:
        validate_safe_filename(filename)
    return ok(
        insights_service.get_attack_recommendation(
            mac=mac,
            filename=filename,
            capture_id=capture_id,
            combined_build_id=combined_build_id,
        )
    )


@router.get("/api/insights/handshake-readiness", tags=["Insights"])
def get_handshake_readiness(
    mac: str | None = Query(default=None),
    filename: str | None = Query(default=None),
    capture_id: str | None = Query(default=None),
    combined_build_id: str | None = Query(default=None),
):
    if not mac and not filename:
        fail("Provide mac or filename")
    if filename:
        validate_safe_filename(filename)
    return ok(
        insights_service.get_handshake_readiness(
            mac=mac,
            filename=filename,
            capture_id=capture_id,
            combined_build_id=combined_build_id,
        )
    )


@router.get("/api/insights/quality-gate", tags=["Insights"])
def get_quality_gate(
    filename: str = Query(...),
    attack_mode: str | None = Query(default=None),
    capture_id: str | None = Query(default=None),
    combined_build_id: str | None = Query(default=None),
    mac: str | None = Query(default=None),
):
    validate_safe_filename(filename)
    return ok(
        insights_service.evaluate_quality_gate(
            filename,
            attack_mode=attack_mode,
            capture_id=capture_id,
            combined_build_id=combined_build_id,
            mac=mac,
        )
    )
