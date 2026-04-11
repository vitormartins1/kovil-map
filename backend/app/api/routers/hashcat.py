from fastapi import APIRouter, Body
from app.services.crack_service import crack_service
from app.schemas.jobs import HashcatJobRequest, HashcatAssociationPreviewRequest
from app.utils.responses import ok, fail
from app.utils.validators import validate_safe_filename

router = APIRouter()


@router.get("/api/hashcat/rules", tags=["Hashcat"])
def get_hashcat_rules():
    return ok(crack_service.get_hashcat_rules())


@router.get("/api/hashcat/masks", tags=["Hashcat"])
def get_hashcat_masks():
    return ok(crack_service.get_hashcat_masks())


@router.get("/api/hashcat/devices", tags=["Hashcat"])
def get_hashcat_devices():
    return ok(crack_service.get_hashcat_devices())


@router.post("/api/hashcat/jobs", tags=["Hashcat"])
def start_cracking(payload: HashcatJobRequest = Body(...)):
    filename = payload.filename
    validate_safe_filename(filename)
    return ok(
        crack_service.run_hashcat(
            filename,
            payload.attack_mode,
            payload.workload_profile,
            payload.wordlist,
            payload.rule_file,
            payload.custom_mask,
            payload.is_optimized,
            payload.is_slow,
            payload.device_id,
            payload.enable_potfile,
            payload.wordlist_2,
            payload.enable_increment,
            payload.increment_min,
            payload.increment_max,
            payload.mask_file,
            payload.association_hint,
            payload.association_hints,
            capture_id=payload.capture_id,
            combined_build_id=payload.combined_build_id,
            mac=payload.mac,
            skip_quality_gate=payload.skip_quality_gate,
        )
    )


@router.post("/api/hashcat/association/preview", tags=["Hashcat"])
def preview_association(
    payload: HashcatAssociationPreviewRequest = Body(...),
):
    filename = payload.filename
    validate_safe_filename(filename)

    mode = (payload.mode or "association").strip().lower()
    if mode not in {"association", "association_hint_first"}:
        fail("Invalid association mode", status_code=400)

    result = crack_service.preview_hashcat_association(
        filename,
        mode=mode,
        association_hint=payload.association_hint,
        association_hints=payload.association_hints,
        capture_id=payload.capture_id,
        combined_build_id=payload.combined_build_id,
        mac=payload.mac,
    )
    if result.get("status") != "success":
        fail(
            result.get("message", "Failed to preview association candidates"),
            status_code=400,
        )

    return ok(result)
