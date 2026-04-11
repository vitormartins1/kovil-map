from typing import List

from fastapi import APIRouter, Body, Query

from app.jobs import rawsniffer_jobs
from app.jobs.rawsniffer_jobs import start_rawsniffer_job
from app.schemas.jobs import RawSnifferExtractRequest
from app.services.crack_service import crack_service
from app.services.data_loader import reload_data
from app.services.rawsniffer_service import rawsniffer_service
from app.utils.responses import fail, ok
from app.utils.validators import validate_safe_filename

router = APIRouter()

_needs_hash_enrichment = rawsniffer_jobs._needs_hash_enrichment


def _rawsniffer_worker(job, emit):
    return rawsniffer_jobs._rawsniffer_worker_impl(
        job,
        emit,
        crack_service=crack_service,
        reload_data=reload_data,
        needs_hash_enrichment=_needs_hash_enrichment,
    )


@router.get("/api/rawsniffer/files", tags=["RawSniffer"])
def list_rawsniffer_files():
    return ok(rawsniffer_service.list_files())


@router.delete("/api/rawsniffer/files/{filename}", tags=["RawSniffer"])
def delete_rawsniffer_file(filename: str):
    validate_safe_filename(filename)
    if not filename.lower().endswith(".pcap") or filename.upper().startswith("HS_"):
        fail("Invalid rawsniffer filename", status_code=400)

    result = rawsniffer_service.delete_file(filename)
    if result.get("status") != "success":
        message = result.get("message", "Failed to delete RAW file")
        status_code = 404 if "not found" in message.lower() else 500
        fail(message, status_code=status_code)
    return ok(result)


@router.get("/api/rawsniffer/hashes", tags=["RawSniffer"])
def list_rawsniffer_hashes():
    return ok(rawsniffer_service.list_generated_hashes())


@router.get("/api/rawsniffer/metadata", tags=["RawSniffer"])
def get_rawsniffer_metadata(
    filename: str | None = Query(default=None),
    raw_item_id: str | None = Query(default=None),
    refresh: bool = Query(default=False),
):
    if filename:
        validate_safe_filename(filename)
    if not filename and not raw_item_id:
        fail("filename or raw_item_id required", status_code=400)

    if refresh:
        result = rawsniffer_service.extract_metadata(
            filename or "", force=True, raw_item_id=raw_item_id
        )
        if result.get("status") != "success":
            fail(result.get("message", "Failed to extract metadata"), status_code=400)
        return ok(result)

    metadata = rawsniffer_service.get_metadata(filename, raw_item_id=raw_item_id)
    if metadata is None:
        fail("Metadata not found for file", status_code=404)
    return ok(metadata)


@router.post("/api/rawsniffer/analyze", tags=["RawSniffer"])
def analyze_rawsniffer_capture(payload: dict = Body(...)):
    raw_item_id = str((payload or {}).get("raw_item_id") or "").strip()
    force = bool((payload or {}).get("force", False))
    if not raw_item_id:
        fail("raw_item_id required", status_code=400)

    result = rawsniffer_service.extract_analysis(raw_item_id, force=force)
    if result.get("status") != "success":
        fail(result.get("message", "Failed to analyze RAW capture"), status_code=400)
    return ok(result)


@router.get("/api/rawsniffer/analysis/{raw_item_id}", tags=["RawSniffer"])
def get_rawsniffer_analysis(raw_item_id: str):
    result = rawsniffer_service.get_analysis(raw_item_id)
    if result is None:
        fail("Analysis not found for RAW capture", status_code=404)
    return ok(result)


@router.post("/api/rawsniffer/extract", tags=["RawSniffer"])
def extract_rawsniffer_metadata(payload: RawSnifferExtractRequest = Body(...)):
    filename = payload.filename
    force = bool(payload.force)
    only_pending = bool(payload.only_pending)

    files: List[str]
    if filename:
        validate_safe_filename(filename)
        files = [filename]
    elif only_pending:
        files = rawsniffer_service.get_pending_files()
    else:
        files = [item["filename"] for item in rawsniffer_service.list_files()]

    if not files:
        return ok(
            {
                "status": "noop",
                "message": "No raw files to process",
                "total_files": 0,
                "job_id": None,
            }
        )

    job_id = start_rawsniffer_job(files, force=force)
    return ok(
        {
            "status": "started",
            "job_id": job_id,
            "total_files": len(files),
            "force": force,
            "only_pending": only_pending,
        }
    )
