from fastapi import APIRouter, Body
from app.core.job_manager import job_manager
from app.schemas.jobs import JobPatchRequest
from app.utils.responses import ok, fail

router = APIRouter()


@router.patch("/api/jobs/{job_id}", tags=["Jobs"])
def update_job(job_id: str, payload: JobPatchRequest = Body(...)):
    if payload.status != "canceled":
        fail(
            "Only status=canceled is supported", code="invalid_status", status_code=400
        )
    success, message = job_manager.cancel_job(job_id)
    if not success:
        fail(message, status_code=400)
    return ok({"message": message})


@router.get("/api/jobs/{job_id}", tags=["Jobs"])
def get_job_status(job_id: str):
    job = job_manager.get_job(job_id)
    if not job:
        fail("Job not found", status_code=404)
    return ok(job)


@router.get("/api/jobs", tags=["Jobs"])
def list_jobs():
    return ok(job_manager.list_jobs())
