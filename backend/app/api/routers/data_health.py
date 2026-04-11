from fastapi import APIRouter

from app.services.data_health_service import data_health_service
from app.utils.responses import ok

router = APIRouter()


@router.get("/api/data-health/summary", tags=["DataHealth"])
def get_data_health_summary():
    return ok(data_health_service.get_summary())
