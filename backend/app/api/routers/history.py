from fastapi import APIRouter
from app.services.history_service import history_service
from app.utils.responses import ok

router = APIRouter()


@router.delete("/api/history", tags=["History"])
def clear_history():
    count = history_service.clear_all_history()
    return ok({"deleted_count": count})
