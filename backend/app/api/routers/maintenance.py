from fastapi import APIRouter

from app.api.ws.handlers import manager
from app.services.maintenance_service import maintenance_service
from app.utils.responses import ok

router = APIRouter()


@router.delete("/api/maintenance/details", tags=["Maintenance"])
async def clear_details_files():
    result = maintenance_service.clear_details_files()
    await manager.broadcast({"type": "data_update", "payload": "map_data"})
    return ok(result)


@router.delete("/api/maintenance/cache", tags=["Maintenance"])
async def clear_cache():
    result = maintenance_service.clear_cache()
    await manager.broadcast({"type": "data_update", "payload": "map_data"})
    return ok(result)
