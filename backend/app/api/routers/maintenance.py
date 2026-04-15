from fastapi import APIRouter, Body

from app.api.ws.handlers import manager
from app.schemas.maintenance import DemoInstallRequest
from app.services.maintenance_service import maintenance_service
from app.utils.responses import fail, ok

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


@router.get("/api/maintenance/demo", tags=["Maintenance"])
def get_demo_status():
    return ok(maintenance_service.get_demo_status())


@router.post("/api/maintenance/demo/install", tags=["Maintenance"])
def install_demo_data(payload: DemoInstallRequest = Body(default=DemoInstallRequest())):
    try:
        result = maintenance_service.start_demo_install(
            profile_id=payload.profile_id,
            frontend_state=payload.frontend_state,
        )
    except Exception as exc:
        fail(str(exc), status_code=409)
    return ok(result)


@router.delete("/api/maintenance/demo", tags=["Maintenance"])
def remove_demo_data():
    try:
        result = maintenance_service.start_demo_remove()
    except Exception as exc:
        fail(str(exc), status_code=409)
    return ok(result)
