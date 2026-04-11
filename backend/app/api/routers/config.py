from fastapi import APIRouter, Body
from app.core.config import load_config, save_config, sanitize_config_for_client
from app.schemas.config import ConfigUpdateRequest
from app.utils.responses import ok
from app.api import deps

router = APIRouter()


@router.get("/api/config", tags=["Config"])
def get_configuration():
    return ok(sanitize_config_for_client(load_config()))


@router.put("/api/config", tags=["Config"])
def update_configuration(config: ConfigUpdateRequest = Body(...)):
    if hasattr(config, "model_dump"):
        payload = config.model_dump(exclude_unset=True)
    else:  # pragma: no cover - compat fallback for older pydantic
        payload = config.dict(exclude_unset=True)
    new_conf = save_config(payload)
    deps.sync_service.reload_config()
    return ok(sanitize_config_for_client(new_conf))
