from fastapi import APIRouter
from app.utils.responses import ok
from app.api import deps

router = APIRouter()


@router.get("/", tags=["Health"])
def read_root():
    return ok({"service": "Mockgotchi Backend", "status": "online"})


@router.get("/api/health", tags=["Health"])
def get_status():
    return ok(deps.app_state)
