from fastapi import APIRouter
from app.services.data_loader import load_real_data
from app.utils.responses import ok

router = APIRouter()


@router.get("/api/map/data", tags=["Map"])
def get_map_data():
    return ok(load_real_data())
