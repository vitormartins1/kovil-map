from fastapi import APIRouter
from app.services.crack_service import crack_service
from app.services.demo_data_service import demo_data_service
from app.utils.responses import ok

router = APIRouter()


@router.get("/api/wordlists/custom", tags=["Wordlists"])
def get_custom_wordlists():
    custom = crack_service.get_custom_wordlists()
    demo = demo_data_service.get_demo_wordlists()
    return ok(sorted([*custom, *demo], key=lambda item: item.get("name") or ""))
