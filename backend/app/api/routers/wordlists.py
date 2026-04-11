from fastapi import APIRouter
from app.services.crack_service import crack_service
from app.utils.responses import ok

router = APIRouter()


@router.get("/api/wordlists/custom", tags=["Wordlists"])
def get_custom_wordlists():
    return ok(crack_service.get_custom_wordlists())
