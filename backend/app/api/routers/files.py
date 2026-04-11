import os
from fastapi import APIRouter, Query
from app.core.config import HANDSHAKES_DIR
from app.utils.handshake_artifacts import resolve_artifact_path
from app.utils.responses import ok, fail
from app.utils.validators import validate_safe_filename

router = APIRouter()


@router.get("/api/files/{filename}", tags=["Files"])
def get_file_content(
    filename: str,
    capture_id: str | None = Query(default=None),
    combined_build_id: str | None = Query(default=None),
    mac: str | None = Query(default=None),
):
    validate_safe_filename(filename)
    path = resolve_artifact_path(
        filename,
        handshakes_dir=HANDSHAKES_DIR,
        capture_id=capture_id,
        combined_build_id=combined_build_id,
        mac=mac,
    )
    if not path or not os.path.exists(path):
        fail("File not found", status_code=404)
    if os.path.getsize(path) > 1024 * 1024:
        fail("File too large", status_code=400)
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return ok(f.read())
    except Exception as e:
        fail(str(e), status_code=500)
