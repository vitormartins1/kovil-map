import os
from app.core.config import HANDSHAKES_DIR
from app.utils.responses import fail


def validate_safe_filename(filename: str):
    if not filename:
        fail("Filename required", status_code=400)
    if ".." in filename or "/" in filename or "\\" in filename:
        fail("Invalid filename characters", status_code=400)
    safe_base = os.path.abspath(HANDSHAKES_DIR)
    full_path = os.path.abspath(os.path.join(safe_base, filename))
    if not full_path.startswith(safe_base):
        fail("Path traversal attempt detected", status_code=400)
    return filename
