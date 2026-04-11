import os
import json
from fastapi import APIRouter
from app.core.config import HANDSHAKES_DIR
from app.utils.responses import ok, fail
from app.utils.validators import validate_safe_filename

router = APIRouter()


@router.get("/api/batches", tags=["Batches"])
def list_multi_files():
    files = []
    if not os.path.exists(HANDSHAKES_DIR):
        return ok([])
    for f in os.listdir(HANDSHAKES_DIR):
        if f.startswith("batch_") and f.endswith(".22000"):
            path = os.path.join(HANDSHAKES_DIR, f)
            stat = os.stat(path)
            manifest_path = os.path.join(HANDSHAKES_DIR, f"{f}.batch.json")
            count = None
            if os.path.exists(manifest_path):
                try:
                    with open(manifest_path, "r", encoding="utf-8") as mf:
                        data = json.load(mf)
                        count = len(data.get("items", []))
                except Exception:
                    pass
            files.append(
                {
                    "name": f,
                    "size": stat.st_size,
                    "modified": stat.st_mtime,
                    "count": count,
                }
            )
    return ok(sorted(files, key=lambda x: x["modified"], reverse=True))


@router.get("/api/batches/{filename}", tags=["Batches"])
def get_multi_file_content(filename: str):
    validate_safe_filename(filename)
    if not filename.startswith("batch_") or not filename.endswith(".22000"):
        fail("Invalid batch filename")
    manifest_path = os.path.join(HANDSHAKES_DIR, f"{filename}.batch.json")
    if not os.path.exists(manifest_path):
        return ok({"items": []})
    try:
        with open(manifest_path, "r", encoding="utf-8") as mf:
            data = json.load(mf)
        items = data.get("items", []) or []
        enriched = []
        for item in items:
            cracked = False
            try:
                fname = item.get("filename") if isinstance(item, dict) else None
                if fname:
                    base_name = fname.rsplit(".", 1)[0]
                    cracked_path = os.path.join(
                        HANDSHAKES_DIR, f"{base_name}.pcap.cracked"
                    )
                    cracked = (
                        os.path.exists(cracked_path)
                        and os.path.getsize(cracked_path) > 0
                    )
            except Exception:
                cracked = False
            if isinstance(item, dict):
                item = {**item, "cracked": cracked}
            enriched.append(item)
        return ok({"items": enriched})
    except Exception as e:
        fail(str(e), status_code=500)


@router.get("/api/batches/{filename}/files", tags=["Batches"])
def get_batch_files(filename: str):
    validate_safe_filename(filename)
    if not filename.startswith("batch_") or not filename.endswith(".22000"):
        fail("Invalid batch filename")
    base = filename.rsplit(".", 1)[0]
    files = []
    base_dir = HANDSHAKES_DIR

    candidates = [f"{base}.22000", f"{base}.try", f"{base}.cracked"]
    for name in candidates:
        path = os.path.join(base_dir, name)
        if os.path.exists(path):
            stat = os.stat(path)
            files.append(
                {
                    "name": name,
                    "size": stat.st_size,
                    "modified": stat.st_mtime,
                    "type": name.split(".")[-1],
                }
            )

    return ok(files)


@router.delete("/api/batches/{filename}", tags=["Batches"])
def delete_multi_file(filename: str):
    validate_safe_filename(filename)
    if not filename.startswith("batch_") or not filename.endswith(".22000"):
        fail("Invalid batch filename")
    target_path = os.path.join(HANDSHAKES_DIR, filename)
    manifest_path = os.path.join(HANDSHAKES_DIR, f"{filename}.batch.json")
    base = filename.rsplit(".", 1)[0]
    try_path = os.path.join(HANDSHAKES_DIR, f"{base}.try")
    cracked_path = os.path.join(HANDSHAKES_DIR, f"{base}.cracked")

    deleted = []
    for path in [target_path, manifest_path, try_path, cracked_path]:
        if os.path.exists(path):
            try:
                os.remove(path)
                deleted.append(os.path.basename(path))
            except Exception as e:
                fail(str(e), status_code=500)

    return ok({"deleted": deleted})
