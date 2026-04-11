import os

from app.core.config import HANDSHAKES_DIR
from app.core.job_manager import job_manager
from app.services.data_loader import reload_data
from app.services.fingerprint_service import fingerprint_service


def _fingerprint_worker_impl(
    job,
    emit,
    *,
    fingerprint_service,
    reload_data,
    handshakes_dir,
):
    """Worker para processar fingerprints de arquivos Bruce em background"""
    meta = job.get("meta", {}) or {}
    files_to_process = meta.get("files_to_process", [])
    force_files = set(meta.get("force_files", []))
    reason_by_file = (
        meta.get("reason_by_file", {})
        if isinstance(meta.get("reason_by_file"), dict)
        else {}
    )
    total = len(files_to_process)
    items = []

    for idx, filename in enumerate(files_to_process):
        base_name = filename.rsplit(".", 1)[0]
        details_path = os.path.join(handshakes_dir, f"{base_name}.details")
        plan_reason = reason_by_file.get(filename)

        item = {
            "file": filename,
            "status": "PROCESSING",
        }
        if plan_reason:
            item["reason"] = plan_reason
        items.append(item)

        # Atualiza progresso
        job["progress_data"]["current_step"] = idx + 1
        job["progress_data"]["percentage"] = int(((idx + 1) / total) * 100)
        job["progress_data"]["stage"] = "RUNNING"
        job["progress_data"]["extra"] = filename
        job["progress_data"]["items"] = items
        emit(
            "job_progress",
            {"job_id": job["id"], "data": job["progress_data"].copy()},
        )

        # Se detalhes já existem e não foi marcado para forçar, pula.
        if os.path.exists(details_path) and filename not in force_files:
            item["status"] = "SKIPPED"
            item["reason"] = item.get("reason") or "details_already_exist"
            continue

        # Processa fingerprint
        try:
            extract_result = fingerprint_service.extract(
                filename, filename in force_files
            )
            if extract_result.get("status") == "success":
                item["status"] = "SUCCESS"
                item["details_count"] = extract_result.get("details_count", 0)
            else:
                item["status"] = "FAILED"
                item["reason"] = extract_result.get("message", "Unknown error")
        except Exception as exc:
            item["status"] = "FAILED"
            item["reason"] = str(exc)

        # Atualiza item
        job["progress_data"]["items"] = items
        emit(
            "job_progress",
            {"job_id": job["id"], "data": job["progress_data"].copy()},
        )

    # Após processar todos, recarrega dados se houver sucesso
    try:
        reload_data()
        # Use the thread-safe job emit helper to schedule the broadcast
        # (we're running inside a worker thread so can't await manager.broadcast)
        try:
            emit("data_update", "map_data")
        except Exception:
            # Fallback to job_manager scheduler if emit isn't available
            try:
                job_manager._fire_and_forget_emit("data_update", "map_data")
            except Exception:
                pass
    except Exception:
        pass


def _fingerprint_worker(job, emit):
    return _fingerprint_worker_impl(
        job,
        emit,
        fingerprint_service=fingerprint_service,
        reload_data=reload_data,
        handshakes_dir=HANDSHAKES_DIR,
    )
