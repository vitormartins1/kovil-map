import os
from typing import List

from app.core.config import BRUCE_PCAP_DIR, HANDSHAKES_DIR
from app.core.job_manager import job_manager
from app.services.crack_service import crack_service
from app.services.data_loader import reload_data
from app.services.rawsniffer_service import rawsniffer_service


def _raw_hash_output_path(filename: str) -> str:
    import os

    base = os.path.basename(filename).rsplit(".", 1)[0]
    return os.path.join(HANDSHAKES_DIR, f"{base}.22000")


def _needs_hash_enrichment(filename: str) -> bool:
    resolve_record = getattr(rawsniffer_service, "resolve_raw_record", None)
    record = resolve_record(filename) if callable(resolve_record) else None
    raw_path = (
        str(record.get("path") or "")
        if record
        else os.path.join(BRUCE_PCAP_DIR, os.path.basename(filename))
    )
    hash_path = _raw_hash_output_path(filename)

    if not raw_path or not os.path.exists(raw_path):
        return False
    if not os.path.exists(hash_path):
        return True
    try:
        if os.path.getsize(hash_path) <= 0:
            return True
        return os.path.getmtime(raw_path) > os.path.getmtime(hash_path)
    except OSError:
        return True


def _rawsniffer_worker_impl(
    job,
    emit,
    *,
    crack_service,
    reload_data,
    needs_hash_enrichment,
):
    files_to_process = job.get("meta", {}).get("files_to_process", [])
    force = bool(job.get("meta", {}).get("force", False))
    total = len(files_to_process)
    items = []
    enrichment_summary = {
        "attempted": 0,
        "success": 0,
        "failed": 0,
        "skipped": 0,
    }

    for idx, filename in enumerate(files_to_process):
        resolve_record = getattr(rawsniffer_service, "resolve_raw_record", None)
        raw_record = resolve_record(filename) if callable(resolve_record) else None
        raw_item_id = (
            str(raw_record.get("raw_item_id") or "").strip() if raw_record else ""
        )
        item = {
            "file": filename,
            "status": "PROCESSING",
        }
        items.append(item)

        job["progress_data"]["current_step"] = idx + 1
        job["progress_data"]["percentage"] = (
            int(((idx + 1) / total) * 100) if total > 0 else 100
        )
        job["progress_data"]["stage"] = "RUNNING"
        job["progress_data"]["extra"] = filename
        job["progress_data"]["items"] = items
        emit(
            "job_progress",
            {"job_id": job["id"], "data": job["progress_data"].copy()},
        )

        try:
            result = rawsniffer_service.extract_metadata(filename, force=force)
            if result.get("status") == "success":
                item["status"] = "CACHED" if result.get("cached") else "SUCCESS"
                stats = result.get("data", {}).get("stats", {})
                item["networks_count"] = int(stats.get("networks_count", 0))
                item["beacon_frames"] = int(stats.get("beacon_frames", 0))
                item["eapol_frames"] = int(stats.get("eapol_frames", 0))

                # Auto-enriquecimento: gera/atualiza .22000 para RAW com EAPOL detectado.
                if int(stats.get("eapol_frames", 0)) > 0:
                    if needs_hash_enrichment(filename):
                        enrichment_summary["attempted"] += 1
                        if raw_item_id:
                            conversion = crack_service.convert_pcap_now(
                                filename,
                                raw_item_id=raw_item_id,
                            )
                        else:
                            conversion = crack_service.convert_pcap_now(filename)
                        item["hash_enrichment"] = {
                            "status": conversion.get("status", "error"),
                            "output_file": conversion.get("output_file"),
                        }
                        if conversion.get("status") == "success":
                            enrichment_summary["success"] += 1
                        else:
                            enrichment_summary["failed"] += 1
                            item["hash_enrichment"]["reason"] = conversion.get(
                                "message", "unknown error"
                            )
                    else:
                        enrichment_summary["skipped"] += 1
                        item["hash_enrichment"] = {
                            "status": "SKIPPED",
                            "reason": "up_to_date",
                            "output_file": os.path.basename(
                                _raw_hash_output_path(filename)
                            ),
                        }
                else:
                    enrichment_summary["skipped"] += 1
                    item["hash_enrichment"] = {
                        "status": "SKIPPED",
                        "reason": "no_eapol_detected",
                    }
            else:
                item["status"] = "FAILED"
                item["reason"] = result.get("message", "Unknown error")
        except Exception as exc:
            item["status"] = "FAILED"
            item["reason"] = str(exc)

        job["progress_data"]["items"] = items
        job["progress_data"]["enrichment"] = enrichment_summary
        emit(
            "job_progress",
            {"job_id": job["id"], "data": job["progress_data"].copy()},
        )

    try:
        reload_data()
        try:
            emit("data_update", "map_data")
        except Exception:
            try:
                job_manager._fire_and_forget_emit("data_update", "map_data")
            except Exception:
                pass
    except Exception:
        pass


def _rawsniffer_worker(job, emit):
    return _rawsniffer_worker_impl(
        job,
        emit,
        crack_service=crack_service,
        reload_data=reload_data,
        needs_hash_enrichment=_needs_hash_enrichment,
    )


def start_rawsniffer_job(files: List[str], force: bool = False) -> str | None:
    if not files:
        return None
    return job_manager.start_multi_job(
        _rawsniffer_worker,
        job_type="rawsniffer_multi",
        total_steps=len(files),
        meta={"files_to_process": files, "force": force},
    )
