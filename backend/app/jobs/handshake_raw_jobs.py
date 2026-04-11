from __future__ import annotations

from typing import Dict, List, Optional

from app.core.job_manager import job_manager
from app.services.data_loader import reload_data
from app.services.rawsniffer_service import rawsniffer_service


def _raw_prepare_all_worker(job, emit):
    meta = job.get("meta", {}) or {}
    bssid = str(meta.get("bssid") or "").strip()
    force = bool(meta.get("force", False))
    ssid_hint = str(meta.get("ssid_hint") or "").strip() or None
    source_files = meta.get("source_files")
    if not isinstance(source_files, list):
        source_files = None

    items: List[Dict] = []

    def _progress(step: Dict):
        index = int(step.get("index") or 0)
        total = int(step.get("total") or 0)
        source_file = str(step.get("source_file") or "").strip()
        status = str(step.get("status") or "running").strip().lower() or "running"
        reason = str(step.get("reason") or "").strip()
        valid_lines = int(step.get("valid_lines") or 0)
        added_lines = int(step.get("added_lines") or 0)

        item = {
            "source_file": source_file,
            "status": status,
        }
        if reason:
            item["reason"] = reason
        if valid_lines > 0:
            item["valid_lines"] = valid_lines
        if added_lines > 0:
            item["added_lines"] = added_lines
        items.append(item)

        percentage = 0
        if total > 0:
            percentage = min(100, max(0, int((index / total) * 100)))

        job["progress_data"]["current_step"] = index
        job["progress_data"]["total_steps"] = total
        job["progress_data"]["percentage"] = percentage
        job["progress_data"]["stage"] = "RUNNING"
        job["progress_data"]["extra"] = source_file
        job["progress_data"]["items"] = items

        emit(
            "job_progress",
            {"job_id": job["id"], "data": job["progress_data"].copy()},
        )

    result = rawsniffer_service.prepare_canonical_hash_for_bssid(
        bssid,
        force=force,
        source_files=source_files,
        ssid_hint=ssid_hint,
        progress_callback=_progress,
    )
    status = str(result.get("status") or "").strip().lower()

    processed = int(result.get("processed") or 0)
    succeeded = int(result.get("succeeded") or 0)
    failed = int(result.get("failed") or 0)
    canonical_hash = result.get("canonical_hash")

    progress_items = result.get("items")
    if isinstance(progress_items, list):
        job["progress_data"]["items"] = progress_items
    else:
        job["progress_data"]["items"] = items

    job["progress_data"]["current_step"] = processed
    if int(job["progress_data"].get("total_steps") or 0) <= 0:
        job["progress_data"]["total_steps"] = processed
    job["progress_data"]["processed"] = processed
    job["progress_data"]["succeeded"] = succeeded
    job["progress_data"]["failed"] = failed
    if canonical_hash:
        job["progress_data"]["canonical_hash"] = canonical_hash
    if result.get("message"):
        job["progress_data"]["extra"] = str(result["message"])

    job["meta"]["raw_prepare_summary"] = {
        "status": status or "error",
        "processed": processed,
        "succeeded": succeeded,
        "failed": failed,
        "canonical_hash": canonical_hash,
    }

    should_reload = status in {"success", "success_partial"}
    if should_reload:
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

    if status == "success":
        job["progress_data"]["percentage"] = 100
        job["progress_data"]["stage"] = "COMPLETED"
        return
    if status == "success_partial":
        job["progress_data"]["percentage"] = 100
        job["progress_data"]["stage"] = "PARTIAL"
        return
    if status == "up_to_date":
        job["progress_data"]["percentage"] = 100
        job["progress_data"]["stage"] = "UP TO DATE"
        return

    job["status"] = "failed"
    job["progress_data"]["stage"] = "ERROR"
    job["progress_data"]["percentage"] = 100 if processed > 0 else 0


def start_raw_prepare_all_job(
    bssid: str,
    *,
    force: bool = False,
    source_files: Optional[List[str]] = None,
    ssid_hint: Optional[str] = None,
    total_steps: Optional[int] = None,
) -> str:
    expected_steps = int(
        total_steps or (len(source_files) if isinstance(source_files, list) else 0) or 1
    )
    return job_manager.start_multi_job(
        _raw_prepare_all_worker,
        job_type="raw_prepare_all",
        total_steps=expected_steps,
        meta={
            "bssid": bssid,
            "force": bool(force),
            "source_files": source_files,
            "ssid_hint": ssid_hint,
        },
    )
