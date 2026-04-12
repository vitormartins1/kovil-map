import asyncio
import logging
import os
import json
import time
from fastapi import APIRouter, Body
from app.services.data_loader import (
    reload_data,
    get_wardrive_summary,
    list_bruce_handshake_files,
    list_m5evil_handshake_files,
)
from app.api.ws.handlers import manager
from app.schemas.sync import (
    BruceProbeRequest,
    M5EvilProbeRequest,
    PwnagotchiProbeRequest,
    SyncRequest,
    SyncTrustHostKeyRequest,
)
from app.utils.responses import ok
from app.api import deps
from app.services.rawsniffer_service import rawsniffer_service
from app.core.config import HANDSHAKES_DIR
from app.core.job_manager import job_manager
from app.jobs import fingerprint_jobs
from app.services.fingerprint_service import fingerprint_service
from app.jobs.rawsniffer_jobs import start_rawsniffer_job

router = APIRouter()
logger = logging.getLogger(__name__)


_SYNC_PROCESS_TEMPLATES = {
    "pwnagotchi_handshakes": {
        "status": "running",
        "details": "Pwnagotchi handshakes",
        "percentage": 15,
        "stage": "RUNNING",
        "extra": "Importing handshake captures and GPS sidecars from Pwnagotchi SSH",
        "target": "pwnagotchi",
        "mode": "handshakes",
    },
    "handshakes": {
        "status": "running",
        "details": "M5Evil handshakes",
        "percentage": 15,
        "stage": "RUNNING",
        "extra": "Importing handshake captures from Admin WebUI",
        "target": "m5evil",
        "mode": "handshakes",
    },
    "rawsniffer": {
        "status": "queued",
        "details": "M5Evil raw sniffer",
        "percentage": 0,
        "stage": "QUEUED",
        "extra": "Queued behind M5Evil handshakes",
        "target": "m5evil",
        "mode": "rawsniffer",
    },
    "mastersniffer": {
        "status": "queued",
        "details": "M5Evil master sniffer",
        "percentage": 0,
        "stage": "QUEUED",
        "extra": "Queued behind M5Evil RAW sniffer",
        "target": "m5evil",
        "mode": "mastersniffer",
    },
    "wardrive": {
        "status": "queued",
        "details": "M5Evil Wardrive CSVs",
        "percentage": 0,
        "stage": "QUEUED",
        "extra": "Queued behind M5Evil Master Sniffer",
        "target": "m5evil",
        "mode": "wardrive",
    },
    "bruce_handshakes": {
        "status": "running",
        "details": "Bruce handshakes",
        "percentage": 15,
        "stage": "RUNNING",
        "extra": "Importing handshake captures from Bruce WebUI",
        "target": "bruce",
        "mode": "handshakes",
    },
    "bruce_rawsniffer": {
        "status": "queued",
        "details": "Bruce raw sniffer",
        "percentage": 0,
        "stage": "QUEUED",
        "extra": "Queued behind Bruce handshakes",
        "target": "bruce",
        "mode": "rawsniffer",
    },
    "bruce_wardrive": {
        "status": "queued",
        "details": "Bruce Wardrive CSVs",
        "percentage": 0,
        "stage": "QUEUED",
        "extra": "Queued behind Bruce RAW sniffer",
        "target": "bruce",
        "mode": "wardrive",
    },
}


def _register_sync_process_jobs(process_id_map):
    for mode, process_id in (process_id_map or {}).items():
        if not process_id:
            continue
        template = _SYNC_PROCESS_TEMPLATES.get(mode)
        if not template:
            continue
        job_manager.register_external_job(
            process_id,
            job_type="sync_import",
            command="internal:sync",
            status=template["status"],
            total_steps=1,
            meta={
                "display_type": "SYNC",
                "display_details": template["details"],
                "no_cancel": True,
                "sync_target": template["target"],
                "sync_mode": template["mode"],
            },
            progress_data={
                "percentage": template["percentage"],
                "speed": "",
                "eta": "",
                "stage": template["stage"],
                "extra": template["extra"],
                "current_step": 0,
                "total_steps": 1,
            },
        )


def _complete_sync_process_job(process_id, *, status, stage, extra):
    if not process_id:
        return
    job_manager.complete_external_job(
        process_id,
        status=status,
        progress_data={
            "percentage": 100,
            "stage": stage,
            "extra": extra,
        },
    )


def _finalize_sync_process_jobs(process_id_map, details):
    pwn_remote = details.get("pwnagotchi_remote_sync") or {}
    pwn_total = int(pwn_remote.get("handshake_files_to_download") or 0)
    pwn_downloaded = int(pwn_remote.get("downloaded_handshakes") or 0)
    pwn_failed = int(pwn_remote.get("handshake_files_failed") or 0)
    if pwn_total <= 0:
        _complete_sync_process_job(
            process_id_map.get("pwnagotchi_handshakes"),
            status="up_to_date",
            stage="UP TO DATE",
            extra="No new files",
        )
    elif pwn_failed > 0:
        _complete_sync_process_job(
            process_id_map.get("pwnagotchi_handshakes"),
            status="partial",
            stage="PARTIAL",
            extra=f"{pwn_downloaded}/{pwn_total} | {pwn_failed} failed",
        )
    else:
        _complete_sync_process_job(
            process_id_map.get("pwnagotchi_handshakes"),
            status="success",
            stage="COMPLETED",
            extra=f"{pwn_downloaded}/{pwn_total}",
        )

    m5_remote = details.get("m5evil_remote_sync") or {}
    for mode, downloaded_key, total_key, failed_key in (
        (
            "handshakes",
            "downloaded_handshakes",
            "handshake_files_to_download",
            "handshake_files_failed",
        ),
        (
            "rawsniffer",
            "downloaded_rawsniffer_pcaps",
            "rawsniffer_files_to_download",
            "rawsniffer_files_failed",
        ),
        (
            "mastersniffer",
            "downloaded_mastersniffer_pcaps",
            "mastersniffer_files_to_download",
            "mastersniffer_files_failed",
        ),
        (
            "wardrive",
            "downloaded_wardrive_csvs",
            "wardrive_files_to_download",
            "wardrive_files_failed",
        ),
    ):
        total = int(m5_remote.get(total_key) or 0)
        downloaded = int(m5_remote.get(downloaded_key) or 0)
        failed = int(m5_remote.get(failed_key) or 0)
        if total <= 0:
            _complete_sync_process_job(
                process_id_map.get(mode),
                status="up_to_date",
                stage="UP TO DATE",
                extra="No new files",
            )
        elif failed > 0:
            _complete_sync_process_job(
                process_id_map.get(mode),
                status="partial",
                stage="PARTIAL",
                extra=f"{downloaded}/{total} | {failed} failed",
            )
        else:
            _complete_sync_process_job(
                process_id_map.get(mode),
                status="success",
                stage="COMPLETED",
                extra=f"{downloaded}/{total}",
            )

    bruce_remote = details.get("bruce_remote_sync") or {}
    for mode, downloaded_key, total_key, failed_key in (
        (
            "bruce_handshakes",
            "downloaded_handshakes",
            "handshake_files_to_download",
            "handshake_files_failed",
        ),
        (
            "bruce_rawsniffer",
            "downloaded_rawsniffer_pcaps",
            "rawsniffer_files_to_download",
            "rawsniffer_files_failed",
        ),
        (
            "bruce_wardrive",
            "downloaded_wardrive_csvs",
            "wardrive_files_to_download",
            "wardrive_files_failed",
        ),
    ):
        total = int(bruce_remote.get(total_key) or 0)
        downloaded = int(bruce_remote.get(downloaded_key) or 0)
        failed = int(bruce_remote.get(failed_key) or 0)
        if total <= 0:
            _complete_sync_process_job(
                process_id_map.get(mode),
                status="up_to_date",
                stage="UP TO DATE",
                extra="No new files",
            )
        elif failed > 0:
            _complete_sync_process_job(
                process_id_map.get(mode),
                status="partial",
                stage="PARTIAL",
                extra=f"{downloaded}/{total} | {failed} failed",
            )
        else:
            _complete_sync_process_job(
                process_id_map.get(mode),
                status="success",
                stage="COMPLETED",
                extra=f"{downloaded}/{total}",
            )


def _fingerprint_worker(job, emit):
    return fingerprint_jobs._fingerprint_worker_impl(
        job,
        emit,
        fingerprint_service=fingerprint_service,
        reload_data=reload_data,
        handshakes_dir=HANDSHAKES_DIR,
    )


def _plan_prefixed_fingerprint_files(
    handshake_files,
    downloaded_files=None,
    *,
    include_all_missing_invalid=False,
):
    """
    Planeja quais arquivos baseados em HS_<MAC>.pcap devem passar pelo fingerprint:
    - sem .details -> processa (incremental)
    - .details inválido -> processa forçado
    - .details válido com SSID vazio -> processa forçado
    """
    files_to_process = []
    force_files = []
    reason_by_file = {}
    counts = {
        "hidden_refresh": 0,
        "missing_details": 0,
        "invalid_details": 0,
    }

    downloaded_set = {
        str(name)
        for name in (downloaded_files or [])
        if isinstance(name, str) and name.lower().endswith(".pcap")
    }

    for filename in handshake_files:
        base_name = filename.rsplit(".", 1)[0]
        details_path = os.path.join(HANDSHAKES_DIR, f"{base_name}.details")
        should_queue_missing = include_all_missing_invalid or filename in downloaded_set

        if not os.path.exists(details_path):
            if should_queue_missing:
                files_to_process.append(filename)
                reason_by_file[filename] = "missing_details"
                counts["missing_details"] += 1
            continue

        try:
            with open(details_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except Exception:
            if should_queue_missing:
                files_to_process.append(filename)
                force_files.append(filename)
                reason_by_file[filename] = "invalid_details"
                counts["invalid_details"] += 1
            continue

        ssid = payload.get("ssid") if isinstance(payload, dict) else None
        if ssid is None or not str(ssid).strip():
            files_to_process.append(filename)
            force_files.append(filename)
            reason_by_file[filename] = "hidden_refresh"
            counts["hidden_refresh"] += 1

    return {
        "files_to_process": files_to_process,
        "force_files": force_files,
        "reason_by_file": reason_by_file,
        "counts": counts,
    }


@router.post("/api/sync", tags=["Sync"])
async def trigger_sync(payload: SyncRequest = Body(default=SyncRequest())):
    force = payload.force
    target_force = {
        "pwnagotchi": bool(
            payload.pwn_force_sync if payload.pwn_force_sync is not None else force
        ),
        "m5evil": bool(
            payload.m5_force_sync if payload.m5_force_sync is not None else force
        ),
        "bruce": bool(
            payload.bruce_force_sync if payload.bruce_force_sync is not None else force
        ),
    }
    m5_progress_ids = {
        "pwnagotchi_handshakes": str(payload.pwn_handshakes_process_id or "").strip(),
        "handshakes": str(payload.m5_handshakes_process_id or "").strip(),
        "rawsniffer": str(payload.m5_rawsniffer_process_id or "").strip(),
        "mastersniffer": str(payload.m5_mastersniffer_process_id or "").strip(),
        "wardrive": str(payload.m5_wardrive_process_id or "").strip(),
        "bruce_handshakes": str(payload.bruce_handshakes_process_id or "").strip(),
        "bruce_rawsniffer": str(payload.bruce_rawsniffer_process_id or "").strip(),
        "bruce_wardrive": str(payload.bruce_wardrive_process_id or "").strip(),
    }
    _register_sync_process_jobs(m5_progress_ids)

    def _emit_sync_progress(mode, data):
        process_id = m5_progress_ids.get(str(mode or "").strip().lower())
        if not process_id:
            return
        job_manager.update_external_job(process_id, progress_data=data)
        job_manager._fire_and_forget_emit(
            "job_progress",
            {"job_id": process_id, "data": data},
        )

    sync_started_at = time.perf_counter()
    result = await asyncio.to_thread(
        deps.sync_service.perform_sync,
        force=force,
        progress_callback=_emit_sync_progress,
        target_force=target_force,
    )
    remote_sync_ms = round((time.perf_counter() - sync_started_at) * 1000, 2)
    result_details = (
        result.get("details") if isinstance(result.get("details"), dict) else {}
    )
    pwn_remote = (
        result_details.get("pwnagotchi_remote_sync")
        if isinstance(result_details.get("pwnagotchi_remote_sync"), dict)
        else {}
    )
    m5_remote = (
        result_details.get("m5evil_remote_sync")
        if isinstance(result_details.get("m5evil_remote_sync"), dict)
        else {}
    )
    bruce_remote = (
        result_details.get("bruce_remote_sync")
        if isinstance(result_details.get("bruce_remote_sync"), dict)
        else {}
    )

    fingerprint_plan_started_at = time.perf_counter()
    bruce_files = await asyncio.to_thread(list_bruce_handshake_files)
    m5evil_files = await asyncio.to_thread(list_m5evil_handshake_files)
    logger.info(f"[SYNC] Bruce files found: {bruce_files}")
    logger.info(f"[SYNC] M5 Evil files found: {m5evil_files}")
    bruce_fingerprint_plan = await asyncio.to_thread(
        _plan_prefixed_fingerprint_files,
        bruce_files,
        include_all_missing_invalid=True,
    )
    m5evil_fingerprint_plan = await asyncio.to_thread(
        _plan_prefixed_fingerprint_files,
        m5evil_files,
        include_all_missing_invalid=True,
    )
    fingerprint_plan_ms = round(
        (time.perf_counter() - fingerprint_plan_started_at) * 1000, 2
    )
    bruce_files_to_process = bruce_fingerprint_plan.get("files_to_process", [])
    bruce_force_files = bruce_fingerprint_plan.get("force_files", [])
    bruce_reason_by_file = bruce_fingerprint_plan.get("reason_by_file", {})
    bruce_plan_counts = bruce_fingerprint_plan.get("counts", {})
    m5evil_files_to_process = m5evil_fingerprint_plan.get("files_to_process", [])
    m5evil_force_files = m5evil_fingerprint_plan.get("force_files", [])
    m5evil_reason_by_file = m5evil_fingerprint_plan.get("reason_by_file", {})
    m5evil_plan_counts = m5evil_fingerprint_plan.get("counts", {})
    logger.info(
        "[SYNC] Bruce fingerprint plan: total=%s force=%s hidden=%s missing=%s invalid=%s",
        len(bruce_files_to_process),
        len(bruce_force_files),
        bruce_plan_counts.get("hidden_refresh", 0),
        bruce_plan_counts.get("missing_details", 0),
        bruce_plan_counts.get("invalid_details", 0),
    )
    logger.info(
        "[SYNC] M5 Evil fingerprint plan: total=%s force=%s hidden=%s missing=%s invalid=%s",
        len(m5evil_files_to_process),
        len(m5evil_force_files),
        m5evil_plan_counts.get("hidden_refresh", 0),
        m5evil_plan_counts.get("missing_details", 0),
        m5evil_plan_counts.get("invalid_details", 0),
    )

    # Se houve algum sync remoto bem-sucedido, recarrega cache base imediatamente
    if result.get("status") == "success" or result_details.get("any_remote_success"):
        await asyncio.to_thread(reload_data)
        await manager.broadcast({"type": "data_update", "payload": "map_data"})

    details = result_details
    details["wardrive"] = get_wardrive_summary()

    # Inicia job para fingerprints em background
    bruce_fingerprint_job_id = None
    m5evil_fingerprint_job_id = None
    fingerprint_queue_started_at = time.perf_counter()
    if bruce_files_to_process:
        logger.info(
            f"[SYNC] Starting Bruce fingerprint job for {len(bruce_files_to_process)} files"
        )
        bruce_fingerprint_job_id = job_manager.start_multi_job(
            _fingerprint_worker,
            job_type="fingerprint_multi",
            total_steps=len(bruce_files_to_process),
            meta={
                "files_to_process": bruce_files_to_process,
                "force_files": bruce_force_files,
                "reason_by_file": bruce_reason_by_file,
            },
        )
        logger.info(f"[SYNC] Created Bruce fingerprint job: {bruce_fingerprint_job_id}")
    else:
        logger.info("[SYNC] No Bruce files to process for fingerprinting")
    if m5evil_files_to_process:
        logger.info(
            f"[SYNC] Starting M5 Evil fingerprint job for {len(m5evil_files_to_process)} files"
        )
        m5evil_fingerprint_job_id = job_manager.start_multi_job(
            _fingerprint_worker,
            job_type="fingerprint_multi",
            total_steps=len(m5evil_files_to_process),
            meta={
                "files_to_process": m5evil_files_to_process,
                "force_files": m5evil_force_files,
                "reason_by_file": m5evil_reason_by_file,
            },
        )
        logger.info(
            f"[SYNC] Created M5 Evil fingerprint job: {m5evil_fingerprint_job_id}"
        )
    else:
        logger.info("[SYNC] No M5 Evil files to process for fingerprinting")
    fingerprint_queue_ms = round(
        (time.perf_counter() - fingerprint_queue_started_at) * 1000, 2
    )

    rawsniffer_queue_started_at = time.perf_counter()
    raw_files = await asyncio.to_thread(rawsniffer_service.list_files)
    raw_pending = await asyncio.to_thread(rawsniffer_service.get_pending_files)
    rawsniffer_job_id = None
    if (
        result.get("status") == "success" or result_details.get("any_remote_success")
    ) and raw_pending:
        logger.info(f"[SYNC] Starting rawsniffer job for {len(raw_pending)} files")
        rawsniffer_job_id = start_rawsniffer_job(raw_pending, force=False)
        logger.info(f"[SYNC] Created rawsniffer job: {rawsniffer_job_id}")
    rawsniffer_queue_ms = round(
        (time.perf_counter() - rawsniffer_queue_started_at) * 1000, 2
    )

    details["bruce"] = {
        "handshakes_seen": len(bruce_files),
        "handshakes_to_process": len(bruce_files_to_process),
        "handshakes_hidden_refresh": bruce_plan_counts.get("hidden_refresh", 0),
        "handshakes_missing_details": bruce_plan_counts.get("missing_details", 0),
        "handshakes_invalid_details": bruce_plan_counts.get("invalid_details", 0),
        "fingerprint_job_id": bruce_fingerprint_job_id,
    }
    details["m5evil"] = {
        "handshakes_seen": len(m5evil_files),
        "handshakes_to_process": len(m5evil_files_to_process),
        "handshakes_hidden_refresh": m5evil_plan_counts.get("hidden_refresh", 0),
        "handshakes_missing_details": m5evil_plan_counts.get("missing_details", 0),
        "handshakes_invalid_details": m5evil_plan_counts.get("invalid_details", 0),
        "fingerprint_job_id": m5evil_fingerprint_job_id,
    }
    details["rawsniffer"] = {
        "files_seen": len(raw_files),
        "files_to_process": len(raw_pending),
        "job_id": rawsniffer_job_id,
    }
    details["sync_stages"] = {
        "remote_sync": {
            "status": result.get("status"),
            "message": result.get("message"),
        },
        "pwnagotchi_remote_sync": {
            "status": pwn_remote.get("status", "skipped"),
            "message": pwn_remote.get("message"),
            "downloaded_handshakes": len(
                pwn_remote.get("details", {}).get("handshakes", []) or []
            ),
            "downloaded_wardrive_csvs": len(
                pwn_remote.get("details", {}).get("wardrive_csvs", []) or []
            ),
            "handshake_remote_files_found": pwn_remote.get("details", {}).get(
                "handshake_remote_files_found", 0
            ),
            "handshake_files_to_download": pwn_remote.get("details", {}).get(
                "handshake_files_to_download", 0
            ),
            "handshake_files_failed": pwn_remote.get("details", {}).get(
                "handshake_files_failed", 0
            ),
            "sync_ms": pwn_remote.get("details", {}).get("sync_ms", 0),
        },
        "m5evil_remote_sync": {
            "status": m5_remote.get("status", "skipped"),
            "message": m5_remote.get("message"),
            "downloaded_handshakes": len(
                m5_remote.get("details", {}).get("handshakes", []) or []
            ),
            "downloaded_rawsniffer_pcaps": len(
                m5_remote.get("details", {}).get("rawsniffer_pcaps", []) or []
            ),
            "downloaded_mastersniffer_pcaps": len(
                m5_remote.get("details", {}).get("mastersniffer_pcaps", []) or []
            ),
            "downloaded_wardrive_csvs": len(
                m5_remote.get("details", {}).get("wardrive_csvs", []) or []
            ),
            "handshake_remote_files_found": m5_remote.get("details", {}).get(
                "handshake_remote_files_found", 0
            ),
            "handshake_files_to_download": m5_remote.get("details", {}).get(
                "handshake_files_to_download", 0
            ),
            "handshake_files_failed": m5_remote.get("details", {}).get(
                "handshake_files_failed", 0
            ),
            "rawsniffer_remote_files_found": m5_remote.get("details", {}).get(
                "rawsniffer_remote_files_found", 0
            ),
            "rawsniffer_files_to_download": m5_remote.get("details", {}).get(
                "rawsniffer_files_to_download", 0
            ),
            "rawsniffer_files_failed": m5_remote.get("details", {}).get(
                "rawsniffer_files_failed", 0
            ),
            "mastersniffer_remote_files_found": m5_remote.get("details", {}).get(
                "mastersniffer_remote_files_found", 0
            ),
            "mastersniffer_files_to_download": m5_remote.get("details", {}).get(
                "mastersniffer_files_to_download", 0
            ),
            "mastersniffer_files_failed": m5_remote.get("details", {}).get(
                "mastersniffer_files_failed", 0
            ),
            "wardrive_remote_files_found": m5_remote.get("details", {}).get(
                "wardrive_remote_files_found", 0
            ),
            "wardrive_files_to_download": m5_remote.get("details", {}).get(
                "wardrive_files_to_download", 0
            ),
            "wardrive_files_failed": m5_remote.get("details", {}).get(
                "wardrive_files_failed", 0
            ),
            "sync_ms": m5_remote.get("details", {}).get("sync_ms", 0),
            "connection_ok": m5_remote.get("details", {}).get("connection_ok"),
            "auth_ok": m5_remote.get("details", {}).get("auth_ok"),
            "browse_root_ok": m5_remote.get("details", {}).get("browse_root_ok"),
            "handshake_path_ok": m5_remote.get("details", {}).get("handshake_path_ok"),
            "rawsniffer_path_ok": m5_remote.get("details", {}).get(
                "rawsniffer_path_ok"
            ),
            "wardrive_path_ok": m5_remote.get("details", {}).get("wardrive_path_ok"),
            "failure_phase": m5_remote.get("details", {}).get("failure_phase"),
            "url_used": m5_remote.get("details", {}).get("url_used"),
        },
        "bruce_remote_sync": {
            "status": bruce_remote.get("status", "skipped"),
            "message": bruce_remote.get("message"),
            "downloaded_handshakes": len(
                bruce_remote.get("details", {}).get("handshakes", []) or []
            ),
            "downloaded_rawsniffer_pcaps": len(
                bruce_remote.get("details", {}).get("rawsniffer_pcaps", []) or []
            ),
            "downloaded_wardrive_csvs": len(
                bruce_remote.get("details", {}).get("wardrive_csvs", []) or []
            ),
            "handshake_remote_files_found": bruce_remote.get("details", {}).get(
                "handshake_remote_files_found", 0
            ),
            "handshake_files_to_download": bruce_remote.get("details", {}).get(
                "handshake_files_to_download", 0
            ),
            "handshake_files_failed": bruce_remote.get("details", {}).get(
                "handshake_files_failed", 0
            ),
            "rawsniffer_remote_files_found": bruce_remote.get("details", {}).get(
                "rawsniffer_remote_files_found", 0
            ),
            "rawsniffer_files_to_download": bruce_remote.get("details", {}).get(
                "rawsniffer_files_to_download", 0
            ),
            "rawsniffer_files_failed": bruce_remote.get("details", {}).get(
                "rawsniffer_files_failed", 0
            ),
            "wardrive_remote_files_found": bruce_remote.get("details", {}).get(
                "wardrive_remote_files_found", 0
            ),
            "wardrive_files_to_download": bruce_remote.get("details", {}).get(
                "wardrive_files_to_download", 0
            ),
            "wardrive_files_failed": bruce_remote.get("details", {}).get(
                "wardrive_files_failed", 0
            ),
            "sync_ms": bruce_remote.get("details", {}).get("sync_ms", 0),
            "connection_ok": bruce_remote.get("details", {}).get("connection_ok"),
            "auth_ok": bruce_remote.get("details", {}).get("auth_ok"),
            "handshake_path_ok": bruce_remote.get("details", {}).get(
                "handshake_path_ok"
            ),
            "rawsniffer_path_ok": bruce_remote.get("details", {}).get(
                "rawsniffer_path_ok"
            ),
            "wardrive_path_ok": bruce_remote.get("details", {}).get("wardrive_path_ok"),
            "failure_phase": bruce_remote.get("details", {}).get("failure_phase"),
            "url_used": bruce_remote.get("details", {}).get("url_used"),
        },
        "bruce_fingerprint": {
            "status": "queued" if bruce_fingerprint_job_id else "skipped",
            "planned_files": len(bruce_files_to_process),
            "forced_files": len(bruce_force_files),
            "job_id": bruce_fingerprint_job_id,
        },
        "m5evil_fingerprint": {
            "status": "queued" if m5evil_fingerprint_job_id else "skipped",
            "planned_files": len(m5evil_files_to_process),
            "forced_files": len(m5evil_force_files),
            "job_id": m5evil_fingerprint_job_id,
        },
        "rawsniffer_extract": {
            "status": "queued" if rawsniffer_job_id else "skipped",
            "planned_files": len(raw_pending),
            "job_id": rawsniffer_job_id,
        },
    }
    details["metrics"] = {
        "remote_sync_ms": remote_sync_ms,
        "fingerprint_plan_ms": fingerprint_plan_ms,
        "fingerprint_queue_ms": fingerprint_queue_ms,
        "rawsniffer_queue_ms": rawsniffer_queue_ms,
        "pwnagotchi_remote_sync_ms": pwn_remote.get("details", {}).get("sync_ms", 0),
        "m5evil_remote_sync_ms": m5_remote.get("details", {}).get("sync_ms", 0),
        "bruce_remote_sync_ms": bruce_remote.get("details", {}).get("sync_ms", 0),
    }
    details["pwnagotchi_remote_sync"] = {
        "downloaded_handshakes": len(
            pwn_remote.get("details", {}).get("handshakes", []) or []
        ),
        "downloaded_wardrive_csvs": len(
            pwn_remote.get("details", {}).get("wardrive_csvs", []) or []
        ),
        "handshake_remote_files_found": pwn_remote.get("details", {}).get(
            "handshake_remote_files_found", 0
        ),
        "handshake_files_to_download": pwn_remote.get("details", {}).get(
            "handshake_files_to_download", 0
        ),
        "handshake_files_failed": pwn_remote.get("details", {}).get(
            "handshake_files_failed", 0
        ),
        "errors": pwn_remote.get("details", {}).get("errors", []) or [],
        "sync_ms": pwn_remote.get("details", {}).get("sync_ms", 0),
        "status": pwn_remote.get("status", "skipped"),
        "message": pwn_remote.get("message"),
    }
    details["m5evil_remote_sync"] = {
        "downloaded_handshakes": len(
            m5_remote.get("details", {}).get("handshakes", []) or []
        ),
        "downloaded_rawsniffer_pcaps": len(
            m5_remote.get("details", {}).get("rawsniffer_pcaps", []) or []
        ),
        "downloaded_mastersniffer_pcaps": len(
            m5_remote.get("details", {}).get("mastersniffer_pcaps", []) or []
        ),
        "downloaded_wardrive_csvs": len(
            m5_remote.get("details", {}).get("wardrive_csvs", []) or []
        ),
        "handshake_remote_files_found": m5_remote.get("details", {}).get(
            "handshake_remote_files_found", 0
        ),
        "handshake_files_to_download": m5_remote.get("details", {}).get(
            "handshake_files_to_download", 0
        ),
        "handshake_files_failed": m5_remote.get("details", {}).get(
            "handshake_files_failed", 0
        ),
        "rawsniffer_remote_files_found": m5_remote.get("details", {}).get(
            "rawsniffer_remote_files_found", 0
        ),
        "rawsniffer_files_to_download": m5_remote.get("details", {}).get(
            "rawsniffer_files_to_download", 0
        ),
        "rawsniffer_files_failed": m5_remote.get("details", {}).get(
            "rawsniffer_files_failed", 0
        ),
        "mastersniffer_remote_files_found": m5_remote.get("details", {}).get(
            "mastersniffer_remote_files_found", 0
        ),
        "mastersniffer_files_to_download": m5_remote.get("details", {}).get(
            "mastersniffer_files_to_download", 0
        ),
        "mastersniffer_files_failed": m5_remote.get("details", {}).get(
            "mastersniffer_files_failed", 0
        ),
        "wardrive_remote_files_found": m5_remote.get("details", {}).get(
            "wardrive_remote_files_found", 0
        ),
        "wardrive_files_to_download": m5_remote.get("details", {}).get(
            "wardrive_files_to_download", 0
        ),
        "wardrive_files_failed": m5_remote.get("details", {}).get(
            "wardrive_files_failed", 0
        ),
        "errors": m5_remote.get("details", {}).get("errors", []) or [],
        "sync_ms": m5_remote.get("details", {}).get("sync_ms", 0),
        "status": m5_remote.get("status", "skipped"),
    }
    details["bruce_remote_sync"] = {
        "downloaded_handshakes": len(
            bruce_remote.get("details", {}).get("handshakes", []) or []
        ),
        "downloaded_rawsniffer_pcaps": len(
            bruce_remote.get("details", {}).get("rawsniffer_pcaps", []) or []
        ),
        "downloaded_wardrive_csvs": len(
            bruce_remote.get("details", {}).get("wardrive_csvs", []) or []
        ),
        "handshake_remote_files_found": bruce_remote.get("details", {}).get(
            "handshake_remote_files_found", 0
        ),
        "handshake_files_to_download": bruce_remote.get("details", {}).get(
            "handshake_files_to_download", 0
        ),
        "handshake_files_failed": bruce_remote.get("details", {}).get(
            "handshake_files_failed", 0
        ),
        "rawsniffer_remote_files_found": bruce_remote.get("details", {}).get(
            "rawsniffer_remote_files_found", 0
        ),
        "rawsniffer_files_to_download": bruce_remote.get("details", {}).get(
            "rawsniffer_files_to_download", 0
        ),
        "rawsniffer_files_failed": bruce_remote.get("details", {}).get(
            "rawsniffer_files_failed", 0
        ),
        "wardrive_remote_files_found": bruce_remote.get("details", {}).get(
            "wardrive_remote_files_found", 0
        ),
        "wardrive_files_to_download": bruce_remote.get("details", {}).get(
            "wardrive_files_to_download", 0
        ),
        "wardrive_files_failed": bruce_remote.get("details", {}).get(
            "wardrive_files_failed", 0
        ),
        "errors": bruce_remote.get("details", {}).get("errors", []) or [],
        "sync_ms": bruce_remote.get("details", {}).get("sync_ms", 0),
        "status": bruce_remote.get("status", "skipped"),
    }
    _finalize_sync_process_jobs(m5_progress_ids, details)
    result["details"] = details

    return ok(result)


@router.post("/api/sync/trust-host-key", tags=["Sync"])
async def trust_host_key(
    payload: SyncTrustHostKeyRequest = Body(default=SyncTrustHostKeyRequest()),
):
    result = await asyncio.to_thread(
        deps.sync_service.trust_remote_host_key,
        host=payload.host,
        port=payload.port,
        replace=payload.replace,
        target=payload.target,
    )
    return ok(result)


@router.post("/api/sync/pwnagotchi/probe", tags=["Sync"])
async def probe_pwnagotchi_ssh(
    payload: PwnagotchiProbeRequest = Body(default=PwnagotchiProbeRequest()),
):
    overrides = payload.model_dump(exclude_none=True)
    result = await asyncio.to_thread(
        deps.sync_service.probe_pwnagotchi_ssh,
        overrides,
    )
    return ok(result)


@router.post("/api/sync/m5evil/probe", tags=["Sync"])
async def probe_m5evil_admin_webui(
    payload: M5EvilProbeRequest = Body(default=M5EvilProbeRequest()),
):
    overrides = payload.model_dump(exclude_none=True)
    result = await asyncio.to_thread(
        deps.sync_service.probe_m5evil_admin_webui,
        overrides,
    )
    return ok(result)


@router.post("/api/sync/bruce/probe", tags=["Sync"])
async def probe_bruce_webui(
    payload: BruceProbeRequest = Body(default=BruceProbeRequest()),
):
    overrides = payload.model_dump(exclude_none=True)
    result = await asyncio.to_thread(
        deps.sync_service.probe_bruce_webui,
        overrides,
    )
    return ok(result)
