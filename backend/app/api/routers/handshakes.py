import os
import logging

from fastapi import APIRouter, Body

from app.jobs.handshake_raw_jobs import start_raw_prepare_all_job
from app.core.config import (
    HANDSHAKES_DIR,
    BRUCE_HANDSHAKES_DIR,
    BRUCE_PCAP_DIR,
    M5EVIL_HANDSHAKES_DIR,
)
from app.services.data_loader import reload_data
from app.services import handshake_catalog as handshake_catalog_service
from app.services.crack_service import crack_service
from app.services.rawsniffer_service import rawsniffer_service
from app.utils.responses import fail, ok

router = APIRouter()
logger = logging.getLogger(__name__)


def _sync_catalog_roots():
    handshake_catalog_service.HANDSHAKES_DIR = HANDSHAKES_DIR
    handshake_catalog_service.BRUCE_HANDSHAKES_DIR = BRUCE_HANDSHAKES_DIR
    handshake_catalog_service.BRUCE_PCAP_DIR = BRUCE_PCAP_DIR
    handshake_catalog_service.M5EVIL_HANDSHAKES_DIR = M5EVIL_HANDSHAKES_DIR


def _serialize_artifact(artifact: dict | None) -> dict | None:
    if not isinstance(artifact, dict):
        return None
    payload = {
        "name": artifact.get("name"),
        "size": artifact.get("size"),
        "modified": artifact.get("modified"),
        "type": artifact.get("type"),
        "artifact_scope": artifact.get("artifact_scope") or "shared_legacy",
        "artifact_owner_capture_id": artifact.get("artifact_owner_capture_id"),
        "capture_specific": bool(artifact.get("capture_specific")),
        "legacy_sidecar": bool(artifact.get("legacy_sidecar")),
        "shared_legacy": bool(artifact.get("shared_legacy")),
    }
    if artifact.get("valid_hash_lines") is not None:
        payload["valid_hash_lines"] = int(artifact.get("valid_hash_lines") or 0)
    return payload


def _serialize_capture(capture: dict, preferred_capture_id: str | None) -> dict:
    artifacts = capture.get("artifacts") or {}
    return {
        "capture_id": capture.get("capture_id"),
        "source": capture.get("source"),
        "device_label": capture.get("device_label"),
        "source_filename": capture.get("source_filename"),
        "source_path_role": capture.get("source_path_role"),
        "ssid": capture.get("ssid") or "",
        "resolved_ssid": capture.get("resolved_ssid") or "",
        "quality": dict(capture.get("quality") or {}),
        "is_preferred": capture.get("capture_id") == preferred_capture_id,
        "artifacts": {
            "pcap": _serialize_artifact(artifacts.get("pcap")),
            "details": [
                _serialize_artifact(item)
                for item in (artifacts.get("details") or [])
                if _serialize_artifact(item)
            ],
            "hash_22000": [
                _serialize_artifact(item)
                for item in (artifacts.get("hash_22000") or [])
                if _serialize_artifact(item)
            ],
            "cracked": [
                _serialize_artifact(item)
                for item in (artifacts.get("cracked") or [])
                if _serialize_artifact(item)
            ],
            "history": [
                _serialize_artifact(item)
                for item in (artifacts.get("history") or [])
                if _serialize_artifact(item)
            ],
            "other": [
                _serialize_artifact(item)
                for item in (artifacts.get("other") or [])
                if _serialize_artifact(item)
            ],
        },
        "legacy_shared_artifacts": any(
            bool(item.get("shared_legacy"))
            for group in (
                artifacts.get("details") or [],
                artifacts.get("hash_22000") or [],
                artifacts.get("cracked") or [],
                artifacts.get("history") or [],
                artifacts.get("other") or [],
            )
            for item in group
            if isinstance(item, dict)
        ),
    }


@router.get("/api/handshakes/{mac}/files", tags=["Handshakes"])
def list_handshake_files(mac: str):
    _sync_catalog_roots()
    files = handshake_catalog_service.list_handshake_files(mac)
    clean_mac = mac.replace(":", "").lower()
    seen_keys = {
        (
            str(item.get("name") or ""),
            str(item.get("capture_id") or ""),
            str(item.get("source_path_role") or ""),
        )
        for item in files
        if isinstance(item, dict)
    }

    ignored_extensions = (".gps.json", ".geo.json", ".paw-gps.json")
    ignored_legacy_token = "__wdrs__raw_"

    if os.path.exists(HANDSHAKES_DIR):
        try:
            filenames = os.listdir(HANDSHAKES_DIR)
        except OSError:
            filenames = []
        for name in filenames:
            if clean_mac not in name.lower():
                continue
            lower_name = name.lower()
            if name.endswith(ignored_extensions):
                continue
            if lower_name.startswith("raw_") and lower_name.endswith(".22000"):
                continue
            if lower_name.endswith(".wdrs.json"):
                continue
            if ignored_legacy_token in lower_name:
                continue
            path = os.path.join(HANDSHAKES_DIR, name)
            if not os.path.exists(path):
                continue
            try:
                stat = os.stat(path)
            except OSError:
                continue
            if stat.st_size == 0 and name.endswith(".22000"):
                continue
            entry = {
                "name": name,
                "size": stat.st_size,
                "modified": stat.st_mtime,
                "type": name.split(".")[-1],
                "capture_id": None,
                "source": "legacy",
                "device_label": "Legacy",
                "source_path_role": "handshakes",
                "legacy_shared": False,
                "artifact_scope": "shared_legacy",
                "artifact_owner_capture_id": None,
                "is_preferred": False,
            }
            key = (entry["name"], "", entry["source_path_role"])
            if key in seen_keys:
                continue
            files.append(entry)
            seen_keys.add(key)

    files.sort(
        key=lambda item: (
            -float(item.get("modified") or 0.0),
            str(item.get("name") or "").lower(),
            str(item.get("capture_id") or ""),
        )
    )
    return ok(files)


@router.get("/api/handshakes/{mac}/set", tags=["Handshakes"])
def get_handshake_set(mac: str):
    _sync_catalog_roots()
    handshake_set = handshake_catalog_service.get_handshake_set(mac)
    if not handshake_set:
        fail("Handshake set not found", status_code=404)

    preferred_capture_id = handshake_set.get("preferred_capture_id")
    captures = [
        _serialize_capture(capture, preferred_capture_id)
        for capture in (handshake_set.get("captures") or [])
    ]
    payload = {
        "handshake_set_id": handshake_set.get("handshake_set_id"),
        "mac": handshake_set.get("mac"),
        "resolved_ssid": handshake_set.get("resolved_ssid") or "",
        "sources": list(handshake_set.get("sources") or []),
        "preferred_capture_id": preferred_capture_id,
        "artifact_summary": dict(handshake_set.get("artifact_summary") or {}),
        "captures": captures,
        "flat_files": list(handshake_set.get("flat_files") or []),
        "combined_candidates": [
            {
                **dict(item),
                "included_capture_ids": list(item.get("included_capture_ids") or []),
                "included_captures": [
                    dict(capture)
                    for capture in (item.get("included_captures") or [])
                    if isinstance(capture, dict)
                ],
            }
            for item in (handshake_set.get("combined_candidates") or [])
            if isinstance(item, dict)
        ],
    }
    return ok(payload)


@router.post("/api/handshakes/{mac}/combine-captures", tags=["Handshakes"])
def combine_handshake_captures(mac: str, payload: dict | None = Body(default=None)):
    capture_ids = [
        str(item or "").strip()
        for item in ((payload or {}).get("capture_ids") or [])
        if str(item or "").strip()
    ]
    _sync_catalog_roots()
    result = crack_service.build_combined_candidate(
        mac, capture_ids=capture_ids or None
    )
    if result.get("status") != "success":
        fail(
            result.get("message", "Failed to build combined candidate"), status_code=400
        )
    try:
        reload_data()
    except Exception as exc:
        logger.warning(
            "Combined candidate build succeeded but reload_data failed: %s", exc
        )
    return ok(result)


@router.get("/api/handshakes/{mac}/raw-context", tags=["Handshakes"])
def get_handshake_raw_context(mac: str):
    return ok(rawsniffer_service.get_raw_context_for_bssid(mac))


@router.post("/api/handshakes/{mac}/raw-prepare", tags=["Handshakes"])
def prepare_handshake_from_raw(
    mac: str,
    payload: dict = Body(...),
):
    raw_item_id = str((payload or {}).get("raw_item_id") or "").strip() or None
    source_file = os.path.basename(
        str((payload or {}).get("source_file") or "").strip()
    )
    force = bool((payload or {}).get("force", False))

    if not source_file and not raw_item_id:
        fail("source_file or raw_item_id is required", status_code=400)

    result = rawsniffer_service.prepare_raw_item_for_bssid(
        mac,
        raw_item_id=raw_item_id,
        source_file=source_file or None,
        force=force,
    )

    if result.get("status") == "error":
        fail(
            result.get("message", "Failed to prepare RAW handshake context"),
            status_code=400,
        )

    reloaded = False
    if result.get("status") in {"success", "success_partial"}:
        try:
            reload_data()
            reloaded = True
        except Exception as exc:
            logger.warning("RAW prepare succeeded but reload_data failed: %s", exc)

    response = dict(result)
    response["reloaded"] = reloaded
    return ok(response)


@router.post("/api/handshakes/{mac}/raw-prepare-all", tags=["Handshakes"])
def prepare_all_handshakes_from_raw(
    mac: str,
    payload: dict | None = Body(default=None),
):
    force = bool((payload or {}).get("force", False))

    context = rawsniffer_service.get_raw_context_for_bssid(mac)
    if not context.get("present"):
        fail("No RAW context found for this BSSID", status_code=400)

    context_files = context.get("files")
    if not isinstance(context_files, list):
        context_files = []
    context_hash_files = context.get("hash_files")
    if not isinstance(context_hash_files, list):
        context_hash_files = []

    total_hash_files = len(
        [
            item
            for item in context_hash_files
            if isinstance(item, dict) and str(item.get("filename") or "").strip()
        ]
    )
    total_pcap_files = len(
        [
            item
            for item in context_files
            if isinstance(item, dict) and str(item.get("source_file") or "").strip()
        ]
    )
    total_files = total_hash_files if total_hash_files > 0 else total_pcap_files
    if total_files <= 0:
        fail("No RAW source files available for this BSSID", status_code=400)

    job_id = start_raw_prepare_all_job(
        mac,
        force=force,
        source_files=None,
        ssid_hint=None,
        total_steps=total_files,
    )
    return ok(
        {
            "status": "started",
            "job_id": job_id,
            "force": force,
            "total_files": total_files,
        }
    )
