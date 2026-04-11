import os
import json
import csv
import itertools
import re
import logging
import time
from app.core.config import (
    HANDSHAKES_DIR,
    WARDRIVE_DIR,
    BRUCE_PCAP_DIR,
    BRUCE_HANDSHAKES_DIR,
    M5EVIL_DIR,
    M5EVIL_HANDSHAKES_DIR,
)
from app.services.spatial_normalizer import (
    normalize_network_positions,
)
from app.services import handshake_catalog as handshake_catalog_service
from app.services.data_loader_wardrive_helpers import (
    _classify_wardrive_device,
    _extract_device_classification,
    _infer_encryption,
    _infer_encryption_from_details,
    _merge_wardrive_session_observation,
    _normalize_mac,
    _normalize_wardrive_accuracy,
    _parse_float,
    _parse_wigle_timestamp,
    _wardrive_session_base_name_from_filename,
)
from app.services.data_loader_wardrive_manifest_helpers import (
    _build_unique_wardrive_session_id as _build_unique_wardrive_session_id_helper,
    _build_wardrive_manifest_indexes as _build_wardrive_manifest_indexes_helper,
    _build_wardrive_merged_session_id as _build_wardrive_merged_session_id_helper,
    _compute_wardrive_file_sha256 as _compute_wardrive_file_sha256_helper,
    _default_wardrive_manifest as _default_wardrive_manifest_helper,
    _discover_wardrive_csv_files as _discover_wardrive_csv_files_helper,
    _make_wardrive_manifest_entry as _make_wardrive_manifest_entry_helper,
    _normalize_wardrive_manifest_entry as _normalize_wardrive_manifest_entry_helper,
    _read_wardrive_csv_merge_sections as _read_wardrive_csv_merge_sections_helper,
    _resolve_wardrive_manifest_entry_path as _resolve_wardrive_manifest_entry_path_helper,
    _wardrive_manifest_path as _wardrive_manifest_path_helper,
    _wardrive_merged_dir as _wardrive_merged_dir_helper,
    _wardrive_relative_path as _wardrive_relative_path_helper,
    _wardrive_session_tags_path as _wardrive_session_tags_path_helper,
)
from app.services.data_loader_raw_metadata_helpers import (
    _merge_raw_metadata as _merge_raw_metadata_helper,
    _normalize_raw_metadata_source as _normalize_raw_metadata_source_helper,
    _raw_metadata_dirs as _raw_metadata_dirs_helper,
    _raw_metadata_source_id as _raw_metadata_source_id_helper,
)
from app.services.data_loader_handshake_helpers import (
    _load_details_for_base as _load_details_for_base_helper,
    _load_prefixed_handshake_entries as _load_prefixed_handshake_entries_helper,
    _merge_external_handshake_entries as _merge_external_handshake_entries_helper,
)
from app.services.data_loader_primary_ingest_helpers import (
    _load_gps_handshake_entries as _load_gps_handshake_entries_helper,
    _merge_no_gps_pcap_entries as _merge_no_gps_pcap_entries_helper,
)
from app.services.data_loader_merge_helpers import (
    _finalize_loaded_data as _finalize_loaded_data_helper,
    _merge_wardrive_entries as _merge_wardrive_entries_helper,
)

# Cache Global
_DATA_CACHE = None
_DATA_REVISION = 0
_WARDRIVE_SUMMARY = {"files_count": 0, "networks_count": 0, "sessions_count": 0}
_WARDRIVE_SESSIONS = []
_WARDRIVE_SESSION_TAGS = None
_WARDRIVE_MANIFEST = None
_WARDRIVE_MANIFEST_PATH = None
_HS_HANDSHAKE_RE = re.compile(r"^HS_([0-9A-Fa-f]{12})")
WARDRIVE_TRANSPORT_MODES = (
    "walk",
    "bike",
    "motorcycle",
    "boat",
    "plane",
    "helicopter",
    "car",
    "bus",
    "train",
    "metro",
)
logger = logging.getLogger(__name__)

_WARDRIVE_MANIFEST_VERSION = 1
_WARDRIVE_MERGED_DIRNAME = "merged"

def get_wardrive_summary():
    global _DATA_CACHE
    if _DATA_CACHE is None:
        _DATA_CACHE = _load_from_disk()
    return dict(_WARDRIVE_SUMMARY)


def get_wardrive_sessions():
    global _DATA_CACHE
    if _DATA_CACHE is None:
        _DATA_CACHE = _load_from_disk()
    return [dict(item) for item in _WARDRIVE_SESSIONS]


def get_wardrive_transport_modes():
    return tuple(WARDRIVE_TRANSPORT_MODES)


def get_data_revision():
    return int(_DATA_REVISION)


def has_wardrive_files():
    return bool(_get_active_wardrive_manifest_entries())


def has_bruce_files():
    return bool(list_bruce_handshake_files())


def list_bruce_handshake_files():
    return sorted(_collect_bruce_handshakes().values())


def has_m5evil_files():
    return bool(list_m5evil_handshake_files())


def list_m5evil_handshake_files():
    return sorted(_collect_m5evil_handshakes().values())


def _collect_prefixed_handshakes(roots):
    # root_priority menor = maior prioridade em empate
    candidates = {}
    for root_priority, root in enumerate(roots):
        if not os.path.exists(root):
            continue
        try:
            filenames = os.listdir(root)
        except OSError:
            continue
        for filename in filenames:
            if not filename.lower().endswith(".pcap"):
                continue
            full_path = os.path.join(root, filename)
            if not os.path.isfile(full_path):
                continue
            match = _HS_HANDSHAKE_RE.match(filename)
            if not match:
                continue
            try:
                mtime = os.path.getmtime(full_path)
            except OSError:
                continue
            mac_raw = match.group(1)
            mac = ":".join(mac_raw[i : i + 2] for i in range(0, 12, 2)).upper()
            selected = candidates.get(mac)
            candidate = {
                "filename": filename,
                "mtime": mtime,
                "root_priority": root_priority,
            }
            if selected is None:
                candidates[mac] = candidate
                continue
            if candidate["mtime"] > selected["mtime"]:
                candidates[mac] = candidate
                continue
            if candidate["mtime"] == selected["mtime"]:
                if candidate["root_priority"] < selected["root_priority"]:
                    candidates[mac] = candidate
                    continue
                if (
                    candidate["root_priority"] == selected["root_priority"]
                    and candidate["filename"] < selected["filename"]
                ):
                    candidates[mac] = candidate

    return {mac: data["filename"] for mac, data in candidates.items()}


def _collect_bruce_handshakes():
    return _collect_prefixed_handshakes((BRUCE_HANDSHAKES_DIR, BRUCE_PCAP_DIR))


def _collect_m5evil_handshakes():
    return _collect_prefixed_handshakes((M5EVIL_HANDSHAKES_DIR,))


def _apply_handshake_set_summaries(data):
    handshake_catalog_service.HANDSHAKES_DIR = HANDSHAKES_DIR
    handshake_catalog_service.BRUCE_HANDSHAKES_DIR = BRUCE_HANDSHAKES_DIR
    handshake_catalog_service.BRUCE_PCAP_DIR = BRUCE_PCAP_DIR
    handshake_catalog_service.M5EVIL_HANDSHAKES_DIR = M5EVIL_HANDSHAKES_DIR
    catalog = handshake_catalog_service.build_handshake_catalog()

    for mac, item in list(data.items()):
        if not isinstance(item, dict):
            continue

        handshake_set = catalog.get(mac)
        if handshake_set:
            preferred = handshake_set.get("preferred_capture") or {}
            preferred_details = preferred.get("details_payload") or {}
            preferred_artifacts = preferred.get("artifacts") or {}
            summary = {
                "handshake_set_id": handshake_set.get("handshake_set_id"),
                "handshake_capture_count": len(handshake_set.get("captures") or []),
                "preferred_handshake_capture_id": handshake_set.get(
                    "preferred_capture_id"
                ),
                "preferred_handshake_filename": preferred.get("source_filename"),
                "preferred_handshake_source": preferred.get("source"),
                "preferred_handshake_quality": (preferred.get("quality") or {}).get(
                    "score"
                ),
                "handshake_artifact_summary": dict(
                    handshake_set.get("artifact_summary") or {}
                ),
            }
            item.update(summary)
            item["handshake"] = True
            item["handshake_files"] = sorted(
                {
                    entry.get("name")
                    for entry in (handshake_set.get("flat_files") or [])
                    if entry.get("name")
                }
            )
            sources = list(item.get("sources") or [])
            for source in handshake_set.get("sources") or []:
                if source not in sources:
                    sources.append(source)
            item["sources"] = sources
            if isinstance(preferred_details, dict) and preferred_details:
                device_type, device_confidence = _extract_device_classification(
                    preferred_details
                )
                item["device_type"] = device_type
                item["device_confidence"] = device_confidence
                item["encryption"] = _infer_encryption_from_details(preferred_details)
            if not str(item.get("ssid") or "").strip():
                item["ssid"] = handshake_set.get("resolved_ssid") or ""
            if not item.get("pass"):
                cracked_files = preferred_artifacts.get("cracked") or []
                cracked_path = (
                    cracked_files[0].get("path")
                    if cracked_files and isinstance(cracked_files[0], dict)
                    else None
                )
                if cracked_path and os.path.exists(cracked_path):
                    try:
                        with open(cracked_path, "r", encoding="utf-8") as handle:
                            item["pass"] = handle.read().strip() or None
                    except Exception:
                        pass
        else:
            item.setdefault("handshake_set_id", None)
            item.setdefault("handshake_capture_count", 0)
            item.setdefault("preferred_handshake_capture_id", None)
            item.setdefault("preferred_handshake_filename", None)
            item.setdefault("preferred_handshake_source", None)
            item.setdefault("preferred_handshake_quality", None)
            item.setdefault(
                "handshake_artifact_summary",
                {
                    "captures": 0,
                    "pcap": 0,
                    "details": 0,
                    "hash_22000": 0,
                    "cracked": 0,
                    "history": 0,
                },
            )

        item["preferred_geo_source"] = item.get("sourceType")


def _set_wardrive_summary(files_count, networks_count, sessions_count=0):
    global _WARDRIVE_SUMMARY
    _WARDRIVE_SUMMARY = {
        "files_count": files_count,
        "networks_count": networks_count,
        "sessions_count": sessions_count,
    }


def _set_wardrive_sessions(sessions):
    global _WARDRIVE_SESSIONS
    _WARDRIVE_SESSIONS = [
        dict(item) for item in _apply_wardrive_transport_tags(sessions)
    ]


def _wardrive_session_tags_path():
    return _wardrive_session_tags_path_helper(WARDRIVE_DIR)


def _wardrive_manifest_path():
    return _wardrive_manifest_path_helper(WARDRIVE_DIR)


def _wardrive_merged_dir():
    return _wardrive_merged_dir_helper(WARDRIVE_DIR, _WARDRIVE_MERGED_DIRNAME)


def _default_wardrive_manifest():
    return _default_wardrive_manifest_helper(_WARDRIVE_MANIFEST_VERSION)


def _normalize_wardrive_manifest_entry(raw_entry):
    return _normalize_wardrive_manifest_entry_helper(
        raw_entry,
        parse_float=_parse_float,
    )


def _load_wardrive_manifest():
    global _WARDRIVE_MANIFEST, _WARDRIVE_MANIFEST_PATH

    path = _wardrive_manifest_path()
    if isinstance(_WARDRIVE_MANIFEST, dict) and str(
        _WARDRIVE_MANIFEST_PATH or ""
    ) == str(path):
        return {
            "version": int(
                _WARDRIVE_MANIFEST.get("version") or _WARDRIVE_MANIFEST_VERSION
            ),
            "files": [dict(item) for item in (_WARDRIVE_MANIFEST.get("files") or [])],
        }

    manifest = _default_wardrive_manifest()
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            if isinstance(payload, dict):
                manifest["version"] = int(
                    payload.get("version") or _WARDRIVE_MANIFEST_VERSION
                )
                entries = []
                for raw_entry in payload.get("files") or []:
                    entry = _normalize_wardrive_manifest_entry(raw_entry)
                    if entry is not None:
                        entries.append(entry)
                manifest["files"] = entries
        except Exception as exc:
            logger.warning("Erro ao carregar manifest wardrive: %s", exc)

    _WARDRIVE_MANIFEST = {
        "version": int(manifest.get("version") or _WARDRIVE_MANIFEST_VERSION),
        "files": [dict(item) for item in (manifest.get("files") or [])],
    }
    _WARDRIVE_MANIFEST_PATH = path
    return {
        "version": int(_WARDRIVE_MANIFEST["version"]),
        "files": [dict(item) for item in _WARDRIVE_MANIFEST["files"]],
    }


def _save_wardrive_manifest(manifest):
    global _WARDRIVE_MANIFEST, _WARDRIVE_MANIFEST_PATH

    os.makedirs(WARDRIVE_DIR, exist_ok=True)
    path = _wardrive_manifest_path()
    normalized_entries = []
    seen_paths = set()
    seen_session_ids = set()

    for raw_entry in (manifest or {}).get("files") or []:
        entry = _normalize_wardrive_manifest_entry(raw_entry)
        if entry is None:
            continue
        rel_path = entry["relative_path"]
        session_id = entry["session_id"]
        if rel_path in seen_paths or session_id in seen_session_ids:
            continue
        seen_paths.add(rel_path)
        seen_session_ids.add(session_id)
        normalized_entries.append(entry)

    normalized_entries.sort(
        key=lambda item: (
            str(item.get("status") or ""),
            str(item.get("relative_path") or ""),
            str(item.get("session_id") or ""),
        )
    )

    payload = {
        "version": int((manifest or {}).get("version") or _WARDRIVE_MANIFEST_VERSION),
        "files": normalized_entries,
    }

    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2, sort_keys=True)
    os.replace(tmp_path, path)
    _WARDRIVE_MANIFEST = {
        "version": int(payload["version"]),
        "files": [dict(item) for item in payload["files"]],
    }
    _WARDRIVE_MANIFEST_PATH = path
    return {
        "version": int(_WARDRIVE_MANIFEST["version"]),
        "files": [dict(item) for item in _WARDRIVE_MANIFEST["files"]],
    }


def _wardrive_relative_path(file_path):
    return _wardrive_relative_path_helper(file_path, WARDRIVE_DIR)


def _resolve_wardrive_manifest_entry_path(entry):
    return _resolve_wardrive_manifest_entry_path_helper(entry, WARDRIVE_DIR)


def _discover_wardrive_csv_files():
    return _discover_wardrive_csv_files_helper(WARDRIVE_DIR, _WARDRIVE_MERGED_DIRNAME)


def _compute_wardrive_file_sha256(file_path):
    return _compute_wardrive_file_sha256_helper(file_path)


def _build_wardrive_manifest_indexes(entries):
    return _build_wardrive_manifest_indexes_helper(
        entries,
        normalize_entry=_normalize_wardrive_manifest_entry,
    )


def _build_unique_wardrive_session_id(base_name, existing_ids):
    return _build_unique_wardrive_session_id_helper(base_name, existing_ids)


def _make_wardrive_manifest_entry(
    *,
    session_id,
    filename,
    relative_path,
    sha256,
    role,
    status,
    imported_at=None,
    merged_at=None,
    merged_from_session_ids=None,
    source_leaf_session_ids=None,
    source_hashes=None,
    duplicate_of_session_id=None,
):
    return _make_wardrive_manifest_entry_helper(
        _normalize_wardrive_manifest_entry,
        session_id=session_id,
        filename=filename,
        relative_path=relative_path,
        sha256=sha256,
        role=role,
        status=status,
        imported_at=imported_at,
        merged_at=merged_at,
        merged_from_session_ids=merged_from_session_ids,
        source_leaf_session_ids=source_leaf_session_ids,
        source_hashes=source_hashes,
        duplicate_of_session_id=duplicate_of_session_id,
    )


def _sync_wardrive_manifest():
    manifest = _load_wardrive_manifest()
    entries = [dict(item) for item in (manifest.get("files") or [])]
    existing_ids = {
        str(item.get("session_id") or "").strip()
        for item in entries
        if item is not None
    }

    now_ts = time.time()
    by_rel_path, _by_session_id, by_hash = _build_wardrive_manifest_indexes(entries)

    for file_path in _discover_wardrive_csv_files():
        try:
            sha256 = _compute_wardrive_file_sha256(file_path)
        except Exception as exc:
            logger.warning(
                "Erro ao calcular hash do wardrive %s: %s",
                os.path.basename(file_path),
                exc,
            )
            continue

        relative_path = _wardrive_relative_path(file_path)
        filename = os.path.basename(file_path)
        existing = by_rel_path.get(relative_path)
        default_role = (
            "merged"
            if relative_path.startswith(f"{_WARDRIVE_MERGED_DIRNAME}/")
            else "original"
        )

        if existing is not None:
            existing["filename"] = filename
            existing["sha256"] = sha256
            existing["relative_path"] = relative_path
            if not existing.get("role"):
                existing["role"] = default_role
            source_hashes = []
            for hash_value in [sha256] + list(existing.get("source_hashes") or []):
                normalized = str(hash_value or "").strip().lower()
                if normalized and normalized not in source_hashes:
                    source_hashes.append(normalized)
            existing["source_hashes"] = source_hashes
            if not existing.get("source_leaf_session_ids"):
                existing["source_leaf_session_ids"] = [existing["session_id"]]
            continue

        duplicate_entry = by_hash.get(sha256)
        base_session_id = _wardrive_session_base_name_from_filename(filename)
        session_id = _build_unique_wardrive_session_id(base_session_id, existing_ids)
        existing_ids.add(session_id)

        if duplicate_entry is not None:
            entry = _make_wardrive_manifest_entry(
                session_id=session_id,
                filename=filename,
                relative_path=relative_path,
                sha256=sha256,
                role=default_role,
                status="ignored",
                imported_at=now_ts,
                merged_at=_parse_float(duplicate_entry.get("merged_at")),
                merged_from_session_ids=list(
                    duplicate_entry.get("merged_from_session_ids") or []
                ),
                source_leaf_session_ids=list(
                    duplicate_entry.get("source_leaf_session_ids")
                    or [duplicate_entry.get("session_id")]
                ),
                source_hashes=list(duplicate_entry.get("source_hashes") or [sha256]),
                duplicate_of_session_id=duplicate_entry.get("session_id"),
            )
        else:
            entry = _make_wardrive_manifest_entry(
                session_id=session_id,
                filename=filename,
                relative_path=relative_path,
                sha256=sha256,
                role=default_role,
                status="active",
                imported_at=now_ts,
                merged_at=now_ts if default_role == "merged" else None,
                merged_from_session_ids=[],
                source_leaf_session_ids=[session_id],
                source_hashes=[sha256],
            )
        entries.append(entry)
        by_rel_path[relative_path] = entry
        for hash_value in [entry.get("sha256")] + list(
            entry.get("source_hashes") or []
        ):
            normalized = str(hash_value or "").strip().lower()
            if normalized and normalized not in by_hash:
                by_hash[normalized] = entry

    saved = _save_wardrive_manifest(
        {
            "version": manifest.get("version") or _WARDRIVE_MANIFEST_VERSION,
            "files": entries,
        }
    )
    return saved


def _get_active_wardrive_manifest_entries():
    manifest = _sync_wardrive_manifest()
    active_entries = []
    for raw_entry in manifest.get("files") or []:
        entry = _normalize_wardrive_manifest_entry(raw_entry)
        if entry is None or entry.get("status") != "active":
            continue
        path = _resolve_wardrive_manifest_entry_path(entry)
        if not path or not os.path.isfile(path):
            continue
        active_entries.append(entry)
    active_entries.sort(
        key=lambda item: (
            str(item.get("role") or ""),
            str(item.get("relative_path") or ""),
            str(item.get("session_id") or ""),
        )
    )
    return active_entries


def _load_wardrive_session_tags():
    global _WARDRIVE_SESSION_TAGS
    if isinstance(_WARDRIVE_SESSION_TAGS, dict):
        return dict(_WARDRIVE_SESSION_TAGS)

    path = _wardrive_session_tags_path()
    tags = {}
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            if isinstance(payload, dict):
                for raw_session_id, raw_mode in payload.items():
                    session_id = str(raw_session_id or "").strip()
                    mode = str(raw_mode or "").strip().lower()
                    if not session_id or mode not in WARDRIVE_TRANSPORT_MODES:
                        continue
                    tags[session_id] = mode
        except Exception as exc:
            logger.warning("Erro ao carregar tags de sessao wardrive: %s", exc)

    _WARDRIVE_SESSION_TAGS = dict(tags)
    return dict(tags)


def _save_wardrive_session_tags(tags):
    global _WARDRIVE_SESSION_TAGS

    os.makedirs(WARDRIVE_DIR, exist_ok=True)
    path = _wardrive_session_tags_path()
    normalized = {}
    for raw_session_id, raw_mode in (tags or {}).items():
        session_id = str(raw_session_id or "").strip()
        mode = str(raw_mode or "").strip().lower()
        if not session_id or mode not in WARDRIVE_TRANSPORT_MODES:
            continue
        normalized[session_id] = mode

    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(normalized, f, ensure_ascii=False, indent=2, sort_keys=True)
    os.replace(tmp_path, path)
    _WARDRIVE_SESSION_TAGS = dict(normalized)
    return dict(normalized)


def _apply_wardrive_transport_tags(sessions):
    tags = _load_wardrive_session_tags()
    merged = []
    for item in sessions or []:
        enriched = dict(item)
        session_id = str(enriched.get("session_id") or "").strip()
        enriched["transport_mode"] = tags.get(session_id)
        merged.append(enriched)
    return merged


def set_wardrive_session_tag(session_id, transport_mode=None):
    global _WARDRIVE_SESSIONS

    normalized_session_id = str(session_id or "").strip()
    if not normalized_session_id:
        raise ValueError("session_id is required")

    sessions = get_wardrive_sessions()
    known_ids = {str(item.get("session_id") or "").strip() for item in sessions}
    if normalized_session_id not in known_ids:
        raise ValueError("session_id not found")

    if transport_mode is None or str(transport_mode).strip() == "":
        normalized_mode = None
    else:
        normalized_mode = str(transport_mode).strip().lower()
        if normalized_mode not in WARDRIVE_TRANSPORT_MODES:
            allowed = ", ".join(WARDRIVE_TRANSPORT_MODES)
            raise ValueError(f"Invalid transport_mode. Allowed: {allowed}")

    tags = _load_wardrive_session_tags()
    if normalized_mode is None:
        tags.pop(normalized_session_id, None)
    else:
        tags[normalized_session_id] = normalized_mode
    saved_tags = _save_wardrive_session_tags(tags)

    updated_sessions = []
    updated_session = None
    for item in _WARDRIVE_SESSIONS:
        enriched = dict(item)
        current_id = str(enriched.get("session_id") or "").strip()
        enriched["transport_mode"] = saved_tags.get(current_id)
        if current_id == normalized_session_id:
            updated_session = dict(enriched)
        updated_sessions.append(enriched)

    _WARDRIVE_SESSIONS = updated_sessions
    if updated_session is None:
        updated_session = {
            "session_id": normalized_session_id,
            "transport_mode": normalized_mode,
        }
    return updated_session


def _read_wardrive_csv_merge_sections(file_path):
    return _read_wardrive_csv_merge_sections_helper(file_path)


def _build_wardrive_merged_session_id(existing_ids):
    return _build_wardrive_merged_session_id_helper(existing_ids)


def merge_wardrive_sessions(session_ids):
    normalized_session_ids = []
    for raw_session_id in session_ids or []:
        session_id = str(raw_session_id or "").strip()
        if session_id and session_id not in normalized_session_ids:
            normalized_session_ids.append(session_id)

    if len(normalized_session_ids) < 2:
        raise ValueError("session_ids must include at least 2 sessions")
    if len(normalized_session_ids) > 3:
        raise ValueError("session_ids supports up to 3 sessions")

    manifest = _sync_wardrive_manifest()
    entries = []
    by_session_id = {}
    existing_ids = set()
    existing_paths = set()
    for raw_entry in manifest.get("files") or []:
        entry = _normalize_wardrive_manifest_entry(raw_entry)
        if entry is None:
            continue
        entries.append(entry)
        existing_ids.add(entry["session_id"])
        existing_paths.add(entry["relative_path"])
        if entry.get("status") == "active":
            path = _resolve_wardrive_manifest_entry_path(entry)
            if path and os.path.isfile(path):
                by_session_id[entry["session_id"]] = entry

    missing_ids = [
        session_id
        for session_id in normalized_session_ids
        if session_id not in by_session_id
    ]
    if missing_ids:
        raise ValueError(
            "session_ids not found or inactive: " + ", ".join(sorted(missing_ids))
        )

    os.makedirs(_wardrive_merged_dir(), exist_ok=True)
    merged_session_id = _build_wardrive_merged_session_id(existing_ids)
    merged_filename = f"{merged_session_id}.csv"
    merged_relative_path = f"{_WARDRIVE_MERGED_DIRNAME}/{merged_filename}"
    while merged_relative_path in existing_paths or os.path.exists(
        os.path.join(WARDRIVE_DIR, merged_relative_path)
    ):
        existing_ids.add(merged_session_id)
        merged_session_id = _build_wardrive_merged_session_id(existing_ids)
        merged_filename = f"{merged_session_id}.csv"
        merged_relative_path = f"{_WARDRIVE_MERGED_DIRNAME}/{merged_filename}"
    merged_path = os.path.join(WARDRIVE_DIR, merged_relative_path)

    merge_header = None
    column_header = None
    merged_lines = []
    source_leaf_session_ids = []
    source_hashes = []
    merge_sources = []
    merged_at = time.time()

    for session_id in normalized_session_ids:
        entry = by_session_id[session_id]
        source_path = _resolve_wardrive_manifest_entry_path(entry)
        if not source_path or not os.path.isfile(source_path):
            raise ValueError(f"session source file missing: {session_id}")

        wigle_header, columns_header, data_lines = _read_wardrive_csv_merge_sections(
            source_path
        )
        if merge_header is None and wigle_header is not None:
            merge_header = wigle_header
        if column_header is None:
            column_header = columns_header
        merged_lines.extend(data_lines)

        for leaf_session_id in entry.get("source_leaf_session_ids") or [session_id]:
            normalized_leaf_id = str(leaf_session_id or "").strip()
            if normalized_leaf_id and normalized_leaf_id not in source_leaf_session_ids:
                source_leaf_session_ids.append(normalized_leaf_id)
        for hash_value in [entry.get("sha256")] + list(
            entry.get("source_hashes") or []
        ):
            normalized_hash = str(hash_value or "").strip().lower()
            if normalized_hash and normalized_hash not in source_hashes:
                source_hashes.append(normalized_hash)
        merge_sources.append(
            {
                "session_id": session_id,
                "relative_path": entry.get("relative_path"),
                "filename": entry.get("filename"),
            }
        )

    if column_header is None:
        raise ValueError("No valid wardrive CSV headers found for merge")

    tmp_path = f"{merged_path}.tmp"
    with open(tmp_path, "w", encoding="utf-8", newline="") as f:
        if merge_header is not None:
            f.write(merge_header)
        f.write(column_header)
        for line in merged_lines:
            f.write(line)
    os.replace(tmp_path, merged_path)
    merged_sha256 = _compute_wardrive_file_sha256(merged_path)
    if merged_sha256 not in source_hashes:
        source_hashes.insert(0, merged_sha256)

    updated_entries = []
    for raw_entry in entries:
        entry = _normalize_wardrive_manifest_entry(raw_entry)
        if entry is None:
            continue
        if entry["session_id"] in normalized_session_ids:
            entry["status"] = "ignored"
        updated_entries.append(entry)

    merged_entry = _make_wardrive_manifest_entry(
        session_id=merged_session_id,
        filename=merged_filename,
        relative_path=merged_relative_path,
        sha256=merged_sha256,
        role="merged",
        status="active",
        imported_at=merged_at,
        merged_at=merged_at,
        merged_from_session_ids=source_leaf_session_ids,
        source_leaf_session_ids=source_leaf_session_ids,
        source_hashes=source_hashes,
    )
    updated_entries.append(merged_entry)
    _save_wardrive_manifest(
        {
            "version": manifest.get("version") or _WARDRIVE_MANIFEST_VERSION,
            "files": updated_entries,
        }
    )

    return {
        **merged_entry,
        "source_path": merged_path,
        "merge_sources": merge_sources,
    }


def _load_details_for_base(base_name):
    return _load_details_for_base_helper(base_name, HANDSHAKES_DIR)


def _load_prefixed_handshake_entries(candidates, roots, source_name):
    return _load_prefixed_handshake_entries_helper(
        candidates,
        roots,
        source_name,
        handshakes_dir=HANDSHAKES_DIR,
        load_details_for_base=_load_details_for_base,
        infer_encryption_from_details=_infer_encryption_from_details,
        extract_device_classification=_extract_device_classification,
    )


def _load_bruce_entries():
    return _load_prefixed_handshake_entries(
        _collect_bruce_handshakes(),
        (BRUCE_HANDSHAKES_DIR, BRUCE_PCAP_DIR),
        "brucegotchi",
    )


def _load_m5evil_entries():
    return _load_prefixed_handshake_entries(
        _collect_m5evil_handshakes(),
        (M5EVIL_HANDSHAKES_DIR,),
        "m5evil",
    )


def _merge_external_handshake_entries(data, entries, source_name):
    return _merge_external_handshake_entries_helper(data, entries, source_name)


def _raw_metadata_dirs():
    return _raw_metadata_dirs_helper(BRUCE_PCAP_DIR, M5EVIL_DIR)


def _normalize_raw_metadata_source(metadata, metadata_dir):
    return _normalize_raw_metadata_source_helper(metadata, metadata_dir, M5EVIL_DIR)


def _raw_metadata_source_id(source, source_path_role):
    return _raw_metadata_source_id_helper(source, source_path_role)


def _merge_raw_metadata(data):
    return _merge_raw_metadata_helper(
        data,
        bruce_pcap_dir=BRUCE_PCAP_DIR,
        m5evil_dir=M5EVIL_DIR,
        normalize_mac=_normalize_mac,
        logger=logger,
    )


def _load_wardrive_entries():
    entries = {}
    if not os.path.exists(WARDRIVE_DIR):
        _set_wardrive_summary(0, 0, 0)
        _set_wardrive_sessions([])
        return entries

    manifest_entries = _get_active_wardrive_manifest_entries()
    files_count = len(manifest_entries)
    sessions_summary = []

    for manifest_entry in manifest_entries:
        file_path = _resolve_wardrive_manifest_entry_path(manifest_entry)
        if not file_path:
            continue
        session_id = str(manifest_entry.get("session_id") or "").strip()
        session_summary = {
            "session_id": session_id,
            "label": session_id,
            "source_file": os.path.basename(file_path),
            "started_at": None,
            "ended_at": None,
            "networks_count": 0,
            "points_count": 0,
            "session_type": str(manifest_entry.get("role") or "original"),
            "merged_from_session_ids": list(
                manifest_entry.get("merged_from_session_ids") or []
            ),
            "merged_at": _parse_float(manifest_entry.get("merged_at")),
        }
        session_macs = set()
        try:
            with open(
                file_path, "r", encoding="utf-8", errors="ignore", newline=""
            ) as f:
                first_line = f.readline()
                wardrive_device = _classify_wardrive_device(
                    source_file=os.path.basename(file_path),
                    wigle_header=first_line,
                )
                if first_line.lower().startswith("wiglewifi-"):
                    reader = csv.DictReader(f)
                else:
                    reader = csv.DictReader(itertools.chain([first_line], f))

                for row in reader:
                    if not row:
                        continue
                    normalized_row = {
                        (k.lstrip("\ufeff") if isinstance(k, str) else k): v
                        for k, v in row.items()
                    }

                    row_type = (
                        (normalized_row.get("Type") or normalized_row.get("type") or "")
                        .strip()
                        .upper()
                    )
                    if row_type != "WIFI":
                        continue

                    raw_mac = (
                        normalized_row.get("MAC")
                        or normalized_row.get("BSSID")
                        or normalized_row.get("mac")
                        or normalized_row.get("bssid")
                    )
                    mac = _normalize_mac(raw_mac)
                    if not mac:
                        continue

                    ssid = (
                        normalized_row.get("SSID") or normalized_row.get("ssid") or ""
                    ).strip()
                    lat = _parse_float(
                        normalized_row.get("CurrentLatitude")
                        or normalized_row.get("Latitude")
                        or normalized_row.get("lat")
                    )
                    lng = _parse_float(
                        normalized_row.get("CurrentLongitude")
                        or normalized_row.get("Longitude")
                        or normalized_row.get("lng")
                        or normalized_row.get("lon")
                    )
                    if lat is None or lng is None:
                        continue
                    if lat == 0 and lng == 0:
                        continue

                    source_acc = _parse_float(
                        normalized_row.get("AccuracyMeters")
                        or normalized_row.get("Accuracy")
                        or normalized_row.get("accuracy")
                    )
                    acc = _normalize_wardrive_accuracy(
                        mac,
                        source_acc,
                        source_file=os.path.basename(file_path),
                        wigle_header=first_line,
                    )

                    channel = _parse_float(
                        normalized_row.get("Channel") or normalized_row.get("channel")
                    )
                    if channel is not None:
                        channel = int(channel)

                    frequency = _parse_float(
                        normalized_row.get("Frequency")
                        or normalized_row.get("frequency")
                        or normalized_row.get("freq")
                    )
                    if frequency is not None:
                        frequency = int(frequency)

                    rssi = _parse_float(
                        normalized_row.get("RSSI")
                        or normalized_row.get("rssi")
                        or normalized_row.get("signal")
                    )

                    altitude = _parse_float(
                        normalized_row.get("AltitudeMeters")
                        or normalized_row.get("Altitude")
                        or normalized_row.get("altitude")
                    )

                    ts_first = _parse_wigle_timestamp(
                        normalized_row.get("FirstSeen")
                        or normalized_row.get("firstseen")
                        or normalized_row.get("FirstSeenUTC")
                    )

                    ts = _parse_wigle_timestamp(
                        normalized_row.get("LastSeen")
                        or normalized_row.get("lastseen")
                        or normalized_row.get("LastSeenUTC")
                    )
                    if ts is None:
                        ts = ts_first
                    if ts is None:
                        ts = os.path.getmtime(file_path)
                    if ts_first is None:
                        ts_first = ts

                    session_summary["points_count"] += 1
                    session_macs.add(mac)
                    if ts_first is not None:
                        if (
                            session_summary["started_at"] is None
                            or ts_first < session_summary["started_at"]
                        ):
                            session_summary["started_at"] = ts_first
                    if ts is not None:
                        if (
                            session_summary["ended_at"] is None
                            or ts > session_summary["ended_at"]
                        ):
                            session_summary["ended_at"] = ts

                    encryption = _infer_encryption(
                        normalized_row.get("AuthMode") or normalized_row.get("authmode")
                    )

                    wardrive_observation = {
                        "session_id": session_id,
                        "source_file": os.path.basename(file_path),
                        "device": wardrive_device,
                        "ssid": ssid,
                        "lat": lat,
                        "lng": lng,
                        "acc": acc,
                        "rawLatitude": lat,
                        "rawLongitude": lng,
                        "rawAccuracy": acc,
                        "sourceAccuracyMeters": source_acc,
                        "rawAltitude": altitude,
                        "displayLatitude": lat,
                        "displayLongitude": lng,
                        "displayAltitude": altitude,
                        "ts_last": ts,
                        "ts_first": ts_first,
                        "channel": channel,
                        "frequency": frequency,
                        "rssi": rssi,
                        "altitude": altitude,
                        "encryption": encryption,
                        "session_type": session_summary["session_type"],
                        "merged_from_session_ids": list(
                            session_summary["merged_from_session_ids"]
                        ),
                        "merged_at": session_summary["merged_at"],
                    }

                    entry_data = {
                        "mac": mac,
                        "ssid": ssid,
                        "lat": lat,
                        "lng": lng,
                        "acc": acc,
                        "ts_last": ts,
                        "ts_first": ts_first,
                        "encryption": encryption,
                        "channel": channel,
                        "frequency": frequency,
                        "rssi": rssi,
                        "altitude": altitude,
                        # Raw coordinates from CSV (preserved for audit trail)
                        "rawLatitude": lat,
                        "rawLongitude": lng,
                        "rawAccuracy": acc,
                        "sourceAccuracyMeters": source_acc,
                        "rawAltitude": altitude,
                        # Display coordinates (may be adjusted by spatial normalization)
                        "displayLatitude": lat,
                        "displayLongitude": lng,
                        "displayAltitude": altitude,
                        # Spatial normalization tracking
                        "sessionId": session_id,
                        "sessionSourceFile": os.path.basename(file_path),
                        "wardrive_sessions": [dict(wardrive_observation)],
                    }

                    existing = entries.get(mac)
                    if existing:
                        observations = list(existing.get("wardrive_sessions") or [])
                        _merge_wardrive_session_observation(
                            observations, wardrive_observation
                        )
                        if existing.get("ts_first") is not None and (
                            entry_data["ts_first"] is None
                            or existing["ts_first"] < entry_data["ts_first"]
                        ):
                            entry_data["ts_first"] = existing["ts_first"]
                        entry_data["wardrive_sessions"] = observations

                        if ts > existing["ts_last"]:
                            entries[mac] = entry_data
                        elif ts == existing["ts_last"] and acc < existing["acc"]:
                            entries[mac] = entry_data
                        else:
                            existing["wardrive_sessions"] = observations
                            if entry_data.get("ts_first") and (
                                not existing.get("ts_first")
                                or entry_data["ts_first"] < existing["ts_first"]
                            ):
                                existing["ts_first"] = entry_data["ts_first"]

                            for field in [
                                "channel",
                                "frequency",
                                "rssi",
                                "altitude",
                            ]:
                                if (
                                    existing.get(field) is None
                                    and entry_data.get(field) is not None
                                ):
                                    existing[field] = entry_data[field]

                            if (
                                not existing.get("encryption")
                                or str(existing.get("encryption")).upper() == "UNK"
                            ) and entry_data.get("encryption"):
                                existing["encryption"] = entry_data["encryption"]
                    else:
                        entries[mac] = entry_data
        except Exception as e:
            logger.warning(
                "Erro ao ler wardrive %s: %s", os.path.basename(file_path), e
            )
        session_summary["networks_count"] = len(session_macs)
        sessions_summary.append(session_summary)

    sessions_summary.sort(
        key=lambda item: (
            -(item.get("ended_at") or 0),
            str(item.get("session_id") or ""),
        )
    )
    _set_wardrive_sessions(sessions_summary)
    _set_wardrive_summary(files_count, len(entries), len(sessions_summary))
    return entries


def load_real_data():
    """
    Retorna os dados do cache. Se o cache estiver vazio, carrega do disco.
    """
    global _DATA_CACHE
    if _DATA_CACHE is None:
        logger.info("Cache vazio. Carregando dados do disco.")
        _DATA_CACHE = _load_from_disk()
    return _DATA_CACHE


def reload_data():
    """
    Força o recarregamento dos dados do disco e atualiza o cache.
    Deve ser chamado após Sync ou Cracking bem-sucedido.
    """
    global _DATA_CACHE
    logger.info("Invalidando cache e recarregando dados.")
    _DATA_CACHE = _load_from_disk()
    return _DATA_CACHE


def _load_gps_handshake_entries():
    return _load_gps_handshake_entries_helper(
        HANDSHAKES_DIR,
        load_details_for_base=_load_details_for_base,
        infer_encryption_from_details=_infer_encryption_from_details,
        extract_device_classification=_extract_device_classification,
        logger=logger,
    )


def _merge_no_gps_pcap_entries(data):
    return _merge_no_gps_pcap_entries_helper(
        data,
        HANDSHAKES_DIR,
        load_details_for_base=_load_details_for_base,
        infer_encryption_from_details=_infer_encryption_from_details,
        extract_device_classification=_extract_device_classification,
    )


def _merge_wardrive_entries(data, wardrive_entries):
    return _merge_wardrive_entries_helper(data, wardrive_entries)


def _finalize_loaded_data(data):
    return _finalize_loaded_data_helper(
        data,
        merge_raw_metadata=_merge_raw_metadata,
        normalize_network_positions=normalize_network_positions,
        apply_handshake_set_summaries=_apply_handshake_set_summaries,
    )


def _load_from_disk():
    """
    Lê os arquivos .gps.json, .geo.json e .paw-gps.json da pasta de dados
    e retorna um dicionário estruturado para o frontend.
    (Lógica original movida para cá)
    """
    global _DATA_REVISION
    _DATA_REVISION += 1

    data = {}

    if not os.path.exists(HANDSHAKES_DIR):
        return data

    data = _load_gps_handshake_entries()
    data = _merge_no_gps_pcap_entries(data)

    bruce_entries = _load_bruce_entries()
    _merge_external_handshake_entries(data, bruce_entries, "brucegotchi")

    m5evil_entries = _load_m5evil_entries()
    _merge_external_handshake_entries(data, m5evil_entries, "m5evil")

    wardrive_entries = _load_wardrive_entries()
    data = _merge_wardrive_entries(data, wardrive_entries)
    return _finalize_loaded_data(data)
