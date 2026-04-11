import glob
import hashlib
import os
import re
import time
from datetime import datetime, timezone


def _wardrive_session_tags_path(wardrive_dir):
    return os.path.join(wardrive_dir, "session_tags.json")


def _wardrive_manifest_path(wardrive_dir):
    return os.path.join(wardrive_dir, "manifest.json")


def _wardrive_merged_dir(wardrive_dir, merged_dir_name):
    return os.path.join(wardrive_dir, merged_dir_name)


def _default_wardrive_manifest(manifest_version):
    return {
        "version": manifest_version,
        "files": [],
    }


def _normalize_string_list(values):
    normalized = []
    for raw_value in values or []:
        value = str(raw_value or "").strip()
        if value and value not in normalized:
            normalized.append(value)
    return normalized


def _normalize_wardrive_manifest_entry(raw_entry, *, parse_float):
    if not isinstance(raw_entry, dict):
        return None

    session_id = str(raw_entry.get("session_id") or "").strip()
    filename = str(raw_entry.get("filename") or "").strip()
    relative_path = str(raw_entry.get("relative_path") or "").strip()
    if not session_id or not filename or not relative_path:
        return None

    role = str(raw_entry.get("role") or "original").strip().lower()
    if role not in {"original", "merged"}:
        role = "original"

    status = str(raw_entry.get("status") or "active").strip().lower()
    if status not in {"active", "ignored"}:
        status = "active"

    entry = {
        "session_id": session_id,
        "filename": filename,
        "relative_path": relative_path.replace("\\", "/"),
        "sha256": str(raw_entry.get("sha256") or "").strip().lower(),
        "role": role,
        "status": status,
        "imported_at": parse_float(raw_entry.get("imported_at")) or time.time(),
        "merged_at": parse_float(raw_entry.get("merged_at")),
        "merged_from_session_ids": _normalize_string_list(
            raw_entry.get("merged_from_session_ids")
        ),
        "source_leaf_session_ids": _normalize_string_list(
            raw_entry.get("source_leaf_session_ids")
        ),
        "source_hashes": _normalize_string_list(raw_entry.get("source_hashes")),
        "duplicate_of_session_id": str(
            raw_entry.get("duplicate_of_session_id") or ""
        ).strip()
        or None,
    }
    if not entry["source_leaf_session_ids"]:
        entry["source_leaf_session_ids"] = [session_id]
    if entry["sha256"] and entry["sha256"] not in entry["source_hashes"]:
        entry["source_hashes"].insert(0, entry["sha256"])
    return entry


def _wardrive_relative_path(file_path, wardrive_dir):
    try:
        rel_path = os.path.relpath(file_path, wardrive_dir)
    except Exception:
        rel_path = os.path.basename(file_path)
    return str(rel_path).replace("\\", "/")


def _resolve_wardrive_manifest_entry_path(entry, wardrive_dir):
    relative_path = str(entry.get("relative_path") or "").strip()
    if not relative_path:
        return None
    return os.path.join(wardrive_dir, relative_path)


def _discover_wardrive_csv_files(wardrive_dir, merged_dir_name):
    if not os.path.isdir(wardrive_dir):
        return []

    files = []
    seen = set()
    patterns = [
        os.path.join(wardrive_dir, "*.csv"),
        os.path.join(_wardrive_merged_dir(wardrive_dir, merged_dir_name), "*.csv"),
    ]
    for pattern in patterns:
        for path in sorted(glob.glob(pattern)):
            if not os.path.isfile(path):
                continue
            normalized = os.path.normpath(path)
            if normalized in seen:
                continue
            seen.add(normalized)
            files.append(path)
    return files


def _compute_wardrive_file_sha256(file_path):
    digest = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(131072), b""):
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _build_wardrive_manifest_indexes(entries, *, normalize_entry):
    by_rel_path = {}
    by_session_id = {}
    by_hash = {}

    for entry in entries or []:
        normalized = normalize_entry(entry)
        if normalized is None:
            continue
        by_rel_path[normalized["relative_path"]] = normalized
        by_session_id[normalized["session_id"]] = normalized
        for hash_value in [normalized.get("sha256")] + list(
            normalized.get("source_hashes") or []
        ):
            digest = str(hash_value or "").strip().lower()
            if digest and digest not in by_hash:
                by_hash[digest] = normalized

    return by_rel_path, by_session_id, by_hash


def _build_unique_wardrive_session_id(base_name, existing_ids):
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", str(base_name or "").strip()).strip("-_")
    if not slug:
        slug = "wardrive"
    candidate = slug
    counter = 2
    while candidate in existing_ids:
        candidate = f"{slug}-{counter}"
        counter += 1
    return candidate


def _make_wardrive_manifest_entry(normalize_entry, **kwargs):
    return normalize_entry(
        {
            "session_id": kwargs.get("session_id"),
            "filename": kwargs.get("filename"),
            "relative_path": kwargs.get("relative_path"),
            "sha256": kwargs.get("sha256"),
            "role": kwargs.get("role"),
            "status": kwargs.get("status"),
            "imported_at": (
                kwargs.get("imported_at")
                if kwargs.get("imported_at") is not None
                else time.time()
            ),
            "merged_at": kwargs.get("merged_at"),
            "merged_from_session_ids": list(
                kwargs.get("merged_from_session_ids") or []
            ),
            "source_leaf_session_ids": list(
                kwargs.get("source_leaf_session_ids") or []
            ),
            "source_hashes": list(kwargs.get("source_hashes") or []),
            "duplicate_of_session_id": kwargs.get("duplicate_of_session_id"),
        }
    )


def _read_wardrive_csv_merge_sections(file_path):
    with open(file_path, "r", encoding="utf-8", errors="ignore", newline="") as f:
        lines = f.readlines()

    wigle_header = None
    columns_header = None
    data_start_idx = None

    for idx, line in enumerate(lines):
        normalized = str(line).lstrip("\ufeff")
        stripped = normalized.strip()
        if idx == 0 and stripped.lower().startswith("wiglewifi-"):
            wigle_header = line if line.endswith("\n") else f"{line}\n"
            continue
        if stripped:
            columns_header = line if line.endswith("\n") else f"{line}\n"
            data_start_idx = idx + 1
            break

    if columns_header is None:
        raise ValueError(f"Invalid wardrive CSV header: {os.path.basename(file_path)}")

    data_lines = [
        line if line.endswith("\n") else f"{line}\n" for line in lines[data_start_idx:]
    ]
    return wigle_header, columns_header, data_lines


def _build_wardrive_merged_session_id(existing_ids):
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return _build_unique_wardrive_session_id(f"merged-{timestamp}", existing_ids)
