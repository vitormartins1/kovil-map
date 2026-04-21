import hashlib
import json
import os
from typing import Any

from app.core.config import HANDSHAKES_DIR

CAPTURE_ARTIFACT_FILENAMES = {
    "details": "capture.details",
    "22000": "capture.22000",
    "history": "capture.try",
    "cracked": "capture.cracked",
    "manifest": "manifest.json",
}

CAPTURE_ARTIFACT_EXTENSIONS = {
    "details": ".details",
    "22000": ".22000",
    "history": ".try",
    "cracked": ".cracked",
    "pcap_cracked": ".pcap.cracked",
    "key": ".key",
}

COMBINED_ARTIFACT_FILENAMES = {
    "22000": "combined.22000",
    "history": "combined.try",
    "cracked": "combined.cracked",
    "manifest": "manifest.json",
}


def _safe_segment(value: str | None, fallback: str = "unknown") -> str:
    text = "".join(
        ch if ch.isalnum() or ch in {"-", "_", "."} else "_"
        for ch in str(value or "").strip()
    ).strip("._")
    return text or fallback


def _normalize_mac_token(mac: str | None) -> str:
    cleaned = "".join(ch for ch in str(mac or "") if ch.isalnum()).lower()
    return cleaned or "unknown"


def get_capture_root(handshakes_dir: str = HANDSHAKES_DIR, ensure: bool = False) -> str:
    root = os.path.join(handshakes_dir, "captures")
    if ensure:
        os.makedirs(root, exist_ok=True)
    return root


def get_capture_dir(
    capture_id: str | None, handshakes_dir: str = HANDSHAKES_DIR, ensure: bool = False
) -> str | None:
    capture_key = _safe_segment(capture_id, fallback="")
    if not capture_key:
        return None
    path = os.path.join(get_capture_root(handshakes_dir, ensure=ensure), capture_key)
    if ensure:
        os.makedirs(path, exist_ok=True)
    return path


def get_capture_artifact_path(
    capture_id: str | None,
    artifact_type: str,
    handshakes_dir: str = HANDSHAKES_DIR,
    ensure_parent: bool = False,
) -> str | None:
    filename = CAPTURE_ARTIFACT_FILENAMES.get(str(artifact_type or "").strip().lower())
    if not filename:
        return None
    capture_dir = get_capture_dir(
        capture_id, handshakes_dir=handshakes_dir, ensure=ensure_parent
    )
    if not capture_dir:
        return None
    return os.path.join(capture_dir, filename)


def _strip_capture_extension(filename: str | None) -> str:
    name = os.path.basename(str(filename or "").strip())
    lower_name = name.lower()
    for ext in (
        ".pcapng",
        ".pcap",
        ".22000",
        ".pcap.cracked",
        ".cracked",
        ".details",
        ".try",
    ):
        if lower_name.endswith(ext):
            return name[: -len(ext)]
    return os.path.splitext(name)[0]


def get_capture_artifact_filename(
    source_filename: str | None,
    artifact_type: str,
    *,
    pcap_cracked: bool = False,
) -> str | None:
    base_name = _strip_capture_extension(source_filename)
    if not base_name:
        return None
    normalized_type = str(artifact_type or "").strip().lower()
    if normalized_type == "cracked" and pcap_cracked:
        normalized_type = "pcap_cracked"
    extension = CAPTURE_ARTIFACT_EXTENSIONS.get(normalized_type)
    if not extension:
        return None
    return f"{base_name}{extension}"


def get_source_sidecar_path(
    source_path: str | None,
    artifact_type: str,
    *,
    ensure_parent: bool = False,
    pcap_cracked: bool = False,
) -> str | None:
    if not source_path:
        return None
    filename = get_capture_artifact_filename(
        os.path.basename(str(source_path)),
        artifact_type,
        pcap_cracked=pcap_cracked,
    )
    if not filename:
        return None
    parent = os.path.dirname(str(source_path))
    if ensure_parent and parent:
        os.makedirs(parent, exist_ok=True)
    return os.path.join(parent, filename)


def get_capture_source_artifact_path(
    capture_id: str | None,
    artifact_type: str,
    handshakes_dir: str = HANDSHAKES_DIR,
    ensure_parent: bool = False,
    pcap_cracked: bool = False,
) -> str | None:
    capture_key = str(capture_id or "").strip()
    if not capture_key:
        return None
    try:
        from app.services.handshake_catalog import resolve_capture_pcap

        capture = resolve_capture_pcap(capture_key)
    except Exception:
        capture = None
    source_path = capture.get("path") if isinstance(capture, dict) else None
    if source_path:
        return get_source_sidecar_path(
            source_path,
            artifact_type,
            ensure_parent=ensure_parent,
            pcap_cracked=pcap_cracked,
        )
    return get_capture_artifact_path(
        capture_key,
        artifact_type,
        handshakes_dir=handshakes_dir,
        ensure_parent=ensure_parent,
    )


def get_combined_root(
    handshakes_dir: str = HANDSHAKES_DIR, ensure: bool = False
) -> str:
    root = os.path.join(handshakes_dir, "combined")
    if ensure:
        os.makedirs(root, exist_ok=True)
    return root


def get_combined_mac_dir(
    mac: str | None, handshakes_dir: str = HANDSHAKES_DIR, ensure: bool = False
) -> str | None:
    mac_token = _normalize_mac_token(mac)
    if not mac_token or mac_token == "unknown":
        return None

    path = os.path.join(
        get_combined_root(handshakes_dir, ensure=ensure),
        mac_token,
    )
    if ensure:
        os.makedirs(path, exist_ok=True)
    return path


def create_combined_build_id(capture_ids: list[str]) -> str:
    joined = "|".join(sorted(_safe_segment(item) for item in capture_ids if item))
    digest = hashlib.sha1(joined.encode("utf-8")).hexdigest()[:12]
    return f"build-{digest}"


def get_combined_build_dir(
    mac: str | None,
    build_id: str | None,
    handshakes_dir: str = HANDSHAKES_DIR,
    ensure: bool = False,
) -> str | None:
    build_key = _safe_segment(build_id, fallback="")
    if not build_key:
        return None
    mac_dir = get_combined_mac_dir(mac, handshakes_dir=handshakes_dir, ensure=ensure)
    if not mac_dir:
        return None
    path = os.path.join(
        mac_dir,
        build_key,
    )
    if ensure:
        os.makedirs(path, exist_ok=True)
    return path


def get_combined_artifact_path(
    mac: str | None,
    build_id: str | None,
    artifact_type: str,
    handshakes_dir: str = HANDSHAKES_DIR,
    ensure_parent: bool = False,
) -> str | None:
    filename = COMBINED_ARTIFACT_FILENAMES.get(str(artifact_type or "").strip().lower())
    if not filename:
        return None
    build_dir = get_combined_build_dir(
        mac, build_id, handshakes_dir=handshakes_dir, ensure=ensure_parent
    )
    if not build_dir:
        return None
    return os.path.join(build_dir, filename)


def _safe_stat(path: str) -> os.stat_result | None:
    try:
        return os.stat(path)
    except OSError:
        return None


def build_artifact_entry(
    *,
    path: str,
    name: str | None,
    artifact_type: str,
    artifact_scope: str,
    capture_id: str | None = None,
    combined_build_id: str | None = None,
) -> dict[str, Any] | None:
    stat = _safe_stat(path)
    if not stat or not os.path.exists(path):
        return None
    return {
        "name": str(name or os.path.basename(path)),
        "path": path,
        "size": int(stat.st_size),
        "modified": float(stat.st_mtime),
        "type": str(artifact_type or ""),
        "artifact_scope": str(artifact_scope or "shared_legacy"),
        "artifact_owner_capture_id": str(capture_id or "") or None,
        "combined_build_id": str(combined_build_id or "") or None,
        "capture_specific": artifact_scope == "capture",
        "legacy_sidecar": artifact_scope == "shared_legacy",
        "shared_legacy": artifact_scope == "shared_legacy",
    }


def list_capture_artifacts(
    capture_id: str | None,
    handshakes_dir: str = HANDSHAKES_DIR,
    source_path: str | None = None,
) -> dict[str, Any]:
    capture_dir = get_capture_dir(capture_id, handshakes_dir=handshakes_dir)
    manifest = read_json(
        get_capture_artifact_path(capture_id, "manifest", handshakes_dir)
    )
    artifacts = {
        "pcap": None,
        "details": [],
        "hash_22000": [],
        "cracked": [],
        "history": [],
        "other": [],
        "manifest": manifest,
    }
    source_specs = (
        ("details", "details", get_source_sidecar_path(source_path, "details")),
        ("hash_22000", "22000", get_source_sidecar_path(source_path, "22000")),
        ("cracked", "cracked", get_source_sidecar_path(source_path, "cracked")),
        (
            "cracked",
            "cracked",
            get_source_sidecar_path(source_path, "cracked", pcap_cracked=True),
        ),
        ("history", "try", get_source_sidecar_path(source_path, "history")),
    )
    seen_paths: set[str] = set()
    for target_group, artifact_type, path in source_specs:
        if not path or not os.path.exists(path):
            continue
        artifact = build_artifact_entry(
            path=path,
            name=os.path.basename(path),
            artifact_type=artifact_type,
            artifact_scope="capture",
            capture_id=capture_id,
        )
        if artifact:
            artifacts[target_group].append(artifact)
            seen_paths.add(os.path.abspath(path))

    if not capture_dir or not os.path.isdir(capture_dir):
        return artifacts

    mapping = {
        CAPTURE_ARTIFACT_FILENAMES["details"]: (
            "details",
            "details",
            get_capture_artifact_filename(source_path, "details"),
        ),
        CAPTURE_ARTIFACT_FILENAMES["22000"]: (
            "hash_22000",
            "22000",
            get_capture_artifact_filename(source_path, "22000"),
        ),
        CAPTURE_ARTIFACT_FILENAMES["cracked"]: (
            "cracked",
            "cracked",
            get_capture_artifact_filename(source_path, "cracked"),
        ),
        CAPTURE_ARTIFACT_FILENAMES["history"]: (
            "history",
            "try",
            get_capture_artifact_filename(source_path, "history"),
        ),
    }
    for name in sorted(os.listdir(capture_dir)):
        if name == CAPTURE_ARTIFACT_FILENAMES["manifest"]:
            continue
        full_path = os.path.join(capture_dir, name)
        if os.path.abspath(full_path) in seen_paths:
            continue
        target_group, artifact_type, display_name = mapping.get(
            name, ("other", name.split(".")[-1], name)
        )
        if any(
            item.get("type") == artifact_type and item.get("name") == display_name
            for item in artifacts.get(target_group, [])
        ):
            continue
        artifact = build_artifact_entry(
            path=full_path,
            name=display_name or name,
            artifact_type=artifact_type,
            artifact_scope="capture",
            capture_id=capture_id,
        )
        if artifact:
            artifacts[target_group].append(artifact)
    return artifacts


def list_combined_candidates(
    mac: str | None, handshakes_dir: str = HANDSHAKES_DIR
) -> list[dict[str, Any]]:
    mac_dir = get_combined_mac_dir(mac, handshakes_dir=handshakes_dir)
    if not mac_dir or not os.path.isdir(mac_dir):
        return []

    candidates: list[dict[str, Any]] = []

    try:
        items = os.listdir(mac_dir)
    except OSError:
        return []

    for build_id in sorted(items):
        build_dir = os.path.join(mac_dir, build_id)
        if not os.path.isdir(build_dir):
            continue
        hash_path = get_combined_artifact_path(
            mac, build_id, "22000", handshakes_dir=handshakes_dir
        )
        manifest_path = get_combined_artifact_path(
            mac, build_id, "manifest", handshakes_dir=handshakes_dir
        )
        hash_artifact = (
            build_artifact_entry(
                path=hash_path,
                name=os.path.basename(hash_path),
                artifact_type="22000",
                artifact_scope="combined",
                combined_build_id=build_id,
            )
            if hash_path
            else None
        )
        if not hash_artifact:
            continue
        history_artifact = build_artifact_entry(
            path=get_combined_artifact_path(
                mac, build_id, "history", handshakes_dir=handshakes_dir
            ),
            name=COMBINED_ARTIFACT_FILENAMES["history"],
            artifact_type="try",
            artifact_scope="combined",
            combined_build_id=build_id,
        )
        cracked_artifact = build_artifact_entry(
            path=get_combined_artifact_path(
                mac, build_id, "cracked", handshakes_dir=handshakes_dir
            ),
            name=COMBINED_ARTIFACT_FILENAMES["cracked"],
            artifact_type="cracked",
            artifact_scope="combined",
            combined_build_id=build_id,
        )
        manifest = read_json(manifest_path)
        candidates.append(
            {
                "build_id": build_id,
                "mac": _normalize_mac_token(mac),
                "hash_file": hash_artifact,
                "history_file": history_artifact,
                "cracked_file": cracked_artifact,
                "manifest": manifest if isinstance(manifest, dict) else {},
            }
        )
    candidates.sort(
        key=lambda item: -float((item.get("hash_file") or {}).get("modified") or 0.0)
    )
    return candidates


def resolve_artifact_path(
    filename: str | None,
    *,
    handshakes_dir: str = HANDSHAKES_DIR,
    capture_id: str | None = None,
    combined_build_id: str | None = None,
    mac: str | None = None,
) -> str | None:
    name = os.path.basename(str(filename or "").strip())
    if not name:
        return None

    if capture_id:
        try:
            from app.services.handshake_catalog import resolve_capture_pcap

            capture = resolve_capture_pcap(capture_id)
        except Exception:
            capture = None
        source_path = capture.get("path") if isinstance(capture, dict) else None
        if source_path:
            source_candidate = os.path.join(os.path.dirname(source_path), name)
            if os.path.exists(source_candidate):
                return source_candidate

        capture_dir = get_capture_dir(capture_id, handshakes_dir=handshakes_dir)
        if capture_dir:
            candidate = os.path.join(capture_dir, name)
            if os.path.exists(candidate):
                return candidate

    if combined_build_id:
        if mac:
            build_dir = get_combined_build_dir(
                mac, combined_build_id, handshakes_dir=handshakes_dir
            )
            if build_dir:
                candidate = os.path.join(build_dir, name)
                if os.path.exists(candidate):
                    return candidate
        combined_root = get_combined_root(handshakes_dir=handshakes_dir)
        if os.path.isdir(combined_root):
            for mac_token in os.listdir(combined_root):
                build_dir = os.path.join(
                    combined_root, mac_token, _safe_segment(combined_build_id)
                )
                candidate = os.path.join(build_dir, name)
                if os.path.exists(candidate):
                    return candidate

    legacy_candidate = os.path.join(handshakes_dir, name)
    if os.path.exists(legacy_candidate):
        return legacy_candidate
    return None


def read_json(path: str | None) -> dict[str, Any] | None:
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return payload if isinstance(payload, dict) else None
    except Exception:
        return None


def write_json(path: str | None, payload: dict[str, Any]) -> str | None:
    if not path:
        return None
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
    return path
