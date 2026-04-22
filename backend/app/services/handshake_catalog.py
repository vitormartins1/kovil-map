import glob
import hashlib
import json
import logging
import os
import re
from typing import Any

from app.core.config import (
    BRUCE_HANDSHAKES_DIR,
    BRUCE_PCAP_DIR,
    HANDSHAKES_DIR,
    M5EVIL_HANDSHAKES_DIR,
)
from app.utils.handshake_artifacts import (
    get_capture_artifact_path,
    get_source_sidecar_path,
    list_capture_artifacts,
    list_combined_candidates,
    read_json,
)

logger = logging.getLogger(__name__)

_HS_RE = re.compile(r"^HS_([0-9A-Fa-f]{12})")
_TRAILING_MAC_RE = re.compile(r"^(?P<ssid>.+?)_(?P<mac>[0-9A-Fa-f]{12})$")
_HIDDEN_SSID_VALUES = {"", "hidden", "hs"}
_IGNORED_EXTENSIONS = (".gps.json", ".geo.json", ".paw-gps.json")
_IGNORED_LEGACY_TOKEN = "__wdrs__raw_"

_SOURCE_DEVICE_LABELS = {
    "pwnagotchi": "Pwnagotchi",
    "brucegotchi": "Brucegotchi",
    "m5evil": "M5Evil",
}

_SOURCE_TIE_BREAK = {
    "pwnagotchi": 0,
    "brucegotchi": 1,
    "m5evil": 2,
}


def _get_scan_roots() -> tuple[dict[str, str], ...]:
    return (
        {
            "source": "pwnagotchi",
            "device_label": "Pwnagotchi",
            "role": "handshakes",
            "root": HANDSHAKES_DIR,
            "kind": "legacy",
        },
        {
            "source": "brucegotchi",
            "device_label": "Brucegotchi",
            "role": "bruce_handshakes",
            "root": BRUCE_HANDSHAKES_DIR,
            "kind": "prefixed",
        },
        {
            "source": "brucegotchi",
            "device_label": "Brucegotchi",
            "role": "bruce_pcap",
            "root": BRUCE_PCAP_DIR,
            "kind": "prefixed",
        },
        {
            "source": "m5evil",
            "device_label": "M5Evil",
            "role": "m5evil_handshakes",
            "root": M5EVIL_HANDSHAKES_DIR,
            "kind": "prefixed",
        },
    )


def normalize_mac(raw: str | None) -> str | None:
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", str(raw or ""))
    if len(cleaned) != 12:
        return None
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2)).upper()


def normalize_mac_token(raw: str | None) -> str | None:
    normalized = normalize_mac(raw)
    if not normalized:
        return None
    return normalized.replace(":", "").lower()


def _safe_stat(path: str) -> os.stat_result | None:
    try:
        return os.stat(path)
    except OSError:
        return None


def _safe_read_json(path: str) -> dict[str, Any] | None:
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        return payload if isinstance(payload, dict) else None
    except Exception:
        return None


def _infer_ssid_from_legacy_filename(filename: str) -> str:
    stem = os.path.basename(str(filename or "")).rsplit(".", 1)[0]
    match = _TRAILING_MAC_RE.match(stem)
    if not match:
        return ""
    return str(match.group("ssid") or "").strip()


def _extract_mac_and_ssid(filename: str, kind: str) -> tuple[str | None, str]:
    stem = os.path.basename(str(filename or "")).rsplit(".", 1)[0]
    if kind == "prefixed":
        match = _HS_RE.match(stem)
        if not match:
            return None, ""
        return normalize_mac(match.group(1)), ""

    match = _TRAILING_MAC_RE.match(stem)
    if not match:
        return None, ""
    return normalize_mac(match.group("mac")), str(match.group("ssid") or "").strip()


def _make_capture_id(source: str, role: str, filename: str) -> str:
    token = f"{source}|{role}|{os.path.basename(filename)}"
    digest = hashlib.sha1(token.encode("utf-8")).hexdigest()[:16]
    return f"{source}-{role}-{digest}"


def _classify_file_type(name: str) -> str:
    lower_name = str(name or "").lower()
    if lower_name.endswith(".pcap") or lower_name.endswith(".pcapng"):
        return "pcap"
    if lower_name.endswith(".details"):
        return "details"
    if lower_name.endswith(".22000"):
        return "22000"
    if lower_name.endswith(".cracked") or lower_name.endswith(".pcap.cracked"):
        return "cracked"
    if lower_name.endswith(".try"):
        return "try"
    return os.path.basename(name).split(".")[-1].lower()


def _should_ignore_handshake_list_file(name: str) -> bool:
    lower_name = str(name or "").lower()
    if not name or name.endswith(_IGNORED_EXTENSIONS):
        return True
    if lower_name.startswith("raw_") and lower_name.endswith(".22000"):
        return True
    if lower_name.endswith(".wdrs.json"):
        return True
    if _IGNORED_LEGACY_TOKEN in lower_name:
        return True
    return False


def _build_artifact_entry(
    *,
    path: str,
    role: str,
    capture_id: str,
    source: str,
    device_label: str,
    artifact_kind: str = "file",
    capture_source_path: str | None = None,
) -> dict[str, Any] | None:
    stat = _safe_stat(path)
    if not stat:
        return None
    if stat.st_size == 0 and str(path).lower().endswith(".22000"):
        return None

    name = os.path.basename(path)
    return {
        "name": name,
        "path": path,
        "size": int(stat.st_size),
        "modified": float(stat.st_mtime),
        "type": _classify_file_type(name),
        "source": source,
        "device_label": device_label,
        "capture_id": capture_id,
        "source_path_role": role,
        "artifact_kind": artifact_kind,
        "artifact_scope": "capture" if artifact_kind == "pcap" else "shared_legacy",
        "artifact_owner_capture_id": capture_id if artifact_kind == "pcap" else None,
        "capture_specific": artifact_kind == "pcap",
        "legacy_sidecar": artifact_kind != "pcap" and role == "handshakes",
        "shared_legacy": False,
        "capture_source_path": capture_source_path,
    }


def _find_related_legacy_artifacts(
    base_name: str, capture_id: str, source: str, device_label: str
) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    pattern = os.path.join(HANDSHAKES_DIR, f"{base_name}*")
    for path in glob.glob(pattern):
        name = os.path.basename(path)
        if _should_ignore_handshake_list_file(name):
            continue
        artifact = _build_artifact_entry(
            path=path,
            role="handshakes",
            capture_id=capture_id,
            source=source,
            device_label=device_label,
            artifact_kind="legacy",
        )
        if artifact:
            artifacts.append(artifact)
    return artifacts


def _count_valid_hash_lines(path: str) -> int:
    if not path or not os.path.exists(path):
        return 0
    valid = 0
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for raw_line in handle:
                line = str(raw_line or "").strip()
                if line.upper().startswith("WPA*"):
                    valid += 1
    except Exception:
        return 0
    return valid


def _details_richness(details: dict[str, Any] | None) -> tuple[int, list[str]]:
    if not isinstance(details, dict):
        return 0, []

    richness = 0
    reasons: list[str] = []
    security = details.get("security")
    classification = details.get("classification")
    radio = details.get("radio")
    wps = details.get("wps")
    vendor = str(details.get("vendor") or "").strip()

    if isinstance(security, dict) and security:
        richness += 4
        reasons.append("Security profile extracted")
    if isinstance(classification, dict) and classification.get("type"):
        richness += 3
        reasons.append("Device classification present")
    if isinstance(radio, dict) and any(
        radio.get(key) not in (None, "") for key in ("channel", "band", "frequency_mhz")
    ):
        richness += 2
        reasons.append("Radio telemetry present")
    if isinstance(wps, dict) and wps.get("present"):
        richness += 2
        reasons.append("WPS metadata present")
    if vendor:
        richness += 1
        reasons.append("Vendor identified")
    return richness, reasons


def _quality_tier(score: int) -> str:
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _is_hidden_ssid(value: str | None) -> bool:
    text = str(value or "").strip()
    if not text:
        return True
    lowered = text.lower()
    if lowered in _HIDDEN_SSID_VALUES:
        return True
    return lowered.startswith("hidden_") or lowered.startswith("hs_")


def _score_capture(capture: dict[str, Any]) -> dict[str, Any]:
    score = 0
    reasons: list[str] = []
    artifacts = capture.get("artifacts") or {}
    pcap = artifacts.get("pcap")
    hashes = artifacts.get("hash_22000") or []
    details_files = artifacts.get("details") or []
    cracked_files = artifacts.get("cracked") or []
    details_payload = capture.get("details_payload")

    pcap_size = int((pcap or {}).get("size") or 0)
    if pcap_size > 0:
        score += 8
        reasons.append("PCAP present")
    if pcap_size >= 512:
        score += 4
        reasons.append("PCAP has usable size")
    elif pcap_size and pcap_size < 128:
        score -= 8
        reasons.append("PCAP is very small")

    hash_valid_lines = 0
    freshest_hash_mtime = None
    invalid_hash_present = False
    for item in hashes:
        hash_valid_lines += int(item.get("valid_hash_lines") or 0)
        item_mtime = item.get("modified")
        if item_mtime is not None:
            freshest_hash_mtime = max(freshest_hash_mtime or item_mtime, item_mtime)
        if (
            int(item.get("size") or 0) <= 0
            or int(item.get("valid_hash_lines") or 0) <= 0
        ):
            invalid_hash_present = True

    if hash_valid_lines > 0:
        score += 36
        reasons.append(f"Valid .22000 available ({hash_valid_lines} line(s))")
    elif hashes:
        score -= 12
        reasons.append("Hash artifact is empty or invalid")

    if invalid_hash_present:
        score -= 6

    richness, richness_reasons = _details_richness(details_payload)
    if details_files and isinstance(details_payload, dict):
        score += 18
        reasons.append("Fingerprint details available")
        if richness:
            score += min(richness * 3, 12)
            reasons.extend(richness_reasons[:3])

    if cracked_files:
        score += 8
        reasons.append("Cracked credential artifact present")

    pcap_mtime = (pcap or {}).get("modified")
    if (
        pcap_mtime is not None
        and freshest_hash_mtime is not None
        and freshest_hash_mtime < pcap_mtime
    ):
        score -= 5
        reasons.append(".22000 older than source PCAP")

    freshest_details_mtime = None
    for item in details_files:
        item_mtime = item.get("modified")
        if item_mtime is not None:
            freshest_details_mtime = max(
                freshest_details_mtime or item_mtime, item_mtime
            )
    if (
        pcap_mtime is not None
        and freshest_details_mtime is not None
        and freshest_details_mtime < pcap_mtime
    ):
        score -= 3
        reasons.append("Details older than source PCAP")

    if _is_hidden_ssid(capture.get("resolved_ssid")):
        score -= 3
        reasons.append("SSID hidden or unresolved")

    if not hashes and not details_files:
        reasons.append("Only raw capture available")

    return {
        "score": int(score),
        "tier": _quality_tier(int(score)),
        "reasons": reasons,
        "valid_hash_lines": int(hash_valid_lines),
        "details_richness": int(richness),
    }


def _build_capture_record(
    *,
    source: str,
    device_label: str,
    role: str,
    root: str,
    filename: str,
    kind: str,
) -> dict[str, Any] | None:
    full_path = os.path.join(root, filename)
    stat = _safe_stat(full_path)
    if not stat or not os.path.isfile(full_path):
        return None

    mac, ssid_from_filename = _extract_mac_and_ssid(filename, kind)
    if not mac:
        return None

    capture_id = _make_capture_id(source, role, filename)
    base_name = os.path.basename(filename).rsplit(".", 1)[0]
    capture_artifacts = list_capture_artifacts(
        capture_id, handshakes_dir=HANDSHAKES_DIR, source_path=full_path
    )
    details_payload = read_json(
        get_source_sidecar_path(full_path, "details")
    ) or read_json(
        get_capture_artifact_path(capture_id, "details", handshakes_dir=HANDSHAKES_DIR)
    )
    resolved_ssid = ""
    if isinstance(details_payload, dict):
        resolved_ssid = str(details_payload.get("ssid") or "").strip()
    if not resolved_ssid:
        resolved_ssid = ssid_from_filename

    pcap_artifact = _build_artifact_entry(
        path=full_path,
        role=role,
        capture_id=capture_id,
        source=source,
        device_label=device_label,
        artifact_kind="pcap",
        capture_source_path=full_path,
    )
    if not pcap_artifact:
        return None

    artifacts_by_type: dict[str, Any] = {
        "pcap": pcap_artifact,
        "details": list(capture_artifacts.get("details") or []),
        "hash_22000": list(capture_artifacts.get("hash_22000") or []),
        "cracked": list(capture_artifacts.get("cracked") or []),
        "history": list(capture_artifacts.get("history") or []),
        "other": list(capture_artifacts.get("other") or []),
    }
    for item in artifacts_by_type["hash_22000"]:
        item["valid_hash_lines"] = _count_valid_hash_lines(item["path"])

    capture = {
        "capture_id": capture_id,
        "mac": mac,
        "source": source,
        "device_label": device_label,
        "source_filename": filename,
        "source_path": full_path,
        "source_path_role": role,
        "source_root": root,
        "basename": base_name,
        "ssid": ssid_from_filename,
        "resolved_ssid": resolved_ssid,
        "details_payload": details_payload,
        "artifacts": artifacts_by_type,
    }
    capture["quality"] = _score_capture(capture)
    return capture


def _scan_capture_candidates() -> list[dict[str, Any]]:
    captures: list[dict[str, Any]] = []
    seen_paths: set[str] = set()

    for descriptor in _get_scan_roots():
        root = descriptor["root"]
        if not root or not os.path.exists(root):
            continue
        try:
            filenames = sorted(os.listdir(root))
        except OSError:
            continue

        for filename in filenames:
            lower_name = filename.lower()
            if not (lower_name.endswith(".pcap") or lower_name.endswith(".pcapng")):
                continue
            full_path = os.path.join(root, filename)
            normalized_path = os.path.abspath(full_path)
            if normalized_path in seen_paths:
                continue
            seen_paths.add(normalized_path)

            from app.utils.pcap import validate_pcap_file

            valid, reason = validate_pcap_file(full_path)
            if not valid:
                logger.warning("Skipping invalid capture PCAP %s: %s", filename, reason)
                continue

            capture = _build_capture_record(
                source=descriptor["source"],
                device_label=descriptor["device_label"],
                role=descriptor["role"],
                root=root,
                filename=filename,
                kind=descriptor["kind"],
            )
            if capture:
                captures.append(capture)

    return captures


def _mark_shared_legacy_artifacts(captures: list[dict[str, Any]]) -> None:
    artifact_owners: dict[str, set[str]] = {}
    for capture in captures:
        for artifact_list in capture.get("artifacts", {}).values():
            items = (
                artifact_list if isinstance(artifact_list, list) else [artifact_list]
            )
            for artifact in items:
                if not isinstance(artifact, dict):
                    continue
                if not artifact.get("legacy_sidecar"):
                    continue
                artifact_owners.setdefault(artifact["path"], set()).add(
                    capture["capture_id"]
                )

    for capture in captures:
        for key, artifact_list in list((capture.get("artifacts") or {}).items()):
            items = (
                artifact_list if isinstance(artifact_list, list) else [artifact_list]
            )
            normalized_items = []
            for artifact in items:
                if not isinstance(artifact, dict):
                    continue
                artifact = dict(artifact)
                owners = artifact_owners.get(artifact["path"], set())
                artifact["shared_legacy"] = len(owners) > 1
                normalized_items.append(artifact)
            capture["artifacts"][key] = (
                normalized_items
                if isinstance(artifact_list, list)
                else (normalized_items[0] if normalized_items else None)
            )


def _flatten_capture_files(capture: dict[str, Any]) -> list[dict[str, Any]]:
    files: list[dict[str, Any]] = []
    artifacts = capture.get("artifacts") or {}
    pcap = artifacts.get("pcap")
    if isinstance(pcap, dict) and not _should_ignore_handshake_list_file(
        pcap.get("name", "")
    ):
        files.append(
            {
                "name": pcap["name"],
                "size": pcap["size"],
                "modified": pcap["modified"],
                "type": pcap["type"],
                "capture_id": capture["capture_id"],
                "source": capture["source"],
                "device_label": capture["device_label"],
                "source_path_role": capture["source_path_role"],
                "legacy_shared": False,
                "artifact_scope": str(pcap.get("artifact_scope") or "capture"),
                "artifact_owner_capture_id": pcap.get("artifact_owner_capture_id")
                or capture["capture_id"],
                "is_preferred": False,
            }
        )
    for key in ("details", "hash_22000", "cracked", "history", "other"):
        for artifact in artifacts.get(key) or []:
            if _should_ignore_handshake_list_file(artifact.get("name", "")):
                continue
            files.append(
                {
                    "name": artifact["name"],
                    "size": artifact["size"],
                    "modified": artifact["modified"],
                    "type": artifact["type"],
                    "capture_id": capture["capture_id"],
                    "source": capture["source"],
                    "device_label": capture["device_label"],
                    "source_path_role": capture["source_path_role"],
                    "legacy_shared": bool(artifact.get("shared_legacy")),
                    "artifact_scope": str(
                        artifact.get("artifact_scope")
                        or (
                            "shared_legacy"
                            if artifact.get("shared_legacy")
                            else "capture"
                        )
                    ),
                    "artifact_owner_capture_id": artifact.get(
                        "artifact_owner_capture_id"
                    )
                    or (
                        capture["capture_id"]
                        if not artifact.get("shared_legacy")
                        else None
                    ),
                    "is_preferred": False,
                }
            )
    return files


def _capture_sort_key(capture: dict[str, Any]) -> tuple[Any, ...]:
    quality = capture.get("quality") or {}
    source = str(capture.get("source") or "")
    pcap = (capture.get("artifacts") or {}).get("pcap") or {}
    return (
        -int(quality.get("score") or 0),
        _SOURCE_TIE_BREAK.get(source, 99),
        -int(quality.get("valid_hash_lines") or 0),
        -int((pcap or {}).get("size") or 0),
        str(capture.get("source_filename") or "").lower(),
    )


def _artifact_summary(captures: list[dict[str, Any]]) -> dict[str, int]:
    summary = {
        "captures": len(captures),
        "pcap": 0,
        "details": 0,
        "hash_22000": 0,
        "cracked": 0,
        "history": 0,
        "combined": 0,
    }
    for capture in captures:
        artifacts = capture.get("artifacts") or {}
        if artifacts.get("pcap"):
            summary["pcap"] += 1
        summary["details"] += len(artifacts.get("details") or [])
        summary["hash_22000"] += len(artifacts.get("hash_22000") or [])
        summary["cracked"] += len(artifacts.get("cracked") or [])
        summary["history"] += len(artifacts.get("history") or [])
    return summary


def _serialize_combined_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    hash_file = candidate.get("hash_file") or {}
    manifest = candidate.get("manifest") or {}
    included_capture_ids = [
        str(item)
        for item in (manifest.get("included_capture_ids") or [])
        if str(item or "").strip()
    ]
    included_captures = []
    for item in manifest.get("included_captures") or []:
        if not isinstance(item, dict):
            continue
        capture_id = str(item.get("capture_id") or "").strip()
        if not capture_id:
            continue
        included_captures.append(
            {
                "capture_id": capture_id,
                "source": item.get("source"),
                "device_label": item.get("device_label"),
                "source_filename": item.get("source_filename"),
                "source_kind": item.get("source_kind"),
                "valid_hash_lines": int(item.get("valid_hash_lines") or 0),
            }
        )
    return {
        "build_id": candidate.get("build_id"),
        "name": hash_file.get("name"),
        "size": hash_file.get("size"),
        "modified": hash_file.get("modified"),
        "type": hash_file.get("type") or "22000",
        "combined_build_id": candidate.get("build_id"),
        "artifact_scope": "combined",
        "artifact_owner_capture_id": None,
        "included_capture_ids": included_capture_ids,
        "included_capture_count": len(included_capture_ids),
        "included_captures": included_captures,
        "deduped_hash_count": int(manifest.get("deduped_hash_count") or 0),
        "cracked_present": bool(candidate.get("cracked_file")),
        "history_present": bool(candidate.get("history_file")),
    }


def build_handshake_catalog() -> dict[str, dict[str, Any]]:
    captures = _scan_capture_candidates()
    _mark_shared_legacy_artifacts(captures)

    sets: dict[str, dict[str, Any]] = {}
    for capture in captures:
        mac = capture["mac"]
        handshake_set = sets.setdefault(
            mac,
            {
                "handshake_set_id": normalize_mac_token(mac) or mac,
                "mac": mac,
                "resolved_ssid": "",
                "sources": [],
                "captures": [],
                "preferred_capture_id": None,
                "preferred_capture": None,
                "artifact_summary": {},
                "flat_files": [],
                "combined_candidates": [],
            },
        )
        handshake_set["captures"].append(capture)
        if capture["source"] not in handshake_set["sources"]:
            handshake_set["sources"].append(capture["source"])

    for handshake_set in sets.values():
        captures = sorted(handshake_set["captures"], key=_capture_sort_key)
        preferred = captures[0] if captures else None
        if preferred:
            handshake_set["preferred_capture_id"] = preferred["capture_id"]
            handshake_set["preferred_capture"] = preferred
        handshake_set["captures"] = captures
        handshake_set["artifact_summary"] = _artifact_summary(captures)

        resolved_ssid = ""
        for candidate in captures:
            maybe_ssid = str(candidate.get("resolved_ssid") or "").strip()
            if maybe_ssid and not _is_hidden_ssid(maybe_ssid):
                resolved_ssid = maybe_ssid
                break
        if not resolved_ssid and preferred:
            resolved_ssid = str(
                preferred.get("resolved_ssid") or preferred.get("ssid") or ""
            ).strip()
        handshake_set["resolved_ssid"] = resolved_ssid
        handshake_set["combined_candidates"] = [
            _serialize_combined_candidate(item)
            for item in list_combined_candidates(
                handshake_set.get("mac"), handshakes_dir=HANDSHAKES_DIR
            )
        ]
        handshake_set["artifact_summary"]["combined"] = len(
            handshake_set["combined_candidates"]
        )

        flat_files: list[dict[str, Any]] = []
        for capture in captures:
            entries = _flatten_capture_files(capture)
            for entry in entries:
                entry["is_preferred"] = bool(
                    preferred and entry["capture_id"] == preferred["capture_id"]
                )
            flat_files.extend(entries)
        flat_files.sort(
            key=lambda item: (
                -float(item.get("modified") or 0.0),
                str(item.get("name") or "").lower(),
                str(item.get("capture_id") or ""),
            )
        )
        handshake_set["flat_files"] = flat_files

    return sets


def get_handshake_set(mac: str | None) -> dict[str, Any] | None:
    normalized = normalize_mac(mac)
    if not normalized:
        return None
    return build_handshake_catalog().get(normalized)


def list_handshake_files(mac: str | None) -> list[dict[str, Any]]:
    handshake_set = get_handshake_set(mac)
    if not handshake_set:
        return []
    return [dict(item) for item in handshake_set.get("flat_files") or []]


def resolve_capture(capture_id: str | None) -> dict[str, Any] | None:
    capture_key = str(capture_id or "").strip()
    if not capture_key:
        return None
    catalog = build_handshake_catalog()
    for handshake_set in catalog.values():
        for capture in handshake_set.get("captures") or []:
            if capture.get("capture_id") == capture_key:
                return capture
    return None


def resolve_capture_pcap(capture_id: str | None) -> dict[str, Any] | None:
    capture = resolve_capture(capture_id)
    if not capture:
        return None
    pcap = (capture.get("artifacts") or {}).get("pcap") or {}
    path = pcap.get("path")
    if not path or not os.path.exists(path):
        return None
    return {
        "capture_id": capture.get("capture_id"),
        "filename": capture.get("source_filename"),
        "path": path,
        "source": capture.get("source"),
        "device_label": capture.get("device_label"),
        "source_path_role": capture.get("source_path_role"),
        "basename": capture.get("basename"),
        "mac": capture.get("mac"),
    }


def summarize_handshake_set_for_network(mac: str | None) -> dict[str, Any] | None:
    handshake_set = get_handshake_set(mac)
    if not handshake_set:
        return None
    preferred = handshake_set.get("preferred_capture") or {}
    return {
        "handshake_set_id": handshake_set.get("handshake_set_id"),
        "handshake_capture_count": len(handshake_set.get("captures") or []),
        "preferred_handshake_capture_id": handshake_set.get("preferred_capture_id"),
        "preferred_handshake_filename": preferred.get("source_filename"),
        "preferred_handshake_source": preferred.get("source"),
        "preferred_handshake_quality": (preferred.get("quality") or {}).get("score"),
        "handshake_artifact_summary": dict(handshake_set.get("artifact_summary") or {}),
        "handshake_files": sorted(
            {
                item.get("name")
                for item in handshake_set.get("flat_files") or []
                if item.get("name")
            }
        ),
        "sources": list(handshake_set.get("sources") or []),
        "resolved_ssid": handshake_set.get("resolved_ssid") or "",
    }
