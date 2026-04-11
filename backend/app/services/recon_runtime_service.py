from __future__ import annotations

import hashlib
import json as _json
import os
import sys
import time
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any

from app.api.deps import mac_lookup
from app.core.config import HANDSHAKES_DIR
from app.core.job_manager import job_manager
from app.services.data_loader import get_data_revision
from app.services.packet_analysis_service import packet_analysis_service
from app.services.probe_service import probe_service

_KILL_CHAIN_STAGES = [
    "discovered",
    "captured",
    "fingerprinted",
    "hash_ready",
    "under_attack",
    "cracked",
]

_dir_listing_cache: tuple[float, frozenset[str], str] | None = None
_DIR_LISTING_TTL = 5.0

_hash_scan_cache: dict[str, tuple[float, dict]] = {}
_HASH_SCAN_TTL = 30.0

_artifact_signature_cache: tuple[float, str] | None = None
_ARTIFACT_SIGNATURE_TTL = 5.0

_recon_response_cache: dict[tuple[Any, ...], tuple[float, Any]] = {}
_RECON_RESPONSE_CACHE_LIMIT = 192
_RECON_RESPONSE_CACHE_TTL = {
    "kill_chain": 6.0,
    "kill_chain_summary": 6.0,
    "kill_chain_stage": 8.0,
    "vulnerability_matrix": 8.0,
    "target_detail": 10.0,
    "attack_effectiveness": 10.0,
    "temporal_intel": 15.0,
    "audit_report": 15.0,
    "device_fingerprints": 20.0,
    "colocation": 20.0,
    "relationship_graph": 12.0,
    "spectrum": 20.0,
    "signal_landscape": 20.0,
    "probe_derandom": 12.0,
    "probe_geocorrelation": 12.0,
}


def _current_handshakes_dir() -> str:
    recon_module = sys.modules.get("app.api.routers.recon")
    override = getattr(recon_module, "HANDSHAKES_DIR", None) if recon_module else None
    if isinstance(override, str) and override.strip():
        return override
    return HANDSHAKES_DIR


def _get_dir_listing() -> frozenset[str]:
    global _dir_listing_cache
    handshakes_dir = _current_handshakes_dir()
    now = time.time()
    if (
        _dir_listing_cache is not None
        and now - _dir_listing_cache[0] < _DIR_LISTING_TTL
        and _dir_listing_cache[2] == handshakes_dir
    ):
        return _dir_listing_cache[1]
    listing: frozenset[str] = (
        frozenset(os.listdir(handshakes_dir))
        if os.path.isdir(handshakes_dir)
        else frozenset()
    )
    _dir_listing_cache = (now, listing, handshakes_dir)
    return listing


def _clear_caches() -> None:
    global _dir_listing_cache, _artifact_signature_cache
    _dir_listing_cache = None
    _artifact_signature_cache = None
    _hash_scan_cache.clear()
    _recon_response_cache.clear()


def clear_recon_runtime_cache() -> None:
    _clear_caches()


def _cache_response(
    bucket: str,
    params: tuple[Any, ...],
    builder,
    *,
    data_revision: int | None = None,
    ttl: float | None = None,
    extra_signature: tuple[Any, ...] = (),
):
    effective_ttl = float(
        ttl if ttl is not None else _RECON_RESPONSE_CACHE_TTL.get(bucket, 10.0)
    )
    revision = int(data_revision if data_revision is not None else get_data_revision())
    cache_key = (bucket, revision, extra_signature, params)
    now = time.time()
    cached = _recon_response_cache.get(cache_key)
    if cached is not None and now - cached[0] < effective_ttl:
        return deepcopy(cached[1])

    payload = builder()
    _recon_response_cache[cache_key] = (now, deepcopy(payload))
    while len(_recon_response_cache) > _RECON_RESPONSE_CACHE_LIMIT:
        oldest = min(_recon_response_cache.items(), key=lambda item: item[1][0])[0]
        _recon_response_cache.pop(oldest, None)
    return deepcopy(payload)


def _cache_response_get(
    bucket: str,
    params: tuple[Any, ...],
    *,
    data_revision: int | None = None,
    ttl: float | None = None,
    extra_signature: tuple[Any, ...] = (),
):
    effective_ttl = float(
        ttl if ttl is not None else _RECON_RESPONSE_CACHE_TTL.get(bucket, 10.0)
    )
    revision = int(data_revision if data_revision is not None else get_data_revision())
    cache_key = (bucket, revision, extra_signature, params)
    cached = _recon_response_cache.get(cache_key)
    if cached is None or time.time() - cached[0] >= effective_ttl:
        return None
    return deepcopy(cached[1])


def _cache_response_set(
    bucket: str,
    params: tuple[Any, ...],
    payload: Any,
    *,
    data_revision: int | None = None,
    extra_signature: tuple[Any, ...] = (),
):
    revision = int(data_revision if data_revision is not None else get_data_revision())
    cache_key = (bucket, revision, extra_signature, params)
    _recon_response_cache[cache_key] = (time.time(), deepcopy(payload))
    while len(_recon_response_cache) > _RECON_RESPONSE_CACHE_LIMIT:
        oldest = min(_recon_response_cache.items(), key=lambda item: item[1][0])[0]
        _recon_response_cache.pop(oldest, None)
    return deepcopy(payload)


def _probe_cache_signature(status: dict[str, Any] | None) -> tuple[Any, ...]:
    if not isinstance(status, dict):
        return ("probe", "none")
    result = status.get("result")
    if not isinstance(result, dict):
        result = {}
    summary = result.get("summary")
    if not isinstance(summary, dict):
        summary = {}
    return (
        bool(status.get("cached")),
        bool(status.get("stale")),
        int(status.get("pcap_count") or 0),
        int(summary.get("total_probes") or 0),
        int(summary.get("unique_clients") or 0),
        int(summary.get("unique_ssids") or 0),
    )


def _deep_analysis_cache_signature(status: dict[str, Any] | None) -> tuple[Any, ...]:
    if not isinstance(status, dict):
        return ("deep", "none")
    result = status.get("result")
    if not isinstance(result, dict):
        result = {}
    summary = result.get("summary")
    if not isinstance(summary, dict):
        summary = {}
    return (
        bool(status.get("cached")),
        bool(status.get("stale")),
        int(status.get("pcap_count") or 0),
        int(summary.get("total_deauth") or 0),
        int(summary.get("total_disassoc") or 0),
        int(summary.get("targeted_bssids") or 0),
    )


def _recon_artifacts_signature() -> str:
    global _artifact_signature_cache
    handshakes_dir = _current_handshakes_dir()
    now = time.time()
    if (
        _artifact_signature_cache is not None
        and now - _artifact_signature_cache[0] < _ARTIFACT_SIGNATURE_TTL
    ):
        return _artifact_signature_cache[1]

    digest = hashlib.sha1()
    digest.update(handshakes_dir.encode("utf-8", errors="ignore"))
    for name in sorted(_get_dir_listing()):
        path = os.path.join(handshakes_dir, name)
        digest.update(name.encode("utf-8", errors="ignore"))
        try:
            st = os.stat(path)
            digest.update(str(int(st.st_mtime_ns)).encode("ascii"))
            digest.update(str(int(st.st_size)).encode("ascii"))
        except OSError:
            digest.update(b"missing")

    signature = digest.hexdigest()[:24]
    _artifact_signature_cache = (now, signature)
    return signature


def _build_recon_manifest_payload() -> dict[str, Any]:
    dataset_revision = int(get_data_revision())
    artifacts_signature = _recon_artifacts_signature()
    probe_status = probe_service.get_cache_status()
    deep_status = packet_analysis_service.get_cache_status()
    payload = {
        "dataset_revision": dataset_revision,
        "artifacts_signature": artifacts_signature,
        "probe_signature": _probe_cache_signature(probe_status),
        "deep_analysis_signature": _deep_analysis_cache_signature(deep_status),
    }
    raw_scope = _json.dumps(payload, sort_keys=True, separators=(",", ":"))
    payload["scope"] = hashlib.sha1(raw_scope.encode("utf-8")).hexdigest()[:24]
    payload["generated_at"] = datetime.now(timezone.utc).isoformat()
    return payload


def _build_kill_chain_network_entry(
    mac: str, net: dict[str, Any], *, hash_info: dict[str, Any]
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "mac": mac,
        "ssid": net.get("ssid") or "",
        "encryption": _net_encryption(net),
    }
    if hash_info["has_hash"]:
        entry["has_pmkid"] = hash_info["has_pmkid"]
        entry["has_eapol_hash"] = hash_info["has_eapol_hash"]
        entry["pmkid_count"] = hash_info["pmkid_count"]
        entry["eapol_count"] = hash_info["eapol_count"]
    return entry


def _scan_hash_files(mac_clean: str) -> dict:
    handshakes_dir = _current_handshakes_dir()
    cache_key = f"{handshakes_dir}:{mac_clean}"
    cached = _hash_scan_cache.get(cache_key)
    if cached is not None and time.time() - cached[0] < _HASH_SCAN_TTL:
        return cached[1]

    result = {
        "has_hash": False,
        "has_pmkid": False,
        "has_eapol_hash": False,
        "pmkid_count": 0,
        "eapol_count": 0,
        "total_lines": 0,
    }

    for name in _get_dir_listing():
        if mac_clean not in name.lower() or not name.endswith(".22000"):
            continue
        path = os.path.join(handshakes_dir, name)
        try:
            if os.path.getsize(path) == 0:
                continue
        except OSError:
            continue
        result["has_hash"] = True
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as file_handle:
                for line in file_handle:
                    stripped = line.strip()
                    if stripped.startswith("WPA*01*"):
                        result["pmkid_count"] += 1
                        result["has_pmkid"] = True
                    elif stripped.startswith("WPA*02*"):
                        result["eapol_count"] += 1
                        result["has_eapol_hash"] = True
                    if stripped.startswith("WPA*"):
                        result["total_lines"] += 1
        except Exception:
            pass

    _hash_scan_cache[cache_key] = (time.time(), result)
    return result


def _classify_network(
    mac: str, net: dict[str, Any], hash_info: dict[str, Any] | None = None
) -> str:
    if net.get("pass"):
        return "cracked"

    mac_clean = mac.replace(":", "").lower()
    running_jobs = job_manager.list_jobs()
    for job in running_jobs:
        if not isinstance(job, dict):
            continue
        if str(job.get("status") or "").lower() != "running":
            continue
        job_type = str(job.get("type") or "").lower()
        if job_type not in ("cracking", "aircrack"):
            continue
        cmd = job.get("command")
        cmd_text = (
            " ".join(str(part) for part in cmd)
            if isinstance(cmd, list)
            else str(cmd or "")
        )
        if mac_clean in cmd_text.lower():
            return "under_attack"

    if hash_info is None:
        hash_info = _scan_hash_files(mac_clean)
    if hash_info["has_hash"]:
        return "hash_ready"

    has_details = any(
        mac_clean in name.lower() and name.endswith(".details")
        for name in _get_dir_listing()
    )
    if has_details:
        return "fingerprinted"

    if net.get("handshake"):
        return "captured"

    return "discovered"


def _net_encryption(net: dict[str, Any]) -> str:
    return str(net.get("encryption") or "UNK").upper()


def _quick_score(
    mac: str, net: dict[str, Any], *, hash_info: dict[str, Any] | None = None
) -> dict[str, Any]:
    enc = _net_encryption(net)
    if enc == "OPEN":
        return {"score": 0, "readiness_status": "open", "readiness_score": 100}
    if net.get("pass"):
        return {
            "score": 0,
            "readiness_status": "already_cracked",
            "readiness_score": 100,
        }

    score = 35
    mac_clean = mac.replace(":", "").lower()
    if hash_info is None:
        hash_info = _scan_hash_files(mac_clean)

    has_valid_hash = hash_info["has_hash"]
    if has_valid_hash:
        score += 30
        if hash_info["has_pmkid"]:
            score += 5
    else:
        score -= 20

    if net.get("handshake"):
        score += 8

    raw_eapol = int(net.get("raw_eapol_count") or 0)
    raw_beacon = int(net.get("raw_beacon_count") or 0)
    if raw_eapol > 0:
        score += 12
    if raw_beacon > 0:
        score += 4

    score = max(0, min(100, score))

    if has_valid_hash:
        readiness_status = "ready"
        readiness_score = 80
    elif raw_eapol > 0:
        readiness_status = "weak_ready"
        readiness_score = 55
    elif raw_beacon > 0:
        readiness_status = "observed_only"
        readiness_score = 25
    else:
        readiness_status = "not_ready"
        readiness_score = 5

    return {
        "score": score,
        "readiness_status": readiness_status,
        "readiness_score": readiness_score,
    }


def _load_akm_labels(mac: str) -> list[str]:
    mac_clean = mac.replace(":", "").lower()
    handshakes_dir = _current_handshakes_dir()
    if not os.path.isdir(handshakes_dir):
        return []
    for name in os.listdir(handshakes_dir):
        if mac_clean in name.lower() and name.endswith(".details"):
            try:
                with open(
                    os.path.join(handshakes_dir, name), "r", encoding="utf-8"
                ) as file_handle:
                    details = _json.load(file_handle)
                return details.get("security", {}).get("akm", [])
            except Exception:
                return []
    return []


def _build_vuln_flags(
    mac: str,
    net: dict[str, Any],
    score_data: dict[str, Any],
    *,
    hash_info: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    flags: list[dict[str, Any]] = []
    enc = _net_encryption(net)

    if enc == "WPA3":
        flags.append(
            {
                "id": "wpa3",
                "label": "WPA3",
                "severity": "info",
                "description": "WPA3 (SAE) detected – harder to crack, PMKID may still work.",
            }
        )

    if enc == "WEP":
        flags.append(
            {
                "id": "wep",
                "label": "WEP",
                "severity": "critical",
                "description": "WEP encryption is trivially breakable.",
            }
        )

    raw_eapol = int(net.get("raw_eapol_count") or 0)
    if raw_eapol > 0 and score_data.get("readiness_status") != "ready":
        flags.append(
            {
                "id": "eapol_no_hash",
                "label": "EAPOL SEEN",
                "severity": "warning",
                "description": f"EAPOL frames observed ({raw_eapol}) but no valid .22000 hash yet. Convert pending.",
            }
        )

    capture_count = int(net.get("handshake_capture_count") or 0)
    if capture_count >= 3:
        flags.append(
            {
                "id": "multi_capture",
                "label": "MULTI-CAPTURE",
                "severity": "good",
                "description": f"{capture_count} captures available – higher cracking confidence.",
            }
        )

    mac_clean = mac.replace(":", "").lower()
    if hash_info is None:
        hash_info = _scan_hash_files(mac_clean)

    if hash_info["has_pmkid"]:
        flags.append(
            {
                "id": "pmkid",
                "label": "PMKID",
                "severity": "critical",
                "description": (
                    f"PMKID hash available ({hash_info['pmkid_count']} line"
                    f"{'s' if hash_info['pmkid_count'] != 1 else ''}) "
                    "– can be cracked without full handshake."
                ),
            }
        )

    if hash_info["has_eapol_hash"]:
        flags.append(
            {
                "id": "eapol_hash",
                "label": "EAPOL HASH",
                "severity": "good",
                "description": (
                    f"Full EAPOL handshake hash ({hash_info['eapol_count']} line"
                    f"{'s' if hash_info['eapol_count'] != 1 else ''}) "
                    "ready for cracking."
                ),
            }
        )

    ssid = str(net.get("ssid") or "").strip()
    weak_patterns = ["default", "admin", "linksys", "netgear", "tplink", "dlink"]
    if ssid and any(pattern in ssid.lower() for pattern in weak_patterns):
        flags.append(
            {
                "id": "weak_ssid",
                "label": "WEAK SSID",
                "severity": "warning",
                "description": f"SSID '{ssid}' matches a common default pattern – association attack may be effective.",
            }
        )

    if not ssid:
        flags.append(
            {
                "id": "hidden_ssid",
                "label": "HIDDEN",
                "severity": "info",
                "description": "SSID is hidden – targeting requires BSSID-based approach.",
            }
        )

    akm_labels = _load_akm_labels(mac)
    ft_labels = [akm for akm in akm_labels if akm.startswith("FT/")]
    if ft_labels:
        flags.append(
            {
                "id": "ft_enabled",
                "label": "802.11r FT",
                "severity": "info",
                "description": (
                    f"Fast Transition ({', '.join(ft_labels)}) – "
                    "over-the-air roaming may expose PMKID via FT key exchange."
                ),
            }
        )

    return flags, akm_labels


def _build_vulnerability_row(
    mac: str, net: dict[str, Any], *, hash_info: dict[str, Any] | None = None
) -> dict[str, Any]:
    mac_clean = mac.replace(":", "").lower()
    if hash_info is None:
        hash_info = _scan_hash_files(mac_clean)
    enc = _net_encryption(net)
    net_stage = _classify_network(mac, net, hash_info=hash_info)
    score_data = _quick_score(mac, net, hash_info=hash_info)
    flags, akm_labels = _build_vuln_flags(mac, net, score_data, hash_info=hash_info)
    return {
        "mac": mac,
        "ssid": net.get("ssid") or "",
        "encryption": enc,
        "stage": net_stage,
        "attack_score": score_data["score"],
        "readiness_status": score_data["readiness_status"],
        "readiness_score": score_data["readiness_score"],
        "sources": net.get("sources") or [],
        "device_type": net.get("device_type") or "unknown",
        "has_handshake": bool(net.get("handshake")),
        "raw_eapol": int(net.get("raw_eapol_count") or 0),
        "raw_beacon": int(net.get("raw_beacon_count") or 0),
        "has_password": bool(net.get("pass")),
        "has_pmkid": hash_info["has_pmkid"],
        "has_eapol_hash": hash_info["has_eapol_hash"],
        "pmkid_count": hash_info["pmkid_count"],
        "eapol_hash_count": hash_info["eapol_count"],
        "flags": flags,
        "akm": akm_labels,
        "lat": net.get("lat"),
        "lng": net.get("lng"),
    }


def _resolve_dataset_network(
    dataset: dict[str, Any], mac: str
) -> tuple[str, dict[str, Any]] | tuple[None, None]:
    normalized = str(mac or "").strip().replace("-", ":")
    if not normalized:
        return None, None
    candidates = [normalized, normalized.lower(), normalized.upper()]
    for candidate in candidates:
        net = dataset.get(candidate)
        if isinstance(net, dict):
            return candidate, net
    normalized_lower = normalized.lower()
    for candidate, net in dataset.items():
        if str(candidate or "").lower() == normalized_lower and isinstance(net, dict):
            return candidate, net
    return None, None


def _resolve_probe_vendor(mac_or_oui: str | None) -> str:
    normalized = str(mac_or_oui or "").strip().upper()
    if not normalized:
        return "Unknown"
    vendor = mac_lookup(normalized)
    vendor_text = str(vendor or "").strip()
    return vendor_text or "Unknown"
