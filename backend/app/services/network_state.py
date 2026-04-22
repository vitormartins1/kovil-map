from __future__ import annotations

from typing import Any

MIN_USABLE_PCAP_BYTES = 512


def is_open_encryption(encryption: str | None) -> bool:
    enc = str(encryption or "").strip().upper()
    return enc in {"OPEN", "WEP"}


def has_gps_fix(item: dict[str, Any]) -> bool:
    try:
        lat = float(item.get("lat"))
        lng = float(item.get("lng"))
    except (TypeError, ValueError):
        return False
    return not (lat == 0.0 and lng == 0.0)


def _safe_int(value: Any) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def classify_network_state(item: dict[str, Any]) -> dict[str, Any]:
    encryption = str(item.get("encryption") or "UNK").strip().upper()
    open_like = is_open_encryption(encryption)
    gps_backed = (
        has_gps_fix(item) and str(item.get("type") or "").strip().lower() != "no-gps"
    )

    usable_pcap_artifact = bool(item.get("usable_pcap_artifact"))
    usable_hash_artifact = bool(item.get("usable_hash_artifact"))
    cracked_artifact_present = bool(item.get("cracked_artifact_present"))
    partial_handshake_artifact = bool(item.get("partial_handshake_artifact"))
    raw_handshake_evidence = bool(item.get("raw_handshake_evidence"))
    has_partial_artifact_path = partial_handshake_artifact or raw_handshake_evidence
    has_usable_artifact_path = usable_pcap_artifact or usable_hash_artifact
    cracked = bool(item.get("pass")) or cracked_artifact_present

    if cracked:
        state = "cracked"
    elif open_like:
        state = "open"
    elif has_usable_artifact_path:
        state = "locked" if gps_backed else "no_gps_locked"
    elif has_partial_artifact_path:
        state = "not_ready"
    else:
        state = "gps_only" if gps_backed else "no_gps_only"

    return {
        "network_state": state,
        "locked": state == "locked",
        "cracked": state == "cracked",
        "gps_only": state == "gps_only",
        "no_gps_locked": state == "no_gps_locked",
        "not_ready": state == "not_ready",
        "attackable": state in {"locked", "no_gps_locked", "not_ready"},
        "has_usable_artifact_path": has_usable_artifact_path,
        "has_partial_artifact_path": has_partial_artifact_path,
        "usable_pcap_artifact": usable_pcap_artifact,
        "usable_hash_artifact": usable_hash_artifact,
        "cracked_artifact_present": cracked_artifact_present,
        "partial_handshake_artifact": partial_handshake_artifact,
        "raw_handshake_evidence": raw_handshake_evidence,
        "is_open_network": open_like,
    }


def handshake_artifact_flags(
    *,
    preferred_pcap_size: Any = 0,
    valid_hash_lines: Any = 0,
    details_count: Any = 0,
    cracked_count: Any = 0,
    pcap_count: Any = 0,
    raw_eapol_count: Any = 0,
    raw_pmkid_count: Any = 0,
) -> dict[str, bool]:
    pcap_size = _safe_int(preferred_pcap_size)
    hashes = _safe_int(valid_hash_lines)
    details = _safe_int(details_count)
    cracked = _safe_int(cracked_count)
    pcap = _safe_int(pcap_count)
    raw_eapol = _safe_int(raw_eapol_count)
    raw_pmkid = _safe_int(raw_pmkid_count)

    usable_pcap_artifact = pcap_size >= MIN_USABLE_PCAP_BYTES
    usable_hash_artifact = hashes > 0
    cracked_artifact_present = cracked > 0
    partial_handshake_artifact = (
        not usable_pcap_artifact
        and not usable_hash_artifact
        and (pcap > 0 or details > 0)
    )
    raw_handshake_evidence = raw_eapol > 0 or raw_pmkid > 0

    return {
        "usable_pcap_artifact": usable_pcap_artifact,
        "usable_hash_artifact": usable_hash_artifact,
        "cracked_artifact_present": cracked_artifact_present,
        "partial_handshake_artifact": partial_handshake_artifact,
        "raw_handshake_evidence": raw_handshake_evidence,
    }
