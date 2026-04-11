"""Probe Request Intelligence router.

Exposes endpoints for analysing probe request frames extracted from
PCAP files via tshark.  Feeds the SIGINT tab in the Recon Center.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any

from fastapi import APIRouter, Query

from app.api.deps import mac_lookup
from app.services.probe_service import probe_service
from app.services.data_loader import load_real_data
from app.jobs.recon_jobs import start_probe_intel_job
from app.utils.responses import fail, ok

router = APIRouter()

_UUID_LIKE_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_HEX_LIKE_RE = re.compile(r"^(?:0x)?[0-9a-f]{8,}$", re.IGNORECASE)
_GENERATED_PREFIXES = (
    "direct-",
    "androidap",
    "iphone",
    "ipad",
    "galaxy",
    "pixel",
    "moto",
    "redmi",
    "oppo",
    "vivo",
    "huawei",
    "honor",
    "tplink",
    "tp-link",
    "linksys",
    "netgear",
    "dlink",
    "hp-",
    "epson",
    "canon",
    "printer",
    "wifi-",
    "wlan_",
    "ssid-",
    "ap_",
)


def _probe_net_encryption(net: dict[str, Any]) -> str:
    enc = str(net.get("encryption") or net.get("security") or "").strip().upper()
    if not enc:
        return "UNKNOWN"
    if "WPA3" in enc:
        return "WPA3"
    if "WPA2" in enc:
        return "WPA2"
    if "WEP" in enc:
        return "WEP"
    if enc == "OPEN" or "OPEN" in enc:
        return "OPEN"
    if "WPA" in enc:
        return "WPA"
    return enc


def _normalize_device_type(device_type: Any) -> str:
    value = str(device_type or "unknown").strip().lower()
    return value or "unknown"


def _classify_ssid_shape(ssid: str) -> str:
    raw = str(ssid or "").strip()
    if not raw:
        return "human"
    if _UUID_LIKE_RE.fullmatch(raw):
        return "uuid_like"
    if _HEX_LIKE_RE.fullmatch(raw):
        return "hex_like"

    lowered = raw.lower()
    hex_suffix = bool(re.search(r"[-_][0-9a-f]{4,}$", lowered))
    numeric_suffix = bool(re.search(r"[-_][0-9]{4,}$", lowered))
    has_compact_suffix = bool(re.search(r"[a-z][0-9]{4,}$", lowered))
    if (
        lowered.startswith(_GENERATED_PREFIXES)
        or (len(raw) >= 10 and (hex_suffix or numeric_suffix or has_compact_suffix))
    ):
        return "generated_like"
    return "human"


def _resolve_mac_vendor(mac_or_oui: str | None) -> str:
    value = str(mac_or_oui or "").strip()
    if not value:
        return "Unknown"
    try:
        return mac_lookup.lookup(value) or "Unknown"
    except Exception:
        return "Unknown"


def _empty_known_context() -> dict[str, Any]:
    return {
        "network_count": 0,
        "sample_mac": None,
        "dominant_encryption": None,
        "dominant_device_type": None,
        "sources": [],
    }


def _build_known_ssid_index(dataset: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    known_index: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for mac, net in (dataset or {}).items():
        if not isinstance(net, dict):
            continue
        ssid = str(net.get("ssid") or "").strip()
        if not ssid:
            continue
        known_index[ssid.lower()].append({
            "mac": mac,
            "encryption": _probe_net_encryption(net),
            "device_type": _normalize_device_type(net.get("device_type")),
            "sources": [str(src).strip().lower() for src in (net.get("sources") or []) if str(src).strip()],
        })
    return known_index


def _build_known_context(matches: list[dict[str, Any]]) -> dict[str, Any]:
    if not matches:
        return _empty_known_context()

    enc_counter = Counter(str(item.get("encryption") or "UNKNOWN") for item in matches)
    dev_counter = Counter(str(item.get("device_type") or "unknown") for item in matches)
    sources = sorted({src for item in matches for src in (item.get("sources") or []) if src})
    sample_mac = next((item.get("mac") for item in matches if item.get("mac")), None)
    return {
        "network_count": len(matches),
        "sample_mac": sample_mac,
        "dominant_encryption": enc_counter.most_common(1)[0][0] if enc_counter else None,
        "dominant_device_type": dev_counter.most_common(1)[0][0] if dev_counter else None,
        "sources": sources,
    }


def _enrich_probe_intel_result(result: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(result, dict):
        return result

    payload = dict(result)
    if not payload.get("available"):
        return payload

    dataset = load_real_data() or {}
    known_index = _build_known_ssid_index(dataset)

    enriched_ssids = []
    for ss in payload.get("ssids") or []:
        item = dict(ss)
        normalized = str(item.get("ssid") or "").strip().lower()
        matches = known_index.get(normalized, [])
        item["is_known"] = bool(matches)
        item["name_shape"] = _classify_ssid_shape(str(item.get("ssid") or ""))
        item["known_context"] = _build_known_context(matches)
        enriched_ssids.append(item)

    enriched_clients = []
    for cl in payload.get("clients") or []:
        item = dict(cl)
        ssids = [str(ssid).strip() for ssid in (item.get("ssids_probed") or []) if str(ssid).strip()]
        known_ssids = [ssid for ssid in ssids if known_index.get(ssid.lower())]
        unmatched_ssids = [ssid for ssid in ssids if not known_index.get(ssid.lower())]
        item["vendor"] = _resolve_mac_vendor(item.get("client_mac") or item.get("oui_prefix"))
        item["known_ssid_count"] = len(known_ssids)
        item["unmatched_ssid_count"] = len(unmatched_ssids)
        item["known_ssid_preview"] = known_ssids[:3]
        item["unmatched_ssid_preview"] = unmatched_ssids[:3]
        enriched_clients.append(item)

    payload["ssids"] = enriched_ssids
    payload["clients"] = enriched_clients
    return payload


@router.get("/api/recon/probe-intel", tags=["Recon"])
def get_probe_intel(
    limit: int = Query(default=200, ge=1, le=1000),
):
    """Aggregate probe request intelligence across all available PCAPs."""
    result = _enrich_probe_intel_result(probe_service.analyse(limit=limit))
    return ok(result)


@router.get("/api/recon/probe-intel/status", tags=["Recon"])
def get_probe_intel_status():
    """Return cached probe-intel result and staleness info (fast)."""
    status = dict(probe_service.get_cache_status())
    if status.get("result"):
        status["result"] = _enrich_probe_intel_result(status.get("result"))
    return ok(status)


@router.post("/api/recon/probe-intel/scan", tags=["Recon"])
def start_probe_intel_scan(
    limit: int = Query(default=200, ge=1, le=1000),
):
    """Start a background probe-intel scan job.  Returns job_id."""
    pcaps = probe_service._find_pcaps()
    if not pcaps:
        return ok({"job_id": None, "pcap_count": 0})
    job_id = start_probe_intel_job(pcaps, limit=limit)
    return ok({"job_id": job_id, "pcap_count": len(pcaps)})


@router.get("/api/recon/probe-intel/pcap", tags=["Recon"])
def get_probe_intel_pcap(
    path: str = Query(..., min_length=1),
    limit: int = Query(default=200, ge=1, le=1000),
):
    """Analyse probe requests from a specific PCAP file."""
    import os

    if not os.path.isfile(path):
        return fail("PCAP file not found")
    result = probe_service.analyse_pcap(path, limit=limit)
    return ok(result)
