import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

BROADCAST_MAC = "FF:FF:FF:FF:FF:FF"
HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")


def normalize_mac(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", value)
    if len(cleaned) != 12:
        return None
    cleaned = cleaned.upper()
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))


def decode_ssid(raw_ssid: Optional[str]) -> Tuple[str, Optional[str]]:
    if raw_ssid is None:
        return "", None
    text = str(raw_ssid).strip()
    if not text or text in {"<MISSING>", "<hidden>", "<broadcast>"}:
        return "", None

    if HEX_RE.match(text) and len(text) % 2 == 0:
        try:
            decoded = bytes.fromhex(text).decode("utf-8", errors="ignore").strip()
            if decoded:
                return decoded, text
        except Exception:
            pass

    return text, None


def channel_to_frequency(channel: Optional[int]) -> Optional[int]:
    if channel is None:
        return None
    if channel == 14:
        return 2484
    if 1 <= channel <= 13:
        return 2407 + (channel * 5)
    if 32 <= channel <= 196:
        return 5000 + (channel * 5)
    return None


def to_int(value: Optional[str]) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(float(value))
    except Exception:
        return None


def to_float(value: Optional[str]) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except Exception:
        return None


def parse_subtype(value: Optional[str]) -> Optional[int]:
    if not value:
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    try:
        if text.startswith("0x"):
            return int(text, 16)
        return int(float(text))
    except Exception:
        return None


def parse_output(
    output: str,
    warnings: List[str],
    source_file: str,
    source_stat,
    schema_version: int = 1,
) -> Dict:
    stats = {
        "parsed_lines": 0,
        "beacon_frames": 0,
        "probe_requests": 0,
        "eapol_frames": 0,
        "networks_count": 0,
    }
    first_ts: Optional[float] = None
    networks: Dict[str, Dict] = {}

    def ensure_network(bssid: str) -> Dict:
        net = networks.get(bssid)
        if net is None:
            net = {
                "bssid": bssid,
                "ssid": "",
                "ssid_raw_hex": None,
                "channel": None,
                "frequency_mhz": None,
                "beacon_count": 0,
                "probe_clients": set(),
                "eapol_count": 0,
                "last_seen_abs": None,
            }
            networks[bssid] = net
        return net

    for line in output.splitlines():
        if not line.strip():
            continue

        parts = line.split("\t")
        if len(parts) < 9:
            parts += [""] * (9 - len(parts))
        parts = parts[:9]
        stats["parsed_lines"] += 1

        ts = to_float(parts[0])
        subtype_raw = (parts[1] or "").strip().lower()
        subtype_int = parse_subtype(subtype_raw)
        bssid = normalize_mac(parts[2])
        sa = normalize_mac(parts[3])
        da = normalize_mac(parts[4])
        raw_ssid = parts[5]
        channel = to_int(parts[6])
        eapol_msgnr = (parts[7] or "").strip()
        eapol_type = (parts[8] or "").strip()

        if ts is not None and first_ts is None:
            first_ts = ts

        if subtype_raw in {"0x0008", "0x08"} or subtype_int == 8:
            stats["beacon_frames"] += 1
            if not bssid:
                continue

            net = ensure_network(bssid)
            net["beacon_count"] += 1
            if ts is not None and (
                net["last_seen_abs"] is None or ts > net["last_seen_abs"]
            ):
                net["last_seen_abs"] = ts

            ssid, ssid_raw_hex = decode_ssid(raw_ssid)
            if ssid and not net["ssid"]:
                net["ssid"] = ssid
            if ssid_raw_hex and not net["ssid_raw_hex"]:
                net["ssid_raw_hex"] = ssid_raw_hex

            if channel is not None and net["channel"] is None:
                net["channel"] = channel
                net["frequency_mhz"] = channel_to_frequency(channel)
            continue

        if subtype_raw in {"0x0004", "0x04"} or subtype_int == 4:
            stats["probe_requests"] += 1
            if not sa:
                continue
            target = None
            if bssid and bssid != BROADCAST_MAC:
                target = bssid
            elif da and da != BROADCAST_MAC:
                target = da
            if target and target in networks:
                networks[target]["probe_clients"].add(sa)
            continue

        if (
            eapol_type
            or eapol_msgnr
            or subtype_raw in {"0x0028", "0x28"}
            or subtype_int == 40
        ):
            stats["eapol_frames"] += 1
            candidate = None
            for mac in (bssid, sa, da):
                if mac and mac != BROADCAST_MAC:
                    candidate = mac
                    break
            if not candidate:
                continue
            net = ensure_network(candidate)
            net["eapol_count"] += 1
            if ts is not None and (
                net["last_seen_abs"] is None or ts > net["last_seen_abs"]
            ):
                net["last_seen_abs"] = ts

    out_networks = []
    for bssid, net in networks.items():
        last_seen_offset = None
        if first_ts is not None and net["last_seen_abs"] is not None:
            last_seen_offset = round(max(0.0, net["last_seen_abs"] - first_ts), 6)

        if net["frequency_mhz"] is None:
            net["frequency_mhz"] = channel_to_frequency(net["channel"])

        out_networks.append(
            {
                "bssid": bssid,
                "ssid": net["ssid"],
                "ssid_raw_hex": net["ssid_raw_hex"],
                "channel": net["channel"],
                "frequency_mhz": net["frequency_mhz"],
                "beacon_count": net["beacon_count"],
                "probe_client_count": len(net["probe_clients"]),
                "eapol_count": net["eapol_count"],
                "last_seen_offset_s": last_seen_offset,
            }
        )

    out_networks.sort(
        key=lambda x: (
            int(x.get("beacon_count") or 0),
            int(x.get("eapol_count") or 0),
            int(x.get("probe_client_count") or 0),
        ),
        reverse=True,
    )

    stats["networks_count"] = len(out_networks)

    return {
        "schema_version": schema_version,
        "source_file": source_file,
        "source_size": source_stat.st_size,
        "source_mtime": source_stat.st_mtime,
        "processed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "warnings": warnings,
        "stats": stats,
        "networks": out_networks,
    }
