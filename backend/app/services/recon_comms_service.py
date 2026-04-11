from __future__ import annotations

import math
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

from app.api.deps import mac_lookup
from app.services.recon_runtime_service import _net_encryption
from app.services.spatial_normalizer import generate_deterministic_accuracy
from app.services.to_conquer_service import (
    _build_overlap_polys,
    _meters_scale,
    _to_local_meters,
    build_hull,
    expand_points_by_accuracy,
    polygon_to_zone_parts,
)


def _safe_ts(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return 0.0
        try:
            if text.endswith("Z"):
                dt = datetime.fromisoformat(f"{text[:-1]}+00:00")
            else:
                dt = datetime.fromisoformat(text)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except Exception:
            return 0.0
    return 0.0


def _haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    earth_radius_m = 6_371_000
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2) ** 2
    return earth_radius_m * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def _build_colocation_zone_geometry(members: list[dict[str, Any]]) -> tuple[list[list[dict]], list[list[list[dict]]]]:
    if len(members) < 2:
        return [], []

    center_lat = sum(float(m["lat"]) for m in members) / len(members)
    center_lng = sum(float(m["lng"]) for m in members) / len(members)
    scale = _meters_scale(center_lat)
    m_per_deg_lat = scale["m_per_deg_lat"]
    m_per_deg_lng = scale["m_per_deg_lng"]

    points_local: list[dict[str, Any]] = []
    expanded_points: list[dict[str, Any]] = []
    for member in members:
        lat = member.get("lat")
        lng = member.get("lng")
        mac = str(member.get("mac") or "")
        if lat is None or lng is None:
            continue
        acc = float(member.get("acc") or 0)
        if acc <= 0:
            acc = float(generate_deterministic_accuracy(mac or f"{lat}:{lng}"))
        x, y = _to_local_meters(
            float(lat),
            float(lng),
            center_lat,
            center_lng,
            m_per_deg_lat,
            m_per_deg_lng,
        )
        points_local.append({"lat": lat, "lng": lng, "acc": acc, "x": x, "y": y})
        expanded_points.append({"lat": lat, "lng": lng, "acc": acc})

    if len(points_local) < 2:
        return [], []

    zone_parts: list[list[dict]] = []
    zone_holes: list[list[list[dict]]] = []
    polys_with_counts = _build_overlap_polys(
        points_local,
        center_lat,
        center_lng,
        m_per_deg_lat,
        m_per_deg_lng,
    )

    if polys_with_counts:
        for poly_latlng, _comp_count in polys_with_counts:
            for part in polygon_to_zone_parts(poly_latlng):
                zone_parts.append(part["ring"])
                zone_holes.append(part.get("holes", []))
    else:
        hull = build_hull(expand_points_by_accuracy(expanded_points, acc_segments=8))
        for part in polygon_to_zone_parts(hull):
            zone_parts.append(part["ring"])
            zone_holes.append(part.get("holes", []))

    return zone_parts, zone_holes


def build_device_fingerprints_payload(dataset: dict[str, Any]) -> dict[str, Any]:
    by_type: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "count": 0,
            "encryption": Counter(),
            "channels": Counter(),
            "rssi_vals": [],
            "sample_networks": [],
        }
    )
    by_oui: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "count": 0,
            "vendor": "Unknown",
            "sample_macs": [],
            "encryption": Counter(),
        }
    )
    by_channel: dict[int, dict[str, Any]] = defaultdict(lambda: {"count": 0, "rssi_vals": []})
    total = 0
    raw_beacons = 0
    raw_eapol = 0
    raw_probes = 0

    for mac, net in (dataset or {}).items():
        if not isinstance(net, dict):
            continue
        total += 1

        device_type = str(net.get("device_type") or "unknown")
        info = by_type[device_type]
        info["count"] += 1
        info["encryption"][_net_encryption(net)] += 1

        ssid = net.get("ssid") or ""
        if len(info["sample_networks"]) < 10:
            info["sample_networks"].append({"ssid": ssid or mac, "mac": mac})

        channel = net.get("channel")
        if channel is not None:
            channel = int(channel)
            info["channels"][channel] += 1
            by_channel[channel]["count"] += 1

        rssi = net.get("rssi")
        if rssi is not None:
            rssi_f = float(rssi)
            info["rssi_vals"].append(rssi_f)
            if channel is not None:
                by_channel[channel]["rssi_vals"].append(rssi_f)

        oui = mac[:8].upper() if len(mac) >= 8 else "UNK"
        oui_info = by_oui[oui]
        oui_info["count"] += 1
        oui_info["encryption"][_net_encryption(net)] += 1
        if len(oui_info["sample_macs"]) < 5:
            oui_info["sample_macs"].append({"mac": mac, "ssid": ssid})

        raw_beacons += int(net.get("raw_beacon_count") or 0)
        raw_eapol += int(net.get("raw_eapol_count") or 0)
        raw_probes += int(net.get("raw_probe_peak_count") or 0)

    types = []
    for device_type, info in sorted(by_type.items(), key=lambda item: item[1]["count"], reverse=True):
        rssi_vals = info["rssi_vals"]
        rssi_stats = None
        if rssi_vals:
            rssi_stats = {
                "min": min(rssi_vals),
                "max": max(rssi_vals),
                "avg": round(sum(rssi_vals) / len(rssi_vals), 1),
            }
        types.append(
            {
                "type": device_type,
                "count": info["count"],
                "encryption": dict(info["encryption"].most_common()),
                "channel_distribution": dict(info["channels"].most_common()),
                "rssi_stats": rssi_stats,
                "sample_networks": info["sample_networks"],
            }
        )

    vendor_map: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "count": 0,
            "oui_prefixes": [],
            "sample_macs": [],
            "encryption": Counter(),
        }
    )
    for oui_prefix, info in by_oui.items():
        try:
            vendor = mac_lookup.lookup(oui_prefix) or "Unknown"
        except Exception:
            vendor = "Unknown"
        vendor_entry = vendor_map[vendor]
        vendor_entry["count"] += info["count"]
        if len(vendor_entry["oui_prefixes"]) < 3:
            vendor_entry["oui_prefixes"].append(oui_prefix)
        vendor_entry["encryption"] += info["encryption"]
        for sample_mac in info["sample_macs"]:
            if len(vendor_entry["sample_macs"]) < 5:
                vendor_entry["sample_macs"].append(sample_mac)

    by_vendor = [
        {
            "vendor": vendor_name,
            "count": vendor_data["count"],
            "oui_prefixes": vendor_data["oui_prefixes"],
            "sample_macs": vendor_data["sample_macs"],
            "encryption": dict(vendor_data["encryption"].most_common()),
        }
        for vendor_name, vendor_data in sorted(
            vendor_map.items(), key=lambda item: item[1]["count"], reverse=True
        )
    ][:50]

    channels = []
    for channel_num in sorted(by_channel.keys()):
        channel_info = by_channel[channel_num]
        rssi_vals = channel_info["rssi_vals"]
        channels.append(
            {
                "channel": channel_num,
                "count": channel_info["count"],
                "avg_rssi": round(sum(rssi_vals) / len(rssi_vals), 1) if rssi_vals else None,
            }
        )

    return {
        "total": total,
        "by_type": types,
        "by_oui": by_vendor,
        "by_channel": channels,
        "raw_activity": {
            "beacons": raw_beacons,
            "eapol": raw_eapol,
            "probes": raw_probes,
        },
    }


def build_colocation_payload(dataset: dict[str, Any]) -> dict[str, Any]:
    located: list[dict[str, Any]] = []
    for mac, net in (dataset or {}).items():
        if not isinstance(net, dict):
            continue
        lat = net.get("lat")
        lng = net.get("lng")
        if lat is None or lng is None or (lat == 0 and lng == 0):
            continue
        located.append(
            {
                "mac": mac,
                "ssid": net.get("ssid") or "",
                "lat": lat,
                "lng": lng,
                "acc": net.get("acc") or generate_deterministic_accuracy(mac),
                "encryption": _net_encryption(net),
                "device_type": str(net.get("device_type") or "unknown"),
                "sources": net.get("sources") or [],
                "rssi": net.get("rssi"),
                "ts": _safe_ts(net.get("ts_last") or net.get("ts") or 0),
            }
        )

    if not located:
        return {"clusters": [], "total_located": 0}

    grid_size = 0.00045
    grid: dict[tuple[int, int], list[dict[str, Any]]] = defaultdict(list)
    for network in located:
        cell = (
            round(float(network["lat"]) / grid_size),
            round(float(network["lng"]) / grid_size),
        )
        grid[cell].append(network)

    clusters: list[dict[str, Any]] = []
    for members in grid.values():
        if len(members) < 2:
            continue
        center_lat = sum(float(m["lat"]) for m in members) / len(members)
        center_lng = sum(float(m["lng"]) for m in members) / len(members)
        enc_dist = Counter(m["encryption"] for m in members)
        device_dist = Counter(m["device_type"] for m in members)

        max_dist = 0.0
        for member in members:
            max_dist = max(
                max_dist,
                _haversine_m(center_lat, center_lng, float(member["lat"]), float(member["lng"])),
            )
        radius_m = round(max_dist, 1)

        source_counter: Counter[str] = Counter()
        for member in members:
            for source in member["sources"]:
                source_counter[str(source)] += 1

        rssi_vals = [float(m["rssi"]) for m in members if m.get("rssi") is not None]
        avg_rssi = round(sum(rssi_vals) / len(rssi_vals), 1) if rssi_vals else None

        ssid_words = [str(m["ssid"]).split()[0] for m in members if m.get("ssid")]
        word_counts = Counter(ssid_words)
        if word_counts:
            top_word, top_count = word_counts.most_common(1)[0]
            label = top_word if top_count >= len(members) * 0.5 else "Mixed"
        else:
            label = "Unnamed"

        zone_parts, zone_holes = _build_colocation_zone_geometry(members)
        cluster = {
            "center": {"lat": center_lat, "lng": center_lng},
            "count": len(members),
            "label": label,
            "radius_m": radius_m,
            "dominant_encryption": enc_dist.most_common(1)[0][0] if enc_dist else "UNK",
            "avg_rssi": avg_rssi,
            "points": [
                {"lat": member["lat"], "lng": member["lng"], "acc": member.get("acc")}
                for member in members
            ],
            "parts": zone_parts,
            "networks": [
                {
                    "mac": member["mac"],
                    "ssid": member["ssid"],
                    "encryption": member["encryption"],
                }
                for member in members
            ],
            "encryption_breakdown": dict(enc_dist),
            "device_breakdown": dict(device_dist.most_common()),
            "source_breakdown": dict(source_counter.most_common()),
        }
        if any(zone_holes):
            cluster["holes"] = zone_holes
        clusters.append(cluster)

    clusters.sort(key=lambda cluster: cluster["count"], reverse=True)
    return {"clusters": clusters[:30], "total_located": len(located)}


def build_relationship_graph_payload(
    dataset: dict[str, Any],
    probe_status: dict[str, Any] | None,
) -> dict[str, Any]:
    ap_nodes: list[dict[str, Any]] = []
    ssid_to_mac: dict[str, str] = {}
    for mac, net in (dataset or {}).items():
        if not isinstance(net, dict):
            continue
        ssid = str(net.get("ssid") or "").strip()
        ap_nodes.append(
            {
                "id": mac,
                "type": "ap",
                "label": ssid or mac,
                "encryption": _net_encryption(net),
                "has_password": bool(net.get("pass")),
            }
        )
        if ssid:
            ssid_to_mac[ssid.lower()] = mac

    probe_data = (
        probe_status.get("result")
        if isinstance(probe_status, dict) and probe_status.get("cached")
        else None
    )
    client_nodes: list[dict[str, Any]] = []
    ssid_target_nodes: list[dict[str, Any]] = []
    ssid_target_ids: set[str] = set()
    edges: list[dict[str, Any]] = []
    edge_breakdown: Counter[str] = Counter()

    if probe_data and probe_data.get("available"):
        for client in (probe_data.get("clients") or [])[:100]:
            client_mac = str(client.get("client_mac") or "")
            client_nodes.append(
                {
                    "id": f"client_{client_mac}",
                    "type": "client",
                    "label": client_mac,
                    "probe_count": client.get("probe_count", 0),
                    "avg_signal": client.get("avg_signal"),
                }
            )
            for ssid in client.get("ssids_probed", []) or []:
                normalized_ssid = str(ssid or "").strip() or "<hidden>"
                target_mac = ssid_to_mac.get(normalized_ssid.lower())
                if target_mac:
                    edges.append(
                        {
                            "source": f"client_{client_mac}",
                            "target": target_mac,
                            "ssid": normalized_ssid,
                            "type": "probe_known",
                        }
                    )
                    edge_breakdown["probe_known"] += 1
                    continue
                target_id = f"ssid_{normalized_ssid.lower()}"
                if target_id not in ssid_target_ids:
                    ssid_target_nodes.append(
                        {
                            "id": target_id,
                            "type": "ssid_target",
                            "label": normalized_ssid,
                            "status": "unresolved",
                        }
                    )
                    ssid_target_ids.add(target_id)
                edges.append(
                    {
                        "source": f"client_{client_mac}",
                        "target": target_id,
                        "ssid": normalized_ssid,
                        "type": "probe_unknown",
                    }
                )
                edge_breakdown["probe_unknown"] += 1

    summary = probe_data.get("summary") if probe_data and probe_data.get("available") else {}
    return {
        "nodes": ap_nodes + ssid_target_nodes + client_nodes,
        "edges": edges,
        "ap_count": len(ap_nodes),
        "ssid_target_count": len(ssid_target_nodes),
        "client_count": len(client_nodes),
        "edge_breakdown": {
            "probe_known": edge_breakdown.get("probe_known", 0),
            "probe_unknown": edge_breakdown.get("probe_unknown", 0),
        },
        "probe_context": {
            "cached": bool((probe_status or {}).get("cached")),
            "stale": bool((probe_status or {}).get("stale")),
            "pcap_count": (probe_status or {}).get("pcap_count", 0),
            "available": bool(probe_data and probe_data.get("available")),
            "summary": {
                "total_probes": summary.get("total_probes", 0),
                "unique_clients": summary.get("unique_clients", 0),
                "unique_ssids": summary.get("unique_ssids", 0),
                "pcaps_scanned": summary.get("pcaps_scanned", 0),
                "broadcast_probes": summary.get("broadcast_probes", 0),
            },
        },
    }


def build_spectrum_payload(dataset: dict[str, Any]) -> dict[str, Any]:
    channel_info: dict[int, dict[str, Any]] = defaultdict(
        lambda: {
            "count": 0,
            "rssi_vals": [],
            "encryption": Counter(),
        }
    )
    total_with_channel = 0

    for net in (dataset or {}).values():
        if not isinstance(net, dict):
            continue
        channel = net.get("channel")
        if channel is None:
            continue
        channel = int(channel)
        total_with_channel += 1
        info = channel_info[channel]
        info["count"] += 1
        info["encryption"][_net_encryption(net)] += 1
        rssi = net.get("rssi")
        if rssi is not None:
            info["rssi_vals"].append(float(rssi))

    channels = []
    band_24 = 0
    band_5 = 0
    for channel_num in sorted(channel_info.keys()):
        info = channel_info[channel_num]
        rssi_vals = info["rssi_vals"]
        channels.append(
            {
                "channel": channel_num,
                "count": info["count"],
                "avg_rssi": round(sum(rssi_vals) / len(rssi_vals), 1) if rssi_vals else None,
                "encryption": dict(info["encryption"].most_common()),
            }
        )
        if channel_num <= 14:
            band_24 += info["count"]
        else:
            band_5 += info["count"]

    congested = []
    if total_with_channel > 0:
        threshold = total_with_channel * 0.15
        congested = [channel["channel"] for channel in channels if channel["count"] > threshold]

    return {
        "total_with_channel": total_with_channel,
        "channels": channels,
        "band_24ghz": band_24,
        "band_5ghz": band_5,
        "congested_channels": congested,
    }


def build_signal_landscape_payload(dataset: dict[str, Any]) -> dict[str, Any]:
    buckets = [
        ("<-80", lambda rssi: rssi < -80),
        ("-80:-70", lambda rssi: -80 <= rssi < -70),
        ("-70:-60", lambda rssi: -70 <= rssi < -60),
        ("-60:-50", lambda rssi: -60 <= rssi < -50),
        ("-50:-40", lambda rssi: -50 <= rssi < -40),
        (">-40", lambda rssi: rssi >= -40),
    ]
    bucket_counts = {label: 0 for label, _test in buckets}
    by_encryption: dict[str, list[float]] = defaultdict(list)
    by_source: dict[str, list[float]] = defaultdict(list)
    strong_signals: list[dict[str, Any]] = []
    all_rssi: list[float] = []

    for mac, net in (dataset or {}).items():
        if not isinstance(net, dict):
            continue
        rssi = net.get("rssi")
        if rssi is None:
            continue
        rssi_f = float(rssi)
        all_rssi.append(rssi_f)

        for label, test in buckets:
            if test(rssi_f):
                bucket_counts[label] += 1
                break

        by_encryption[_net_encryption(net)].append(rssi_f)
        for source in net.get("sources") or []:
            by_source[str(source)].append(rssi_f)

        if rssi_f > -50:
            strong_signals.append(
                {
                    "mac": mac,
                    "ssid": net.get("ssid") or "",
                    "rssi": rssi_f,
                    "encryption": _net_encryption(net),
                }
            )

    strong_signals.sort(key=lambda signal: signal["rssi"], reverse=True)

    def _rssi_summary(values: list[float]) -> dict[str, Any] | None:
        if not values:
            return None
        return {
            "min": min(values),
            "max": max(values),
            "avg": round(sum(values) / len(values), 1),
            "count": len(values),
        }

    return {
        "total_with_rssi": len(all_rssi),
        "histogram": bucket_counts,
        "by_encryption": {
            key: _rssi_summary(values) for key, values in sorted(by_encryption.items())
        },
        "by_source": {
            key: _rssi_summary(values) for key, values in sorted(by_source.items())
        },
        "strong_signals": strong_signals[:20],
        "summary": _rssi_summary(all_rssi),
    }
