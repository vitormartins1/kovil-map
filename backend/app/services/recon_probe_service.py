from __future__ import annotations

import math
from collections import Counter, defaultdict
from typing import Any

from app.api.deps import mac_lookup


def _resolve_probe_vendor(mac_or_oui: str | None) -> str:
    value = str(mac_or_oui or "").strip()
    if not value:
        return "Unknown"
    try:
        return mac_lookup.lookup(value) or "Unknown"
    except Exception:
        return "Unknown"


def _haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    earth_radius_m = 6_371_000
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = (
        math.sin(dphi / 2) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2) ** 2
    )
    return earth_radius_m * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def _build_probe_known_ssid_index(dataset: dict[str, Any]) -> set[str]:
    known = set()
    for net in (dataset or {}).values():
        if not isinstance(net, dict):
            continue
        ssid = str(net.get("ssid") or "").strip().lower()
        if ssid:
            known.add(ssid)
    return known


def _probe_geo_encryption(net: dict[str, Any]) -> str:
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


def _probe_geo_device_type(device_type: Any) -> str:
    value = str(device_type or "unknown").strip().lower()
    return value or "unknown"


def _valid_geo_point(lat: Any, lng: Any) -> tuple[float, float] | None:
    try:
        lat_f = float(lat)
        lng_f = float(lng)
    except (TypeError, ValueError):
        return None
    if lat_f == 0.0 and lng_f == 0.0:
        return None
    return (lat_f, lng_f)


def _build_probe_geo_index(dataset: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for mac, net in (dataset or {}).items():
        if not isinstance(net, dict):
            continue
        ssid_display = str(net.get("ssid") or "").strip()
        if not ssid_display:
            continue
        coords = _valid_geo_point(net.get("lat"), net.get("lng"))
        if coords is None:
            continue
        lat_f, lng_f = coords
        sources = [
            str(src).strip().lower()
            for src in (net.get("sources") or [])
            if str(src).strip()
        ]
        index[ssid_display.lower()].append(
            {
                "ssid_display": ssid_display,
                "ssid_norm": ssid_display.lower(),
                "mac": str(mac),
                "lat": lat_f,
                "lng": lng_f,
                "encryption": _probe_geo_encryption(net),
                "device_type": _probe_geo_device_type(net.get("device_type")),
                "sources": sources,
            }
        )
    return index


def _cluster_probe_geo_matches(
    matches: list[dict[str, Any]],
    *,
    cluster_radius_m: float = 185.0,
) -> list[dict[str, Any]]:
    clusters: list[dict[str, Any]] = []
    ordered_matches = sorted(
        matches,
        key=lambda item: (
            round(float(item.get("lat") or 0.0), 7),
            round(float(item.get("lng") or 0.0), 7),
            str(item.get("ssid_norm") or ""),
            str(item.get("mac") or ""),
        ),
    )
    for match in ordered_matches:
        lat_f = float(match["lat"])
        lng_f = float(match["lng"])
        best_cluster = None
        best_distance = None
        for cluster in clusters:
            dist = _haversine_m(
                lat_f,
                lng_f,
                float(cluster["center_lat"]),
                float(cluster["center_lng"]),
            )
            if dist <= cluster_radius_m and (
                best_distance is None or dist < best_distance
            ):
                best_cluster = cluster
                best_distance = dist
        if best_cluster is None:
            clusters.append(
                {
                    "points": [match],
                    "center_lat": lat_f,
                    "center_lng": lng_f,
                }
            )
            continue
        best_cluster["points"].append(match)
        count = len(best_cluster["points"])
        best_cluster["center_lat"] = (
            (float(best_cluster["center_lat"]) * (count - 1)) + lat_f
        ) / count
        best_cluster["center_lng"] = (
            (float(best_cluster["center_lng"]) * (count - 1)) + lng_f
        ) / count

    for cluster in clusters:
        points = cluster["points"]
        ssid_count = len({str(point.get("ssid_norm") or "") for point in points})
        max_dist = 0.0
        for point in points:
            max_dist = max(
                max_dist,
                _haversine_m(
                    float(point["lat"]),
                    float(point["lng"]),
                    float(cluster["center_lat"]),
                    float(cluster["center_lng"]),
                ),
            )
        cluster["ssid_count"] = ssid_count
        cluster["network_count"] = len(points)
        cluster["radius_m"] = round(max(25.0, max_dist), 1)
        cluster["score"] = (
            ssid_count * 1000
            + len(points) * 120
            - min(int(round(cluster["radius_m"])), 4000)
        )

    clusters.sort(
        key=lambda cluster: (
            int(cluster["score"]),
            int(cluster["ssid_count"]),
            int(cluster["network_count"]),
            -float(cluster["radius_m"]),
        ),
        reverse=True,
    )
    return clusters


def _rank_probe_geo_ambiguity(
    primary: dict[str, Any],
    alternative: dict[str, Any] | None,
) -> str:
    if not alternative:
        return "low"
    primary_score = max(float(primary.get("score") or 0.0), 1.0)
    alt_score = float(alternative.get("score") or 0.0)
    ratio = alt_score / primary_score
    if ratio >= 0.88:
        return "high"
    if ratio >= 0.6:
        return "medium"
    return "low"


def _rank_probe_geo_confidence(
    *,
    matched_ssid_count: int,
    match_count: int,
    radius_m: float,
    ambiguity_level: str,
) -> str:
    if matched_ssid_count >= 3 and match_count >= 3 and radius_m <= 220:
        confidence = "high"
    elif matched_ssid_count >= 2 and match_count >= 2 and radius_m <= 650:
        confidence = "medium"
    else:
        confidence = "low"

    if ambiguity_level == "high":
        return "medium" if confidence == "high" else "low"
    if ambiguity_level == "medium" and confidence == "high":
        return "medium"
    if radius_m > 900:
        return "low"
    return confidence


def _median_float(values: list[float]) -> float | None:
    cleaned = sorted(float(v) for v in values if v is not None)
    if not cleaned:
        return None
    mid = len(cleaned) // 2
    if len(cleaned) % 2:
        return round(cleaned[mid], 1)
    return round((cleaned[mid - 1] + cleaned[mid]) / 2, 1)


def _build_probe_geo_located_ssids(
    points: list[dict[str, Any]],
    *,
    center_lat: float,
    center_lng: float,
) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for point in points:
        grouped[str(point.get("ssid_norm") or "")].append(point)

    located_ssids: list[dict[str, Any]] = []
    for items in grouped.values():
        if not items:
            continue
        avg_lat = sum(float(item["lat"]) for item in items) / len(items)
        avg_lng = sum(float(item["lng"]) for item in items) / len(items)
        enc_counter = Counter(
            str(item.get("encryption") or "UNKNOWN") for item in items
        )
        dev_counter = Counter(
            str(item.get("device_type") or "unknown") for item in items
        )
        sources = sorted(
            {
                str(src)
                for item in items
                for src in (item.get("sources") or [])
                if str(src).strip()
            }
        )
        sample_mac = next((item.get("mac") for item in items if item.get("mac")), None)
        located_ssids.append(
            {
                "ssid": str(
                    items[0].get("ssid_display") or items[0].get("ssid_norm") or ""
                ),
                "network_count": len(items),
                "sample_mac": sample_mac,
                "dominant_encryption": enc_counter.most_common(1)[0][0],
                "dominant_device_type": dev_counter.most_common(1)[0][0],
                "sources": sources,
                "lat": round(avg_lat, 7),
                "lng": round(avg_lng, 7),
                "distance_to_center_m": round(
                    _haversine_m(avg_lat, avg_lng, center_lat, center_lng), 1
                ),
            }
        )
    located_ssids.sort(
        key=lambda item: (
            float(item.get("distance_to_center_m") or 0.0),
            -int(item.get("network_count") or 0),
            str(item.get("ssid") or "").lower(),
        )
    )
    return located_ssids


def _summarize_derandom_rule(
    random_count: int,
    global_count: int,
    ssid_count: int,
    known_count: int,
) -> str:
    if random_count and global_count:
        base = f"{random_count} randomized and {global_count} global MACs share {ssid_count} probed SSIDs."
    elif random_count:
        base = f"{random_count} randomized MACs share {ssid_count} probed SSIDs."
    else:
        base = f"{global_count} global MACs share {ssid_count} probed SSIDs."
    if known_count:
        base += f" {known_count} of those SSIDs also match known Recon networks."
    return base


def build_probe_derandomization_payload(
    dataset: dict[str, Any],
    status: dict[str, Any] | None,
) -> dict[str, Any]:
    if (
        not isinstance(status, dict)
        or not status.get("cached")
        or not status.get("result")
    ):
        return {"groups": [], "message": "Run probe intel scan first"}

    data = status["result"]
    clients = data.get("clients") or []
    known_ssids = _build_probe_known_ssid_index(dataset)

    fp_groups: dict[frozenset[str], list[dict[str, Any]]] = defaultdict(list)
    fp_display: dict[frozenset[str], dict[str, str]] = defaultdict(dict)
    for client in clients:
        original_ssids = [
            str(ssid).strip()
            for ssid in client.get("ssids_probed", [])
            if str(ssid).strip()
        ]
        ssids = frozenset(ssid.lower() for ssid in original_ssids)
        if len(ssids) < 2:
            continue
        fp_groups[ssids].append(client)
        display_map = fp_display[ssids]
        for ssid in original_ssids:
            display_map.setdefault(ssid.lower(), ssid)

    groups: list[dict[str, Any]] = []
    for ssids, members in fp_groups.items():
        if len(members) < 2:
            continue
        random_macs = []
        real_macs = []
        for member in members:
            mac = str(member.get("client_mac") or "")
            if len(mac) >= 2 and mac[1].lower() in "2367abef":
                random_macs.append(member)
            else:
                real_macs.append(member)

        if len(random_macs) < 2 and len(random_macs) + len(real_macs) < 2:
            continue

        display_aliases = fp_display.get(ssids, {})
        display_ssids = [display_aliases.get(ssid, ssid) for ssid in sorted(ssids)]
        known_preview = [
            display_aliases.get(ssid, ssid)
            for ssid in sorted(ssids)
            if ssid in known_ssids
        ]
        member_pool = sorted(
            random_macs, key=lambda item: item.get("probe_count", 0), reverse=True
        ) + sorted(
            real_macs,
            key=lambda item: item.get("probe_count", 0),
            reverse=True,
        )
        first_seen_vals = [
            member.get("first_seen")
            for member in members
            if member.get("first_seen") is not None
        ]
        last_seen_vals = [
            member.get("last_seen")
            for member in members
            if member.get("last_seen") is not None
        ]

        groups.append(
            {
                "ssid_fingerprint": display_ssids,
                "ssid_count": len(ssids),
                "members": [
                    {
                        "mac": member["client_mac"],
                        "probe_count": member["probe_count"],
                        "avg_signal": member.get("avg_signal"),
                        "is_random": member in random_macs,
                        "randomization_state": (
                            "randomized" if member in random_macs else "global"
                        ),
                        "vendor": _resolve_probe_vendor(member.get("client_mac")),
                        "first_seen": member.get("first_seen"),
                        "last_seen": member.get("last_seen"),
                    }
                    for member in member_pool[:10]
                ],
                "total_macs": len(random_macs) + len(real_macs),
                "random_macs": len(random_macs),
                "global_macs": len(real_macs),
                "confidence": (
                    "high" if len(random_macs) >= 2 and len(ssids) >= 3 else "medium"
                ),
                "known_ssid_count": len(known_preview),
                "known_ssid_preview": known_preview[:3],
                "first_seen": min(first_seen_vals) if first_seen_vals else None,
                "last_seen": max(last_seen_vals) if last_seen_vals else None,
                "rule_summary": _summarize_derandom_rule(
                    len(random_macs),
                    len(real_macs),
                    len(ssids),
                    len(known_preview),
                ),
            }
        )

    groups.sort(key=lambda group: group["total_macs"], reverse=True)
    for index, group in enumerate(groups, start=1):
        group["group_label"] = f"Likely Device {index:02d}"
    return {"groups": groups[:30]}


def build_probe_geocorrelation_payload(
    dataset: dict[str, Any],
    status: dict[str, Any] | None,
) -> dict[str, Any]:
    if (
        not isinstance(status, dict)
        or not status.get("cached")
        or not status.get("result")
    ):
        return {"clients": [], "message": "Run probe intel scan first"}

    data = status["result"]
    clients = data.get("clients") or []
    geo_index = _build_probe_geo_index(dataset)
    result: list[dict[str, Any]] = []
    matched_network_total = 0

    for client in clients[:50]:
        ssids_probed = [
            str(ssid).strip()
            for ssid in (client.get("ssids_probed") or [])
            if str(ssid).strip()
        ]
        if not ssids_probed:
            continue

        all_matches: list[dict[str, Any]] = []
        for ssid in ssids_probed:
            for match in geo_index.get(ssid.lower(), []):
                all_matches.append({**match, "requested_ssid": ssid})

        if not all_matches:
            continue

        clusters = _cluster_probe_geo_matches(all_matches)
        if not clusters:
            continue

        primary = clusters[0]
        alternative = clusters[1] if len(clusters) > 1 else None
        center_lat = round(float(primary["center_lat"]), 7)
        center_lng = round(float(primary["center_lng"]), 7)
        located_ssids = _build_probe_geo_located_ssids(
            primary["points"],
            center_lat=center_lat,
            center_lng=center_lng,
        )
        source_breakdown = Counter(
            str(src)
            for point in primary["points"]
            for src in (point.get("sources") or [])
            if str(src).strip()
        )
        security_breakdown = Counter(
            str(point.get("encryption") or "UNKNOWN") for point in primary["points"]
        )
        ambiguity_level = _rank_probe_geo_ambiguity(primary, alternative)
        matched_ssid_count = int(primary["ssid_count"])
        match_count = int(primary["network_count"])
        total_probed_ssids = len({ssid.lower() for ssid in ssids_probed})
        confidence = _rank_probe_geo_confidence(
            matched_ssid_count=matched_ssid_count,
            match_count=match_count,
            radius_m=float(primary["radius_m"]),
            ambiguity_level=ambiguity_level,
        )
        matched_network_total += match_count

        result.append(
            {
                "client_mac": client["client_mac"],
                "oui_prefix": client.get("oui_prefix"),
                "vendor": _resolve_probe_vendor(
                    client.get("client_mac") or client.get("oui_prefix")
                ),
                "probe_count": client.get("probe_count", 0),
                "avg_signal": client.get("avg_signal"),
                "first_seen": client.get("first_seen"),
                "last_seen": client.get("last_seen"),
                "total_probed_ssids": total_probed_ssids,
                "match_count": match_count,
                "matched_ssid_count": matched_ssid_count,
                "known_match_ratio": round(
                    matched_ssid_count / max(total_probed_ssids, 1), 2
                ),
                "estimated_center": {"lat": center_lat, "lng": center_lng},
                "estimated_radius_m": float(primary["radius_m"]),
                "confidence": confidence,
                "ambiguity_level": ambiguity_level,
                "alternative_cluster_count": max(0, len(clusters) - 1),
                "source_breakdown": dict(source_breakdown),
                "security_breakdown": dict(security_breakdown),
                "located_ssids": located_ssids,
            }
        )

    confidence_rank = {"high": 3, "medium": 2, "low": 1}
    result.sort(
        key=lambda item: (
            confidence_rank.get(str(item.get("confidence") or "low"), 0),
            int(item.get("matched_ssid_count") or 0),
            -(float(item.get("estimated_radius_m") or 0.0)),
            int(item.get("probe_count") or 0),
        ),
        reverse=True,
    )
    radii = [
        float(item["estimated_radius_m"])
        for item in result
        if item.get("estimated_radius_m") is not None
    ]
    summary = {
        "correlated_clients": len(result),
        "high_confidence_clients": sum(
            1 for item in result if item.get("confidence") == "high"
        ),
        "matched_networks": matched_network_total,
        "median_radius_m": _median_float(radii),
    }
    return {
        "summary": summary,
        "clients": result[:24],
        "message": "No geo-correlation data" if not result else None,
    }
