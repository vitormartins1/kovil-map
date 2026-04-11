"""Recon Center endpoints – kill-chain, vulnerability matrix, attack effectiveness,
temporal intelligence, and audit report generation.

All endpoints aggregate data from existing services (DataLoader, Insights,
History, RawSniffer, Analytics) and expose it in formats optimised for the
new Recon Center frontend workspace.
"""

from __future__ import annotations

import math
import os
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from app.core.config import DATA_DIR, HANDSHAKES_DIR
from app.services.data_loader import get_data_revision, load_real_data
from app.services.probe_service import probe_service
from app.services.recon_comms_service import (
    build_colocation_payload,
    build_device_fingerprints_payload,
    build_relationship_graph_payload,
    build_signal_landscape_payload,
    build_spectrum_payload,
)
from app.services.recon_probe_service import (
    build_probe_derandomization_payload,
    build_probe_geocorrelation_payload,
)
from app.services.recon_runtime_service import (
    _KILL_CHAIN_STAGES,
    _build_kill_chain_network_entry,
    _build_recon_manifest_payload,
    _build_vulnerability_row,
    _cache_response,
    _cache_response_get,
    _cache_response_set,
    _classify_network,
    _get_dir_listing,
    _net_encryption,
    _probe_cache_signature,
    _recon_artifacts_signature,
    _resolve_dataset_network,
    _scan_hash_files,
    clear_recon_runtime_cache,
)
from app.utils.responses import fail, ok
from app.api.deps import mac_lookup

import json as _json

router = APIRouter()

# Persistent storage for snapshots
_SNAPSHOT_DIR = os.path.join(DATA_DIR, "recon_snapshots")
os.makedirs(_SNAPSHOT_DIR, exist_ok=True)


def _haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Return the great-circle distance in metres between two lat/lon points."""
    R = 6_371_000  # Earth radius in metres
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def _safe_ts(value: Any) -> float:
    """Convert an ISO string or numeric timestamp to float epoch."""
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


# ---------------------------------------------------------------------------
# 1. Kill Chain
# ---------------------------------------------------------------------------


@router.get("/api/recon/kill-chain", tags=["Recon"])
def get_kill_chain():
    """Aggregate all networks into kill-chain stages with PMKID/EAPOL intel."""
    dataset = load_real_data() or {}
    data_revision = int(get_data_revision())

    def _build():
        stages: dict[str, list[dict]] = {s: [] for s in _KILL_CHAIN_STAGES}

        # Aggregate PMKID/EAPOL counters
        total_pmkid = 0
        total_eapol_hash = 0
        total_with_hash = 0

        for mac, net in dataset.items():
            if not isinstance(net, dict):
                continue
            mac_clean = mac.replace(":", "").lower()
            hash_info = _scan_hash_files(mac_clean)
            stage = _classify_network(mac, net, hash_info=hash_info)

            net_entry = _build_kill_chain_network_entry(mac, net, hash_info=hash_info)

            # Attach hash intel when relevant
            if hash_info["has_hash"]:
                total_with_hash += 1
                if hash_info["has_pmkid"]:
                    total_pmkid += 1
                if hash_info["has_eapol_hash"]:
                    total_eapol_hash += 1

            stages[stage].append(net_entry)

        summary = []
        for stage_name in _KILL_CHAIN_STAGES:
            members = stages[stage_name]
            summary.append(
                {
                    "stage": stage_name,
                    "count": len(members),
                    "networks": members,
                }
            )

        total = sum(s["count"] for s in summary)

        # Compute exclusive hash type counts
        pmkid_only = 0
        eapol_only = 0
        both_types = 0
        for s in summary:
            for n in s["networks"]:
                p = n.get("has_pmkid", False)
                e = n.get("has_eapol_hash", False)
                if p and e:
                    both_types += 1
                elif p:
                    pmkid_only += 1
                elif e:
                    eapol_only += 1

        return ok({
            "total": total,
            "stages": summary,
            "hash_intel": {
                "total_with_hash": total_with_hash,
                "total_pmkid": total_pmkid,
                "total_eapol_hash": total_eapol_hash,
                "pmkid_only": pmkid_only,
                "eapol_only": eapol_only,
                "both": both_types,
            },
        })

    return _cache_response("kill_chain", tuple(), _build, data_revision=data_revision)


@router.get("/api/recon/cache-manifest", tags=["Recon"])
def get_recon_cache_manifest():
    return ok(_build_recon_manifest_payload())


@router.get("/api/recon/kill-chain/summary", tags=["Recon"])
def get_kill_chain_summary():
    dataset = load_real_data() or {}
    data_revision = int(get_data_revision())
    preview_limit = 20

    def _build():
        stage_counts: dict[str, int] = {s: 0 for s in _KILL_CHAIN_STAGES}
        stage_previews: dict[str, list[dict[str, Any]]] = {s: [] for s in _KILL_CHAIN_STAGES}
        total_pmkid = 0
        total_eapol_hash = 0
        total_with_hash = 0
        pmkid_only = 0
        eapol_only = 0
        both_types = 0

        for mac, net in dataset.items():
            if not isinstance(net, dict):
                continue
            mac_clean = mac.replace(":", "").lower()
            hash_info = _scan_hash_files(mac_clean)
            stage = _classify_network(mac, net, hash_info=hash_info)
            stage_counts[stage] += 1
            stage_previews[stage].append(_build_kill_chain_network_entry(mac, net, hash_info=hash_info))
            if not hash_info["has_hash"]:
                continue
            total_with_hash += 1
            if hash_info["has_pmkid"]:
                total_pmkid += 1
            if hash_info["has_eapol_hash"]:
                total_eapol_hash += 1
            if hash_info["has_pmkid"] and hash_info["has_eapol_hash"]:
                both_types += 1
            elif hash_info["has_pmkid"]:
                pmkid_only += 1
            elif hash_info["has_eapol_hash"]:
                eapol_only += 1

        summary = [
            {
                "stage": stage_name,
                "count": stage_counts[stage_name],
                "preview_count": min(stage_counts[stage_name], preview_limit),
                "preview_networks": sorted(
                    stage_previews[stage_name],
                    key=lambda item: ((item.get("ssid") or "").lower(), (item.get("mac") or "").lower()),
                )[:preview_limit],
            }
            for stage_name in _KILL_CHAIN_STAGES
        ]
        total = sum(stage_counts.values())
        return ok({
            "total": total,
            "stages": summary,
            "hash_intel": {
                "total_with_hash": total_with_hash,
                "total_pmkid": total_pmkid,
                "total_eapol_hash": total_eapol_hash,
                "pmkid_only": pmkid_only,
                "eapol_only": eapol_only,
                "both": both_types,
            },
        })

    return _cache_response("kill_chain_summary", tuple(), _build, data_revision=data_revision, ttl=6.0)


@router.get("/api/recon/kill-chain/stage", tags=["Recon"])
def get_kill_chain_stage(
    stage: str = Query(..., description="Kill-chain stage"),
    search: str = Query(default=""),
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    dataset = load_real_data() or {}
    data_revision = int(get_data_revision())
    stage_key = str(stage or "").strip().lower()
    if stage_key not in _KILL_CHAIN_STAGES:
        fail(f"Invalid stage. Allowed: {', '.join(_KILL_CHAIN_STAGES)}")
    search_text = str(search or "").strip().lower()

    def _build():
        networks: list[dict[str, Any]] = []
        for mac, net in dataset.items():
            if not isinstance(net, dict):
                continue
            mac_clean = mac.replace(":", "").lower()
            hash_info = _scan_hash_files(mac_clean)
            net_stage = _classify_network(mac, net, hash_info=hash_info)
            if net_stage != stage_key:
                continue
            entry = _build_kill_chain_network_entry(mac, net, hash_info=hash_info)
            entry["stage"] = stage_key
            if search_text:
                haystack = f"{entry['ssid']} {entry['mac']}".lower()
                if search_text not in haystack:
                    continue
            networks.append(entry)

        networks.sort(key=lambda item: ((item.get("ssid") or "").lower(), (item.get("mac") or "").lower()))
        total_count = len(networks)
        page = networks[offset : offset + limit]
        return ok({
            "stage": stage_key,
            "total": total_count,
            "offset": offset,
            "limit": limit,
            "networks": page,
        })

    return _cache_response(
        "kill_chain_stage",
        (stage_key, search_text, int(limit), int(offset)),
        _build,
        data_revision=data_revision,
        ttl=8.0,
    )


# ---------------------------------------------------------------------------
# 2. Vulnerability Matrix
# ---------------------------------------------------------------------------


@router.get("/api/recon/vulnerability-matrix", tags=["Recon"])
def get_vulnerability_matrix(
    sort_by: str = Query(default="attack_score"),
    sort_dir: str = Query(default="desc"),
    encryption: str = Query(default="all"),
    stage: str = Query(default="all"),
    limit: int = Query(default=100),
    offset: int = Query(default=0),
):
    """Per-network vulnerability profile with scoring and flags."""
    dataset = load_real_data() or {}
    data_revision = int(get_data_revision())
    if limit < 1 or limit > 500:
        fail("limit must be between 1 and 500")
    if offset < 0:
        fail("offset must be >= 0")

    allowed_sort = {"attack_score", "ssid", "encryption", "stage", "readiness_score"}
    if sort_by not in allowed_sort:
        fail(f"Invalid sort_by. Allowed: {', '.join(sorted(allowed_sort))}")
    if sort_dir not in {"asc", "desc"}:
        fail("sort_dir must be 'asc' or 'desc'")

    def _build():
        rows: list[dict] = []
        for mac, net in dataset.items():
            if not isinstance(net, dict):
                continue

            enc = _net_encryption(net)
            if encryption != "all" and enc != encryption.upper():
                continue

            mac_clean = mac.replace(":", "").lower()
            hash_info = _scan_hash_files(mac_clean)

            net_stage = _classify_network(mac, net, hash_info=hash_info)
            if stage != "all" and net_stage != stage:
                continue
            rows.append(_build_vulnerability_row(mac, net, hash_info=hash_info))

        reverse = sort_dir == "desc"
        if sort_by == "attack_score":
            rows.sort(key=lambda r: r.get("attack_score", 0), reverse=reverse)
        elif sort_by == "readiness_score":
            rows.sort(key=lambda r: r.get("readiness_score", 0), reverse=reverse)
        elif sort_by == "ssid":
            rows.sort(key=lambda r: (r.get("ssid") or "").lower(), reverse=reverse)
        elif sort_by == "encryption":
            rows.sort(key=lambda r: r.get("encryption", ""), reverse=reverse)
        elif sort_by == "stage":
            stage_order = {s: i for i, s in enumerate(_KILL_CHAIN_STAGES)}
            rows.sort(
                key=lambda r: stage_order.get(r.get("stage", ""), 99), reverse=reverse
            )

        total_count = len(rows)
        page = rows[offset : offset + limit]
        return ok({"total": total_count, "offset": offset, "limit": limit, "rows": page})

    return _cache_response(
        "vulnerability_matrix",
        (sort_by, sort_dir, encryption.upper(), stage, int(limit), int(offset)),
        _build,
        data_revision=data_revision,
    )


@router.get("/api/recon/target-detail", tags=["Recon"])
def get_target_detail(
    mac: str = Query(..., min_length=2, description="Target MAC address"),
):
    dataset = load_real_data() or {}
    data_revision = int(get_data_revision())
    normalized_mac = str(mac or "").strip().replace("-", ":")

    def _build():
        resolved_mac, net = _resolve_dataset_network(dataset, normalized_mac)
        if not net or not resolved_mac:
            fail("Target not found")
        hash_info = _scan_hash_files(resolved_mac.replace(":", "").lower())
        return ok(_build_vulnerability_row(resolved_mac, net, hash_info=hash_info))

    return _cache_response(
        "target_detail",
        (normalized_mac.lower(),),
        _build,
        data_revision=data_revision,
        extra_signature=(_recon_artifacts_signature(),),
        ttl=10.0,
    )

# ---------------------------------------------------------------------------
# 3. Attack Effectiveness
# ---------------------------------------------------------------------------


@router.get("/api/recon/attack-effectiveness", tags=["Recon"])
def get_attack_effectiveness(
    period: str = Query(default="all"),
):
    """Aggregate cracking history across all networks for effectiveness stats.

    ``period`` – ``24h | 7d | 30d | all`` – filters history entries by time.
    """
    if period not in {"24h", "7d", "30d", "all"}:
        fail("period must be '24h', '7d', '30d', or 'all'")
    dataset = load_real_data() or {}
    data_revision = int(get_data_revision())
    cached = _cache_response_get(
        "attack_effectiveness",
        (period,),
        data_revision=data_revision,
    )
    if cached is not None:
        return cached

    now = time.time()
    period_cutoff = 0.0
    if period == "24h":
        period_cutoff = now - 86400
    elif period == "7d":
        period_cutoff = now - 604800
    elif period == "30d":
        period_cutoff = now - 2592000

    total_attacks = 0
    total_cracked = 0
    total_exhausted = 0
    total_failed = 0

    by_mode: dict[str, dict] = defaultdict(
        lambda: {"attempts": 0, "cracked": 0, "exhausted": 0, "failed": 0,
                 "total_time": 0.0, "timed_count": 0}
    )
    by_encryption: dict[str, dict] = defaultdict(
        lambda: {"targets": 0, "cracked": 0, "attempts": 0}
    )
    wordlist_cracks: Counter = Counter()
    wordlist_uses: Counter = Counter()
    crack_times: list[float] = []

    # O-F2: Cracking velocity — collect (timestamp, mac) for each crack event
    crack_events: list[dict] = []

    enc_seen: dict[str, set] = defaultdict(set)

    for mac, net in dataset.items():
        if not isinstance(net, dict):
            continue

        enc = _net_encryption(net)
        enc_seen[enc].add(mac)

        if net.get("pass"):
            by_encryption[enc]["cracked"] += 1

        # Load history — uses cached dir listing
        mac_clean = mac.replace(":", "").lower()
        history_paths = [
            os.path.join(HANDSHAKES_DIR, name)
            for name in _get_dir_listing()
            if mac_clean in name.lower() and name.endswith(".try")
        ]

        for hp in history_paths:
            try:
                with open(hp, "r", encoding="utf-8") as f:
                    payload = _json.load(f)
                entries = (
                    payload.get("entries", []) if isinstance(payload, dict) else []
                )
            except Exception:
                continue

            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                status = str(entry.get("status") or "").strip().upper()
                if not status:
                    continue

                # Period filter: skip entries outside the window
                entry_ts = _safe_ts(entry.get("end_time") or entry.get("start_time"))
                if period_cutoff > 0 and entry_ts > 0 and entry_ts < period_cutoff:
                    continue

                total_attacks += 1
                by_encryption[enc]["attempts"] += 1

                # Extract mode
                params = entry.get("params") or {}
                mode = str(params.get("attack_mode") or "unknown").strip().lower()
                by_mode[mode]["attempts"] += 1

                # Track wordlist usage (O-F3)
                wl = str(params.get("wordlist") or "").strip()
                wl_name = os.path.basename(wl) if wl else ""
                if wl_name:
                    wordlist_uses[wl_name] += 1

                start = _safe_ts(entry.get("start_time"))
                end = _safe_ts(entry.get("end_time"))
                duration = (end - start) if (start > 0 and end > start) else 0.0

                if status == "CRACKED":
                    total_cracked += 1
                    by_mode[mode]["cracked"] += 1
                    if wl_name:
                        wordlist_cracks[wl_name] += 1
                    if duration > 0:
                        crack_times.append(duration)
                        by_mode[mode]["total_time"] += duration
                        by_mode[mode]["timed_count"] += 1
                    # O-F2: velocity event
                    event_ts = end if end > 0 else start
                    if event_ts > 0:
                        crack_events.append({
                            "ts": datetime.fromtimestamp(event_ts, tz=timezone.utc).isoformat(),
                            "mac": mac,
                            "ssid": net.get("ssid") or "",
                            "mode": mode,
                        })
                elif status == "EXHAUSTED":
                    total_exhausted += 1
                    by_mode[mode]["exhausted"] += 1
                    if duration > 0:
                        by_mode[mode]["total_time"] += duration
                        by_mode[mode]["timed_count"] += 1
                elif status in {"FAILED", "ERROR", "INCOMPLETE"}:
                    total_failed += 1
                    by_mode[mode]["failed"] += 1

    # Finalize encryption stats
    for enc, macs in enc_seen.items():
        by_encryption[enc]["targets"] = len(macs)

    # Sort modes by attempts — include avg_time per mode
    mode_list = []
    for k, v in by_mode.items():
        entry = {"mode": k, "attempts": v["attempts"], "cracked": v["cracked"],
                 "exhausted": v["exhausted"], "failed": v["failed"]}
        if v["timed_count"] > 0:
            entry["avg_time"] = round(v["total_time"] / v["timed_count"], 1)
        else:
            entry["avg_time"] = None
        mode_list.append(entry)
    mode_list.sort(key=lambda x: x["attempts"], reverse=True)

    # O-F3: Wordlist ROI — track cracks AND uses
    wordlist_roi = []
    for name in set(list(wordlist_cracks.keys()) + list(wordlist_uses.keys())):
        cracks = wordlist_cracks.get(name, 0)
        uses = wordlist_uses.get(name, 0)
        rate = round(cracks / uses * 100, 1) if uses > 0 else 0
        wordlist_roi.append({
            "name": name,
            "cracks": cracks,
            "uses": uses,
            "success_rate": rate,
        })
    wordlist_roi.sort(key=lambda x: x["cracks"], reverse=True)

    # Backward-compat: top_wordlists (cracks only, legacy format)
    top_wordlists = [
        {"name": w["name"], "cracks": w["cracks"]}
        for w in wordlist_roi[:10]
    ]

    # Encryption breakdown
    enc_list = sorted(
        [{"encryption": k, **v} for k, v in by_encryption.items()],
        key=lambda x: x["targets"],
        reverse=True,
    )

    avg_crack_time = (
        round(sum(crack_times) / len(crack_times), 1) if crack_times else None
    )

    # O-F2: sort velocity events by timestamp
    crack_events.sort(key=lambda e: e["ts"])

    result = ok(
        {
            "total_attacks": total_attacks,
            "total_cracked": total_cracked,
            "total_exhausted": total_exhausted,
            "total_failed": total_failed,
            "success_rate": (
                round(total_cracked / total_attacks * 100, 1) if total_attacks else 0
            ),
            "period": period,
            "by_mode": mode_list,
            "by_encryption": enc_list,
            "top_wordlists": top_wordlists,
            "wordlist_roi": wordlist_roi[:20],
            "avg_crack_time_seconds": avg_crack_time,
            "crack_velocity": crack_events[:200],
        }
    )
    return _cache_response_set(
        "attack_effectiveness",
        (period,),
        result,
        data_revision=data_revision,
    )


# ---------------------------------------------------------------------------
# 4. Temporal Intelligence
# ---------------------------------------------------------------------------


@router.get("/api/recon/temporal-intel", tags=["Recon"])
def get_temporal_intel():
    """Analyze temporal patterns across all networks."""
    dataset = load_real_data() or {}
    data_revision = int(get_data_revision())
    cached = _cache_response_get("temporal_intel", tuple(), data_revision=data_revision)
    if cached is not None:
        return cached
    now = time.time()
    hour_dist = [0] * 24
    day_dist = [0] * 7  # 0=Monday .. 6=Sunday
    freshness = {"active_24h": 0, "active_7d": 0, "stale_30d": 0, "ancient": 0}
    timestamps: list[float] = []

    # G-F5: Per-source temporal tracking
    source_hour_dist: dict[str, list[int]] = defaultdict(lambda: [0] * 24)
    source_day_dist: dict[str, list[int]] = defaultdict(lambda: [0] * 7)
    source_gps_count: Counter = Counter()
    source_gps_origin: Counter = Counter()  # networks whose GPS came FROM this source
    total_gps = 0

    # G-F4: Track daily new-network discovery for anomaly detection
    daily_counts: Counter = Counter()

    for mac, net in dataset.items():
        if not isinstance(net, dict):
            continue
        ts = _safe_ts(net.get("ts_last"))
        if ts <= 0:
            freshness["ancient"] += 1
            continue
        timestamps.append(ts)

        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        hour_dist[dt.hour] += 1
        day_dist[dt.weekday()] += 1

        has_gps = bool(
            net.get("lat") and net.get("lng")
            and (net.get("lat") != 0 or net.get("lng") != 0)
        )
        if has_gps:
            total_gps += 1

        # G-F5: attribute activity to each source
        sources = net.get("sources") or []
        if not sources:
            sources = ["unknown"]
        for src in sources:
            source_hour_dist[src][dt.hour] += 1
            source_day_dist[src][dt.weekday()] += 1
            if has_gps:
                source_gps_count[src] += 1

        # GPS origin attribution: pwnagotchi GPS takes priority (wardrive never
        # overwrites it), so if a network has pwnagotchi + GPS the origin is
        # pwnagotchi; otherwise wardrive is sub-classified by device.
        if has_gps:
            if "pwnagotchi" in sources:
                source_gps_origin["pwnagotchi"] += 1
            elif "wardrive" in sources:
                # Classify wardrive by device from the wardrive session data
                wd_sessions = net.get("wardrive_sessions") or []
                wd_device = "uncategorized"
                for ws in wd_sessions:
                    d = (ws.get("device") or "").strip()
                    if d and d != "uncategorized":
                        wd_device = d
                        break
                source_gps_origin[f"wardrive:{wd_device}"] += 1
            else:
                # Fallback — attribute to first source
                source_gps_origin[sources[0]] += 1

        # Per-day counter for anomaly detection (use ISO date string)
        daily_counts[dt.strftime("%Y-%m-%d")] += 1

        age = now - ts
        if age < 86400:
            freshness["active_24h"] += 1
        elif age < 604800:
            freshness["active_7d"] += 1
        elif age < 2592000:
            freshness["stale_30d"] += 1
        else:
            freshness["ancient"] += 1

    # Activity windows (top 3 hours)
    hour_labels = [f"{h:02d}:00" for h in range(24)]
    top_hours = sorted(range(24), key=lambda h: hour_dist[h], reverse=True)[:3]
    day_labels = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    top_days = sorted(range(7), key=lambda d: day_dist[d], reverse=True)[:3]

    # Timestamp spread
    first_seen = min(timestamps) if timestamps else None
    last_seen = max(timestamps) if timestamps else None

    # G-F5: Build per-source breakdown
    by_source: dict[str, dict] = {}
    for src in sorted(source_hour_dist.keys()):
        by_source[src] = {
            "hour_distribution": [
                {"hour": hour_labels[i], "count": source_hour_dist[src][i]}
                for i in range(24)
            ],
            "day_distribution": [
                {"day": day_labels[i], "count": source_day_dist[src][i]}
                for i in range(7)
            ],
            "total": sum(source_hour_dist[src]),
            "gps_count": source_gps_count.get(src, 0),
            "gps_origin_count": source_gps_origin.get(src, 0),
        }

    # G-F4: Simple anomaly detection — detect daily spikes (>2× avg) and gaps
    anomalies: list[dict] = []
    if daily_counts:
        counts_list = list(daily_counts.values())
        avg_daily = sum(counts_list) / len(counts_list) if counts_list else 0
        threshold = max(avg_daily * 2, 5)  # at least 5 to avoid noise on tiny datasets
        for date_str, count in sorted(daily_counts.items()):
            if count >= threshold and avg_daily > 0:
                anomalies.append({
                    "type": "spike",
                    "date": date_str,
                    "count": count,
                    "avg": round(avg_daily, 1),
                    "description": f"Spike: {count} networks active on {date_str} (avg {round(avg_daily, 1)})",
                })
        # Detect gaps: if span > 2 days but some days have 0 activity
        if len(daily_counts) >= 2:
            sorted_dates = sorted(daily_counts.keys())
            from datetime import timedelta
            prev_date = datetime.strptime(sorted_dates[0], "%Y-%m-%d")
            for ds in sorted_dates[1:]:
                cur_date = datetime.strptime(ds, "%Y-%m-%d")
                gap_days = (cur_date - prev_date).days
                if gap_days > 2:
                    anomalies.append({
                        "type": "gap",
                        "start": (prev_date + timedelta(days=1)).strftime("%Y-%m-%d"),
                        "end": (cur_date - timedelta(days=1)).strftime("%Y-%m-%d"),
                        "days": gap_days - 1,
                        "description": f"No activity for {gap_days - 1} days ({(prev_date + timedelta(days=1)).strftime('%Y-%m-%d')} – {(cur_date - timedelta(days=1)).strftime('%Y-%m-%d')})",
                    })
                prev_date = cur_date

    return _cache_response_set(
        "temporal_intel",
        tuple(),
        ok(
        {
            "total_networks": len(dataset),
            "freshness": freshness,
            "hour_distribution": [
                {"hour": hour_labels[i], "count": hour_dist[i]} for i in range(24)
            ],
            "day_distribution": [
                {"day": day_labels[i], "count": day_dist[i]} for i in range(7)
            ],
            "top_active_hours": [
                {"hour": hour_labels[h], "count": hour_dist[h]} for h in top_hours
            ],
            "top_active_days": [
                {"day": day_labels[d], "count": day_dist[d]} for d in top_days
            ],
            "first_seen": (
                datetime.fromtimestamp(first_seen, tz=timezone.utc).isoformat()
                if first_seen
                else None
            ),
            "last_seen": (
                datetime.fromtimestamp(last_seen, tz=timezone.utc).isoformat()
                if last_seen
                else None
            ),
            "total_gps": total_gps,
            "gps_origin": dict(source_gps_origin),
            "by_source": by_source,
            "anomalies": anomalies[:20],
        }
        ),
        data_revision=data_revision,
    )


# ---------------------------------------------------------------------------
# 5. Audit Report
# ---------------------------------------------------------------------------


def _build_audit_report_data() -> dict:
    """Build audit report data. Shared by the endpoint, snapshots, and comparison."""
    dataset = load_real_data() or {}

    # --- Methodology ---
    tools = []
    from app.core.config import load_config

    cfg = load_config()
    if cfg.get("hashcat_path"):
        tools.append("hashcat")
    if cfg.get("aircrack_path"):
        tools.append("aircrack-ng")
    if cfg.get("hcxpcapngtool_path"):
        tools.append("hcxpcapngtool")
    if cfg.get("tshark_path"):
        tools.append("tshark")

    sources_used: set[str] = set()
    for net in dataset.values():
        if isinstance(net, dict):
            for s in net.get("sources") or []:
                sources_used.add(s)

    # --- Findings ---
    total = len(dataset)
    enc_dist: Counter = Counter()
    cracked_count = 0
    with_handshake = 0
    with_eapol = 0
    device_dist: Counter = Counter()

    # R-F7: Coverage tracking
    with_gps = 0
    with_fingerprint = 0
    with_raw_data = 0
    multi_source = 0
    with_hash = 0
    hash_cache: dict[str, dict] = {}

    for mac, net in dataset.items():
        if not isinstance(net, dict):
            continue
        enc_dist[_net_encryption(net)] += 1
        if net.get("pass"):
            cracked_count += 1
        if net.get("handshake"):
            with_handshake += 1
        if int(net.get("raw_eapol_count") or 0) > 0:
            with_eapol += 1
        device_dist[net.get("device_type") or "unknown"] += 1

        # Coverage
        if net.get("lat") and net.get("lng"):
            with_gps += 1
        sources = net.get("sources") or []
        if len(sources) >= 2:
            multi_source += 1
        if int(net.get("raw_beacon_count") or 0) > 0 or int(net.get("raw_eapol_count") or 0) > 0:
            with_raw_data += 1
        mac_clean = mac.replace(":", "").lower()
        # Check fingerprint (.details) — uses cached dir listing
        if any(mac_clean in n.lower() and n.endswith(".details") for n in _get_dir_listing()):
            with_fingerprint += 1
        # Check hash
        hash_info = _scan_hash_files(mac_clean)
        hash_cache[mac_clean] = hash_info
        if hash_info["has_hash"]:
            with_hash += 1

    # --- Statistics ---
    crackable = sum(
        1
        for net in dataset.values()
        if isinstance(net, dict)
        and _net_encryption(net) not in {"OPEN", "UNK"}
        and not net.get("pass")
    )

    timestamps = [
        _safe_ts(net.get("ts_last"))
        for net in dataset.values()
        if isinstance(net, dict) and _safe_ts(net.get("ts_last")) > 0
    ]

    # R-F1: Recommendations engine (rule-based)
    recommendations: list[dict] = []

    eapol_no_hash_count = 0
    pmkid_targets = 0
    wep_count = enc_dist.get("WEP", 0)
    for mac, net in dataset.items():
        if not isinstance(net, dict):
            continue
        mc = mac.replace(":", "").lower()
        hi = hash_cache.get(mc) or _scan_hash_files(mc)
        if int(net.get("raw_eapol_count") or 0) > 0 and not hi["has_hash"]:
            eapol_no_hash_count += 1
        if hi["has_pmkid"] and not net.get("pass"):
            pmkid_targets += 1

    if eapol_no_hash_count > 0:
        recommendations.append({
            "priority": "high",
            "action": "convert_hashes",
            "description": f"{eapol_no_hash_count} network(s) have EAPOL evidence but no .22000 hash — convert captures with hcxpcapngtool.",
            "count": eapol_no_hash_count,
        })
    if pmkid_targets > 0:
        recommendations.append({
            "priority": "high",
            "action": "attack_pmkid",
            "description": f"{pmkid_targets} uncracked target(s) with PMKID available — prioritize hashcat mode 22000.",
            "count": pmkid_targets,
        })
    if wep_count > 0:
        recommendations.append({
            "priority": "medium",
            "action": "attack_wep",
            "description": f"{wep_count} WEP network(s) detected — use aircrack-ng direct attack (trivially breakable).",
            "count": wep_count,
        })
    if with_handshake > with_hash:
        gap = with_handshake - with_hash
        recommendations.append({
            "priority": "medium",
            "action": "extract_hashes",
            "description": f"{gap} network(s) have handshake captures but no extracted hash — run hash extraction pipeline.",
            "count": gap,
        })
    if crackable > 0 and cracked_count == 0:
        recommendations.append({
            "priority": "low",
            "action": "start_cracking",
            "description": f"{crackable} crackable network(s) with 0 cracks — begin attack operations.",
            "count": crackable,
        })

    # R-F2: Risk scoring per encryption type
    risk_scoring: list[dict] = []
    for enc, count in enc_dist.most_common():
        enc_cracked = sum(
            1 for net in dataset.values()
            if isinstance(net, dict) and _net_encryption(net) == enc and net.get("pass")
        )
        enc_rate = round(enc_cracked / count * 100, 1) if count > 0 else 0
        if enc == "OPEN":
            grade = "N/A"
        elif enc == "WEP":
            grade = "F"
        elif enc_rate >= 60:
            grade = "A"
        elif enc_rate >= 40:
            grade = "B"
        elif enc_rate >= 20:
            grade = "C"
        elif enc_rate >= 10:
            grade = "D"
        else:
            grade = "F"
        risk_scoring.append({
            "encryption": enc,
            "total": count,
            "cracked": enc_cracked,
            "crack_rate": enc_rate,
            "grade": grade,
        })

    # R-F7: Coverage analysis
    coverage = {
        "total": total,
        "with_gps": with_gps,
        "with_gps_pct": round(with_gps / total * 100, 1) if total else 0,
        "with_fingerprint": with_fingerprint,
        "with_fingerprint_pct": round(with_fingerprint / total * 100, 1) if total else 0,
        "with_raw_data": with_raw_data,
        "with_raw_data_pct": round(with_raw_data / total * 100, 1) if total else 0,
        "with_hash": with_hash,
        "with_hash_pct": round(with_hash / total * 100, 1) if total else 0,
        "multi_source": multi_source,
        "multi_source_pct": round(multi_source / total * 100, 1) if total else 0,
    }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "methodology": {
            "tools": tools,
            "sources": sorted(sources_used),
            "total_networks_analyzed": total,
        },
        "findings": {
            "total_networks": total,
            "cracked": cracked_count,
            "crackable_remaining": crackable,
            "with_handshake": with_handshake,
            "with_eapol_evidence": with_eapol,
            "encryption_distribution": dict(enc_dist.most_common()),
            "device_distribution": dict(device_dist.most_common()),
            "crack_rate_percent": (
                round(cracked_count / total * 100, 1) if total else 0
            ),
        },
        "statistics": {
            "first_observation": (
                datetime.fromtimestamp(
                    min(timestamps), tz=timezone.utc
                ).isoformat()
                if timestamps
                else None
            ),
            "last_observation": (
                datetime.fromtimestamp(
                    max(timestamps), tz=timezone.utc
                ).isoformat()
                if timestamps
                else None
            ),
            "observation_span_days": (
                round((max(timestamps) - min(timestamps)) / 86400, 1)
                if len(timestamps) >= 2
                else 0
            ),
        },
        "recommendations": recommendations,
        "risk_scoring": risk_scoring,
        "coverage": coverage,
    }


@router.get("/api/recon/audit-report", tags=["Recon"])
def get_audit_report():
    """Generate a structured audit report for the current dataset."""
    load_real_data()
    data_revision = int(get_data_revision())
    cached = _cache_response_get("audit_report", tuple(), data_revision=data_revision)
    if cached is not None:
        return cached
    return _cache_response_set(
        "audit_report",
        tuple(),
        ok(_build_audit_report_data()),
        data_revision=data_revision,
    )


# ---------------------------------------------------------------------------
# 6. Kill-Chain Snapshots  (S-F3)
# ---------------------------------------------------------------------------

_KC_SNAPSHOT_FILE = os.path.join(_SNAPSHOT_DIR, "killchain_history.json")


def _load_kc_snapshots() -> list[dict]:
    """Load kill-chain snapshot history from disk."""
    if not os.path.isfile(_KC_SNAPSHOT_FILE):
        return []
    try:
        with open(_KC_SNAPSHOT_FILE, "r") as f:
            data = _json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _save_kc_snapshots(snapshots: list[dict]) -> None:
    with open(_KC_SNAPSHOT_FILE, "w") as f:
        _json.dump(snapshots, f)


@router.post("/api/recon/kill-chain/snapshot", tags=["Recon"])
def create_kc_snapshot():
    """Take a point-in-time snapshot of kill-chain stage counts."""
    dataset = load_real_data() or {}
    counts: dict[str, int] = {s: 0 for s in _KILL_CHAIN_STAGES}
    for mac, net in dataset.items():
        if not isinstance(net, dict):
            continue
        mac_clean = mac.replace(":", "").lower()
        hash_info = _scan_hash_files(mac_clean)
        stage = _classify_network(mac, net, hash_info=hash_info)
        counts[stage] += 1

    snapshot = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "total": sum(counts.values()),
        "counts": counts,
    }
    snapshots = _load_kc_snapshots()
    snapshots.append(snapshot)
    # Keep max 100 snapshots
    if len(snapshots) > 100:
        snapshots = snapshots[-100:]
    _save_kc_snapshots(snapshots)
    return ok(snapshot)


@router.get("/api/recon/kill-chain/history", tags=["Recon"])
def get_kc_history():
    """Return kill-chain snapshot history for sparklines / trend charts."""
    snapshots = _load_kc_snapshots()
    return ok({"snapshots": snapshots, "count": len(snapshots)})


# ---------------------------------------------------------------------------
# 7. Audit Report Snapshots & Comparison  (R-F5)
# ---------------------------------------------------------------------------

_REPORT_SNAPSHOT_DIR = os.path.join(_SNAPSHOT_DIR, "reports")
os.makedirs(_REPORT_SNAPSHOT_DIR, exist_ok=True)


@router.post("/api/recon/audit-report/snapshot", tags=["Recon"])
def save_report_snapshot():
    """Save current audit report as a named snapshot."""
    report_data = _build_audit_report_data()
    snap_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = os.path.join(_REPORT_SNAPSHOT_DIR, f"report_{snap_id}.json")
    with open(path, "w") as f:
        _json.dump(report_data, f)
    return ok({"snapshot_id": snap_id, "path": path})


@router.get("/api/recon/audit-report/snapshots", tags=["Recon"])
def list_report_snapshots():
    """List available report snapshots."""
    snaps: list[dict] = []
    if os.path.isdir(_REPORT_SNAPSHOT_DIR):
        for name in sorted(os.listdir(_REPORT_SNAPSHOT_DIR)):
            if name.startswith("report_") and name.endswith(".json"):
                snap_id = name[7:-5]
                path = os.path.join(_REPORT_SNAPSHOT_DIR, name)
                try:
                    ts = os.path.getmtime(path)
                    snaps.append({
                        "id": snap_id,
                        "created": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
                    })
                except OSError:
                    pass
    return ok({"snapshots": snaps})


@router.get("/api/recon/audit-report/compare", tags=["Recon"])
def compare_report_snapshots(
    snapshot_id: str = Query(..., description="Snapshot ID to compare against current"),
):
    """Compare current report with a saved snapshot."""
    if not snapshot_id or "/" in snapshot_id or "\\" in snapshot_id or ".." in snapshot_id:
        fail("Invalid snapshot ID")
    path = os.path.join(_REPORT_SNAPSHOT_DIR, f"report_{snapshot_id}.json")
    if not os.path.isfile(path):
        return fail("Snapshot not found")

    try:
        with open(path, "r") as f:
            old = _json.load(f)
    except Exception:
        return fail("Could not read snapshot")

    current = _generate_audit_report_data()

    old_f = old.get("findings", {})
    cur_f = current.get("findings", {})

    delta = {
        "snapshot_id": snapshot_id,
        "snapshot_date": old.get("generated_at", ""),
        "current_date": current.get("generated_at", ""),
        "total_networks": {"old": old_f.get("total_networks", 0), "new": cur_f.get("total_networks", 0)},
        "cracked": {"old": old_f.get("cracked", 0), "new": cur_f.get("cracked", 0)},
        "crack_rate_percent": {"old": old_f.get("crack_rate_percent", 0), "new": cur_f.get("crack_rate_percent", 0)},
        "crackable_remaining": {"old": old_f.get("crackable_remaining", 0), "new": cur_f.get("crackable_remaining", 0)},
        "with_handshake": {"old": old_f.get("with_handshake", 0), "new": cur_f.get("with_handshake", 0)},
    }
    # Compute deltas
    for key in ["total_networks", "cracked", "crack_rate_percent", "crackable_remaining", "with_handshake"]:
        delta[key]["delta"] = delta[key]["new"] - delta[key]["old"]

    # Encryption comparison
    old_enc = old_f.get("encryption_distribution", {})
    cur_enc = cur_f.get("encryption_distribution", {})
    all_enc_types = set(old_enc.keys()) | set(cur_enc.keys())
    enc_diff = {}
    for enc in sorted(all_enc_types):
        enc_diff[enc] = {
            "old": old_enc.get(enc, 0),
            "new": cur_enc.get(enc, 0),
            "delta": cur_enc.get(enc, 0) - old_enc.get(enc, 0),
        }
    delta["encryption"] = enc_diff

    return ok(delta)


def _generate_audit_report_data() -> dict:
    """Generate audit report data dict (reusable by snapshot/compare)."""
    return _build_audit_report_data()


# ---------------------------------------------------------------------------
# 8. Attack Planner  (O-F6)
# ---------------------------------------------------------------------------

class AttackPlanRequest(BaseModel):
    targets: list[str] = Field(..., description="List of MAC addresses")
    strategy: str = Field(default="auto", description="auto|dictionary|bruteforce|pmk")
    wordlist: str | None = Field(default=None)


@router.post("/api/recon/attack-plan", tags=["Recon"])
def create_attack_plan(plan: AttackPlanRequest):
    """Create a batch attack plan for selected targets.

    Returns planned operations with estimated details — does NOT start jobs.
    """
    dataset = load_real_data() or {}
    operations: list[dict] = []

    for mac in plan.targets[:50]:  # cap at 50
        mac_upper = mac.upper().replace("-", ":")
        mac_lower = mac_upper.lower()
        net = dataset.get(mac_upper) or dataset.get(mac_lower)
        if not net or not isinstance(net, dict):
            operations.append({"mac": mac_upper, "skip": True, "reason": "not_found"})
            continue

        mac_clean = mac_upper.replace(":", "").lower()
        hash_info = _scan_hash_files(mac_clean)
        enc = _net_encryption(net)

        if net.get("pass"):
            operations.append({"mac": mac_upper, "ssid": net.get("ssid", ""), "skip": True, "reason": "already_cracked"})
            continue

        op: dict[str, Any] = {
            "mac": mac_upper,
            "ssid": net.get("ssid", ""),
            "encryption": enc,
            "skip": False,
        }

        strategy = plan.strategy

        # Auto-select strategy
        if strategy == "auto":
            if enc == "WEP":
                strategy = "aircrack_wep"
            elif hash_info["has_pmkid"]:
                strategy = "pmk" if not plan.wordlist else "dictionary"
            elif hash_info["has_hash"]:
                strategy = "dictionary"
            else:
                op["skip"] = True
                op["reason"] = "no_hash"
                operations.append(op)
                continue

        op["strategy"] = strategy
        op["has_hash"] = hash_info["has_hash"]
        op["has_pmkid"] = hash_info["has_pmkid"]

        if strategy == "dictionary":
            op["mode"] = "hashcat"
            op["wordlist"] = plan.wordlist or "rockyou.txt"
            op["estimated_time"] = "varies"
        elif strategy == "bruteforce":
            op["mode"] = "hashcat_bruteforce"
            op["estimated_time"] = "long"
        elif strategy == "pmk":
            op["mode"] = "pmk_attack"
            op["estimated_time"] = "fast"
        elif strategy == "aircrack_wep":
            op["mode"] = "aircrack_wep"
            op["estimated_time"] = "seconds"

        operations.append(op)

    executable = [o for o in operations if not o.get("skip")]
    return ok({
        "total_targets": len(plan.targets),
        "executable": len(executable),
        "skipped": len(operations) - len(executable),
        "operations": operations,
    })


# ---------------------------------------------------------------------------
# 9. COMMS Intelligence  (C-F1, C-F2, C-F3)
# ---------------------------------------------------------------------------

@router.get("/api/recon/comms/device-fingerprints", tags=["Recon"])
def get_device_fingerprints():
    """C-F2: Aggregate device types by OUI / manufacturer.

    Groups networks by device_type with encryption, channel, and RSSI
    stats.  Also returns channel distribution and raw-sniffer activity
    totals.
    """
    dataset = load_real_data() or {}
    data_revision = int(get_data_revision())
    cached = _cache_response_get("device_fingerprints", tuple(), data_revision=data_revision)
    if cached is not None:
        return cached
    return _cache_response_set(
        "device_fingerprints",
        tuple(),
        ok(build_device_fingerprints_payload(dataset)),
        data_revision=data_revision,
    )


@router.get("/api/recon/comms/colocation", tags=["Recon"])
def get_colocation_analysis():
    """C-F3: Identify networks that co-locate (appear together in space/time).

    Groups networks sharing GPS coordinates within ~50m radius.  Returns
    enriched cluster cards with radius, source breakdown, dominant
    encryption, RSSI stats, and a heuristic label.
    """
    dataset = load_real_data() or {}
    data_revision = int(get_data_revision())
    cached = _cache_response_get("colocation", tuple(), data_revision=data_revision)
    if cached is not None:
        return cached
    return _cache_response_set(
        "colocation",
        tuple(),
        ok(build_colocation_payload(dataset)),
        data_revision=data_revision,
    )


@router.get("/api/recon/comms/relationship-graph", tags=["Recon"])
def get_relationship_graph():
    """C-F1: Network-Client relationship graph for visualization.

    Nodes = known APs + probing clients.
    Edges = probe requests linking clients to SSIDs.
    """
    dataset = load_real_data() or {}
    data_revision = int(get_data_revision())
    probe_status = probe_service.get_cache_status()
    probe_signature = _probe_cache_signature(probe_status)
    cached = _cache_response_get(
        "relationship_graph",
        tuple(),
        data_revision=data_revision,
        extra_signature=probe_signature,
    )
    if cached is not None:
        return cached

    return _cache_response_set(
        "relationship_graph",
        tuple(),
        ok(build_relationship_graph_payload(dataset, probe_status)),
        data_revision=data_revision,
        extra_signature=probe_signature,
    )


@router.get("/api/recon/comms/spectrum", tags=["Recon"])
def get_spectrum_analysis():
    """C-F4: WiFi channel usage, band split, and congestion analysis.

    Aggregates channel data already loaded from wardrive CSVs and raw
    sniffer metadata to produce a spectrum overview without any new
    data collection pipeline.
    """
    dataset = load_real_data() or {}
    data_revision = int(get_data_revision())
    cached = _cache_response_get("spectrum", tuple(), data_revision=data_revision)
    if cached is not None:
        return cached
    return _cache_response_set(
        "spectrum",
        tuple(),
        ok(build_spectrum_payload(dataset)),
        data_revision=data_revision,
    )


@router.get("/api/recon/comms/signal-landscape", tags=["Recon"])
def get_signal_landscape():
    """C-F5: RSSI distribution, per-encryption and per-source signal stats.

    Buckets RSSI values into ranges and highlights physically-proximate
    strong-signal targets useful for operational prioritisation.
    """
    dataset = load_real_data() or {}
    data_revision = int(get_data_revision())
    cached = _cache_response_get("signal_landscape", tuple(), data_revision=data_revision)
    if cached is not None:
        return cached
    return _cache_response_set(
        "signal_landscape",
        tuple(),
        ok(build_signal_landscape_payload(dataset)),
        data_revision=data_revision,
    )


@router.get("/api/recon/probe-intel/derandom", tags=["Recon"])
def get_probe_derandomization():
    """SI-F5: Heuristic MAC de-randomization analysis.

    Groups clients by probe SSID fingerprint similarity.
    Random MACs probing the same set of SSIDs are likely the same device.
    """
    status = probe_service.get_cache_status()
    dataset = load_real_data() or {}
    data_revision = int(get_data_revision())
    probe_signature = _probe_cache_signature(status)
    cached = _cache_response_get(
        "probe_derandom",
        tuple(),
        data_revision=data_revision,
        extra_signature=probe_signature,
    )
    if cached is not None:
        return cached
    if not status.get("cached") or not status.get("result"):
        return _cache_response_set(
            "probe_derandom",
            tuple(),
            ok({"groups": [], "message": "Run probe intel scan first"}),
            data_revision=data_revision,
            extra_signature=probe_signature,
        )

    return _cache_response_set(
        "probe_derandom",
        tuple(),
        ok(build_probe_derandomization_payload(dataset, status)),
        data_revision=data_revision,
        extra_signature=probe_signature,
    )


@router.get("/api/recon/probe-intel/geocorrelation", tags=["Recon"])
def get_probe_geocorrelation():
    """SI-F7: Cross-reference probe SSIDs with GPS-located networks.

    For each client, if probed SSIDs match known networks with GPS,
    estimate client location radius.
    """
    dataset = load_real_data() or {}
    status = probe_service.get_cache_status()
    data_revision = int(get_data_revision())
    probe_signature = _probe_cache_signature(status)
    cached = _cache_response_get(
        "probe_geocorrelation",
        tuple(),
        data_revision=data_revision,
        extra_signature=probe_signature,
    )
    if cached is not None:
        return cached
    if not status.get("cached") or not status.get("result"):
        return _cache_response_set(
            "probe_geocorrelation",
            tuple(),
            ok({"clients": [], "message": "Run probe intel scan first"}),
            data_revision=data_revision,
            extra_signature=probe_signature,
        )

    return _cache_response_set(
        "probe_geocorrelation",
        tuple(),
        ok(build_probe_geocorrelation_payload(dataset, status)),
        data_revision=data_revision,
        extra_signature=probe_signature,
    )
