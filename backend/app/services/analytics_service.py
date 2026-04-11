import math
import time
from collections import Counter
from copy import deepcopy
from datetime import UTC, datetime
from typing import Dict, List, Tuple

from app.services.data_loader import get_wardrive_sessions, load_real_data
from app.services.zones_service import cluster_points


class AnalyticsService:
    SCHEMA_VERSION = 1
    _EARTH_RADIUS_M = 6_371_000.0

    _ALLOWED_METRICS = {"density", "opportunity", "eapol", "beacon", "probe"}
    _ALLOWED_TIME_WINDOWS = {"all", "24h"}
    _ALLOWED_SOURCES = {"all", "pwn", "bruce", "m5", "ward", "raw"}
    _ALLOWED_SECURITY = {"all", "locked", "open", "cracked"}
    _ALLOWED_DEVICE_TYPES = {
        "all",
        "router_ap",
        "phone_hotspot",
        "camera_ap",
        "printer_ap",
        "iot_ap",
        "unknown",
    }
    _DEVICE_TYPE_ALIASES = {
        "router": "router_ap",
        "ap_router": "router_ap",
        "hotspot": "phone_hotspot",
        "mobile_hotspot": "phone_hotspot",
        "camera": "camera_ap",
        "printer": "printer_ap",
        "iot": "iot_ap",
    }

    def __init__(self):
        self._rows_cache_signature: Tuple[int, int, int] | None = None
        self._rows_cache: List[Dict] = []
        self._response_cache: Dict[Tuple, Dict] = {}

    @staticmethod
    def _haversine_meters(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        d_lat = lat2_rad - lat1_rad
        d_lng = math.radians(lng2 - lng1)
        a = (
            math.sin(d_lat / 2) ** 2
            + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(d_lng / 2) ** 2
        )
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(max(0.0, 1 - a)))
        return AnalyticsService._EARTH_RADIUS_M * c

    @staticmethod
    def _percentile(values: List[float], percentile: float) -> float:
        if not values:
            return 0.0
        p = AnalyticsService._clamp(float(percentile), 0.0, 100.0)
        ordered = sorted(float(item) for item in values)
        if len(ordered) == 1:
            return ordered[0]
        rank = (p / 100.0) * (len(ordered) - 1)
        lower_idx = int(math.floor(rank))
        upper_idx = int(math.ceil(rank))
        if lower_idx == upper_idx:
            return ordered[lower_idx]
        fraction = rank - lower_idx
        return ordered[lower_idx] + (ordered[upper_idx] - ordered[lower_idx]) * fraction

    def _nearest_neighbor_distances(
        self, rows: List[Dict], sample_limit: int = 350
    ) -> List[float]:
        if len(rows) < 2:
            return []

        selected_rows = rows
        if len(rows) > sample_limit:
            step = max(1, len(rows) // sample_limit)
            selected_rows = rows[::step][:sample_limit]

        points: List[Tuple[float, float]] = [
            (float(row.get("lat") or 0.0), float(row.get("lng") or 0.0))
            for row in selected_rows
        ]
        if len(points) < 2:
            return []

        distances: List[float] = []
        for idx, (lat, lng) in enumerate(points):
            nearest = None
            for jdx, (other_lat, other_lng) in enumerate(points):
                if idx == jdx:
                    continue
                distance = self._haversine_meters(lat, lng, other_lat, other_lng)
                if nearest is None or distance < nearest:
                    nearest = distance
            if nearest is not None and math.isfinite(nearest):
                distances.append(float(nearest))
        return distances

    def _compute_adaptive_eps_m(self, rows: List[Dict]) -> Tuple[float, float]:
        nearest_distances = self._nearest_neighbor_distances(rows)
        nearest_p75 = (
            self._percentile(nearest_distances, 75.0) if nearest_distances else 100.0
        )
        eps_m = self._clamp(nearest_p75 * 1.35, 70.0, 220.0)
        return float(eps_m), float(nearest_p75)

    @staticmethod
    def _cross(
        o: Tuple[float, float], a: Tuple[float, float], b: Tuple[float, float]
    ) -> float:
        return (a[0] - o[0]) * (b[1] - o[1]) - (a[1] - o[1]) * (b[0] - o[0])

    def _convex_hull_mesh(self, members: List[Dict]) -> List[Dict[str, float]]:
        points = sorted(
            {
                (
                    round(float(item.get("lng") or 0.0), 7),
                    round(float(item.get("lat") or 0.0), 7),
                )
                for item in members
            }
        )
        if len(points) < 3:
            return []

        lower: List[Tuple[float, float]] = []
        for point in points:
            while len(lower) >= 2 and self._cross(lower[-2], lower[-1], point) <= 0:
                lower.pop()
            lower.append(point)

        upper: List[Tuple[float, float]] = []
        for point in reversed(points):
            while len(upper) >= 2 and self._cross(upper[-2], upper[-1], point) <= 0:
                upper.pop()
            upper.append(point)

        hull = lower[:-1] + upper[:-1]
        if len(hull) < 3:
            return []

        return [{"lat": lat, "lng": lng} for lng, lat in hull]

    def _fallback_mesh(
        self, center_lat: float, center_lng: float, radius_m: float
    ) -> List[Dict[str, float]]:
        radius = max(20.0, float(radius_m))
        lat_deg = radius / 111_320.0
        lng_deg = radius / (
            111_320.0 * max(0.25, abs(math.cos(math.radians(center_lat))))
        )
        return [
            {"lat": round(center_lat + lat_deg * 0.8, 7), "lng": round(center_lng, 7)},
            {
                "lat": round(center_lat + lat_deg * 0.2, 7),
                "lng": round(center_lng + lng_deg, 7),
            },
            {
                "lat": round(center_lat - lat_deg * 0.8, 7),
                "lng": round(center_lng + lng_deg * 0.45, 7),
            },
            {
                "lat": round(center_lat - lat_deg * 0.8, 7),
                "lng": round(center_lng - lng_deg * 0.45, 7),
            },
            {
                "lat": round(center_lat + lat_deg * 0.2, 7),
                "lng": round(center_lng - lng_deg, 7),
            },
        ]

    def _build_hotspot_mesh(
        self, members: List[Dict], center_lat: float, center_lng: float, radius_m: float
    ) -> List[Dict[str, float]]:
        hull_mesh = self._convex_hull_mesh(members)
        if hull_mesh:
            return hull_mesh
        return self._fallback_mesh(center_lat, center_lng, radius_m)

    def _cluster_metric_value(self, cluster: Dict, metric: str) -> float:
        if metric == "density":
            return float(cluster.get("members_count") or 0)
        if metric == "eapol":
            return float(cluster.get("raw_eapol_sum") or 0)
        if metric == "beacon":
            return float(cluster.get("raw_beacon_sum") or 0)
        if metric == "probe":
            return float(cluster.get("raw_probe_peak_sum") or 0)
        return float(cluster.get("opportunity_avg") or 0.0)

    def _build_hotspot_clusters(
        self, rows: List[Dict], metric: str, eps_m: float, min_samples: int
    ) -> List[Dict]:
        zones = cluster_points(rows, eps_m=eps_m, min_samples=min_samples)
        clusters: List[Dict] = []

        for zone in zones:
            members = [
                item for item in (zone.get("points") or []) if isinstance(item, dict)
            ]
            members_count = len(members)
            if members_count <= 0:
                continue

            center = zone.get("center") or {}
            center_lat = float(center.get("lat") or 0.0)
            center_lng = float(center.get("lng") or 0.0)

            lat_values = [float(item.get("lat") or 0.0) for item in members]
            lng_values = [float(item.get("lng") or 0.0) for item in members]
            extent_bbox = {
                "min_lat": round(min(lat_values), 7),
                "min_lng": round(min(lng_values), 7),
                "max_lat": round(max(lat_values), 7),
                "max_lng": round(max(lng_values), 7),
            }

            distances_to_center = [
                self._haversine_meters(
                    float(item.get("lat") or 0.0),
                    float(item.get("lng") or 0.0),
                    center_lat,
                    center_lng,
                )
                for item in members
            ]
            radius_m = int(
                round(
                    self._clamp(
                        self._percentile(distances_to_center, 90.0), 35.0, 260.0
                    )
                )
            )

            channel_counter = Counter()
            source_counter = Counter()
            locked_count = 0
            raw_eapol_sum = 0
            raw_beacon_sum = 0
            raw_probe_peak_sum = 0
            opportunity_sum = 0

            for member in members:
                if member.get("locked"):
                    locked_count += 1
                raw_eapol_sum += int(member.get("raw_eapol_count") or 0)
                raw_beacon_sum += int(member.get("raw_beacon_count") or 0)
                raw_probe_peak_sum += int(member.get("raw_probe_peak_count") or 0)
                opportunity_sum += int(member.get("opportunity_network_score") or 0)

                ch = member.get("channel")
                if ch is None:
                    ch = self._derive_channel_from_frequency(
                        member.get("frequency_mhz")
                    )
                if ch is not None:
                    channel_counter[int(ch)] += 1

                source_flags = member.get("source_flags") or {}
                for source_name in ("pwn", "bruce", "m5", "ward", "raw"):
                    if source_flags.get(source_name):
                        source_counter[source_name] += 1

            members_sorted = sorted(
                members,
                key=lambda item: (
                    -int(bool(item.get("locked"))),
                    int(bool(item.get("cracked"))),
                    -int(item.get("raw_eapol_count") or 0),
                    -int(item.get("opportunity_network_score") or 0),
                    -int(item.get("ts_last") or 0),
                    str(item.get("mac") or ""),
                ),
            )
            candidate_macs = [
                str(item.get("mac") or "").strip().upper()
                for item in members_sorted
                if str(item.get("mac") or "").strip()
            ]
            # Keep order stable while deduplicating.
            candidate_macs = list(dict.fromkeys(candidate_macs))

            cluster_item = {
                "center_lat": round(center_lat, 7),
                "center_lng": round(center_lng, 7),
                "radius_m": radius_m,
                "members_count": members_count,
                "networks_count": members_count,
                "locked_count": locked_count,
                "raw_eapol_sum": raw_eapol_sum,
                "raw_beacon_sum": raw_beacon_sum,
                "raw_probe_peak_sum": raw_probe_peak_sum,
                "opportunity_avg": round(float(opportunity_sum) / members_count, 4),
                "top_channels": [int(ch) for ch, _ in channel_counter.most_common(3)],
                "top_sources": [
                    str(name).upper() for name, _ in source_counter.most_common(3)
                ],
                "candidate_macs": candidate_macs,
                "sample_macs": candidate_macs[:8],
                "extent_bbox": extent_bbox,
                "mesh": self._build_hotspot_mesh(
                    members=members,
                    center_lat=center_lat,
                    center_lng=center_lng,
                    radius_m=radius_m,
                ),
                "algorithm_meta": {
                    "eps_m": round(float(eps_m), 3),
                    "min_samples": int(min_samples),
                },
            }
            cluster_item["raw_value"] = self._cluster_metric_value(cluster_item, metric)
            clusters.append(cluster_item)

        return clusters

    @staticmethod
    def _wardrive_context_signature(context: Dict) -> Tuple:
        top_modes = tuple(
            (
                str(item.get("transport_mode") or ""),
                int(item.get("sessions_count") or 0),
                int(item.get("networks_count") or 0),
                int(item.get("points_count") or 0),
            )
            for item in (context.get("top_transport_modes") or [])
        )
        return (
            int(context.get("sessions_count") or 0),
            int(context.get("networks_count") or 0),
            int(context.get("points_count") or 0),
            top_modes,
        )

    def _get_wardrive_context(self, *, time_window: str) -> Dict:
        sessions = get_wardrive_sessions()
        now_ts = int(time.time())
        filtered_sessions: List[Dict] = []

        for item in sessions:
            started_at = self._safe_float(item.get("started_at"))
            ended_at = self._safe_float(item.get("ended_at"))
            if time_window == "24h":
                ref_ts = ended_at if ended_at is not None else started_at
                if ref_ts is None or ref_ts < (now_ts - 86_400):
                    continue
            filtered_sessions.append(item)

        buckets: Dict[str, Dict] = {}
        for item in filtered_sessions:
            mode = str(item.get("transport_mode") or "").strip().lower()
            if not mode:
                continue
            if mode not in buckets:
                buckets[mode] = {
                    "transport_mode": mode,
                    "sessions_count": 0,
                    "networks_count": 0,
                    "points_count": 0,
                }
            buckets[mode]["sessions_count"] += 1
            buckets[mode]["networks_count"] += int(item.get("networks_count") or 0)
            buckets[mode]["points_count"] += int(item.get("points_count") or 0)

        top_transport_modes = sorted(
            buckets.values(),
            key=lambda item: (
                -int(item.get("networks_count") or 0),
                -int(item.get("sessions_count") or 0),
                str(item.get("transport_mode") or ""),
            ),
        )[:8]

        return {
            "sessions_count": len(filtered_sessions),
            "networks_count": sum(
                int(item.get("networks_count") or 0) for item in filtered_sessions
            ),
            "points_count": sum(
                int(item.get("points_count") or 0) for item in filtered_sessions
            ),
            "top_transport_modes": top_transport_modes,
        }

    @staticmethod
    def _clamp(value: float, lower: float, upper: float) -> float:
        return max(lower, min(upper, value))

    @staticmethod
    def _is_open_encryption(encryption: str | None) -> bool:
        enc = str(encryption or "").strip().upper()
        return enc in {"OPEN", "WEP"}

    def _normalize_device_type(self, device_type: str | None) -> str:
        raw = str(device_type or "unknown").strip().lower()
        if not raw:
            return "unknown"
        mapped = self._DEVICE_TYPE_ALIASES.get(raw, raw)
        return mapped if mapped in self._ALLOWED_DEVICE_TYPES else "unknown"

    def _is_locked(self, item: Dict) -> bool:
        return (
            not bool(item.get("pass"))
            and not self._is_open_encryption(item.get("encryption"))
            and bool(item.get("handshake"))
        )

    @staticmethod
    def _normalize_sources(sources: List[str] | None) -> List[str]:
        if isinstance(sources, list) and len(sources) > 0:
            return [
                str(source).strip().lower() for source in sources if str(source).strip()
            ]
        return ["pwnagotchi"]

    def _source_flags(self, sources: List[str]) -> Dict[str, bool]:
        normalized = {str(source or "").strip().lower() for source in sources}
        has_ward = "wardrive" in normalized
        has_raw = any(
            source in {
                "bruce_raw",
                "bruce_raw_sniffing",
                "m5evil_raw_sniffing",
                "m5evil_master_raw_sniffing",
                "rawsniffer",
            }
            for source in normalized
        )
        has_bruce = any(
            source in {"brucegotchi", "bruce_raw", "bruce_raw_sniffing"}
            for source in normalized
        )
        has_m5 = "m5evil" in normalized or any(
            source in {"m5evil_raw_sniffing", "m5evil_master_raw_sniffing"}
            for source in normalized
        )
        has_pwn = "pwnagotchi" in normalized or len(normalized) == 0
        return {
            "pwn": has_pwn,
            "bruce": has_bruce,
            "m5": has_m5,
            "ward": has_ward,
            "raw": has_raw,
        }

    def _opportunity_network_score(self, row: Dict) -> int:
        score = 0

        locked = bool(row.get("locked"))
        cracked = bool(row.get("cracked"))
        raw_eapol = int(row.get("raw_eapol_count") or 0)
        raw_beacon = int(row.get("raw_beacon_count") or 0)
        raw_probe_peak = int(row.get("raw_probe_peak_count") or 0)
        source_raw = bool(row.get("source_flags", {}).get("raw"))

        if locked:
            score += 40
        if raw_eapol > 0:
            score += 25
        if raw_beacon > 0:
            score += min(15, int(math.floor(math.log10(raw_beacon + 1) * 6)))
        if raw_probe_peak > 0:
            score += min(10, raw_probe_peak * 2)
        if source_raw:
            score += 5
        if cracked:
            score -= 30

        return int(self._clamp(score, 0, 100))

    @staticmethod
    def _safe_float(value) -> float | None:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _safe_int(value) -> int | None:
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return None

    def _has_gps(self, item: Dict) -> bool:
        lat = self._safe_float(item.get("lat"))
        lng = self._safe_float(item.get("lng"))
        if lat is None or lng is None:
            return False
        if lat == 0.0 and lng == 0.0:
            return False
        return True

    def _dataset_signature(self, dataset: Dict) -> Tuple[int, int, int]:
        if not isinstance(dataset, dict):
            return (0, 0, 0)

        checksum = 0
        max_ts = 0
        for mac in sorted(dataset.keys()):
            item = dataset.get(mac) or {}
            ts_last = int(float(item.get("ts_last") or 0))
            max_ts = max(max_ts, ts_last)

            raw_beacon = int(item.get("raw_beacon_count") or 0)
            raw_eapol = int(item.get("raw_eapol_count") or 0)
            raw_probe = int(item.get("raw_probe_peak_count") or 0)
            channel = (
                int(item.get("channel") or 0) if item.get("channel") is not None else 0
            )
            cracked = 1 if item.get("pass") else 0
            device_type = self._normalize_device_type(item.get("device_type"))
            device_conf = int(float(item.get("device_confidence") or 0) * 100)

            mac_score = sum(ord(ch) for ch in str(mac))
            checksum = (
                checksum
                + mac_score
                + ts_last
                + raw_beacon * 3
                + raw_eapol * 5
                + raw_probe * 7
                + channel * 11
                + cracked * 13
                + sum(ord(ch) for ch in device_type)
                + device_conf
            ) % 2_147_483_647

        return (len(dataset), max_ts, checksum)

    def _build_rows(self, dataset: Dict) -> List[Dict]:
        rows: List[Dict] = []
        if not isinstance(dataset, dict):
            return rows

        for mac, item in dataset.items():
            if not isinstance(item, dict) or not self._has_gps(item):
                continue

            lat = self._safe_float(item.get("lat"))
            lng = self._safe_float(item.get("lng"))
            if lat is None or lng is None:
                continue

            sources = self._normalize_sources(item.get("sources"))
            source_flags = self._source_flags(sources)
            cracked = bool(item.get("pass"))
            is_open = self._is_open_encryption(item.get("encryption"))
            locked = self._is_locked(item)

            channel = self._safe_int(item.get("channel"))
            frequency = self._safe_int(item.get("frequency"))

            row = {
                "mac": str(mac).upper(),
                "lat": lat,
                "lng": lng,
                "encryption": str(item.get("encryption") or "UNK").upper(),
                "channel": channel,
                "frequency_mhz": frequency,
                "ts_last": int(float(item.get("ts_last") or 0)),
                "sources": sources,
                "source_flags": source_flags,
                "cracked": cracked,
                "is_open": is_open,
                "locked": locked,
                "raw_beacon_count": int(item.get("raw_beacon_count") or 0),
                "raw_eapol_count": int(item.get("raw_eapol_count") or 0),
                "raw_probe_peak_count": int(item.get("raw_probe_peak_count") or 0),
                "device_type": self._normalize_device_type(item.get("device_type")),
                "device_confidence": float(item.get("device_confidence") or 0.0),
            }
            row["opportunity_network_score"] = self._opportunity_network_score(row)
            rows.append(row)

        return rows

    def _ensure_rows_cache(self) -> Tuple[List[Dict], Tuple[int, int, int]]:
        dataset = load_real_data() or {}
        signature = self._dataset_signature(dataset)
        if signature != self._rows_cache_signature:
            self._rows_cache = self._build_rows(dataset)
            self._rows_cache_signature = signature
            self._response_cache = {}
        return self._rows_cache, signature

    def _validate_common_filters(
        self,
        *,
        metric: str = "opportunity",
        time_window: str = "all",
        source: str = "all",
        security: str = "all",
        device_type: str = "all",
    ) -> Tuple[str, str, str, str, str]:
        metric_v = str(metric or "opportunity").strip().lower()
        time_v = str(time_window or "all").strip().lower()
        source_v = str(source or "all").strip().lower()
        security_v = str(security or "all").strip().lower()
        device_type_v = str(device_type or "all").strip().lower()

        if metric_v not in self._ALLOWED_METRICS:
            metric_v = "opportunity"
        if time_v not in self._ALLOWED_TIME_WINDOWS:
            time_v = "all"
        if source_v not in self._ALLOWED_SOURCES:
            source_v = "all"
        if security_v not in self._ALLOWED_SECURITY:
            security_v = "all"
        if device_type_v not in self._ALLOWED_DEVICE_TYPES:
            device_type_v = "all"

        return metric_v, time_v, source_v, security_v, device_type_v

    def _apply_filters(
        self,
        rows: List[Dict],
        *,
        time_window: str,
        source: str,
        security: str,
        device_type: str,
        channel: int | None,
    ) -> List[Dict]:
        now_ts = int(time.time())
        out: List[Dict] = []
        for row in rows:
            if time_window == "24h" and int(row.get("ts_last") or 0) < (
                now_ts - 86_400
            ):
                continue

            if source != "all" and not bool(row.get("source_flags", {}).get(source)):
                continue

            if security == "locked" and not bool(row.get("locked")):
                continue
            if security == "open" and not bool(row.get("is_open")):
                continue
            if security == "cracked" and not bool(row.get("cracked")):
                continue
            if (
                device_type != "all"
                and self._normalize_device_type(row.get("device_type")) != device_type
            ):
                continue

            if channel is not None and int(row.get("channel") or -1) != int(channel):
                continue

            out.append(row)
        return out

    def _cell_key(self, lat: float, lng: float, cell_size_m: int) -> Tuple[int, int]:
        x = self._EARTH_RADIUS_M * math.radians(lng) * math.cos(math.radians(lat))
        y = self._EARTH_RADIUS_M * math.radians(lat)
        return (int(math.floor(x / cell_size_m)), int(math.floor(y / cell_size_m)))

    def _build_cells(self, rows: List[Dict], cell_size_m: int) -> List[Dict]:
        buckets: Dict[Tuple[int, int], Dict] = {}

        for row in rows:
            key = self._cell_key(float(row["lat"]), float(row["lng"]), cell_size_m)
            cell = buckets.get(key)
            if cell is None:
                cell = {
                    "lat_sum": 0.0,
                    "lng_sum": 0.0,
                    "points_count": 0,
                    "locked_count": 0,
                    "raw_eapol_sum": 0,
                    "raw_beacon_sum": 0,
                    "raw_probe_peak_sum": 0,
                    "opportunity_sum": 0,
                    "sample_macs": [],
                    "channel_counter": Counter(),
                    "source_counter": Counter(),
                }
                buckets[key] = cell

            cell["lat_sum"] += float(row["lat"])
            cell["lng_sum"] += float(row["lng"])
            cell["points_count"] += 1
            cell["locked_count"] += 1 if row.get("locked") else 0
            cell["raw_eapol_sum"] += int(row.get("raw_eapol_count") or 0)
            cell["raw_beacon_sum"] += int(row.get("raw_beacon_count") or 0)
            cell["raw_probe_peak_sum"] += int(row.get("raw_probe_peak_count") or 0)
            cell["opportunity_sum"] += int(row.get("opportunity_network_score") or 0)

            if len(cell["sample_macs"]) < 8:
                cell["sample_macs"].append(str(row.get("mac")))

            channel = row.get("channel")
            if channel is not None:
                cell["channel_counter"][int(channel)] += 1

            source_flags = row.get("source_flags", {})
            for key_name in ("pwn", "bruce", "m5", "ward", "raw"):
                if source_flags.get(key_name):
                    cell["source_counter"][key_name] += 1

        out_cells: List[Dict] = []
        for cell in buckets.values():
            points = int(cell["points_count"] or 0)
            if points <= 0:
                continue
            lat = float(cell["lat_sum"]) / points
            lng = float(cell["lng_sum"]) / points
            out_cells.append(
                {
                    "lat": round(lat, 7),
                    "lng": round(lng, 7),
                    "points_count": points,
                    "locked_count": int(cell["locked_count"] or 0),
                    "raw_eapol_sum": int(cell["raw_eapol_sum"] or 0),
                    "raw_beacon_sum": int(cell["raw_beacon_sum"] or 0),
                    "raw_probe_peak_sum": int(cell["raw_probe_peak_sum"] or 0),
                    "opportunity_avg": round(
                        float(cell["opportunity_sum"]) / points, 4
                    ),
                    "sample_macs": list(cell["sample_macs"]),
                    "channel_counter": cell["channel_counter"],
                    "source_counter": cell["source_counter"],
                }
            )

        return out_cells

    @staticmethod
    def _cell_metric_value(cell: Dict, metric: str) -> float:
        if metric == "density":
            return float(cell.get("points_count") or 0)
        if metric == "eapol":
            return float(cell.get("raw_eapol_sum") or 0)
        if metric == "beacon":
            return float(cell.get("raw_beacon_sum") or 0)
        if metric == "probe":
            return float(cell.get("raw_probe_peak_sum") or 0)
        return float(cell.get("opportunity_avg") or 0.0)

    def _normalize_0_100(self, value: float, min_value: float, max_value: float) -> int:
        if max_value <= min_value:
            return 100 if value > 0 else 0
        normalized = ((value - min_value) / (max_value - min_value)) * 100.0
        return int(round(self._clamp(normalized, 0.0, 100.0)))

    def _cache_get(self, key: Tuple) -> Dict | None:
        payload = self._response_cache.get(key)
        return deepcopy(payload) if payload is not None else None

    def _cache_set(self, key: Tuple, payload: Dict) -> Dict:
        self._response_cache[key] = deepcopy(payload)
        return deepcopy(payload)

    def clear_cache(self) -> None:
        self._rows_cache_signature = None
        self._rows_cache = []
        self._response_cache = {}

    @staticmethod
    def _generated_at() -> str:
        return datetime.now(UTC).isoformat().replace("+00:00", "Z")

    def _filters_payload(
        self,
        *,
        metric: str,
        time_window: str,
        source: str,
        security: str,
        channel: int | None,
        device_type: str | None = None,
        cell_size_m: int | None = None,
        limit: int | None = None,
    ) -> Dict:
        payload = {
            "metric": metric,
            "time_window": time_window,
            "source": source,
            "security": security,
            "channel": channel,
        }
        if device_type is not None:
            payload["device_type"] = device_type
        if cell_size_m is not None:
            payload["cell_size_m"] = cell_size_m
        if limit is not None:
            payload["limit"] = limit
        return payload

    def get_heatmap(
        self,
        *,
        metric: str = "opportunity",
        time_window: str = "all",
        source: str = "all",
        security: str = "all",
        device_type: str = "all",
        channel: int | None = None,
        cell_size_m: int = 120,
    ) -> Dict:
        metric_v, time_v, source_v, security_v, device_type_v = (
            self._validate_common_filters(
                metric=metric,
                time_window=time_window,
                source=source,
                security=security,
                device_type=device_type,
            )
        )
        channel_v = int(channel) if channel is not None else None
        cell_size_v = int(self._clamp(int(cell_size_m), 50, 300))

        rows, signature = self._ensure_rows_cache()
        cache_key = (
            "heatmap",
            signature,
            metric_v,
            time_v,
            source_v,
            security_v,
            device_type_v,
            channel_v,
            cell_size_v,
        )
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        filtered = self._apply_filters(
            rows,
            time_window=time_v,
            source=source_v,
            security=security_v,
            device_type=device_type_v,
            channel=channel_v,
        )
        cells = self._build_cells(filtered, cell_size_v)

        values = [self._cell_metric_value(cell, metric_v) for cell in cells]
        value_min = min(values) if values else 0.0
        value_max = max(values) if values else 0.0
        value_avg = (sum(values) / len(values)) if values else 0.0

        response_cells = []
        for cell in cells:
            response_cells.append(
                {
                    "lat": cell["lat"],
                    "lng": cell["lng"],
                    "value": round(self._cell_metric_value(cell, metric_v), 4),
                    "points_count": int(cell["points_count"]),
                    "locked_count": int(cell["locked_count"]),
                    "raw_eapol_sum": int(cell["raw_eapol_sum"]),
                    "raw_beacon_sum": int(cell["raw_beacon_sum"]),
                    "raw_probe_peak_sum": int(cell["raw_probe_peak_sum"]),
                    "sample_macs": list(cell["sample_macs"])[:5],
                }
            )

        response_cells.sort(
            key=lambda item: (
                float(item.get("value") or 0),
                int(item.get("points_count") or 0),
            ),
            reverse=True,
        )

        payload = {
            "schema_version": self.SCHEMA_VERSION,
            "generated_at": self._generated_at(),
            "filters": self._filters_payload(
                metric=metric_v,
                time_window=time_v,
                source=source_v,
                security=security_v,
                device_type=device_type_v,
                channel=channel_v,
                cell_size_m=cell_size_v,
            ),
            "stats": {
                "networks_count": len(filtered),
                "cells_count": len(response_cells),
                "metric": metric_v,
                "value_min": round(value_min, 4),
                "value_max": round(value_max, 4),
                "value_avg": round(value_avg, 4),
            },
            "cells": response_cells,
        }
        return self._cache_set(cache_key, payload)

    @staticmethod
    def _derive_channel_from_frequency(frequency_mhz: int | None) -> int | None:
        if frequency_mhz is None:
            return None
        freq = int(frequency_mhz)
        if freq == 2484:
            return 14
        if 2412 <= freq <= 2472:
            return int((freq - 2407) / 5)
        if 5000 <= freq <= 5900:
            return int((freq - 5000) / 5)
        return None

    def get_channel_summary(
        self,
        *,
        metric: str = "opportunity",
        time_window: str = "all",
        source: str = "all",
        security: str = "all",
        device_type: str = "all",
        channel: int | None = None,
    ) -> Dict:
        metric_v, time_v, source_v, security_v, device_type_v = (
            self._validate_common_filters(
                metric=metric,
                time_window=time_window,
                source=source,
                security=security,
                device_type=device_type,
            )
        )
        channel_v = int(channel) if channel is not None else None
        wardrive_context = self._get_wardrive_context(time_window=time_v)
        wardrive_signature = self._wardrive_context_signature(wardrive_context)

        rows, signature = self._ensure_rows_cache()
        cache_key = (
            "channel_summary",
            signature,
            metric_v,
            time_v,
            source_v,
            security_v,
            device_type_v,
            channel_v,
            wardrive_signature,
        )
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        filtered = self._apply_filters(
            rows,
            time_window=time_v,
            source=source_v,
            security=security_v,
            device_type=device_type_v,
            channel=channel_v,
        )

        channel_map: Dict[int, Dict] = {}
        for row in filtered:
            ch = row.get("channel")
            if ch is None:
                ch = self._derive_channel_from_frequency(row.get("frequency_mhz"))
            if ch is None:
                continue
            ch = int(ch)

            info = channel_map.get(ch)
            if info is None:
                info = {
                    "channel": ch,
                    "frequency_mhz": int(row.get("frequency_mhz") or 0) or None,
                    "networks": 0,
                    "locked": 0,
                    "open": 0,
                    "cracked": 0,
                    "raw_eapol_networks": 0,
                    "raw_beacon_sum": 0,
                    "raw_probe_peak_sum": 0,
                    "_raw_score": 0.0,
                }
                channel_map[ch] = info

            info["networks"] += 1
            info["locked"] += 1 if row.get("locked") else 0
            info["open"] += 1 if row.get("is_open") else 0
            info["cracked"] += 1 if row.get("cracked") else 0

            raw_eapol = int(row.get("raw_eapol_count") or 0)
            raw_beacon = int(row.get("raw_beacon_count") or 0)
            raw_probe = int(row.get("raw_probe_peak_count") or 0)
            if raw_eapol > 0:
                info["raw_eapol_networks"] += 1
            info["raw_beacon_sum"] += raw_beacon
            info["raw_probe_peak_sum"] += raw_probe

            if info["frequency_mhz"] is None and row.get("frequency_mhz"):
                info["frequency_mhz"] = int(row.get("frequency_mhz"))

        channels = list(channel_map.values())
        for item in channels:
            item["_raw_score"] = (
                10 * int(item["locked"])
                + 6 * int(item["raw_eapol_networks"])
                + 2 * math.log10(int(item["raw_beacon_sum"]) + 1)
                + 2 * int(item["raw_probe_peak_sum"])
                - 8 * int(item["cracked"])
            )

        scores = [float(item["_raw_score"]) for item in channels]
        score_min = min(scores) if scores else 0.0
        score_max = max(scores) if scores else 0.0

        for item in channels:
            item["opportunity_score"] = self._normalize_0_100(
                float(item["_raw_score"]),
                score_min,
                score_max,
            )
            item.pop("_raw_score", None)

        channels.sort(
            key=lambda item: (
                int(item.get("opportunity_score") or 0),
                int(item.get("networks") or 0),
            ),
            reverse=True,
        )

        device_map: Dict[str, Dict] = {}
        for row in filtered:
            d_type = self._normalize_device_type(row.get("device_type"))
            info = device_map.get(d_type)
            if info is None:
                info = {
                    "device_type": d_type,
                    "networks": 0,
                    "locked": 0,
                    "open": 0,
                    "cracked": 0,
                    "raw_eapol_networks": 0,
                    "raw_beacon_sum": 0,
                    "raw_probe_peak_sum": 0,
                    "_raw_score": 0.0,
                }
                device_map[d_type] = info

            info["networks"] += 1
            info["locked"] += 1 if row.get("locked") else 0
            info["open"] += 1 if row.get("is_open") else 0
            info["cracked"] += 1 if row.get("cracked") else 0

            raw_eapol = int(row.get("raw_eapol_count") or 0)
            raw_beacon = int(row.get("raw_beacon_count") or 0)
            raw_probe = int(row.get("raw_probe_peak_count") or 0)
            if raw_eapol > 0:
                info["raw_eapol_networks"] += 1
            info["raw_beacon_sum"] += raw_beacon
            info["raw_probe_peak_sum"] += raw_probe

            info["_raw_score"] = (
                10 * int(info["locked"])
                + 6 * int(info["raw_eapol_networks"])
                + 2 * math.log10(int(info["raw_beacon_sum"]) + 1)
                + 2 * int(info["raw_probe_peak_sum"])
                - 8 * int(info["cracked"])
            )

        device_summary = list(device_map.values())
        device_scores = [float(item["_raw_score"]) for item in device_summary]
        device_min = min(device_scores) if device_scores else 0.0
        device_max = max(device_scores) if device_scores else 0.0
        for item in device_summary:
            item["opportunity_score"] = self._normalize_0_100(
                float(item["_raw_score"]),
                device_min,
                device_max,
            )
            item.pop("_raw_score", None)
        device_summary.sort(
            key=lambda item: (
                int(item.get("opportunity_score") or 0),
                int(item.get("networks") or 0),
            ),
            reverse=True,
        )

        payload = {
            "schema_version": self.SCHEMA_VERSION,
            "generated_at": self._generated_at(),
            "filters": self._filters_payload(
                metric=metric_v,
                time_window=time_v,
                source=source_v,
                security=security_v,
                device_type=device_type_v,
                channel=channel_v,
            ),
            "channels": channels,
            "device_summary": device_summary,
            "wardrive_context": wardrive_context,
        }
        return self._cache_set(cache_key, payload)

    def _recommended_action(self, hotspot: Dict) -> str:
        locked = int(hotspot.get("locked_count") or 0)
        raw_eapol = int(hotspot.get("raw_eapol_sum") or 0)
        score = int(hotspot.get("score") or 0)
        if locked <= 0:
            return "observe_only"
        if raw_eapol > 0 and score >= 70:
            return "prioritize_cracking"
        if raw_eapol == 0 and int(hotspot.get("raw_beacon_sum") or 0) > 0:
            return "collect_eapol_first"
        if score >= 45:
            return "survey_and_prioritize"
        return "monitor"

    def _decision_factors(self, hotspot: Dict) -> List[str]:
        factors: List[str] = []
        locked = int(hotspot.get("locked_count") or 0)
        networks = int(
            hotspot.get("networks_count") or hotspot.get("members_count") or 0
        )
        raw_eapol = int(hotspot.get("raw_eapol_sum") or 0)
        raw_beacon = int(hotspot.get("raw_beacon_sum") or 0)
        top_channels = [
            str(item) for item in (hotspot.get("top_channels") or []) if str(item)
        ]
        top_sources = [
            str(item) for item in (hotspot.get("top_sources") or []) if str(item)
        ]
        score = int(hotspot.get("score") or 0)
        action = str(hotspot.get("recommended_action") or "").strip().replace("_", " ")

        if locked > 0:
            factors.append(f"{locked} locked networks concentrate in this hotspot.")
        if raw_eapol > 0:
            factors.append(
                f"{raw_eapol} RAW EAPOL observations improve crack readiness."
            )
        elif raw_beacon > 0:
            factors.append(
                f"{raw_beacon} RAW beacons were seen, but EAPOL still needs collection."
            )
        if top_channels:
            factors.append(f"Dominant channels: {', '.join(top_channels[:3])}.")
        if top_sources:
            factors.append(f"Strongest sources: {', '.join(top_sources[:3])}.")
        if score >= 70:
            factors.append("This cluster scores as a high-priority campaign candidate.")
        elif score >= 45:
            factors.append(
                "This cluster is worth surveying before committing cracking effort."
            )
        if action and not any(
            "campaign" in factor.lower() or "surveying" in factor.lower()
            for factor in factors
        ):
            factors.append(f"Recommended action: {action}.")
        if not factors:
            factors.append(
                f"{max(networks, 0)} networks share a stable spatial footprint in this area."
            )
        return factors[:5]

    def get_hotspots(
        self,
        *,
        metric: str = "opportunity",
        time_window: str = "all",
        source: str = "all",
        security: str = "all",
        device_type: str = "all",
        channel: int | None = None,
        cell_size_m: int = 120,
        limit: int = 12,
    ) -> Dict:
        metric_v, time_v, source_v, security_v, device_type_v = (
            self._validate_common_filters(
                metric=metric,
                time_window=time_window,
                source=source,
                security=security,
                device_type=device_type,
            )
        )
        channel_v = int(channel) if channel is not None else None
        limit_v = int(self._clamp(int(limit), 1, 50))

        rows, signature = self._ensure_rows_cache()
        cell_size_v = int(self._clamp(int(cell_size_m), 50, 300))
        cache_key = (
            "hotspots",
            signature,
            metric_v,
            time_v,
            source_v,
            security_v,
            device_type_v,
            channel_v,
            limit_v,
        )
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        filtered = self._apply_filters(
            rows,
            time_window=time_v,
            source=source_v,
            security=security_v,
            device_type=device_type_v,
            channel=channel_v,
        )
        eps_m, nearest_neighbor_p75_m = self._compute_adaptive_eps_m(filtered)
        min_samples = 2 if len(filtered) < 20 else 3
        clusters = self._build_hotspot_clusters(
            filtered,
            metric=metric_v,
            eps_m=eps_m,
            min_samples=min_samples,
        )
        if not clusters:
            payload = {
                "schema_version": self.SCHEMA_VERSION,
                "generated_at": self._generated_at(),
                "metric": metric_v,
                "algorithm": {
                    "name": "adaptive_dbscan",
                    "eps_m": round(eps_m, 3),
                    "min_samples": int(min_samples),
                    "nearest_neighbor_p75_m": round(nearest_neighbor_p75_m, 3),
                    "cell_size_m_ignored": int(cell_size_v),
                },
                "filters": self._filters_payload(
                    metric=metric_v,
                    time_window=time_v,
                    source=source_v,
                    security=security_v,
                    device_type=device_type_v,
                    channel=channel_v,
                    cell_size_m=cell_size_v,
                    limit=limit_v,
                ),
                "hotspots": [],
            }
            return self._cache_set(cache_key, payload)

        values = [float(item.get("raw_value") or 0.0) for item in clusters]
        value_min = min(values)
        value_max = max(values)

        sorted_clusters = sorted(
            clusters,
            key=lambda item: (
                float(item.get("raw_value") or 0.0),
                int(item.get("members_count") or 0),
                int(item.get("locked_count") or 0),
            ),
            reverse=True,
        )
        top_clusters = sorted_clusters[:limit_v]

        hotspots: List[Dict] = []
        for idx, cluster in enumerate(top_clusters, start=1):
            value = float(cluster.get("raw_value") or 0.0)
            if metric_v == "opportunity":
                score = int(round(self._clamp(value, 0.0, 100.0)))
            else:
                score = self._normalize_0_100(value, value_min, value_max)

            hotspot = {
                "id": f"H{idx}",
                "center_lat": cluster["center_lat"],
                "center_lng": cluster["center_lng"],
                "radius_m": int(cluster["radius_m"]),
                "score": score,
                "networks_count": int(cluster["networks_count"]),
                "members_count": int(cluster["members_count"]),
                "locked_count": int(cluster["locked_count"]),
                "top_channels": list(cluster["top_channels"]),
                "top_sources": list(cluster["top_sources"]),
                "candidate_macs": list(cluster["candidate_macs"]),
                "sample_macs": list(cluster["sample_macs"]),
                "raw_eapol_sum": int(cluster["raw_eapol_sum"]),
                "raw_beacon_sum": int(cluster["raw_beacon_sum"]),
                "raw_probe_peak_sum": int(cluster["raw_probe_peak_sum"]),
                "extent_bbox": dict(cluster["extent_bbox"]),
                "mesh": list(cluster["mesh"]),
                "algorithm_meta": {
                    **dict(cluster.get("algorithm_meta") or {}),
                    "nearest_neighbor_p75_m": round(nearest_neighbor_p75_m, 3),
                },
            }
            hotspot["recommended_action"] = self._recommended_action(hotspot)
            hotspot["decision_factors"] = self._decision_factors(hotspot)
            hotspots.append(hotspot)

        payload = {
            "schema_version": self.SCHEMA_VERSION,
            "generated_at": self._generated_at(),
            "metric": metric_v,
            "algorithm": {
                "name": "adaptive_dbscan",
                "eps_m": round(eps_m, 3),
                "min_samples": int(min_samples),
                "nearest_neighbor_p75_m": round(nearest_neighbor_p75_m, 3),
                "candidate_strategy": "locked_desc,cracked_asc,raw_eapol_desc,opportunity_desc,ts_last_desc",
                "cell_size_m_ignored": int(cell_size_v),
            },
            "filters": self._filters_payload(
                metric=metric_v,
                time_window=time_v,
                source=source_v,
                security=security_v,
                device_type=device_type_v,
                channel=channel_v,
                cell_size_m=cell_size_v,
                limit=limit_v,
            ),
            "hotspots": hotspots,
        }
        return self._cache_set(cache_key, payload)


analytics_service = AnalyticsService()
