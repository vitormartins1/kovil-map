import glob
import json
import logging
import math
import os
import re
import time
import unicodedata
import xml.etree.ElementTree as ET
import zipfile
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from shapely.geometry import MultiPolygon, Point, Polygon, shape
from shapely.geometry.base import BaseGeometry
from shapely.ops import unary_union
from shapely.strtree import STRtree

from app.core.config import MAPS_DIR
from app.services.data_loader import (
    get_data_revision,
    get_wardrive_transport_modes,
    get_wardrive_sessions,
    get_wardrive_summary,
    load_real_data,
    merge_wardrive_sessions,
    reload_data,
    set_wardrive_session_tag,
)
from app.services.zones_service import cluster_points

try:
    import shapefile  # type: ignore
except Exception:  # pragma: no cover - optional runtime dependency in some envs
    shapefile = None


logger = logging.getLogger(__name__)


FORMAT_RANK = {
    "geojson": 0,
    "shp": 1,
    "kmz": 2,
}

SUPPORTED_EXTENSIONS = (".geojson", ".json", ".shp", ".kmz")
SHAPEFILE_SIDE_CAR_EXTENSIONS = (".dbf", ".shx", ".prj", ".cpg")
SUPPORTED_CRS_HINTS = ("4326", "SIRGAS_2000", "WGS_1984", "WGS 84")

KML_NS = {"kml": "http://www.opengis.net/kml/2.2"}


@dataclass
class CountryManifest:
    code: str
    name: str
    default_locale: str
    labels: Dict[str, str]
    path: str


@dataclass
class DatasetManifest:
    country_code: str
    country_name: str
    dataset_id: str
    dataset_source: str
    version: str
    enabled: bool
    priority: int
    level_key: str
    level_label: str
    depth: int
    depth_role: str
    geometry_format: str
    crs: str
    metadata_path: str
    source_path: Optional[str]
    path_glob: Optional[str]
    id_fields: List[str]
    name_fields: List[str]
    parent_resolvers: List[Dict[str, Any]]
    include_in_hierarchy: bool


@dataclass
class ParentHint:
    target_level_key: str
    target_key: str
    value: str


@dataclass
class RegionEntry:
    id: str
    country_code: str
    country_name: str
    level_key: str
    level_label: str
    depth: int
    depth_role: str
    name: str
    code: str
    parent_id: Optional[str]
    parent_hints: List[ParentHint]
    source_format: str
    source_path: str
    source_rank: int
    dataset_id: str
    dataset_source: str
    priority: int
    include_in_hierarchy: bool
    geometries: List[BaseGeometry] = field(default_factory=list)


class _LevelSpatialIndex:
    def __init__(self, rows: List[Tuple[str, BaseGeometry]]):
        self.rows = rows
        self.geometries = [row[1] for row in rows]
        self.tree = STRtree(self.geometries) if self.geometries else None
        self.id_by_wkb = {geom.wkb: region_id for region_id, geom in rows}

    def query(self, point: Point) -> List[Tuple[str, BaseGeometry]]:
        if self.tree is None:
            return []

        candidates = self.tree.query(point)
        if candidates is None:
            return []

        results: List[Tuple[str, BaseGeometry]] = []
        for candidate in candidates:
            if isinstance(candidate, int):
                geom = self.geometries[int(candidate)]
                region_id = self.rows[int(candidate)][0]
                results.append((region_id, geom))
                continue

            if hasattr(candidate, "item"):
                try:
                    idx = int(candidate.item())
                    geom = self.geometries[idx]
                    region_id = self.rows[idx][0]
                    results.append((region_id, geom))
                    continue
                except Exception:
                    pass

            if isinstance(candidate, BaseGeometry):
                region_id = self.id_by_wkb.get(candidate.wkb)
                if region_id:
                    results.append((region_id, candidate))

        return results


class WardriveRegionsService:
    def __init__(self):
        self._cache_signature: Optional[Tuple[Tuple[str, int, int], ...]] = None
        self._maps_revision: int = 0
        self._regions_by_id: Dict[str, RegionEntry] = {}
        self._regions_lookup: Dict[Tuple[str, str], Dict[str, Dict[str, str]]] = {}
        self._spatial_indexes: Dict[str, _LevelSpatialIndex] = {}
        self._level_depths: Dict[str, int] = {}
        self._level_labels: Dict[str, str] = {}
        self._max_hierarchy_depth_by_country: Dict[str, int] = {}
        self._countries: Dict[str, CountryManifest] = {}
        self._dataset_inventory: List[Dict[str, Any]] = []
        self._legacy_inventory: List[Dict[str, Any]] = []
        self._maps_summary: Dict[str, Any] = {}
        self._classification_cache: "OrderedDict[Tuple[Any, ...], Dict[str, Any]]" = (
            OrderedDict()
        )
        self._hierarchy_cache: "OrderedDict[Tuple[Any, ...], Dict[str, Any]]" = (
            OrderedDict()
        )
        self._zones_cache: "OrderedDict[Tuple[Any, ...], Dict[str, Any]]" = (
            OrderedDict()
        )
        self._outline_cache: (
            "OrderedDict[Tuple[Any, ...], List[List[Dict[str, float]]]]"
        ) = OrderedDict()
        self._max_classification_cache_entries = 64
        self._max_hierarchy_cache_entries = 64
        self._max_zones_cache_entries = 256
        self._max_outline_cache_entries = 512

    def get_hierarchy(
        self,
        time_window: str = "all",
        source: str = "all",
        session_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        self._ensure_index()

        normalized_time = self._normalize_time_window(time_window)
        normalized_session_ids = self._normalize_session_ids(session_ids)
        normalized_source = (
            "ward" if normalized_session_ids else self._normalize_source_filter(source)
        )
        scope = self._runtime_cache_scope(
            time_window=normalized_time,
            source=normalized_source,
            session_ids=normalized_session_ids,
        )
        hierarchy_key = ("hierarchy",) + scope
        cached_hierarchy = self._lru_get(self._hierarchy_cache, hierarchy_key)
        if cached_hierarchy is not None:
            return cached_hierarchy

        classification = self._get_classification(
            time_window=normalized_time,
            source=normalized_source,
            session_ids=normalized_session_ids,
        )
        stats_by_region = classification["stats_by_region"]

        regions_payload = []
        for region in sorted(self._regions_by_id.values(), key=self._region_sort_key):
            if not region.include_in_hierarchy:
                continue

            stats = stats_by_region.get(region.id, self._empty_stats())
            if stats["networks_count"] <= 0:
                continue

            regions_payload.append(self._serialize_region(region, stats=stats))

        payload = {
            "maps_summary": dict(self._maps_summary),
            "regions": regions_payload,
            "unmapped_summary": classification["unmapped_summary"],
            "filters": {
                "time_window": normalized_time,
                "source": normalized_source,
                "session_ids": normalized_session_ids,
            },
        }
        self._lru_set(
            self._hierarchy_cache,
            hierarchy_key,
            payload,
            self._max_hierarchy_cache_entries,
        )
        return payload

    def get_region_zones(
        self,
        region_id: str,
        eps_m: float = 200.0,
        min_samples: int = 3,
        time_window: str = "all",
        source: str = "all",
        session_ids: Optional[List[str]] = None,
        comparison_mode: str = "standard",
        active_session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        self._ensure_index()

        normalized_region_id = str(region_id or "").strip()
        if not normalized_region_id:
            raise ValueError("region_id is required")

        normalized_time = self._normalize_time_window(time_window)
        normalized_session_ids = self._normalize_session_ids(session_ids)
        normalized_source = (
            "ward" if normalized_session_ids else self._normalize_source_filter(source)
        )
        classification = self._get_classification(
            time_window=normalized_time,
            source=normalized_source,
            session_ids=normalized_session_ids,
        )
        target_points, region_payload, region_stats = self._resolve_region_context(
            classification=classification,
            region_id=normalized_region_id,
        )
        normalized_comparison_mode = (
            "focus_active"
            if str(comparison_mode or "").strip().lower() == "focus_active"
            else "standard"
        )
        supports_focus_active = (
            normalized_comparison_mode == "focus_active"
            and 2 <= len(normalized_session_ids) <= 3
        )
        effective_comparison_mode = (
            "focus_active" if supports_focus_active else "standard"
        )

        zones_scope = self._runtime_cache_scope(
            time_window=normalized_time,
            source=normalized_source,
            session_ids=normalized_session_ids,
        )
        zones_key = (
            "zones",
            normalized_region_id,
            round(float(eps_m), 6),
            int(min_samples),
            effective_comparison_mode,
        ) + zones_scope
        cached_zones_payload = self._lru_get(self._zones_cache, zones_key)
        if cached_zones_payload is not None:
            if effective_comparison_mode == "focus_active":
                resolved_active_session_id = self._resolve_active_session_id(
                    active_session_id=active_session_id,
                    session_ids=normalized_session_ids,
                )
                return self._apply_focus_active_zone_preset(
                    cached_zones_payload,
                    active_session_id=resolved_active_session_id,
                )
            return cached_zones_payload

        if effective_comparison_mode == "focus_active":
            payload = self._build_focus_active_region_zones_payload(
                region_id=normalized_region_id,
                region_payload=region_payload,
                region_stats=region_stats,
                eps_m=eps_m,
                min_samples=min_samples,
                time_window=normalized_time,
                source=normalized_source,
                session_ids=normalized_session_ids,
            )
        else:
            zones = self._build_zones(
                target_points, eps_m=eps_m, min_samples=min_samples
            )
            payload = {
                "region": region_payload,
                "zones": zones,
                "stats": region_stats,
                "params": {
                    "eps_m": float(eps_m),
                    "min_samples": int(min_samples),
                    "time_window": normalized_time,
                    "source": normalized_source,
                    "session_ids": normalized_session_ids,
                    "comparison_mode": "standard",
                    "active_session_id": None,
                },
            }
        self._lru_set(
            self._zones_cache, zones_key, payload, self._max_zones_cache_entries
        )
        if effective_comparison_mode == "focus_active":
            resolved_active_session_id = self._resolve_active_session_id(
                active_session_id=active_session_id,
                session_ids=normalized_session_ids,
            )
            return self._apply_focus_active_zone_preset(
                payload,
                active_session_id=resolved_active_session_id,
            )
        return payload

    def _resolve_region_context(
        self, *, classification: Dict[str, Any], region_id: str
    ) -> Tuple[List[Dict[str, float]], Dict[str, Any], Dict[str, int]]:
        points_by_region = classification["points_by_region"]
        unmapped_points = classification["unmapped_points"]

        if region_id == "unmapped":
            target_points = unmapped_points
            region_payload = {
                "id": "unmapped",
                "level": "unmapped",
                "level_key": "unmapped",
                "level_label": "Sem mapa",
                "depth": 999,
                "depth_role": "fallback",
                "country_code": None,
                "country_name": None,
                "name": "UNMAPPED",
                "code": "UNMAPPED",
                "parent_id": None,
                "bbox": self._bounds_from_points(target_points),
                "center": self._center_from_points(target_points),
                "outline": [],
                "source_format": "fallback",
                "dataset_id": "unmapped",
                "dataset_source": "fallback",
                "lineage": [],
                "display_path": "UNMAPPED",
            }
            region_stats = classification["unmapped_summary"]
            return target_points, region_payload, region_stats

        region = self._regions_by_id.get(region_id)
        if not region:
            raise ValueError("region_id not found")

        target_points = points_by_region.get(region.id, [])
        region_payload = self._serialize_region(
            region, stats=classification["stats_by_region"].get(region.id)
        )
        region_payload["outline"] = self._region_outline(region)
        region_stats = classification["stats_by_region"].get(
            region.id, self._empty_stats()
        )
        return target_points, region_payload, region_stats

    def _resolve_active_session_id(
        self, *, active_session_id: Optional[str], session_ids: List[str]
    ) -> Optional[str]:
        normalized_active = str(active_session_id or "").strip()
        if normalized_active and normalized_active in session_ids:
            return normalized_active
        return session_ids[0] if session_ids else None

    def _build_focus_active_region_zones_payload(
        self,
        *,
        region_id: str,
        region_payload: Dict[str, Any],
        region_stats: Dict[str, int],
        eps_m: float,
        min_samples: int,
        time_window: str,
        source: str,
        session_ids: List[str],
    ) -> Dict[str, Any]:
        sessions_by_id = {
            str(item.get("session_id") or "").strip(): dict(item)
            for item in get_wardrive_sessions()
            if str(item.get("session_id") or "").strip()
        }
        session_zone_map: Dict[str, List[Dict[str, Any]]] = {}
        session_geometry_map: Dict[str, Optional[BaseGeometry]] = {}

        for session_id in session_ids:
            classification = self._get_classification(
                time_window=time_window,
                source=source,
                session_ids=[session_id],
            )
            session_points, _, _ = self._resolve_region_context(
                classification=classification,
                region_id=region_id,
            )
            base_zones = self._build_zones(
                session_points, eps_m=eps_m, min_samples=min_samples
            )
            session_meta = sessions_by_id.get(session_id) or {"session_id": session_id}
            session_label = (
                str(
                    session_meta.get("label")
                    or session_meta.get("source_file")
                    or session_id
                ).strip()
                or session_id
            )
            decorated_zones = [
                {
                    **zone,
                    "session_id": session_id,
                    "session_label": session_label,
                    "zone_role": "primary",
                }
                for zone in base_zones
            ]
            session_zone_map[session_id] = decorated_zones
            session_geometry_map[session_id] = self._zones_to_geometry(decorated_zones)

        layers_by_active_session: Dict[str, Dict[str, Any]] = {}
        for active_id in session_ids:
            primary_zones = [dict(zone) for zone in session_zone_map.get(active_id, [])]
            other_session_ids = [
                session_id for session_id in session_ids if session_id != active_id
            ]
            other_geometries = [
                geom
                for session_id, geom in session_geometry_map.items()
                if session_id in other_session_ids
                and geom is not None
                and not geom.is_empty
            ]
            secondary_geometry = (
                unary_union(other_geometries) if other_geometries else None
            )
            active_geometry = session_geometry_map.get(active_id)
            if (
                secondary_geometry is not None
                and not secondary_geometry.is_empty
                and active_geometry is not None
                and not active_geometry.is_empty
            ):
                secondary_geometry = secondary_geometry.difference(active_geometry)

            secondary_zone = self._build_focus_active_secondary_zone(
                active_session_id=active_id,
                secondary_geometry=secondary_geometry,
                other_session_ids=other_session_ids,
                other_zones=[
                    zone
                    for session_id in other_session_ids
                    for zone in session_zone_map.get(session_id, [])
                ],
            )
            layers_by_active_session[active_id] = {
                "primary_zones": primary_zones,
                "secondary_zone": secondary_zone,
            }

        default_active_session_id = session_ids[0] if session_ids else None
        payload = {
            "region": region_payload,
            "zones": [],
            "stats": region_stats,
            "params": {
                "eps_m": float(eps_m),
                "min_samples": int(min_samples),
                "time_window": time_window,
                "source": source,
                "session_ids": session_ids,
                "comparison_mode": "focus_active",
                "active_session_id": default_active_session_id,
            },
            "comparison": {
                "mode": "focus_active",
                "session_ids": session_ids,
                "active_session_id": default_active_session_id,
                "layers_by_active_session": layers_by_active_session,
            },
        }
        return self._apply_focus_active_zone_preset(
            payload, active_session_id=default_active_session_id
        )

    def _build_focus_active_secondary_zone(
        self,
        *,
        active_session_id: str,
        secondary_geometry: Optional[BaseGeometry],
        other_session_ids: List[str],
        other_zones: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        if secondary_geometry is None or secondary_geometry.is_empty:
            return None

        parts = self._geometry_to_parts(secondary_geometry, simplify_tolerance=0.0)
        if not parts:
            return None

        return {
            "id": f"secondary:{active_session_id}",
            "count": sum(int(zone.get("count") or 0) for zone in other_zones),
            "center": self._center_from_geometry(secondary_geometry),
            "parts": parts,
            "zone_role": "secondary",
            "session_id": None,
            "session_label": "OTHER SELECTED SESSIONS",
            "comparison_session_ids": other_session_ids,
        }

    def _apply_focus_active_zone_preset(
        self, payload: Dict[str, Any], *, active_session_id: Optional[str]
    ) -> Dict[str, Any]:
        comparison = payload.get("comparison") or {}
        layers_by_active_session = comparison.get("layers_by_active_session") or {}
        session_ids = list(comparison.get("session_ids") or [])
        effective_active_session_id = self._resolve_active_session_id(
            active_session_id=active_session_id,
            session_ids=session_ids,
        )
        active_layers = layers_by_active_session.get(effective_active_session_id) or {}
        zones = [dict(zone) for zone in (active_layers.get("primary_zones") or [])]
        secondary_zone = active_layers.get("secondary_zone")
        if secondary_zone:
            zones.append(dict(secondary_zone))

        comparison_payload = dict(comparison)
        comparison_payload["active_session_id"] = effective_active_session_id
        params_payload = dict(payload.get("params") or {})
        params_payload["active_session_id"] = effective_active_session_id

        return {
            **payload,
            "zones": zones,
            "params": params_payload,
            "comparison": comparison_payload,
        }

    def get_maps_inventory(self) -> Dict[str, Any]:
        self._ensure_index()
        return dict(self._maps_summary)

    def get_sessions(self, time_window: str = "all") -> Dict[str, Any]:
        normalized_time = self._normalize_time_window(time_window)
        data = load_real_data() or {}
        sessions = get_wardrive_sessions()
        now_ts = int(time.time())

        filtered_sessions: List[Dict[str, Any]] = []
        for item in sessions:
            started_at = self._safe_float(item.get("started_at"))
            ended_at = self._safe_float(item.get("ended_at"))
            if normalized_time == "24h":
                ref_ts = ended_at if ended_at is not None else started_at
                if ref_ts is None or ref_ts < now_ts - 86_400:
                    continue
            filtered_sessions.append(dict(item))

        distance_by_session = self._build_session_distance_map(
            session_ids=[
                str(item.get("session_id") or "").strip() for item in filtered_sessions
            ],
            data=data,
        )
        filtered_sessions = [
            {
                **item,
                "distance_m": int(
                    distance_by_session.get(
                        str(item.get("session_id") or "").strip(), 0
                    )
                ),
            }
            for item in filtered_sessions
        ]

        filtered_sessions.sort(
            key=lambda item: (
                -(self._safe_float(item.get("ended_at")) or 0),
                str(item.get("session_id") or ""),
            )
        )
        transport_modes = self._aggregate_transport_modes(filtered_sessions)

        return {
            "time_window": normalized_time,
            "sessions": filtered_sessions,
            "summary": {
                "sessions_count": len(filtered_sessions),
                "networks_count": sum(
                    int(item.get("networks_count") or 0) for item in filtered_sessions
                ),
                "points_count": sum(
                    int(item.get("points_count") or 0) for item in filtered_sessions
                ),
                "transport_modes": transport_modes,
                "top_transport_modes": transport_modes[:8],
            },
        }

    def set_session_tag(
        self, session_id: str, transport_mode: Optional[str]
    ) -> Dict[str, Any]:
        load_real_data()
        updated = set_wardrive_session_tag(
            session_id=session_id, transport_mode=transport_mode
        )
        payload = self.get_sessions(time_window="all")
        updated_session = next(
            (
                item
                for item in payload.get("sessions", [])
                if str(item.get("session_id") or "").strip()
                == str(updated.get("session_id") or "").strip()
            ),
            updated,
        )
        return {
            "session": updated_session,
            "summary": payload.get("summary", {}),
            "time_window": payload.get("time_window", "all"),
        }

    def merge_sessions(self, session_ids: Optional[List[str]] = None) -> Dict[str, Any]:
        merged = merge_wardrive_sessions(session_ids or [])
        reload_data()
        self.clear_runtime_cache()

        sessions_payload = self.get_sessions(time_window="all")
        merged_session_id = str(merged.get("session_id") or "").strip()
        merged_session = next(
            (
                item
                for item in sessions_payload.get("sessions", [])
                if str(item.get("session_id") or "").strip() == merged_session_id
            ),
            None,
        )
        if merged_session is None:
            merged_session = {
                "session_id": merged_session_id,
                "source_file": merged.get("filename"),
                "session_type": "merged",
                "merged_from_session_ids": list(
                    merged.get("merged_from_session_ids") or []
                ),
                "merged_at": merged.get("merged_at"),
            }

        return {
            "session": merged_session,
            "merge_sources": list(merged.get("merge_sources") or []),
            "summary": sessions_payload.get("summary", {}),
            "time_window": sessions_payload.get("time_window", "all"),
        }

    def get_session_tracks(
        self, session_ids: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        normalized_session_ids = self._normalize_session_ids(session_ids)
        if not normalized_session_ids:
            raise ValueError("session_ids must include at least 1 session")
        if len(normalized_session_ids) > 3:
            raise ValueError("session_ids supports up to 3 sessions")

        data = load_real_data() or {}
        sessions_by_id = {
            str(item.get("session_id") or "").strip(): dict(item)
            for item in get_wardrive_sessions()
            if str(item.get("session_id") or "").strip()
        }

        tracks = [
            self._build_session_track(
                session_id=session_id,
                session=sessions_by_id.get(session_id) or {"session_id": session_id},
                data=data,
            )
            for session_id in normalized_session_ids
        ]

        return {
            "tracks": tracks,
            "summary": {
                "requested_sessions": len(normalized_session_ids),
                "returned_tracks": len(tracks),
                "comparison_limit": 3,
                "active_replay_limit": 1,
            },
        }

    def _aggregate_transport_modes(
        self, sessions: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        allowed_modes = set(get_wardrive_transport_modes())
        buckets: Dict[str, Dict[str, Any]] = {}

        for item in sessions:
            mode = str(item.get("transport_mode") or "").strip().lower()
            if not mode or mode not in allowed_modes:
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

        return sorted(
            buckets.values(),
            key=lambda item: (
                -int(item.get("networks_count") or 0),
                -int(item.get("sessions_count") or 0),
                str(item.get("transport_mode") or ""),
            ),
        )

    def _build_session_distance_map(
        self, *, session_ids: Iterable[str], data: Dict[str, Any]
    ) -> Dict[str, int]:
        normalized_ids = {
            str(session_id or "").strip()
            for session_id in session_ids
            if str(session_id or "").strip()
        }
        if not normalized_ids:
            return {}

        points_by_session: Dict[str, List[Dict[str, Any]]] = {
            session_id: [] for session_id in normalized_ids
        }
        for item in data.values():
            if not isinstance(item, dict):
                continue
            for obs in item.get("wardrive_sessions") or []:
                session_id = str(obs.get("session_id") or "").strip()
                if session_id not in points_by_session:
                    continue
                lat = self._safe_float(obs.get("rawLatitude", obs.get("lat")))
                lng = self._safe_float(obs.get("rawLongitude", obs.get("lng")))
                if lat is None or lng is None:
                    continue
                if lat == 0.0 and lng == 0.0:
                    continue
                points_by_session[session_id].append(
                    {
                        "lat": float(lat),
                        "lng": float(lng),
                        "ts_last": int(self._safe_float(obs.get("ts_last")) or 0),
                        "acc": round(
                            max(
                                0.0,
                                float(
                                    self._safe_float(
                                        obs.get("rawAccuracy", obs.get("acc"))
                                    )
                                    or 0.0
                                ),
                            ),
                            2,
                        ),
                    }
                )

        distance_by_session: Dict[str, int] = {}
        for session_id, points in points_by_session.items():
            points.sort(
                key=lambda point: (
                    int(point.get("ts_last") or 0),
                    float(point.get("acc") or 0.0),
                    float(point.get("lat") or 0.0),
                    float(point.get("lng") or 0.0),
                )
            )
            thinned_points = self._thin_track_points(points)
            distance_m = 0.0
            for current, nxt in zip(thinned_points, thinned_points[1:]):
                distance_m += self._haversine_meters(
                    float(current["lat"]),
                    float(current["lng"]),
                    float(nxt["lat"]),
                    float(nxt["lng"]),
                )
            distance_by_session[session_id] = int(round(distance_m))

        return distance_by_session

    def _build_session_track(
        self,
        *,
        session_id: str,
        session: Dict[str, Any],
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        points = self._collect_session_track_points(session_id=session_id, data=data)
        points = self._thin_track_points(points)
        bbox = self._bounds_from_points(points) if points else None
        center = self._center_from_points(points) if points else None

        distance_m = 0.0
        for current, nxt in zip(points, points[1:]):
            distance_m += self._haversine_meters(
                float(current["lat"]),
                float(current["lng"]),
                float(nxt["lat"]),
                float(nxt["lng"]),
            )

        started_at = self._safe_float(session.get("started_at"))
        ended_at = self._safe_float(session.get("ended_at"))
        if len(points) >= 2:
            duration_s = max(
                0,
                int(
                    (self._safe_float(points[-1].get("ts_last")) or 0)
                    - (self._safe_float(points[0].get("ts_last")) or 0)
                ),
            )
        else:
            duration_s = max(0, int((ended_at or 0) - (started_at or 0)))

        accuracy_values = [
            float(item["acc"])
            for item in points
            if self._safe_float(item.get("acc")) is not None
        ]
        source_file = str(session.get("source_file") or "").strip()
        label = (
            str(session.get("label") or source_file or session_id).strip() or session_id
        )

        return {
            "session_id": session_id,
            "label": label,
            "source_file": source_file or label,
            "transport_mode": str(session.get("transport_mode") or "").strip().lower()
            or None,
            "bbox": bbox,
            "center": center,
            "points": points,
            "distance_m": int(round(distance_m)),
            "duration_s": int(duration_s),
            "points_count": len(points),
            "avg_accuracy_m": (
                round(sum(accuracy_values) / len(accuracy_values), 2)
                if accuracy_values
                else None
            ),
        }

    def _collect_session_track_points(
        self, *, session_id: str, data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        points: List[Dict[str, Any]] = []
        for item in data.values():
            if not isinstance(item, dict):
                continue
            for obs in item.get("wardrive_sessions") or []:
                if str(obs.get("session_id") or "").strip() != session_id:
                    continue
                lat = self._safe_float(obs.get("rawLatitude", obs.get("lat")))
                lng = self._safe_float(obs.get("rawLongitude", obs.get("lng")))
                if lat is None or lng is None:
                    continue
                if lat == 0.0 and lng == 0.0:
                    continue
                points.append(
                    {
                        "lat": float(lat),
                        "lng": float(lng),
                        "ts_last": int(self._safe_float(obs.get("ts_last")) or 0),
                        "acc": round(
                            max(
                                0.0,
                                float(
                                    self._safe_float(
                                        obs.get("rawAccuracy", obs.get("acc"))
                                    )
                                    or 0.0
                                ),
                            ),
                            2,
                        ),
                    }
                )

        points.sort(
            key=lambda item: (
                int(item.get("ts_last") or 0),
                float(item.get("acc") or 0.0),
                float(item.get("lat") or 0.0),
                float(item.get("lng") or 0.0),
            )
        )
        return points

    def _thin_track_points(self, points: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not points:
            return []

        thinned = [dict(points[0])]
        for point in points[1:]:
            previous = thinned[-1]
            distance_m = self._haversine_meters(
                float(previous["lat"]),
                float(previous["lng"]),
                float(point["lat"]),
                float(point["lng"]),
            )
            ts_delta = abs(
                int(point.get("ts_last") or 0) - int(previous.get("ts_last") or 0)
            )
            if distance_m < 5.0 and ts_delta <= 45:
                if float(point.get("acc") or 0.0) < float(previous.get("acc") or 0.0):
                    thinned[-1] = dict(point)
                continue
            thinned.append(dict(point))
        return thinned

    def _haversine_meters(
        self, lat1: float, lng1: float, lat2: float, lng2: float
    ) -> float:
        radius = 6_371_000.0
        phi1 = math.radians(lat1)
        phi2 = math.radians(lat2)
        d_phi = math.radians(lat2 - lat1)
        d_lambda = math.radians(lng2 - lng1)
        a = (
            math.sin(d_phi / 2.0) ** 2
            + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2.0) ** 2
        )
        return 2.0 * radius * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))

    def clear_runtime_cache(self) -> None:
        self._classification_cache.clear()
        self._hierarchy_cache.clear()
        self._zones_cache.clear()
        self._outline_cache.clear()

    def refresh_runtime(
        self, reload_data_enabled: bool = True, reload_maps: bool = False
    ) -> Dict[str, Any]:
        if reload_data_enabled:
            reload_data()
        else:
            load_real_data()

        if reload_maps:
            self._cache_signature = None

        self.clear_runtime_cache()
        self._ensure_index()

        sessions = get_wardrive_sessions()
        summary = get_wardrive_summary()
        return {
            "status": "ok",
            "reload_data": bool(reload_data_enabled),
            "reload_maps": bool(reload_maps),
            "wardrive_summary": summary,
            "sessions_count": len(sessions),
            "maps_revision": int(self._maps_revision),
            "data_revision": int(get_data_revision()),
        }

    def _region_sort_key(self, region: RegionEntry) -> Tuple[str, int, str, str]:
        return (
            region.country_code,
            int(region.depth),
            self._slugify(region.name),
            region.id,
        )

    def _ensure_index(self) -> None:
        signature = self._maps_signature()
        if signature == self._cache_signature:
            return

        self._cache_signature = signature
        self._maps_revision += 1
        self.clear_runtime_cache()
        self._regions_by_id = {}
        self._regions_lookup = {}
        self._spatial_indexes = {}
        self._level_depths = {}
        self._level_labels = {}
        self._max_hierarchy_depth_by_country = {}
        self._countries = {}
        self._dataset_inventory = []
        self._legacy_inventory = []

        load_summary: Dict[str, Any] = {
            "maps_dir": MAPS_DIR,
            "maps_revision": int(self._maps_revision),
            "data_revision": int(get_data_revision()),
            "files_scanned": 0,
            "supported_files": 0,
            "loaded_files": 0,
            "loaded_datasets": 0,
            "errors": [],
            "formats": {"geojson": 0, "shp": 0, "kmz": 0},
            "countries": [],
            "active_datasets": [],
            "ignored_datasets": [],
            "legacy_ignored": [],
            "incompatible_crs": [],
            "coverage_by_level": {},
        }

        if not os.path.isdir(MAPS_DIR):
            self._maps_summary = load_summary
            return

        file_paths: List[str] = []
        for root, _dirs, files in os.walk(MAPS_DIR):
            for filename in files:
                file_paths.append(os.path.join(root, filename))
        load_summary["files_scanned"] = len(file_paths)

        country_manifests, dataset_manifests, ignored_datasets, legacy_inventory = (
            self._discover_country_packs()
        )
        self._countries = {item.code: item for item in country_manifests}
        self._legacy_inventory = legacy_inventory

        load_summary["countries"] = [
            {
                "country_code": item.code,
                "country_name": item.name,
                "default_locale": item.default_locale,
            }
            for item in sorted(country_manifests, key=lambda item: item.code)
        ]
        load_summary["ignored_datasets"].extend(ignored_datasets)
        load_summary["legacy_ignored"] = list(legacy_inventory)

        for manifest in dataset_manifests:
            self._level_depths[manifest.level_key] = int(manifest.depth)
            self._level_labels[manifest.level_key] = manifest.level_label
            if manifest.include_in_hierarchy:
                current_depth = self._max_hierarchy_depth_by_country.get(
                    manifest.country_code, 0
                )
                self._max_hierarchy_depth_by_country[manifest.country_code] = max(
                    current_depth, int(manifest.depth)
                )
            inventory = {
                "country_code": manifest.country_code,
                "country_name": manifest.country_name,
                "dataset_id": manifest.dataset_id,
                "dataset_source": manifest.dataset_source,
                "version": manifest.version,
                "level_key": manifest.level_key,
                "level_label": manifest.level_label,
                "depth": manifest.depth,
                "depth_role": manifest.depth_role,
                "enabled": manifest.enabled,
                "priority": manifest.priority,
                "geometry_format": manifest.geometry_format,
                "crs": manifest.crs,
                "compatible_crs": self._is_crs_supported(manifest.crs),
                "metadata_path": manifest.metadata_path,
                "source_path": manifest.source_path,
                "path_glob": manifest.path_glob,
                "include_in_hierarchy": manifest.include_in_hierarchy,
                "regions_count": 0,
                "supported_files": 0,
                "loaded_files": 0,
                "errors": [],
            }

            if not inventory["compatible_crs"]:
                load_summary["incompatible_crs"].append(
                    {
                        "dataset_id": manifest.dataset_id,
                        "country_code": manifest.country_code,
                        "level_key": manifest.level_key,
                        "crs": manifest.crs,
                        "metadata_path": manifest.metadata_path,
                    }
                )
                load_summary["ignored_datasets"].append(
                    {
                        "dataset_id": manifest.dataset_id,
                        "country_code": manifest.country_code,
                        "reason": f"Unsupported CRS: {manifest.crs}",
                        "metadata_path": manifest.metadata_path,
                    }
                )
                self._dataset_inventory.append(inventory)
                continue

            dataset_files = self._resolve_dataset_files(manifest)
            inventory["supported_files"] = len(dataset_files)
            load_summary["supported_files"] += len(dataset_files)

            if not dataset_files:
                inventory["errors"].append("No matching files found")
                load_summary["errors"].append(
                    {
                        "path": manifest.metadata_path,
                        "error": "No matching files found",
                    }
                )
                self._dataset_inventory.append(inventory)
                continue

            loaded_any = False
            for path in dataset_files:
                try:
                    loaded_regions_before = len(self._regions_by_id)
                    file_loaded = self._load_map_file(path, manifest)
                    if file_loaded:
                        inventory["loaded_files"] += 1
                        loaded_any = True
                        load_summary["loaded_files"] += 1
                        load_summary["formats"][self._extension_to_format(path)] += 1
                    inventory["regions_count"] += max(
                        0, len(self._regions_by_id) - loaded_regions_before
                    )
                except Exception as exc:
                    logger.warning("Failed loading map file %s: %s", path, exc)
                    inventory["errors"].append(str(exc))
                    load_summary["errors"].append({"path": path, "error": str(exc)})

            if loaded_any:
                load_summary["loaded_datasets"] += 1
                load_summary["active_datasets"].append(
                    {
                        "dataset_id": manifest.dataset_id,
                        "country_code": manifest.country_code,
                        "country_name": manifest.country_name,
                        "level_key": manifest.level_key,
                        "level_label": manifest.level_label,
                        "depth": manifest.depth,
                        "depth_role": manifest.depth_role,
                        "priority": manifest.priority,
                        "loaded_files": inventory["loaded_files"],
                        "regions_count": inventory["regions_count"],
                    }
                )

            self._dataset_inventory.append(inventory)

        self._resolve_missing_parents()
        self._build_spatial_indexes()

        coverage_by_level: Dict[str, Dict[str, Dict[str, int]]] = {}
        for region in self._regions_by_id.values():
            country_bucket = coverage_by_level.setdefault(region.country_code, {})
            level_bucket = country_bucket.setdefault(
                region.level_key,
                {
                    "depth": region.depth,
                    "regions_count": 0,
                    "hierarchy_regions_count": 0,
                },
            )
            level_bucket["regions_count"] += 1
            if region.include_in_hierarchy:
                level_bucket["hierarchy_regions_count"] += 1

        load_summary["coverage_by_level"] = coverage_by_level
        load_summary["regions_count"] = len(self._regions_by_id)
        load_summary["dataset_inventory"] = list(self._dataset_inventory)
        load_summary["maps_revision"] = int(self._maps_revision)
        load_summary["data_revision"] = int(get_data_revision())
        self._maps_summary = load_summary

    def _discover_country_packs(
        self,
    ) -> Tuple[
        List[CountryManifest],
        List[DatasetManifest],
        List[Dict[str, Any]],
        List[Dict[str, Any]],
    ]:
        countries: List[CountryManifest] = []
        datasets: List[DatasetManifest] = []
        ignored: List[Dict[str, Any]] = []
        legacy: List[Dict[str, Any]] = []

        for entry in sorted(os.listdir(MAPS_DIR)):
            abs_path = os.path.join(MAPS_DIR, entry)
            if not os.path.isdir(abs_path):
                continue

            country_json = os.path.join(abs_path, "country.json")
            if os.path.isfile(country_json):
                try:
                    country = self._load_country_manifest(country_json)
                    countries.append(country)
                    country_datasets, country_ignored = self._load_dataset_manifests(
                        country
                    )
                    datasets.extend(country_datasets)
                    ignored.extend(country_ignored)
                except Exception as exc:
                    ignored.append(
                        {
                            "country_code": entry,
                            "reason": str(exc),
                            "metadata_path": country_json,
                        }
                    )
                continue

            legacy.append(self._build_legacy_entry(abs_path))

        datasets.sort(
            key=lambda item: (
                item.country_code,
                int(item.depth),
                int(item.priority),
                item.dataset_id,
            )
        )
        return countries, datasets, ignored, legacy

    def _load_country_manifest(self, path: str) -> CountryManifest:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            raw = json.load(handle) or {}

        code = (
            str(raw.get("country_code") or os.path.basename(os.path.dirname(path)))
            .strip()
            .lower()
        )
        name = str(raw.get("country_name") or code.upper()).strip() or code.upper()
        locale = str(raw.get("default_locale") or "en-US").strip() or "en-US"
        labels = raw.get("labels") if isinstance(raw.get("labels"), dict) else {}
        return CountryManifest(
            code=code,
            name=name,
            default_locale=locale,
            labels={str(k): str(v) for k, v in labels.items()},
            path=os.path.dirname(path),
        )

    def _load_dataset_manifests(
        self,
        country: CountryManifest,
    ) -> Tuple[List[DatasetManifest], List[Dict[str, Any]]]:
        datasets: List[DatasetManifest] = []
        ignored: List[Dict[str, Any]] = []
        pattern = os.path.join(country.path, "layers", "*", "*", "metadata.json")

        for metadata_path in sorted(glob.glob(pattern)):
            with open(metadata_path, "r", encoding="utf-8", errors="ignore") as handle:
                raw = json.load(handle) or {}

            level_dir = os.path.basename(
                os.path.dirname(os.path.dirname(metadata_path))
            )
            depth, default_level_key = self._parse_level_dir(level_dir)
            level_key = (
                str(raw.get("level_key") or default_level_key or "region")
                .strip()
                .lower()
            )
            level_label = str(
                raw.get("level_label")
                or country.labels.get(level_key)
                or level_key.title()
            ).strip()
            enabled = bool(raw.get("enabled", True))
            include_in_hierarchy = bool(
                raw.get(
                    "include_in_hierarchy",
                    raw.get("depth_role", "administrative") != "fallback",
                )
            )

            manifest = DatasetManifest(
                country_code=country.code,
                country_name=country.name,
                dataset_id=str(
                    raw.get("dataset_id")
                    or os.path.basename(os.path.dirname(metadata_path))
                ).strip(),
                dataset_source=str(raw.get("source") or "custom").strip(),
                version=str(raw.get("version") or "unknown").strip(),
                enabled=enabled,
                priority=int(raw.get("priority", 100)),
                level_key=level_key,
                level_label=level_label or level_key.title(),
                depth=depth,
                depth_role=str(raw.get("depth_role") or "administrative")
                .strip()
                .lower(),
                geometry_format=str(raw.get("geometry_format") or "").strip().lower(),
                crs=str(raw.get("crs") or "").strip(),
                metadata_path=metadata_path,
                source_path=self._manifest_rel_path(
                    metadata_path, raw.get("source_path")
                ),
                path_glob=self._manifest_rel_path(metadata_path, raw.get("path_glob")),
                id_fields=[
                    str(item).strip()
                    for item in raw.get("id_fields") or []
                    if str(item).strip()
                ],
                name_fields=[
                    str(item).strip()
                    for item in raw.get("name_fields") or []
                    if str(item).strip()
                ],
                parent_resolvers=list(raw.get("parent_resolvers") or []),
                include_in_hierarchy=include_in_hierarchy,
            )

            if not enabled:
                ignored.append(
                    {
                        "dataset_id": manifest.dataset_id,
                        "country_code": manifest.country_code,
                        "reason": "Dataset disabled",
                        "metadata_path": metadata_path,
                    }
                )
                continue

            datasets.append(manifest)

        return datasets, ignored

    def _parse_level_dir(self, value: str) -> Tuple[int, str]:
        match = re.match(r"^(\d+)-(.+)$", str(value or "").strip())
        if not match:
            return 999, self._slugify(value or "region")
        return int(match.group(1)), self._slugify(match.group(2))

    def _manifest_rel_path(self, metadata_path: str, raw_value: Any) -> Optional[str]:
        text = str(raw_value or "").strip()
        if not text:
            return None
        if os.path.isabs(text):
            return text
        return os.path.join(os.path.dirname(metadata_path), text)

    def _resolve_dataset_files(self, manifest: DatasetManifest) -> List[str]:
        paths: List[str] = []
        if manifest.source_path:
            paths.append(manifest.source_path)
        if manifest.path_glob:
            paths.extend(sorted(glob.glob(manifest.path_glob)))

        resolved: List[str] = []
        seen: set[str] = set()
        for path in paths:
            if not os.path.exists(path):
                continue
            lower = path.lower()
            if os.path.isdir(path):
                for root, _dirs, files in os.walk(path):
                    for filename in sorted(files):
                        child = os.path.join(root, filename)
                        if (
                            child.lower().endswith(SUPPORTED_EXTENSIONS)
                            and child not in seen
                        ):
                            resolved.append(child)
                            seen.add(child)
                continue
            if lower.endswith(SUPPORTED_EXTENSIONS) and path not in seen:
                resolved.append(path)
                seen.add(path)
        return resolved

    def _build_legacy_entry(self, path: str) -> Dict[str, Any]:
        files = 0
        sample_extensions: List[str] = []
        for root, _dirs, filenames in os.walk(path):
            for filename in filenames:
                files += 1
                ext = os.path.splitext(filename)[1].lower()
                if ext and ext not in sample_extensions:
                    sample_extensions.append(ext)
        return {
            "path": path,
            "reason": "Outside canonical country-pack structure",
            "files_count": files,
            "extensions": sorted(sample_extensions),
        }

    def _build_spatial_indexes(self) -> None:
        level_keys = sorted(
            self._level_depths.keys(),
            key=lambda key: (self._level_depths.get(key, 999), key),
        )
        for level_key in level_keys:
            rows: List[Tuple[str, BaseGeometry]] = []
            for region in self._regions_by_id.values():
                if region.level_key != level_key:
                    continue
                for geom in region.geometries:
                    rows.append((region.id, geom))
            self._spatial_indexes[level_key] = _LevelSpatialIndex(rows)

    def _maps_signature(self) -> Tuple[Tuple[str, int, int], ...]:
        if not os.path.isdir(MAPS_DIR):
            return tuple()

        rows: List[Tuple[str, int, int]] = []
        for root, _dirs, files in os.walk(MAPS_DIR):
            for filename in files:
                path = os.path.join(root, filename)
                try:
                    stat = os.stat(path)
                except OSError:
                    continue
                rows.append((path, int(stat.st_mtime), int(stat.st_size)))
        rows.sort()
        return tuple(rows)

    def _load_map_file(self, path: str, manifest: DatasetManifest) -> bool:
        lower = path.lower()
        if lower.endswith(".geojson") or lower.endswith(".json"):
            return self._load_geojson(path, manifest)
        if lower.endswith(".shp"):
            return self._load_shp(path, manifest)
        if lower.endswith(".kmz"):
            return self._load_kmz(path, manifest)
        return False

    def _load_geojson(self, path: str, manifest: DatasetManifest) -> bool:
        with open(path, "r", encoding="utf-8", errors="ignore") as handle:
            raw = json.load(handle)

        if not isinstance(raw, dict) or raw.get("type") != "FeatureCollection":
            return False

        features = raw.get("features") or []
        loaded_any = False
        for feature in features:
            if not isinstance(feature, dict):
                continue
            props = feature.get("properties") or {}
            geometry_data = feature.get("geometry")
            if not geometry_data:
                continue
            geometry = self._safe_geometry(shape(geometry_data))
            if geometry is None:
                continue
            loaded_any = (
                self._add_feature(
                    props=props,
                    geometry=geometry,
                    source_format="geojson",
                    source_path=path,
                    manifest=manifest,
                )
                or loaded_any
            )
        return loaded_any

    def _load_shp(self, path: str, manifest: DatasetManifest) -> bool:
        if shapefile is None:
            raise RuntimeError("pyshp (shapefile) is not available")

        reader = shapefile.Reader(path)
        fields = [f[0] for f in reader.fields[1:]]
        loaded_any = False

        for shape_record in reader.iterShapeRecords():
            props = dict(zip(fields, shape_record.record))
            geometry = self._safe_geometry(shape(shape_record.shape.__geo_interface__))
            if geometry is None:
                continue
            loaded_any = (
                self._add_feature(
                    props=props,
                    geometry=geometry,
                    source_format="shp",
                    source_path=path,
                    manifest=manifest,
                )
                or loaded_any
            )
        return loaded_any

    def _load_kmz(self, path: str, manifest: DatasetManifest) -> bool:
        with zipfile.ZipFile(path, "r") as archive:
            kml_name = next(
                (n for n in archive.namelist() if n.lower().endswith(".kml")), None
            )
            if not kml_name:
                return False
            xml_data = archive.read(kml_name)

        root = ET.fromstring(xml_data)
        placemarks = root.findall(".//kml:Placemark", KML_NS)
        loaded_any = False
        for placemark in placemarks:
            props = self._extract_kml_properties(placemark)
            geometry = self._extract_kml_geometry(placemark)
            if geometry is None:
                continue
            loaded_any = (
                self._add_feature(
                    props=props,
                    geometry=geometry,
                    source_format="kmz",
                    source_path=path,
                    manifest=manifest,
                )
                or loaded_any
            )
        return loaded_any

    def _extract_kml_properties(self, placemark: ET.Element) -> Dict[str, Any]:
        props: Dict[str, Any] = {}

        name_el = placemark.find("kml:name", KML_NS)
        if name_el is not None and name_el.text:
            props["name"] = name_el.text

        for simple_data in placemark.findall(".//kml:SimpleData", KML_NS):
            key = simple_data.attrib.get("name")
            if key:
                props[key] = simple_data.text

        for data in placemark.findall(".//kml:Data", KML_NS):
            key = data.attrib.get("name")
            if not key:
                continue
            value_el = data.find("kml:value", KML_NS)
            props[key] = value_el.text if value_el is not None else None

        return props

    def _extract_kml_geometry(self, placemark: ET.Element) -> Optional[BaseGeometry]:
        polygons: List[Polygon] = []

        for polygon_el in placemark.findall(".//kml:Polygon", KML_NS):
            outer_el = polygon_el.find(
                "kml:outerBoundaryIs/kml:LinearRing/kml:coordinates", KML_NS
            )
            if outer_el is None or not outer_el.text:
                continue
            outer_ring = self._parse_kml_ring(outer_el.text)
            if len(outer_ring) < 3:
                continue

            holes: List[List[Tuple[float, float]]] = []
            for inner_el in polygon_el.findall(
                "kml:innerBoundaryIs/kml:LinearRing/kml:coordinates", KML_NS
            ):
                if inner_el.text:
                    inner_ring = self._parse_kml_ring(inner_el.text)
                    if len(inner_ring) >= 3:
                        holes.append(inner_ring)

            try:
                poly = Polygon(outer_ring, holes)
            except Exception:
                continue

            fixed = self._safe_geometry(poly)
            if isinstance(fixed, Polygon):
                polygons.append(fixed)
            elif isinstance(fixed, MultiPolygon):
                polygons.extend([p for p in fixed.geoms])

        if not polygons:
            return None
        if len(polygons) == 1:
            return polygons[0]
        return self._safe_geometry(MultiPolygon(polygons))

    def _parse_kml_ring(self, coords_text: str) -> List[Tuple[float, float]]:
        points: List[Tuple[float, float]] = []
        chunks = re.split(r"\s+", coords_text.strip())
        for chunk in chunks:
            if not chunk:
                continue
            parts = chunk.split(",")
            if len(parts) < 2:
                continue
            try:
                lng = float(parts[0])
                lat = float(parts[1])
            except Exception:
                continue
            points.append((lng, lat))

        if points and points[0] != points[-1]:
            points.append(points[0])
        return points

    def _safe_geometry(self, geometry: BaseGeometry) -> Optional[BaseGeometry]:
        if geometry is None or geometry.is_empty:
            return None

        if not geometry.is_valid:
            geometry = geometry.buffer(0)
            if geometry.is_empty:
                return None

        if isinstance(geometry, Polygon):
            return geometry
        if isinstance(geometry, MultiPolygon):
            return geometry

        if geometry.geom_type == "GeometryCollection":
            polygons = [
                g for g in geometry.geoms if isinstance(g, (Polygon, MultiPolygon))
            ]
            if not polygons:
                return None
            merged = unary_union(polygons)
            if isinstance(merged, (Polygon, MultiPolygon)):
                return merged
        return None

    def _add_feature(
        self,
        props: Dict[str, Any],
        geometry: BaseGeometry,
        source_format: str,
        source_path: str,
        manifest: DatasetManifest,
    ) -> bool:
        code = self._pick_manifest_prop(props, manifest.id_fields)
        name = self._pick_manifest_prop(props, manifest.name_fields)

        region_name = name or code or os.path.splitext(os.path.basename(source_path))[0]
        region_code = code or self._slugify(region_name)
        parent_hints = self._build_parent_hints(props, manifest)
        parent_id = self._resolve_parent_id(manifest.country_code, parent_hints)

        region_id = self._build_region_id(
            country_code=manifest.country_code,
            level_key=manifest.level_key,
            code=region_code,
            name=region_name,
        )

        source_rank = FORMAT_RANK.get(source_format, 999)
        existing = self._regions_by_id.get(region_id)
        new_precedence = (int(manifest.priority), int(source_rank))

        if existing:
            existing_precedence = (int(existing.priority), int(existing.source_rank))
            if existing_precedence < new_precedence:
                return False
            if existing_precedence > new_precedence:
                existing.country_name = manifest.country_name
                existing.level_label = manifest.level_label
                existing.depth = int(manifest.depth)
                existing.depth_role = manifest.depth_role
                existing.name = region_name
                existing.code = region_code
                existing.parent_id = parent_id
                existing.parent_hints = parent_hints
                existing.source_format = source_format
                existing.source_path = source_path
                existing.source_rank = source_rank
                existing.dataset_id = manifest.dataset_id
                existing.dataset_source = manifest.dataset_source
                existing.priority = int(manifest.priority)
                existing.include_in_hierarchy = manifest.include_in_hierarchy
                existing.geometries = [geometry]
                self._register_region_lookup(existing)
                return True

            existing.parent_hints.extend(parent_hints)
            if existing.parent_id is None:
                existing.parent_id = parent_id
            existing.geometries.append(geometry)
            return True

        region = RegionEntry(
            id=region_id,
            country_code=manifest.country_code,
            country_name=manifest.country_name,
            level_key=manifest.level_key,
            level_label=manifest.level_label,
            depth=int(manifest.depth),
            depth_role=manifest.depth_role,
            name=region_name,
            code=region_code,
            parent_id=parent_id,
            parent_hints=parent_hints,
            source_format=source_format,
            source_path=source_path,
            source_rank=source_rank,
            dataset_id=manifest.dataset_id,
            dataset_source=manifest.dataset_source,
            priority=int(manifest.priority),
            include_in_hierarchy=manifest.include_in_hierarchy,
            geometries=[geometry],
        )
        self._regions_by_id[region.id] = region
        self._register_region_lookup(region)
        return True

    def _build_parent_hints(
        self, props: Dict[str, Any], manifest: DatasetManifest
    ) -> List[ParentHint]:
        hints: List[ParentHint] = []
        for resolver in manifest.parent_resolvers:
            if not isinstance(resolver, dict):
                continue
            target_level_key = self._slugify(
                resolver.get("target_level_key") or resolver.get("target_level") or ""
            )
            if not target_level_key:
                continue
            target_key = str(resolver.get("target_key") or "code").strip().lower()
            source_fields = (
                resolver.get("source_fields") or resolver.get("fields") or []
            )
            if isinstance(source_fields, str):
                source_fields = [source_fields]
            value = self._pick_manifest_prop(
                props, [str(item) for item in source_fields]
            )
            if not value:
                continue
            hints.append(
                ParentHint(
                    target_level_key=target_level_key,
                    target_key=target_key,
                    value=value,
                )
            )
        return hints

    def _register_region_lookup(self, region: RegionEntry) -> None:
        bucket = self._regions_lookup.setdefault(
            (region.country_code, region.level_key), {"code": {}, "name": {}}
        )
        if region.code:
            bucket["code"][self._normalize_lookup_value(region.code)] = region.id
        bucket["name"][self._normalize_lookup_value(region.name)] = region.id

    def _resolve_parent_id(
        self, country_code: str, parent_hints: List[ParentHint]
    ) -> Optional[str]:
        for hint in parent_hints:
            bucket = self._regions_lookup.get((country_code, hint.target_level_key))
            if not bucket:
                continue
            target_bucket = bucket.get(hint.target_key)
            if not target_bucket:
                continue
            match = target_bucket.get(self._normalize_lookup_value(hint.value))
            if match:
                return match
        return None

    def _resolve_missing_parents(self) -> None:
        changed = True
        while changed:
            changed = False
            for region in self._regions_by_id.values():
                if region.parent_id is not None:
                    continue
                parent_id = self._resolve_parent_id(
                    region.country_code, region.parent_hints
                )
                if parent_id:
                    region.parent_id = parent_id
                    changed = True

    def _build_region_id(
        self, country_code: str, level_key: str, code: str, name: str
    ) -> str:
        identity = self._normalize_lookup_value(code or name)
        return f"{country_code}:{level_key}:{identity}"

    def _pick_manifest_prop(self, props: Dict[str, Any], field_names: List[str]) -> str:
        if not isinstance(props, dict):
            return ""

        lower_map = {str(k).lower(): v for k, v in props.items()}
        for key in field_names:
            value = lower_map.get(str(key).lower())
            text = self._as_text(value)
            if text:
                return text
        return ""

    def _normalize_lookup_value(self, value: str) -> str:
        text = self._as_text(value)
        if not text:
            return ""
        digits = re.sub(r"\D+", "", text)
        if digits and digits == text:
            return digits
        return self._slugify(text)

    def _slugify(self, value: str) -> str:
        text = unicodedata.normalize("NFKD", str(value or ""))
        text = text.encode("ascii", "ignore").decode("ascii")
        text = re.sub(r"[^a-zA-Z0-9]+", "-", text.strip().lower())
        return text.strip("-") or "unknown"

    def _as_text(self, value: Any) -> str:
        if value is None:
            return ""
        text = str(value).strip()
        if not text:
            return ""
        if text.lower() in {"nan", "none", "null"}:
            return ""
        return text

    def _normalize_time_window(self, time_window: str) -> str:
        value = str(time_window or "all").strip().lower()
        if value not in {"all", "24h"}:
            return "all"
        return value

    def _normalize_source_filter(self, source: str) -> str:
        value = str(source or "all").strip().lower()
        if value not in {"all", "pwn", "bruce", "ward", "raw"}:
            return "all"
        return value

    def _normalize_session_ids(self, session_ids: Optional[Iterable[str]]) -> List[str]:
        if not session_ids:
            return []

        available_sessions = {
            str(item.get("session_id") or "").strip()
            for item in get_wardrive_sessions()
            if str(item.get("session_id") or "").strip()
        }
        normalized: List[str] = []
        seen: set[str] = set()
        for raw_value in session_ids:
            value = str(raw_value or "").strip()
            if not value or value in seen:
                continue
            normalized.append(value)
            seen.add(value)

        if not normalized:
            return []

        unknown = [value for value in normalized if value not in available_sessions]
        if unknown:
            raise ValueError(f"session_ids not found: {', '.join(unknown)}")
        return normalized

    def _runtime_cache_scope(
        self,
        time_window: str,
        source: str,
        session_ids: Optional[List[str]] = None,
    ) -> Tuple[Any, ...]:
        normalized_session_ids = tuple(
            str(item or "").strip()
            for item in (session_ids or [])
            if str(item or "").strip()
        )
        return (
            int(self._maps_revision),
            int(get_data_revision()),
            str(time_window),
            str(source),
            normalized_session_ids,
        )

    def _lru_get(
        self, cache: "OrderedDict[Tuple[Any, ...], Any]", key: Tuple[Any, ...]
    ) -> Any:
        if key not in cache:
            return None
        value = cache.pop(key)
        cache[key] = value
        return value

    def _lru_set(
        self,
        cache: "OrderedDict[Tuple[Any, ...], Any]",
        key: Tuple[Any, ...],
        value: Any,
        limit: int,
    ) -> None:
        if key in cache:
            cache.pop(key)
        cache[key] = value
        while len(cache) > max(1, int(limit)):
            cache.popitem(last=False)

    def _get_classification(
        self,
        time_window: str,
        source: str,
        session_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        # Ensure revision key reflects the current dataset snapshot.
        load_real_data()
        cache_key = ("classification",) + self._runtime_cache_scope(
            time_window=time_window,
            source=source,
            session_ids=session_ids,
        )
        cached = self._lru_get(self._classification_cache, cache_key)
        if cached is not None:
            return cached

        payload = self._classify_points(
            time_window=time_window,
            source=source,
            session_ids=session_ids,
        )
        self._lru_set(
            self._classification_cache,
            cache_key,
            payload,
            self._max_classification_cache_entries,
        )
        return payload

    def _source_matches(self, sources: Iterable[str], source_filter: str) -> bool:
        normalized = {
            str(s or "").strip().lower() for s in sources if str(s or "").strip()
        }
        if not normalized:
            normalized = {"pwnagotchi"}

        if source_filter == "all":
            return True
        if source_filter == "pwn":
            return "pwnagotchi" in normalized
        if source_filter == "bruce":
            return "brucegotchi" in normalized
        if source_filter == "ward":
            return "wardrive" in normalized
        if source_filter == "raw":
            return any(
                source
                in {
                    "bruce_raw",
                    "bruce_raw_sniffing",
                    "m5evil_raw_sniffing",
                    "m5evil_master_raw_sniffing",
                    "rawsniffer",
                }
                for source in normalized
            )
        return True

    def _ordered_level_keys(self) -> List[str]:
        return sorted(
            self._level_depths.keys(),
            key=lambda key: (-self._level_depths.get(key, 999), key),
        )

    def _item_matches_time_window(
        self, item: Dict[str, Any], time_window: str, now_ts: int
    ) -> bool:
        ts_last = int(self._safe_float(item.get("ts_last")) or 0)
        if time_window == "24h" and ts_last < now_ts - 86_400:
            return False
        return True

    def _build_item_point_payload(
        self, item: Dict[str, Any]
    ) -> Optional[Dict[str, float]]:
        lat = self._safe_float(item.get("lat"))
        lng = self._safe_float(item.get("lng"))
        if lat is None or lng is None:
            return None
        if lat == 0.0 and lng == 0.0:
            return None
        return {
            "lat": float(lat),
            "lng": float(lng),
            "acc": max(0.0, float(self._safe_float(item.get("acc")) or 0.0)),
        }

    def _observation_position(
        self, observation: Dict[str, Any], prefer_display: bool = False
    ) -> Dict[str, Any]:
        if prefer_display:
            lat = observation.get("displayLatitude")
            lng = observation.get("displayLongitude")
            if lat is None or lng is None:
                lat = observation.get("lat")
                lng = observation.get("lng")
        else:
            lat = observation.get("rawLatitude")
            lng = observation.get("rawLongitude")
            if lat is None or lng is None:
                lat = observation.get("lat")
                lng = observation.get("lng")

        acc = observation.get("rawAccuracy")
        if acc is None:
            acc = observation.get("acc")

        return {
            "lat": lat,
            "lng": lng,
            "acc": acc,
            "ts_last": observation.get("ts_last"),
        }

    def _build_selected_wardrive_item(
        self,
        item: Dict[str, Any],
        session_ids: List[str],
        time_window: str,
        now_ts: int,
    ) -> Optional[Dict[str, Any]]:
        observations = [
            obs
            for obs in (item.get("wardrive_sessions") or [])
            if str(obs.get("session_id") or "") in session_ids
        ]
        if not observations:
            return None

        valid_observations = []
        for obs in observations:
            candidate = self._observation_position(obs, prefer_display=True)
            point_payload = self._build_item_point_payload(candidate)
            if point_payload is None:
                continue
            if not self._item_matches_time_window(
                {"ts_last": obs.get("ts_last")}, time_window, now_ts
            ):
                continue
            valid_observations.append(obs)

        if not valid_observations:
            return None

        valid_observations.sort(
            key=lambda obs: (
                -(self._safe_float(obs.get("ts_last")) or 0),
                self._safe_float(obs.get("acc")) or 999999,
            )
        )
        selected = valid_observations[0]
        merged = dict(item)
        merged.update(
            {
                "lat": selected.get("displayLatitude", selected.get("lat")),
                "lng": selected.get("displayLongitude", selected.get("lng")),
                "acc": selected.get("rawAccuracy", selected.get("acc")),
                "ts_last": selected.get("ts_last"),
                "ts_first": selected.get("ts_first"),
                "channel": selected.get("channel"),
                "frequency": selected.get("frequency"),
                "rssi": selected.get("rssi"),
                "altitude": selected.get("altitude"),
                "rawLatitude": selected.get("rawLatitude", selected.get("lat")),
                "rawLongitude": selected.get("rawLongitude", selected.get("lng")),
                "rawAccuracy": selected.get("rawAccuracy", selected.get("acc")),
                "displayLatitude": selected.get("displayLatitude", selected.get("lat")),
                "displayLongitude": selected.get(
                    "displayLongitude", selected.get("lng")
                ),
                "encryption": selected.get("encryption") or item.get("encryption"),
                "sessionId": selected.get("session_id"),
                "sessionSourceFile": selected.get("source_file"),
                "sources": ["wardrive"],
            }
        )
        merged["wardrive_sessions"] = [dict(obs) for obs in valid_observations]
        return merged

    def _classify_point(self, point: Point) -> Optional[str]:
        best_admin: Optional[Tuple[int, float, int, str]] = None
        best_fallback: Optional[Tuple[int, float, int, str]] = None

        for level_key in self._ordered_level_keys():
            index = self._spatial_indexes.get(level_key)
            if index is None:
                continue

            candidates = index.query(point)
            for region_id, geom in candidates:
                try:
                    if not geom.covers(point):
                        continue
                except Exception:
                    continue

                region = self._regions_by_id.get(region_id)
                if region is None:
                    continue

                score = (
                    int(region.depth),
                    float(geom.area),
                    -int(region.priority),
                    region_id,
                )
                if region.depth_role == "fallback":
                    if (
                        best_fallback is None
                        or score[0] > best_fallback[0]
                        or (
                            score[0] == best_fallback[0]
                            and (score[1], score[2], score[3])
                            < (best_fallback[1], best_fallback[2], best_fallback[3])
                        )
                    ):
                        best_fallback = score
                else:
                    if (
                        best_admin is None
                        or score[0] > best_admin[0]
                        or (
                            score[0] == best_admin[0]
                            and (score[1], score[2], score[3])
                            < (best_admin[1], best_admin[2], best_admin[3])
                        )
                    ):
                        best_admin = score

        if best_fallback:
            fallback_region = self._regions_by_id.get(best_fallback[3])
            if fallback_region is not None:
                visible_ancestor = self._nearest_visible_ancestor(fallback_region)
                max_visible_depth = self._max_hierarchy_depth_by_country.get(
                    fallback_region.country_code, 0
                )
                if visible_ancestor is None or int(visible_ancestor.depth) < int(
                    max_visible_depth
                ):
                    return best_fallback[3]
        if best_admin:
            return best_admin[3]
        if best_fallback:
            return best_fallback[3]
        return None

    def _nearest_visible_ancestor(self, region: RegionEntry) -> Optional[RegionEntry]:
        current: Optional[RegionEntry] = region
        while current is not None:
            if current.include_in_hierarchy:
                return current
            current = (
                self._regions_by_id.get(current.parent_id)
                if current.parent_id
                else None
            )
        return None

    def _classify_points(
        self,
        time_window: str,
        source: str,
        session_ids: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        data = load_real_data() or {}
        now_ts = int(time.time())
        normalized_session_ids = list(session_ids or [])

        points_by_region: Dict[str, List[Dict[str, float]]] = {}
        stats_by_region: Dict[str, Dict[str, int]] = {}
        unmapped_points: List[Dict[str, float]] = []
        unmapped_stats = self._empty_stats()

        for item in data.values():
            if not isinstance(item, dict):
                continue

            effective_item = item
            if normalized_session_ids:
                effective_item = self._build_selected_wardrive_item(
                    item=item,
                    session_ids=normalized_session_ids,
                    time_window=time_window,
                    now_ts=now_ts,
                )
                if effective_item is None:
                    continue
            else:
                sources = item.get("sources") or []
                if not self._source_matches(sources, source):
                    continue
                if source == "ward" and item.get("wardrive_sessions"):
                    effective_item = self._build_selected_wardrive_item(
                        item=item,
                        session_ids=[
                            str(obs.get("session_id") or "")
                            for obs in (item.get("wardrive_sessions") or [])
                            if str(obs.get("session_id") or "").strip()
                        ],
                        time_window=time_window,
                        now_ts=now_ts,
                    )
                    if effective_item is None:
                        continue
                else:
                    if not self._item_matches_time_window(item, time_window, now_ts):
                        continue

            point_payload = self._build_item_point_payload(effective_item)
            if point_payload is None:
                continue

            region_id = self._classify_point(
                Point(float(point_payload["lng"]), float(point_payload["lat"]))
            )
            if region_id is None:
                unmapped_points.append(point_payload)
                self._increment_stats(unmapped_stats, effective_item)
                continue

            current = region_id
            while current:
                points_by_region.setdefault(current, []).append(point_payload)
                current_stats = stats_by_region.setdefault(current, self._empty_stats())
                self._increment_stats(current_stats, effective_item)
                current_region = self._regions_by_id.get(current)
                current = current_region.parent_id if current_region else None

        return {
            "points_by_region": points_by_region,
            "stats_by_region": stats_by_region,
            "unmapped_points": unmapped_points,
            "unmapped_summary": unmapped_stats,
        }

    def _serialize_region(
        self, region: RegionEntry, stats: Optional[Dict[str, int]] = None
    ) -> Dict[str, Any]:
        payload = {
            "id": region.id,
            "level": region.level_key,
            "level_key": region.level_key,
            "level_label": region.level_label,
            "depth": int(region.depth),
            "depth_role": region.depth_role,
            "country_code": region.country_code,
            "country_name": region.country_name,
            "parent_id": region.parent_id,
            "name": region.name,
            "code": region.code,
            "bbox": self._bounds_from_geometries(region.geometries),
            "center": self._center_from_geometries(region.geometries),
            "stats": stats or self._empty_stats(),
            "source_format": region.source_format,
            "dataset_id": region.dataset_id,
            "dataset_source": region.dataset_source,
        }
        lineage = self._build_lineage(region)
        payload["lineage"] = lineage
        payload["display_path"] = (
            " > ".join(item["name"] for item in lineage) if lineage else region.name
        )
        return payload

    def _build_lineage(self, region: RegionEntry) -> List[Dict[str, Any]]:
        lineage: List[Dict[str, Any]] = [
            {
                "id": f"{region.country_code}:country",
                "level_key": "country",
                "level_label": "Pais",
                "name": region.country_name,
                "depth": 0,
            }
        ]

        chain: List[RegionEntry] = []
        current: Optional[RegionEntry] = region
        while current is not None:
            chain.append(current)
            current = (
                self._regions_by_id.get(current.parent_id)
                if current.parent_id
                else None
            )

        for item in reversed(chain):
            lineage.append(
                {
                    "id": item.id,
                    "level_key": item.level_key,
                    "level_label": item.level_label,
                    "name": item.name,
                    "depth": item.depth,
                }
            )
        return lineage

    def _increment_stats(self, stats: Dict[str, int], item: Dict[str, Any]) -> None:
        stats["networks_count"] += 1
        if item.get("pass"):
            stats["cracked"] += 1
            return

        encryption = str(item.get("encryption") or "").upper()
        if encryption in {"OPEN", "WEP"}:
            stats["open"] += 1
        else:
            stats["locked"] += 1

    def _empty_stats(self) -> Dict[str, int]:
        return {
            "networks_count": 0,
            "cracked": 0,
            "open": 0,
            "locked": 0,
        }

    def _build_zones(
        self, points: List[Dict[str, float]], eps_m: float, min_samples: int
    ) -> List[Dict[str, Any]]:
        if not points:
            return []

        clusters = cluster_points(points, eps_m=eps_m, min_samples=min_samples)
        zones: List[Dict[str, Any]] = []

        for cluster in clusters:
            cluster_points_list = cluster.get("points") or []
            if len(cluster_points_list) < max(2, min_samples):
                continue

            coords = [
                (float(p["lng"]), float(p["lat"]))
                for p in cluster_points_list
                if p.get("lat") is not None and p.get("lng") is not None
            ]
            if len(coords) < 2:
                continue

            hull = unary_union(
                [
                    Point(lng, lat).buffer(
                        self._meters_to_degrees(
                            lat, max(float(point.get("acc") or 0.0), 8.0)
                        )
                    )
                    for (lng, lat), point in zip(coords, cluster_points_list)
                ]
            )
            if hull is None or hull.is_empty:
                continue

            parts = self._geometry_to_parts(hull, simplify_tolerance=0.0)
            if not parts:
                continue

            zones.append(
                {
                    "id": int(cluster.get("id") or 0),
                    "count": int(cluster.get("count") or len(cluster_points_list)),
                    "center": cluster.get("center")
                    or self._center_from_points(cluster_points_list),
                    "parts": parts,
                }
            )

        if not zones:
            fallback_zone = self._build_fallback_zone(points)
            if fallback_zone is not None:
                zones.append(fallback_zone)

        zones.sort(key=lambda item: int(item.get("id") or 0))
        return zones

    def _build_fallback_zone(
        self, points: List[Dict[str, float]]
    ) -> Optional[Dict[str, Any]]:
        valid_points = [
            point
            for point in (points or [])
            if point.get("lat") is not None and point.get("lng") is not None
        ]
        if not valid_points:
            return None

        hull = unary_union(
            [
                Point(float(point["lng"]), float(point["lat"])).buffer(
                    self._meters_to_degrees(
                        float(point["lat"]),
                        max(float(point.get("acc") or 0.0), 8.0),
                    )
                )
                for point in valid_points
            ]
        )
        if hull is None or hull.is_empty:
            return None

        parts = self._geometry_to_parts(hull, simplify_tolerance=0.0)
        if not parts:
            return None

        return {
            "id": 1,
            "count": len(valid_points),
            "center": self._center_from_points(valid_points),
            "parts": parts,
        }

    def _meters_to_degrees(self, latitude: float, meters: float) -> float:
        meters_per_degree = 111_320.0 * max(0.2, abs(math.cos(math.radians(latitude))))
        return float(meters) / meters_per_degree

    def _geometry_to_parts(
        self, geometry: BaseGeometry, simplify_tolerance: float = 0.0
    ) -> List[Any]:
        if geometry is None or geometry.is_empty:
            return []

        geom = geometry
        if simplify_tolerance > 0:
            geom = geom.simplify(simplify_tolerance, preserve_topology=True)

        parts: List[Any] = []
        if isinstance(geom, Polygon):
            part = self._polygon_to_part(geom)
            if part is not None:
                parts.append(part)
        elif isinstance(geom, MultiPolygon):
            for poly in geom.geoms:
                part = self._polygon_to_part(poly)
                if part is not None:
                    parts.append(part)

        filtered_parts: List[Any] = []
        for part in parts:
            if isinstance(part, list) and part:
                if isinstance(part[0], list):
                    outer = part[0]
                    if len(outer) >= 3:
                        filtered_parts.append(part)
                elif len(part) >= 3:
                    filtered_parts.append(part)
        return filtered_parts

    def _polygon_to_part(self, polygon: Polygon) -> Optional[Any]:
        if polygon is None or polygon.is_empty:
            return None

        outer = [
            {"lat": float(lat), "lng": float(lng)}
            for lng, lat in list(polygon.exterior.coords)
        ]
        if len(outer) < 3:
            return None

        holes = []
        for ring in polygon.interiors:
            coords = [
                {"lat": float(lat), "lng": float(lng)} for lng, lat in list(ring.coords)
            ]
            if len(coords) >= 3:
                holes.append(coords)

        if holes:
            return [outer, *holes]
        return outer

    def _parts_to_geometry(self, parts: List[Any]) -> Optional[BaseGeometry]:
        polygons: List[Polygon] = []
        for part in parts or []:
            rings = (
                part
                if isinstance(part, list) and part and isinstance(part[0], list)
                else [part]
            )
            if not rings:
                continue

            shell = [
                (float(point["lng"]), float(point["lat"]))
                for point in (rings[0] or [])
                if self._safe_float(point.get("lat")) is not None
                and self._safe_float(point.get("lng")) is not None
            ]
            if len(shell) < 3:
                continue

            holes: List[List[Tuple[float, float]]] = []
            for ring in rings[1:]:
                coords = [
                    (float(point["lng"]), float(point["lat"]))
                    for point in (ring or [])
                    if self._safe_float(point.get("lat")) is not None
                    and self._safe_float(point.get("lng")) is not None
                ]
                if len(coords) >= 3:
                    holes.append(coords)

            try:
                polygon = Polygon(shell, holes)
            except Exception:
                continue

            if not polygon.is_valid:
                polygon = polygon.buffer(0)
            if polygon is None or polygon.is_empty:
                continue
            if isinstance(polygon, Polygon):
                polygons.append(polygon)
            elif isinstance(polygon, MultiPolygon):
                polygons.extend(
                    [
                        poly
                        for poly in polygon.geoms
                        if poly is not None and not poly.is_empty
                    ]
                )

        if not polygons:
            return None

        geometry = unary_union(polygons)
        if geometry is None or geometry.is_empty:
            return None
        return geometry

    def _zones_to_geometry(self, zones: List[Dict[str, Any]]) -> Optional[BaseGeometry]:
        geometries = [
            self._parts_to_geometry(zone.get("parts") or [])
            for zone in (zones or [])
            if isinstance(zone, dict)
        ]
        valid_geometries = [
            geometry
            for geometry in geometries
            if geometry is not None and not geometry.is_empty
        ]
        if not valid_geometries:
            return None
        return unary_union(valid_geometries)

    def _center_from_geometry(
        self, geometry: Optional[BaseGeometry]
    ) -> Optional[Dict[str, float]]:
        if geometry is None or geometry.is_empty:
            return None

        centroid = geometry.representative_point()
        return {
            "lat": float(centroid.y),
            "lng": float(centroid.x),
        }

    def _region_outline(self, region: RegionEntry) -> List[List[Dict[str, float]]]:
        cache_key = ("outline", int(self._maps_revision), region.id)
        cached = self._lru_get(self._outline_cache, cache_key)
        if cached is not None:
            return cached

        if not region.geometries:
            return []
        merged = unary_union(region.geometries)
        parts = self._geometry_to_parts(merged, simplify_tolerance=0.00008)
        self._lru_set(
            self._outline_cache,
            cache_key,
            parts,
            self._max_outline_cache_entries,
        )
        return parts

    def _safe_float(self, value: Any) -> Optional[float]:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def _bounds_from_geometries(
        self, geometries: List[BaseGeometry]
    ) -> Optional[Dict[str, float]]:
        if not geometries:
            return None

        min_lng = None
        min_lat = None
        max_lng = None
        max_lat = None

        for geom in geometries:
            if geom is None or geom.is_empty:
                continue
            bounds = geom.bounds
            if len(bounds) != 4:
                continue
            g_min_lng, g_min_lat, g_max_lng, g_max_lat = bounds
            min_lng = g_min_lng if min_lng is None else min(min_lng, g_min_lng)
            min_lat = g_min_lat if min_lat is None else min(min_lat, g_min_lat)
            max_lng = g_max_lng if max_lng is None else max(max_lng, g_max_lng)
            max_lat = g_max_lat if max_lat is None else max(max_lat, g_max_lat)

        if min_lng is None:
            return None

        return {
            "min_lat": float(min_lat),
            "min_lng": float(min_lng),
            "max_lat": float(max_lat),
            "max_lng": float(max_lng),
        }

    def _center_from_geometries(
        self, geometries: List[BaseGeometry]
    ) -> Optional[Dict[str, float]]:
        if not geometries:
            return None
        merged = unary_union(geometries)
        if merged is None or merged.is_empty:
            return None
        point = merged.representative_point()
        return {"lat": float(point.y), "lng": float(point.x)}

    def _bounds_from_points(
        self, points: List[Dict[str, float]]
    ) -> Optional[Dict[str, float]]:
        if not points:
            return None

        lats = [float(item["lat"]) for item in points]
        lngs = [float(item["lng"]) for item in points]
        return {
            "min_lat": float(min(lats)),
            "min_lng": float(min(lngs)),
            "max_lat": float(max(lats)),
            "max_lng": float(max(lngs)),
        }

    def _center_from_points(
        self, points: List[Dict[str, float]]
    ) -> Optional[Dict[str, float]]:
        if not points:
            return None
        return {
            "lat": float(sum(float(item["lat"]) for item in points) / len(points)),
            "lng": float(sum(float(item["lng"]) for item in points) / len(points)),
        }

    def _extension_to_format(self, path: str) -> str:
        lower = path.lower()
        if lower.endswith(".shp"):
            return "shp"
        if lower.endswith(".kmz"):
            return "kmz"
        return "geojson"

    def _is_crs_supported(self, crs: str) -> bool:
        normalized = str(crs or "").upper()
        if not normalized:
            return True
        return any(item in normalized for item in SUPPORTED_CRS_HINTS)


wardrive_regions_service = WardriveRegionsService()
