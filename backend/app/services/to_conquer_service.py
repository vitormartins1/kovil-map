from math import asin, atan2, cos, hypot, pi, sin
from typing import Dict, List, Optional

from shapely.geometry import MultiPoint, Point, Polygon
from shapely.ops import transform, unary_union

from app.services.zones_service import cluster_points

EARTH_RADIUS_M = 6371000.0
METERS_PER_DEG_LAT = 111320.0


def _destination_point(
    lat: float, lng: float, distance_m: float, bearing_deg: float
) -> Dict[str, float]:
    brng = bearing_deg * pi / 180.0
    lat1 = lat * pi / 180.0
    lon1 = lng * pi / 180.0
    d_r = distance_m / EARTH_RADIUS_M

    lat2 = asin(sin(lat1) * cos(d_r) + cos(lat1) * sin(d_r) * cos(brng))

    lon2 = lon1 + atan2(
        sin(brng) * sin(d_r) * cos(lat1),
        cos(d_r) - sin(lat1) * sin(lat2),
    )

    return {"lat": lat2 * 180.0 / pi, "lng": lon2 * 180.0 / pi}


def expand_points_by_accuracy(
    points: List[Dict[str, float]], acc_segments: int
) -> List[Dict[str, float]]:
    if not points:
        return []
    segments = max(4, int(acc_segments))
    step = 360.0 / segments

    expanded: List[Dict[str, float]] = []
    for p in points:
        lat = p.get("lat")
        lng = p.get("lng")
        if lat is None or lng is None:
            continue
        expanded.append({"lat": lat, "lng": lng})
        acc = float(p.get("acc") or 0)
        if acc <= 0:
            continue
        for i in range(segments):
            expanded.append(_destination_point(lat, lng, acc, i * step))
    return expanded


def build_hull(points: List[Dict[str, float]]) -> Optional[Polygon]:
    if not points or len(points) < 3:
        return None
    coords = [(p["lng"], p["lat"]) for p in points if "lat" in p and "lng" in p]
    if len(coords) < 3:
        return None
    hull = MultiPoint(coords).convex_hull
    if hull.is_empty or not isinstance(hull, Polygon):
        return None
    return hull


def polygon_to_parts(poly) -> List[Dict]:
    """Return list of dicts with 'ring' (exterior) and 'holes' (interior rings)."""
    if poly is None or poly.is_empty:
        return []
    parts: List[Dict] = []
    if poly.geom_type == "Polygon":
        exterior = [{"lat": lat, "lng": lng} for lng, lat in poly.exterior.coords]
        holes = [
            [{"lat": lat, "lng": lng} for lng, lat in interior.coords]
            for interior in poly.interiors
        ]
        parts.append({"ring": exterior, "holes": holes})
    elif poly.geom_type == "MultiPolygon":
        for p in poly.geoms:
            exterior = [{"lat": lat, "lng": lng} for lng, lat in p.exterior.coords]
            holes = [
                [{"lat": lat, "lng": lng} for lng, lat in interior.coords]
                for interior in p.interiors
            ]
            parts.append({"ring": exterior, "holes": holes})
    return parts


def polygon_to_zone_parts(poly) -> List[Dict]:
    parts = polygon_to_parts(poly)
    return [p for p in parts if p and p.get("ring") and len(p["ring"]) >= 3]


def _split_parts_to_zones(
    parts: List[Dict], base_id: int, count: int
) -> List[Dict]:
    zones: List[Dict] = []
    if not parts:
        return zones
    rings = [p["ring"] for p in parts]
    holes = [p.get("holes", []) for p in parts]
    if len(parts) == 1:
        zone: Dict = {"id": base_id, "count": count, "parts": rings}
        if any(holes):
            zone["holes"] = holes
        zones.append(zone)
        return zones
    for idx, part in enumerate(parts):
        zone = {"id": base_id * 100 + idx, "count": count, "parts": [part["ring"]]}
        part_holes = part.get("holes", [])
        if part_holes:
            zone["holes"] = [part_holes]
        zones.append(zone)
    return zones


def _meters_scale(lat0: float) -> Dict[str, float]:
    meters_per_deg_lng = METERS_PER_DEG_LAT * cos(lat0 * pi / 180.0)
    if meters_per_deg_lng <= 0:
        meters_per_deg_lng = METERS_PER_DEG_LAT
    return {"m_per_deg_lat": METERS_PER_DEG_LAT, "m_per_deg_lng": meters_per_deg_lng}


def _to_local_meters(
    lat: float,
    lng: float,
    lat0: float,
    lng0: float,
    m_per_deg_lat: float,
    m_per_deg_lng: float,
):
    x = (lng - lng0) * m_per_deg_lng
    y = (lat - lat0) * m_per_deg_lat
    return x, y


def _local_meters_to_latlng(
    x: float,
    y: float,
    lat0: float,
    lng0: float,
    m_per_deg_lat: float,
    m_per_deg_lng: float,
):
    lat = lat0 + (y / m_per_deg_lat)
    lng = lng0 + (x / m_per_deg_lng)
    return lng, lat


def _build_components(points_local: List[Dict[str, float]]):
    n = len(points_local)
    adj: List[List[tuple]] = [[] for _ in range(n)]
    for i in range(n):
        for j in range(i + 1, n):
            pi = points_local[i]
            pj = points_local[j]
            limit = pi["acc"] + pj["acc"]
            dist = hypot(pi["x"] - pj["x"], pi["y"] - pj["y"])
            if dist <= limit:
                is_overlap = dist < limit
                adj[i].append((j, is_overlap))
                adj[j].append((i, is_overlap))

    visited = [False] * n
    components = []
    for i in range(n):
        if visited[i]:
            continue
        stack = [i]
        visited[i] = True
        comp = []
        has_overlap = False
        while stack:
            cur = stack.pop()
            comp.append(cur)
            for nxt, is_overlap in adj[cur]:
                if is_overlap:
                    has_overlap = True
                if not visited[nxt]:
                    visited[nxt] = True
                    stack.append(nxt)
        components.append((comp, has_overlap))
    return components


def _build_overlap_polys(
    points_local: List[Dict[str, float]],
    center_lat: float,
    center_lng: float,
    m_per_deg_lat: float,
    m_per_deg_lng: float,
) -> List[tuple]:
    components = _build_components(points_local)
    polys_with_counts = []
    for comp_idxs, has_overlap in components:
        if len(comp_idxs) < 2 or not has_overlap:
            continue
        circles = []
        for idx in comp_idxs:
            p = points_local[idx]
            circles.append(Point(p["x"], p["y"]).buffer(p["acc"]))
        comp_union = unary_union(circles)
        if comp_union.is_empty:
            continue

        def _to_latlng(x, y, z=None):
            return _local_meters_to_latlng(
                x, y, center_lat, center_lng, m_per_deg_lat, m_per_deg_lng
            )

        poly_latlng = transform(_to_latlng, comp_union)
        if poly_latlng is None or poly_latlng.is_empty:
            continue
        polys_with_counts.append((poly_latlng, len(comp_idxs)))
    return polys_with_counts


def build_to_conquer_zones(
    conquered_points: List[Dict[str, float]],
    to_conquer_points: List[Dict[str, float]],
    eps_m: float = 200.0,
    min_samples: int = 3,
    acc_segments: int = 8,
    min_zone_points: int = 2,
) -> List[Dict]:
    min_zone_points = max(2, int(min_zone_points or 2))
    # Clipping polygons must always use the standard min_samples (3) so that
    # higher-priority zones built with min_samples=3 are correctly reproduced
    # even when the caller requests a higher threshold for the main zones
    # (e.g. discovery zones use min_samples=5).
    clip_min_samples = min(min_samples, 3)
    conquered_clusters = cluster_points(
        conquered_points, eps_m=eps_m, min_samples=clip_min_samples
    )
    to_conquer_clusters = cluster_points(
        to_conquer_points, eps_m=eps_m, min_samples=min_samples
    )

    conquered_polys = []
    for cluster in conquered_clusters:
        pts = cluster.get("points", [])
        if len(pts) < 2:
            continue

        center_lat = cluster.get("center", {}).get("lat")
        center_lng = cluster.get("center", {}).get("lng")
        if center_lat is None or center_lng is None:
            center_lat = sum(p.get("lat", 0) for p in pts) / max(1, len(pts))
            center_lng = sum(p.get("lng", 0) for p in pts) / max(1, len(pts))

        scale = _meters_scale(center_lat)
        m_per_deg_lat = scale["m_per_deg_lat"]
        m_per_deg_lng = scale["m_per_deg_lng"]

        points_local = []
        for p in pts:
            lat = p.get("lat")
            lng = p.get("lng")
            acc = float(p.get("acc") or 0)
            if lat is None or lng is None or acc <= 0:
                continue
            x, y = _to_local_meters(
                lat, lng, center_lat, center_lng, m_per_deg_lat, m_per_deg_lng
            )
            points_local.append({"lat": lat, "lng": lng, "acc": acc, "x": x, "y": y})

        if len(points_local) < 2:
            continue

        components = _build_components(points_local)
        for comp_idxs, has_overlap in components:
            if len(comp_idxs) < 2 or not has_overlap:
                continue

            circles = []
            for idx in comp_idxs:
                p = points_local[idx]
                circles.append(Point(p["x"], p["y"]).buffer(p["acc"]))

            circles_union = unary_union(circles)
            if circles_union.is_empty:
                continue

            def _to_latlng(x, y, z=None):
                return _local_meters_to_latlng(
                    x, y, center_lat, center_lng, m_per_deg_lat, m_per_deg_lng
                )

            final_latlng = transform(_to_latlng, circles_union)
            if final_latlng is not None and not final_latlng.is_empty:
                conquered_polys.append(final_latlng)

    conquered_union = unary_union(conquered_polys) if conquered_polys else None

    zones = []
    for cluster in to_conquer_clusters:
        pts = cluster.get("points", [])
        if len(pts) < 2:
            continue

        center_lat = cluster.get("center", {}).get("lat")
        center_lng = cluster.get("center", {}).get("lng")
        if center_lat is None or center_lng is None:
            center_lat = sum(p.get("lat", 0) for p in pts) / max(1, len(pts))
            center_lng = sum(p.get("lng", 0) for p in pts) / max(1, len(pts))

        scale = _meters_scale(center_lat)
        m_per_deg_lat = scale["m_per_deg_lat"]
        m_per_deg_lng = scale["m_per_deg_lng"]

        points_local = []
        for p in pts:
            lat = p.get("lat")
            lng = p.get("lng")
            acc = float(p.get("acc") or 0)
            if lat is None or lng is None or acc <= 0:
                continue
            x, y = _to_local_meters(
                lat, lng, center_lat, center_lng, m_per_deg_lat, m_per_deg_lng
            )
            points_local.append({"lat": lat, "lng": lng, "acc": acc, "x": x, "y": y})

        if len(points_local) < 2:
            continue

        polys_with_counts = _build_overlap_polys(
            points_local,
            center_lat,
            center_lng,
            m_per_deg_lat,
            m_per_deg_lng,
        )
        for poly_latlng, comp_count in polys_with_counts:
            if comp_count < min_zone_points:
                continue
            final_poly = poly_latlng
            if conquered_union is not None and not conquered_union.is_empty:
                final_poly = poly_latlng.difference(conquered_union)
            parts = polygon_to_zone_parts(final_poly)
            if not parts:
                continue
            zones.extend(
                _split_parts_to_zones(parts, cluster.get("id") or 0, comp_count)
            )

    zones.sort(key=lambda z: z["id"] if z.get("id") is not None else 0)
    return zones


def build_conquered_zones(
    conquered_points: List[Dict[str, float]],
    eps_m: float = 200.0,
    min_samples: int = 3,
    acc_segments: int = 8,
) -> List[Dict]:
    clusters = cluster_points(conquered_points, eps_m=eps_m, min_samples=min_samples)
    zones = []

    for cluster in clusters:
        pts = cluster.get("points", [])
        if len(pts) < 2:
            continue

        center_lat = cluster.get("center", {}).get("lat")
        center_lng = cluster.get("center", {}).get("lng")
        if center_lat is None or center_lng is None:
            center_lat = sum(p.get("lat", 0) for p in pts) / max(1, len(pts))
            center_lng = sum(p.get("lng", 0) for p in pts) / max(1, len(pts))

        scale = _meters_scale(center_lat)
        m_per_deg_lat = scale["m_per_deg_lat"]
        m_per_deg_lng = scale["m_per_deg_lng"]

        points_local = []
        for p in pts:
            lat = p.get("lat")
            lng = p.get("lng")
            acc = float(p.get("acc") or 0)
            if lat is None or lng is None or acc <= 0:
                continue
            x, y = _to_local_meters(
                lat, lng, center_lat, center_lng, m_per_deg_lat, m_per_deg_lng
            )
            points_local.append({"lat": lat, "lng": lng, "acc": acc, "x": x, "y": y})

        if len(points_local) < 2:
            continue

        polys_with_counts = _build_overlap_polys(
            points_local,
            center_lat,
            center_lng,
            m_per_deg_lat,
            m_per_deg_lng,
        )
        if not polys_with_counts:
            continue

        for poly_latlng, comp_count in polys_with_counts:
            parts = polygon_to_zone_parts(poly_latlng)
            if not parts:
                continue
            zones.extend(
                _split_parts_to_zones(parts, cluster.get("id") or 0, comp_count)
            )

    zones.sort(key=lambda z: z["id"] if z.get("id") is not None else 0)
    return zones
