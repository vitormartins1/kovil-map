from __future__ import annotations

import argparse
import csv
import json
import math
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

RJ_BBOX = {
    "lat_min": -23.10,
    "lat_max": -22.80,
    "lng_min": -43.40,
    "lng_max": -43.10,
}
OSRM_BASE = "https://router.project-osrm.org"
GPX_NS = "http://www.topografix.com/GPX/1/1"


@dataclass(frozen=True)
class RouteSpec:
    corridor: str
    route_asset: str
    seed_asset: str
    profile: str
    start_time: str
    loop_waypoints: tuple[tuple[float, float], ...]


ROUTE_SPECS = (
    RouteSpec(
        corridor="Centro + Lapa + Santa Teresa",
        route_asset="centro_lapa_santa_teresa.csv",
        seed_asset="centro_lapa_santa_teresa.gpx",
        profile="driving",
        start_time="2026-04-11T00:15:00Z",
        loop_waypoints=(
            (-22.913710, -43.182320),
            (-22.914820, -43.184650),
            (-22.916380, -43.186260),
            (-22.917680, -43.187820),
            (-22.918760, -43.190020),
            (-22.919340, -43.192140),
            (-22.918420, -43.190460),
            (-22.916880, -43.187980),
            (-22.915280, -43.185320),
            (-22.914120, -43.183760),
            (-22.913710, -43.182320),
        ),
    ),
    RouteSpec(
        corridor="Aterro do Flamengo + Botafogo + Urca",
        route_asset="flamengo_botafogo_urca.csv",
        seed_asset="flamengo_botafogo_urca.gpx",
        profile="driving",
        start_time="2026-04-11T01:10:00Z",
        loop_waypoints=(
            (-22.949120, -43.179920),
            (-22.950140, -43.177480),
            (-22.951540, -43.174720),
            (-22.952880, -43.172360),
            (-22.953140, -43.169540),
            (-22.951980, -43.167900),
            (-22.949980, -43.168800),
            (-22.948720, -43.171420),
            (-22.948460, -43.174760),
            (-22.948900, -43.178220),
            (-22.949120, -43.179920),
        ),
    ),
    RouteSpec(
        corridor="Copacabana + Arpoador + Ipanema + Lagoa",
        route_asset="copacabana_arpoador_ipanema_lagoa.csv",
        seed_asset="copacabana_arpoador_ipanema_lagoa.gpx",
        profile="driving",
        start_time="2026-04-11T02:05:00Z",
        loop_waypoints=(
            (-22.987970, -43.191740),
            (-22.986620, -43.194180),
            (-22.984980, -43.196340),
            (-22.983060, -43.197460),
            (-22.981440, -43.196420),
            (-22.981600, -43.193920),
            (-22.983060, -43.191960),
            (-22.985060, -43.191180),
            (-22.986820, -43.191160),
            (-22.987970, -43.191740),
        ),
    ),
)


def _iso_to_datetime(value: str) -> datetime:
    normalized = str(value or "").replace("Z", "+00:00")
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _to_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _haversine_m(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    radius_m = 6_371_000.0
    phi1 = math.radians(float(lat1))
    phi2 = math.radians(float(lat2))
    d_phi = math.radians(float(lat2) - float(lat1))
    d_lambda = math.radians(float(lng2) - float(lng1))
    a = (
        math.sin(d_phi / 2.0) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2.0) ** 2
    )
    return 2.0 * radius_m * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))


def _assert_bbox(lat: float, lng: float) -> None:
    if not (
        RJ_BBOX["lat_min"] <= float(lat) <= RJ_BBOX["lat_max"]
        and RJ_BBOX["lng_min"] <= float(lng) <= RJ_BBOX["lng_max"]
    ):
        raise ValueError(f"Point outside RJ bbox: {lat},{lng}")


def _fetch_osrm_json(path: str) -> dict[str, Any]:
    url = f"{OSRM_BASE.rstrip('/')}/{path.lstrip('/')}"
    with urllib.request.urlopen(url, timeout=30) as response:
        payload = json.loads(response.read().decode("utf-8"))
    return payload if isinstance(payload, dict) else {}


def _fetch_route_geometry(spec: RouteSpec) -> tuple[list[tuple[float, float]], float]:
    coordinates = ";".join(f"{lng:.6f},{lat:.6f}" for lat, lng in spec.loop_waypoints)
    query = urllib.parse.urlencode({"overview": "full", "geometries": "geojson"})
    payload = _fetch_osrm_json(f"route/v1/{spec.profile}/{coordinates}?{query}")
    routes = list(payload.get("routes") or [])
    if not routes:
        raise ValueError(f"No OSRM route for corridor: {spec.corridor}")
    route = routes[0]
    geometry = route.get("geometry") or {}
    coordinates_payload = list(geometry.get("coordinates") or [])
    points = [(float(lat), float(lng)) for lng, lat in coordinates_payload]
    for lat, lng in points:
        _assert_bbox(lat, lng)
    return points, float(route.get("distance") or 0.0)


def _sample_geometry(
    points: list[tuple[float, float]], *, spacing_m: float
) -> list[tuple[float, float]]:
    if len(points) < 2:
        raise ValueError("Need at least 2 points to sample geometry")
    sampled = [points[0]]
    carry = 0.0
    last = points[0]
    for point in points[1:]:
        distance_m = _haversine_m(last[0], last[1], point[0], point[1])
        if distance_m + carry >= spacing_m:
            sampled.append(point)
            carry = 0.0
            last = point
            continue
        carry += distance_m
        last = point
    if sampled[-1] != points[-1]:
        sampled.append(points[-1])
    return sampled


def _cap_seed_points(
    points: list[tuple[float, float]], *, max_points: int = 90
) -> list[tuple[float, float]]:
    if len(points) <= max_points:
        return list(points)
    indices = {0, len(points) - 1}
    stride = (len(points) - 1) / float(max_points - 1)
    for step in range(1, max_points - 1):
        indices.add(int(round(step * stride)))
    return [points[index] for index in sorted(indices)]


def _write_gpx(
    seed_points: list[tuple[float, float]], *, output_path: Path, start_time: str
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    root = ET.Element(
        f"{{{GPX_NS}}}gpx",
        attrib={"version": "1.1", "creator": "KOVIL MAP Demo V3 Builder"},
    )
    trk = ET.SubElement(root, f"{{{GPX_NS}}}trk")
    name = ET.SubElement(trk, f"{{{GPX_NS}}}name")
    name.text = output_path.stem
    segment = ET.SubElement(trk, f"{{{GPX_NS}}}trkseg")
    current_time = _iso_to_datetime(start_time)
    for index, (lat, lng) in enumerate(seed_points):
        trkpt = ET.SubElement(
            segment,
            f"{{{GPX_NS}}}trkpt",
            attrib={"lat": f"{lat:.6f}", "lon": f"{lng:.6f}"},
        )
        ele = ET.SubElement(trkpt, f"{{{GPX_NS}}}ele")
        ele.text = f"{7.0 + (index % 9) * 0.3:.1f}"
        time_el = ET.SubElement(trkpt, f"{{{GPX_NS}}}time")
        time_el.text = _to_iso(current_time)
        current_time += timedelta(seconds=6)
    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    tree.write(output_path, encoding="utf-8", xml_declaration=True)


def _read_gpx(path: Path) -> list[dict[str, Any]]:
    tree = ET.parse(path)
    points: list[dict[str, Any]] = []
    for trkpt in tree.findall(f".//{{{GPX_NS}}}trkpt"):
        lat = float(trkpt.attrib["lat"])
        lng = float(trkpt.attrib["lon"])
        _assert_bbox(lat, lng)
        ele = trkpt.findtext(f"{{{GPX_NS}}}ele")
        time_text = trkpt.findtext(f"{{{GPX_NS}}}time")
        points.append(
            {
                "lat": lat,
                "lng": lng,
                "altitude_m": float(ele or 0.0),
                "timestamp": str(time_text or ""),
            }
        )
    if len(points) < 2:
        raise ValueError(f"GPX seed must contain at least 2 track points: {path}")
    return points


def _match_gpx_points(
    points: list[dict[str, Any]], *, profile: str
) -> tuple[list[tuple[float, float]], float]:
    coordinates = ";".join(f"{point['lng']:.6f},{point['lat']:.6f}" for point in points)
    query = urllib.parse.urlencode(
        {
            "overview": "full",
            "geometries": "geojson",
            "gaps": "ignore",
            "tidy": "true",
        }
    )
    payload = _fetch_osrm_json(f"match/v1/{profile}/{coordinates}?{query}")
    matchings = list(payload.get("matchings") or [])
    if not matchings:
        raise ValueError("OSRM match API returned no matchings")
    geometry_points: list[tuple[float, float]] = []
    distance_m = 0.0
    for matching in matchings:
        coords = list(((matching.get("geometry") or {}).get("coordinates") or []))
        if not coords:
            continue
        segment_points = [(float(lat), float(lng)) for lng, lat in coords]
        if geometry_points and geometry_points[-1] == segment_points[0]:
            geometry_points.extend(segment_points[1:])
        else:
            geometry_points.extend(segment_points)
        distance_m += float(matching.get("distance") or 0.0)
    if len(geometry_points) < 2:
        raise ValueError("Matched geometry is too short")
    for lat, lng in geometry_points:
        _assert_bbox(lat, lng)
    return geometry_points, distance_m


def _densify_geometry(
    points: list[tuple[float, float]],
    *,
    start_time: str,
    points_per_km: float,
) -> list[dict[str, Any]]:
    if len(points) < 2:
        raise ValueError("Geometry must contain at least 2 points")

    total_distance_m = sum(
        _haversine_m(lat1, lng1, lat2, lng2)
        for (lat1, lng1), (lat2, lng2) in zip(points, points[1:])
    )
    total_distance_km = max(total_distance_m / 1000.0, 0.001)
    target_points = max(2, int(round(total_distance_km * points_per_km)))
    step_m = total_distance_m / max(target_points - 1, 1)

    dense_points = [
        {
            "lat": points[0][0],
            "lng": points[0][1],
            "distance_m": 0.0,
        }
    ]
    next_target_m = step_m
    distance_so_far = 0.0
    for start, end in zip(points, points[1:]):
        segment_m = _haversine_m(start[0], start[1], end[0], end[1])
        segment_start_m = distance_so_far
        distance_so_far += segment_m
        if segment_m <= 0:
            continue
        while next_target_m < distance_so_far:
            ratio = (next_target_m - segment_start_m) / segment_m
            dense_points.append(
                {
                    "lat": start[0] + (end[0] - start[0]) * ratio,
                    "lng": start[1] + (end[1] - start[1]) * ratio,
                    "distance_m": next_target_m,
                }
            )
            next_target_m += step_m
    if (
        dense_points[-1]["lat"] != points[-1][0]
        or dense_points[-1]["lng"] != points[-1][1]
    ):
        dense_points.append(
            {
                "lat": points[-1][0],
                "lng": points[-1][1],
                "distance_m": total_distance_m,
            }
        )

    start_dt = _iso_to_datetime(start_time)
    route_rows: list[dict[str, Any]] = []
    current_dt = start_dt
    previous_distance = 0.0
    for index, point in enumerate(dense_points):
        segment_distance = float(point["distance_m"]) - previous_distance
        speed_kmh = 17.0 + (index % 7) * 1.7
        delta_seconds = (
            0.0 if index == 0 else max(1.0, segment_distance / (speed_kmh / 3.6))
        )
        current_dt += timedelta(seconds=delta_seconds)
        route_rows.append(
            {
                "timestamp": _to_iso(current_dt),
                "lat": round(float(point["lat"]), 6),
                "lng": round(float(point["lng"]), 6),
                "altitude_m": round(7.0 + (index % 13) * 0.2, 1),
                "speed_kmh": round(speed_kmh, 1),
                "accuracy_m": round(4.0 + (index % 5) * 0.2, 1),
            }
        )
        previous_distance = float(point["distance_m"])
    return route_rows


def _validate_route_rows(
    route_rows: list[dict[str, Any]],
    *,
    min_distance_km: float = 1.8,
    max_distance_km: float = 2.6,
    min_points_per_km: float = 240.0,
    max_points_per_km: float = 300.0,
) -> dict[str, Any]:
    if len(route_rows) < 2:
        raise ValueError("Route rows too short")

    distances = []
    total_distance_m = 0.0
    timestamps: list[datetime] = []
    for current, nxt in zip(route_rows, route_rows[1:]):
        step_m = _haversine_m(
            float(current["lat"]),
            float(current["lng"]),
            float(nxt["lat"]),
            float(nxt["lng"]),
        )
        distances.append(step_m)
        total_distance_m += step_m
        timestamps.append(_iso_to_datetime(str(current["timestamp"])))
    timestamps.append(_iso_to_datetime(str(route_rows[-1]["timestamp"])))

    distance_km = total_distance_m / 1000.0
    points_per_km = len(route_rows) / max(distance_km, 0.001)
    if not (min_distance_km <= distance_km <= max_distance_km):
        raise ValueError(f"Route distance {distance_km:.3f}km outside target range")
    if not (min_points_per_km <= points_per_km <= max_points_per_km):
        raise ValueError(f"points_per_km {points_per_km:.2f} outside target range")
    if max(distances) > 18.0:
        raise ValueError(f"Matched route still has a long jump ({max(distances):.2f}m)")
    if any(b <= a for a, b in zip(timestamps, timestamps[1:])):
        raise ValueError("Route timestamps are not strictly increasing")

    return {
        "distance_km": round(distance_km, 3),
        "points_per_km": round(points_per_km, 2),
        "step_distance_m": {
            "median": round(sorted(distances)[len(distances) // 2], 2),
            "p90": round(sorted(distances)[int((len(distances) - 1) * 0.9)], 2),
            "max": round(max(distances), 2),
        },
    }


def _write_route_csv(route_rows: list[dict[str, Any]], *, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=(
                "timestamp",
                "lat",
                "lng",
                "altitude_m",
                "speed_kmh",
                "accuracy_m",
            ),
        )
        writer.writeheader()
        writer.writerows(route_rows)


def build_routes(
    *,
    density_profile_path: Path,
    seeds_root: Path,
    routes_root: Path,
    metadata_path: Path | None = None,
) -> dict[str, Any]:
    profile = json.loads(Path(density_profile_path).read_text(encoding="utf-8"))
    points_per_km = float(profile["points_per_km"])
    results: dict[str, Any] = {}

    for spec in ROUTE_SPECS:
        seed_path = seeds_root / spec.seed_asset
        if seed_path.exists():
            seed_payload = _read_gpx(seed_path)
            seed_points = [
                (float(point["lat"]), float(point["lng"])) for point in seed_payload
            ]
            route_geometry = list(seed_points)
        else:
            route_geometry, _ = _fetch_route_geometry(spec)
            seed_points = _cap_seed_points(
                _sample_geometry(route_geometry, spacing_m=22.0)
            )
            _write_gpx(seed_points, output_path=seed_path, start_time=spec.start_time)
        match_status = "matched"
        try:
            matched_geometry, _ = _match_gpx_points(
                _read_gpx(seed_path),
                profile=spec.profile,
            )
        except Exception as exc:
            matched_geometry = list(route_geometry)
            match_status = f"route_fallback:{type(exc).__name__}"
        route_rows = _densify_geometry(
            matched_geometry,
            start_time=spec.start_time,
            points_per_km=points_per_km,
        )
        stats = _validate_route_rows(route_rows)
        route_path = routes_root / spec.route_asset
        _write_route_csv(route_rows, output_path=route_path)
        results[spec.route_asset] = {
            "corridor": spec.corridor,
            "seed_asset": spec.seed_asset,
            "route_asset": spec.route_asset,
            "match_status": match_status,
            "seed_points": len(seed_points),
            "route_points": len(route_rows),
            **stats,
        }

    if metadata_path is not None:
        metadata_path.parent.mkdir(parents=True, exist_ok=True)
        metadata_path.write_text(
            json.dumps(results, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return results


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build sanitized V3 tourist-loop GPX seeds and route CSVs."
    )
    parser.add_argument("--density-profile", required=True, help="Density profile JSON")
    parser.add_argument("--seeds-root", required=True, help="Output seeds directory")
    parser.add_argument("--routes-root", required=True, help="Output routes directory")
    parser.add_argument("--metadata", required=False, help="Optional metadata JSON")
    args = parser.parse_args()

    results = build_routes(
        density_profile_path=Path(args.density_profile),
        seeds_root=Path(args.seeds_root),
        routes_root=Path(args.routes_root),
        metadata_path=Path(args.metadata) if args.metadata else None,
    )
    print(json.dumps(results, ensure_ascii=True, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
