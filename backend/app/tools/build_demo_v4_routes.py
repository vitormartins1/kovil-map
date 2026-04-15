from __future__ import annotations

import argparse
import csv
import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.tools.build_demo_v3_routes import _assert_bbox, _haversine_m

GPX_NS = "http://www.topografix.com/GPX/1/1"
DEFAULT_POINTS_PER_KM = 282.42


@dataclass(frozen=True)
class V4RouteSpec:
    corridor: str
    route_asset: str
    seed_asset: str
    start_time: str
    transport_mode: str
    route_family: str
    density_multiplier: float
    control_points: tuple[tuple[float, float], ...] = ()
    inherit_route_asset: str | None = None
    inherit_seed_asset: str | None = None
    speed_min_kmh: float = 12.0
    speed_max_kmh: float = 26.0


V4_ROUTE_SPECS = (
    V4RouteSpec(
        corridor="Centro + Lapa + Santa Teresa",
        route_asset="centro_lapa_santa_teresa.csv",
        seed_asset="centro_lapa_santa_teresa.gpx",
        start_time="2026-04-11T00:15:00Z",
        transport_mode="car",
        route_family="road",
        density_multiplier=1.0,
        inherit_route_asset="centro_lapa_santa_teresa.csv",
        inherit_seed_asset="centro_lapa_santa_teresa.gpx",
        speed_min_kmh=17.0,
        speed_max_kmh=27.2,
    ),
    V4RouteSpec(
        corridor="Aterro do Flamengo + Botafogo + Urca",
        route_asset="flamengo_botafogo_urca.csv",
        seed_asset="flamengo_botafogo_urca.gpx",
        start_time="2026-04-11T01:10:00Z",
        transport_mode="car",
        route_family="road",
        density_multiplier=1.0,
        inherit_route_asset="flamengo_botafogo_urca.csv",
        inherit_seed_asset="flamengo_botafogo_urca.gpx",
        speed_min_kmh=17.0,
        speed_max_kmh=27.2,
    ),
    V4RouteSpec(
        corridor="Copacabana + Arpoador + Ipanema + Lagoa",
        route_asset="copacabana_arpoador_ipanema_lagoa.csv",
        seed_asset="copacabana_arpoador_ipanema_lagoa.gpx",
        start_time="2026-04-11T02:05:00Z",
        transport_mode="car",
        route_family="road",
        density_multiplier=1.0,
        inherit_route_asset="copacabana_arpoador_ipanema_lagoa.csv",
        inherit_seed_asset="copacabana_arpoador_ipanema_lagoa.gpx",
        speed_min_kmh=17.0,
        speed_max_kmh=27.2,
    ),
    V4RouteSpec(
        corridor="Aterro Promenade Walk",
        route_asset="aterro_promenade_walk.csv",
        seed_asset="aterro_promenade_walk.gpx",
        start_time="2026-04-11T03:00:00Z",
        transport_mode="walk",
        route_family="pedestrian",
        density_multiplier=0.52,
        speed_min_kmh=4.3,
        speed_max_kmh=6.1,
        control_points=(
            (-22.924900, -43.170450),
            (-22.925450, -43.170500),
            (-22.926100, -43.170620),
            (-22.926950, -43.170880),
            (-22.927850, -43.171250),
            (-22.928800, -43.171620),
            (-22.929850, -43.172050),
            (-22.930950, -43.172520),
            (-22.932000, -43.172980),
            (-22.933050, -43.173430),
            (-22.934200, -43.173920),
            (-22.935350, -43.174400),
            (-22.936450, -43.174850),
            (-22.937600, -43.175320),
            (-22.938700, -43.175780),
            (-22.939850, -43.176240),
            (-22.940900, -43.176640),
            (-22.942050, -43.177000),
            (-22.943250, -43.177340),
            (-22.944150, -43.177620),
        ),
    ),
    V4RouteSpec(
        corridor="Lagoa + Jardim Botanico Bike",
        route_asset="lagoa_jardim_botanico_bike.csv",
        seed_asset="lagoa_jardim_botanico_bike.gpx",
        start_time="2026-04-11T03:35:00Z",
        transport_mode="bike",
        route_family="bike",
        density_multiplier=0.62,
        speed_min_kmh=13.0,
        speed_max_kmh=21.0,
        control_points=(
            (-22.965900, -43.214200),
            (-22.966650, -43.213120),
            (-22.967300, -43.211900),
            (-22.968100, -43.210420),
            (-22.968950, -43.208700),
            (-22.969950, -43.206650),
            (-22.970900, -43.204600),
            (-22.971900, -43.202250),
            (-22.973050, -43.199950),
            (-22.974250, -43.197800),
            (-22.975350, -43.195850),
            (-22.976550, -43.193850),
            (-22.977650, -43.191950),
            (-22.978650, -43.190300),
        ),
    ),
    V4RouteSpec(
        corridor="Lapa + Gloria + Praca Maua Motorcycle",
        route_asset="lapa_gloria_praca_maua_motorcycle.csv",
        seed_asset="lapa_gloria_praca_maua_motorcycle.gpx",
        start_time="2026-04-11T04:10:00Z",
        transport_mode="motorcycle",
        route_family="road",
        density_multiplier=0.82,
        speed_min_kmh=18.0,
        speed_max_kmh=31.0,
        control_points=(
            (-22.914550, -43.181650),
            (-22.913650, -43.180050),
            (-22.912700, -43.178350),
            (-22.911650, -43.176850),
            (-22.910450, -43.175950),
            (-22.908900, -43.175450),
            (-22.907050, -43.175150),
            (-22.905250, -43.175000),
            (-22.903850, -43.175450),
            (-22.902850, -43.176350),
            (-22.902350, -43.177950),
            (-22.903100, -43.179250),
            (-22.904650, -43.180000),
            (-22.906350, -43.180300),
            (-22.908150, -43.180650),
            (-22.910050, -43.181000),
            (-22.912050, -43.181300),
            (-22.913450, -43.181550),
        ),
    ),
    V4RouteSpec(
        corridor="Urca + Botafogo Shore Boat",
        route_asset="urca_botafogo_shore_boat.csv",
        seed_asset="urca_botafogo_shore_boat.gpx",
        start_time="2026-04-11T04:45:00Z",
        transport_mode="boat",
        route_family="water",
        density_multiplier=0.72,
        speed_min_kmh=10.0,
        speed_max_kmh=16.0,
        control_points=(
            (-22.952600, -43.166450),
            (-22.952050, -43.167350),
            (-22.951300, -43.168450),
            (-22.950350, -43.169700),
            (-22.949450, -43.171050),
            (-22.948450, -43.172450),
            (-22.947450, -43.173900),
            (-22.946450, -43.175300),
            (-22.945500, -43.176700),
            (-22.944500, -43.178100),
            (-22.943700, -43.179350),
            (-22.943050, -43.180250),
        ),
    ),
    V4RouteSpec(
        corridor="Maracana + Sao Cristovao + Praca Maua Train",
        route_asset="maracana_sao_cristovao_praca_maua_train.csv",
        seed_asset="maracana_sao_cristovao_praca_maua_train.gpx",
        start_time="2026-04-11T05:20:00Z",
        transport_mode="train",
        route_family="rail",
        density_multiplier=0.97,
        speed_min_kmh=28.0,
        speed_max_kmh=42.0,
        control_points=(
            (-22.912250, -43.230150),
            (-22.911300, -43.228850),
            (-22.910050, -43.227200),
            (-22.908700, -43.225300),
            (-22.907200, -43.223200),
            (-22.905800, -43.221350),
            (-22.904100, -43.218850),
            (-22.902700, -43.216700),
            (-22.901250, -43.214500),
            (-22.900150, -43.212250),
            (-22.899250, -43.209750),
            (-22.898650, -43.206800),
            (-22.898150, -43.203500),
            (-22.897650, -43.200000),
            (-22.897200, -43.196600),
            (-22.896900, -43.193000),
            (-22.896850, -43.189500),
            (-22.896900, -43.186400),
            (-22.897100, -43.183900),
            (-22.897300, -43.181500),
            (-22.897400, -43.179450),
        ),
    ),
    V4RouteSpec(
        corridor="Engenhao + Linha do Trem Corridor",
        route_asset="engenhao_linha_trem_corridor.csv",
        seed_asset="engenhao_linha_trem_corridor.gpx",
        start_time="2026-04-11T06:05:00Z",
        transport_mode="train",
        route_family="rail",
        density_multiplier=0.96,
        speed_min_kmh=27.0,
        speed_max_kmh=40.0,
        control_points=(
            (-22.893850, -43.291900),
            (-22.894100, -43.289900),
            (-22.894350, -43.287700),
            (-22.894650, -43.285500),
            (-22.894900, -43.283300),
            (-22.895050, -43.281250),
            (-22.895100, -43.279100),
            (-22.895200, -43.276950),
            (-22.895350, -43.274850),
            (-22.895500, -43.272700),
            (-22.895600, -43.270400),
            (-22.895700, -43.268050),
            (-22.895800, -43.265950),
        ),
    ),
    V4RouteSpec(
        corridor="Copacabana + Arpoador Shoreline Walk",
        route_asset="copacabana_arpoador_shoreline_walk.csv",
        seed_asset="copacabana_arpoador_shoreline_walk.gpx",
        start_time="2026-04-11T06:40:00Z",
        transport_mode="walk",
        route_family="pedestrian",
        density_multiplier=0.5,
        speed_min_kmh=4.2,
        speed_max_kmh=6.0,
        control_points=(
            (-22.971650, -43.182950),
            (-22.972800, -43.183650),
            (-22.974050, -43.184350),
            (-22.975400, -43.185050),
            (-22.976700, -43.185850),
            (-22.978050, -43.186650),
            (-22.979300, -43.187500),
            (-22.980500, -43.188350),
            (-22.981750, -43.189350),
            (-22.982900, -43.190450),
            (-22.983950, -43.191650),
            (-22.984800, -43.192950),
            (-22.985500, -43.194350),
            (-22.985950, -43.195550),
        ),
    ),
    V4RouteSpec(
        corridor="Centro Historico + Museu do Amanha Metro-Style Session",
        route_asset="centro_historico_museu_amanha_metro.csv",
        seed_asset="centro_historico_museu_amanha_metro.gpx",
        start_time="2026-04-11T07:15:00Z",
        transport_mode="metro",
        route_family="rail",
        density_multiplier=0.9,
        speed_min_kmh=24.0,
        speed_max_kmh=34.0,
        control_points=(
            (-22.908700, -43.177900),
            (-22.907800, -43.178300),
            (-22.906700, -43.178400),
            (-22.905600, -43.178150),
            (-22.904450, -43.177500),
            (-22.903550, -43.176500),
            (-22.902850, -43.175150),
            (-22.902500, -43.173850),
            (-22.902400, -43.172350),
            (-22.902350, -43.170850),
            (-22.902250, -43.169300),
            (-22.902050, -43.167900),
            (-22.901850, -43.166400),
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


def _route_distance_m(points: list[tuple[float, float]]) -> float:
    return sum(
        _haversine_m(lat1, lng1, lat2, lng2)
        for (lat1, lng1), (lat2, lng2) in zip(points, points[1:])
    )


def _densify_points(
    points: list[tuple[float, float]],
    *,
    points_per_km: float = DEFAULT_POINTS_PER_KM,
) -> list[dict[str, float]]:
    if len(points) < 2:
        raise ValueError("Need at least 2 control points")

    total_distance_m = _route_distance_m(points)
    total_distance_km = max(total_distance_m / 1000.0, 0.001)
    target_points = max(2, int(round(total_distance_km * float(points_per_km))))
    step_m = total_distance_m / max(target_points - 1, 1)

    dense_points = [{"lat": points[0][0], "lng": points[0][1], "distance_m": 0.0}]
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
    return dense_points


def _rows_from_dense_points(
    dense_points: list[dict[str, float]],
    *,
    start_time: str,
    speed_min_kmh: float,
    speed_max_kmh: float,
) -> list[dict[str, Any]]:
    start_dt = _iso_to_datetime(start_time)
    route_rows: list[dict[str, Any]] = []
    current_dt = start_dt
    previous_distance = 0.0
    speed_span = max(0.1, float(speed_max_kmh) - float(speed_min_kmh))

    for index, point in enumerate(dense_points):
        segment_distance = float(point["distance_m"]) - previous_distance
        speed_kmh = float(speed_min_kmh) + ((index % 9) / 8.0) * speed_span
        delta_seconds = (
            0.0
            if index == 0
            else max(1.0, segment_distance / max(speed_kmh / 3.6, 0.1))
        )
        current_dt += timedelta(seconds=delta_seconds)
        route_rows.append(
            {
                "timestamp": _to_iso(current_dt),
                "lat": round(float(point["lat"]), 6),
                "lng": round(float(point["lng"]), 6),
                "altitude_m": round(6.5 + (index % 11) * 0.25, 1),
                "speed_kmh": round(speed_kmh, 1),
                "accuracy_m": round(4.0 + (index % 4) * 0.3, 1),
            }
        )
        previous_distance = float(point["distance_m"])
    return route_rows


def _validate_route_rows(
    route_rows: list[dict[str, Any]],
    *,
    min_distance_km: float = 1.4,
    max_distance_km: float = 6.2,
    min_points_per_km: float = 240.0,
    max_points_per_km: float = 300.0,
    max_step_m: float = 18.0,
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
    if max(distances) > max_step_m:
        raise ValueError(f"Route still has a long jump ({max(distances):.2f}m)")
    if any(b <= a for a, b in zip(timestamps, timestamps[1:])):
        raise ValueError("Route timestamps are not strictly increasing")

    sorted_distances = sorted(distances)
    return {
        "distance_km": round(distance_km, 3),
        "points_per_km": round(points_per_km, 2),
        "step_distance_m": {
            "median": round(sorted_distances[len(sorted_distances) // 2], 2),
            "p90": round(
                sorted_distances[int((len(sorted_distances) - 1) * 0.9)],
                2,
            ),
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


def _write_gpx(
    control_points: list[tuple[float, float]], *, output_path: Path, start_time: str
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    root = ET.Element(
        f"{{{GPX_NS}}}gpx",
        attrib={"version": "1.1", "creator": "KOVIL MAP Demo V4 Builder"},
    )
    trk = ET.SubElement(root, f"{{{GPX_NS}}}trk")
    name = ET.SubElement(trk, f"{{{GPX_NS}}}name")
    name.text = output_path.stem
    segment = ET.SubElement(trk, f"{{{GPX_NS}}}trkseg")
    current_time = _iso_to_datetime(start_time)
    for index, (lat, lng) in enumerate(control_points):
        trkpt = ET.SubElement(
            segment,
            f"{{{GPX_NS}}}trkpt",
            attrib={"lat": f"{lat:.6f}", "lon": f"{lng:.6f}"},
        )
        ele = ET.SubElement(trkpt, f"{{{GPX_NS}}}ele")
        ele.text = f"{6.5 + (index % 8) * 0.4:.1f}"
        time_el = ET.SubElement(trkpt, f"{{{GPX_NS}}}time")
        time_el.text = _to_iso(current_time)
        current_time += timedelta(seconds=8)
    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    tree.write(output_path, encoding="utf-8", xml_declaration=True)


def _copy_existing_asset(source_path: Path, target_path: Path) -> None:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_bytes(source_path.read_bytes())


def build_routes(
    *,
    v3_source_root: Path,
    v3_seed_root: Path,
    v4_source_root: Path,
    v4_seed_root: Path,
    metadata_path: Path | None = None,
) -> dict[str, Any]:
    results: dict[str, Any] = {}

    for spec in V4_ROUTE_SPECS:
        if spec.inherit_route_asset:
            source_route = v3_source_root / spec.inherit_route_asset
            source_seed = v3_seed_root / str(spec.inherit_seed_asset or spec.seed_asset)
            target_route = v4_source_root / spec.route_asset
            target_seed = v4_seed_root / spec.seed_asset
            _copy_existing_asset(source_route, target_route)
            _copy_existing_asset(source_seed, target_seed)
            with target_route.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            stats = _validate_route_rows(rows)
            results[spec.route_asset] = {
                "corridor": spec.corridor,
                "seed_asset": spec.seed_asset,
                "route_asset": spec.route_asset,
                "transport_mode": spec.transport_mode,
                "route_family": spec.route_family,
                "density_multiplier": spec.density_multiplier,
                "seed_points": "copied",
                "route_points": len(rows),
                **stats,
            }
            continue

        control_points = list(spec.control_points)
        for lat, lng in control_points:
            _assert_bbox(lat, lng)
        dense_points = _densify_points(control_points)
        route_rows = _rows_from_dense_points(
            dense_points,
            start_time=spec.start_time,
            speed_min_kmh=spec.speed_min_kmh,
            speed_max_kmh=spec.speed_max_kmh,
        )
        stats = _validate_route_rows(route_rows)
        _write_route_csv(route_rows, output_path=v4_source_root / spec.route_asset)
        _write_gpx(
            control_points,
            output_path=v4_seed_root / spec.seed_asset,
            start_time=spec.start_time,
        )
        results[spec.route_asset] = {
            "corridor": spec.corridor,
            "seed_asset": spec.seed_asset,
            "route_asset": spec.route_asset,
            "transport_mode": spec.transport_mode,
            "route_family": spec.route_family,
            "density_multiplier": spec.density_multiplier,
            "seed_points": len(control_points),
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
        description="Build sanitized V4 route sources and GPX seeds."
    )
    parser.add_argument("--v3-routes", required=True, help="V3 routes directory")
    parser.add_argument("--v3-seeds", required=True, help="V3 seeds directory")
    parser.add_argument("--v4-routes", required=True, help="V4 routes directory")
    parser.add_argument("--v4-seeds", required=True, help="V4 seeds directory")
    parser.add_argument("--metadata", required=False, help="Optional metadata JSON")
    args = parser.parse_args()

    results = build_routes(
        v3_source_root=Path(args.v3_routes),
        v3_seed_root=Path(args.v3_seeds),
        v4_source_root=Path(args.v4_routes),
        v4_seed_root=Path(args.v4_seeds),
        metadata_path=Path(args.metadata) if args.metadata else None,
    )
    print(json.dumps(results, ensure_ascii=True, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
