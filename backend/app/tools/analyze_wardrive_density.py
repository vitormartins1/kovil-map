from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from collections import Counter
from pathlib import Path
from typing import Any

RJ_BBOX = {
    "lat_min": -23.10,
    "lat_max": -22.80,
    "lng_min": -43.40,
    "lng_max": -43.10,
}


def _parse_float(value: object) -> float | None:
    try:
        if value is None or str(value).strip() == "":
            return None
        return float(value)
    except (TypeError, ValueError):
        return None


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


def _quantile(sorted_values: list[float], ratio: float) -> float:
    if not sorted_values:
        return 0.0
    index = min(
        len(sorted_values) - 1,
        max(0, int(round((len(sorted_values) - 1) * float(ratio)))),
    )
    return float(sorted_values[index])


def analyze_wardrive_density(input_path: Path) -> dict[str, Any]:
    input_path = Path(input_path)
    with input_path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        first_line = handle.readline()
        reader = csv.DictReader(handle)
        rows = list(reader)

    valid_rows: list[dict[str, Any]] = []
    point_counter: Counter[tuple[float, float]] = Counter()
    unique_bssids: set[str] = set()
    rssi_values: list[int] = []
    channel_counter: Counter[str] = Counter()
    band_counter: Counter[str] = Counter()
    ordered_unique_points: list[tuple[float, float]] = []
    seen_points: set[tuple[float, float]] = set()

    for row in rows:
        lat = _parse_float(
            row.get("CurrentLatitude") or row.get("Latitude") or row.get("lat")
        )
        lng = _parse_float(
            row.get("CurrentLongitude")
            or row.get("Longitude")
            or row.get("lng")
            or row.get("lon")
        )
        if lat is None or lng is None:
            continue
        if not (
            RJ_BBOX["lat_min"] <= lat <= RJ_BBOX["lat_max"]
            and RJ_BBOX["lng_min"] <= lng <= RJ_BBOX["lng_max"]
        ):
            continue

        point_key = (round(lat, 6), round(lng, 6))
        point_counter[point_key] += 1
        if point_key not in seen_points:
            seen_points.add(point_key)
            ordered_unique_points.append(point_key)

        bssid = (
            str(row.get("MAC") or row.get("BSSID") or row.get("mac") or "")
            .strip()
            .upper()
        )
        if bssid:
            unique_bssids.add(bssid)

        rssi = _parse_float(row.get("RSSI"))
        if rssi is not None:
            rssi_values.append(int(round(rssi)))

        channel = str(row.get("Channel") or "").strip()
        if channel:
            channel_counter[channel] += 1

        frequency = _parse_float(row.get("Frequency"))
        if frequency is not None:
            band_counter["5GHz" if float(frequency) >= 5000 else "2.4GHz"] += 1

        valid_rows.append(row)

    if len(ordered_unique_points) < 2:
        raise ValueError("Wardrive reference does not contain enough valid GPS points")

    step_distances_m = [
        _haversine_m(lat1, lng1, lat2, lng2)
        for (lat1, lng1), (lat2, lng2) in zip(
            ordered_unique_points, ordered_unique_points[1:]
        )
    ]
    total_distance_km = sum(step_distances_m) / 1000.0
    if total_distance_km <= 0:
        raise ValueError("Wardrive reference produced zero route distance")

    batch_sizes = sorted(point_counter.values())
    sorted_steps = sorted(step_distances_m)
    sorted_rssi = sorted(rssi_values) if rssi_values else []
    return {
        "source_file": str(input_path),
        "reference_header": first_line.rstrip("\n"),
        "valid_rows": len(valid_rows),
        "valid_unique_points": len(ordered_unique_points),
        "unique_bssids": len(unique_bssids),
        "distance_km": round(total_distance_km, 3),
        "rows_per_km": round(len(valid_rows) / total_distance_km, 2),
        "points_per_km": round(len(ordered_unique_points) / total_distance_km, 2),
        "unique_bssids_per_km": round(len(unique_bssids) / total_distance_km, 2),
        "rows_per_point": round(len(valid_rows) / len(ordered_unique_points), 2),
        "max_same_gps": int(batch_sizes[-1]),
        "batch_size_percentiles": {
            "p50": int(_quantile(batch_sizes, 0.5)),
            "p75": int(_quantile(batch_sizes, 0.75)),
            "p90": int(_quantile(batch_sizes, 0.9)),
            "p95": int(_quantile(batch_sizes, 0.95)),
        },
        "point_batch_histogram": {
            str(size): int(count)
            for size, count in sorted(Counter(batch_sizes).items())
        },
        "step_distance_m": {
            "min": round(min(step_distances_m), 2),
            "median": round(statistics.median(step_distances_m), 2),
            "p90": round(_quantile(sorted_steps, 0.9), 2),
            "max": round(max(step_distances_m), 2),
            "mean": round(statistics.mean(step_distances_m), 2),
        },
        "rssi": (
            {
                "min": int(sorted_rssi[0]),
                "median": int(_quantile(sorted_rssi, 0.5)),
                "p90": int(_quantile(sorted_rssi, 0.9)),
                "max": int(sorted_rssi[-1]),
            }
            if sorted_rssi
            else {}
        ),
        "channels": dict(
            sorted(channel_counter.items(), key=lambda item: int(item[0]))
        ),
        "bands": dict(sorted(band_counter.items())),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze a Wardrive CSV and emit a sanitized density profile."
    )
    parser.add_argument("--input", required=True, help="Wardrive CSV reference path")
    parser.add_argument("--output", required=True, help="Output JSON path")
    args = parser.parse_args()

    payload = analyze_wardrive_density(Path(args.input))
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote density profile to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
