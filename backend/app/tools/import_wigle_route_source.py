from __future__ import annotations

import argparse
import csv
import math
from datetime import datetime, timezone
from pathlib import Path

ROUTE_COLUMNS = (
    "timestamp",
    "lat",
    "lng",
    "altitude_m",
    "speed_kmh",
    "accuracy_m",
)


def _normalize_timestamp(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("Missing Wigle timestamp")
    if "T" in raw:
        normalized = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
    else:
        dt = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
        dt = dt.replace(tzinfo=timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _to_epoch(value: str) -> float:
    normalized = str(value or "").replace("Z", "+00:00")
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


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


def sanitize_wigle_route(input_path: Path, output_path: Path) -> int:
    input_path = Path(input_path)
    output_path = Path(output_path)
    if not input_path.exists():
        raise FileNotFoundError(input_path)

    sanitized_rows: list[dict[str, object]] = []
    previous_row: dict[str, object] | None = None

    with input_path.open("r", encoding="utf-8", errors="ignore", newline="") as handle:
        first_line = handle.readline()
        if first_line.lower().startswith("wiglewifi-"):
            reader = csv.DictReader(handle)
        else:
            reader = csv.DictReader([first_line, *handle])

        for row in reader:
            lat = _parse_float(
                row.get("CurrentLatitude") or row.get("Latitude") or row.get("lat")
            )
            lng = _parse_float(
                row.get("CurrentLongitude")
                or row.get("Longitude")
                or row.get("lng")
                or row.get("lon")
            )
            if lat is None or lng is None or (lat == 0 and lng == 0):
                continue

            timestamp = _normalize_timestamp(
                str(
                    row.get("LastSeen")
                    or row.get("FirstSeen")
                    or row.get("LastSeenUTC")
                    or row.get("FirstSeenUTC")
                    or ""
                )
            )
            altitude = _parse_float(
                row.get("AltitudeMeters") or row.get("Altitude") or row.get("altitude")
            )
            accuracy = _parse_float(
                row.get("AccuracyMeters") or row.get("Accuracy") or row.get("accuracy")
            )
            current = {
                "timestamp": timestamp,
                "lat": round(float(lat), 6),
                "lng": round(float(lng), 6),
                "altitude_m": round(
                    float(altitude if altitude is not None else 0.0), 1
                ),
                "speed_kmh": 0.0,
                "accuracy_m": round(
                    float(accuracy if accuracy is not None else 5.0), 1
                ),
            }

            if previous_row is not None:
                distance_m = _haversine_m(
                    float(previous_row["lat"]),
                    float(previous_row["lng"]),
                    float(current["lat"]),
                    float(current["lng"]),
                )
                if distance_m < 6.0:
                    continue
                delta_s = max(
                    1.0,
                    _to_epoch(str(current["timestamp"]))
                    - _to_epoch(str(previous_row["timestamp"])),
                )
                speed_kmh = min(95.0, (distance_m / delta_s) * 3.6)
                current["speed_kmh"] = round(speed_kmh, 1)
            else:
                current["speed_kmh"] = 18.0

            sanitized_rows.append(current)
            previous_row = current

    if len(sanitized_rows) < 2:
        raise ValueError("Wigle route did not contain enough valid GPS points")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=ROUTE_COLUMNS)
        writer.writeheader()
        writer.writerows(sanitized_rows)
    return len(sanitized_rows)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Convert a Wigle Wardrive CSV into a sanitized route-only CSV."
    )
    parser.add_argument("--input", required=True, help="Path to the source Wigle CSV")
    parser.add_argument(
        "--output", required=True, help="Path to the sanitized route CSV"
    )
    args = parser.parse_args()
    count = sanitize_wigle_route(Path(args.input), Path(args.output))
    print(f"Sanitized {count} GPS points into {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
