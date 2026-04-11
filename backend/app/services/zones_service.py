from math import pi
from typing import Dict, List, Tuple

from sklearn.cluster import DBSCAN

EARTH_RADIUS_M = 6371000.0


def _to_radians(points: List[Dict[str, float]]) -> List[Tuple[float, float]]:
    coords = []
    for p in points:
        lat = p.get("lat")
        lng = p.get("lng")
        if lat is None or lng is None:
            continue
        coords.append((lat * pi / 180.0, lng * pi / 180.0))
    return coords


def cluster_points(
    points: List[Dict[str, float]], eps_m: float = 200.0, min_samples: int = 3
) -> List[Dict]:
    if not points:
        return []

    coords = _to_radians(points)
    if not coords:
        return []

    eps = eps_m / EARTH_RADIUS_M
    model = DBSCAN(
        eps=eps, min_samples=min_samples, metric="haversine", algorithm="ball_tree"
    )
    labels = model.fit(coords).labels_

    clusters: Dict[int, List[Dict[str, float]]] = {}
    for idx, label in enumerate(labels):
        if label == -1:
            continue
        clusters.setdefault(label, []).append(points[idx])

    zones = []
    for cluster_id, cluster_points_list in clusters.items():
        count = len(cluster_points_list)
        center_lat = sum(p["lat"] for p in cluster_points_list) / count
        center_lng = sum(p["lng"] for p in cluster_points_list) / count
        zones.append(
            {
                "id": int(cluster_id),
                "count": count,
                "center": {"lat": center_lat, "lng": center_lng},
                "points": cluster_points_list,
            }
        )

    zones.sort(key=lambda z: z["id"])
    return zones
