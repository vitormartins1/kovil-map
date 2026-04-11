from app.services.zones_service import cluster_points


def test_cluster_points_empty():
    assert cluster_points([]) == []


def test_cluster_points_basic():
    points = [
        {"lat": -22.0, "lng": -43.0},
        {"lat": -22.0001, "lng": -43.0001},
    ]
    zones = cluster_points(points, eps_m=1000, min_samples=1)
    assert len(zones) == 1
    assert zones[0]["count"] == 2


def test_cluster_points_skips_invalid_points():
    points = [
        {"lat": -22.0, "lng": -43.0},
        {"lat": None, "lng": -43.0},
        {"lat": -22.0, "lng": None},
    ]
    zones = cluster_points(points, eps_m=1000, min_samples=1)
    assert len(zones) == 1
    assert zones[0]["count"] == 1


def test_cluster_points_returns_empty_when_all_invalid():
    points = [
        {"lat": None, "lng": None},
        {"lat": None},
        {"lng": -43.0},
    ]
    assert cluster_points(points, eps_m=1000, min_samples=1) == []
