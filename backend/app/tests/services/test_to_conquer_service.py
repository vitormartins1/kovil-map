from shapely.geometry import MultiPolygon, Polygon

from app.services import to_conquer_service as tc_module
from app.services.to_conquer_service import (
    _build_components,
    _build_overlap_polys,
    _local_meters_to_latlng,
    _meters_scale,
    _split_parts_to_zones,
    _to_local_meters,
    build_conquered_zones,
    build_hull,
    build_to_conquer_zones,
    expand_points_by_accuracy,
    polygon_to_parts,
    polygon_to_zone_parts,
)


def test_expand_points_by_accuracy():
    points = [
        {"lat": -22.0, "lng": -43.0, "acc": 10},
        {"lat": -22.1, "lng": -43.1, "acc": 0},
    ]
    expanded = expand_points_by_accuracy(points, acc_segments=6)
    assert len(expanded) > len(points)


def test_build_hull_and_parts():
    points = [
        {"lat": 0.0, "lng": 0.0},
        {"lat": 0.0, "lng": 0.01},
        {"lat": 0.01, "lng": 0.0},
    ]
    hull = build_hull(points)
    assert hull is not None
    parts = polygon_to_parts(hull)
    assert parts and len(parts[0]["ring"]) >= 3


def test_build_conquered_zones_basic():
    points = [
        {"lat": -22.0, "lng": -43.0, "acc": 50},
        {"lat": -22.0001, "lng": -43.0001, "acc": 50},
    ]
    zones = build_conquered_zones(points, eps_m=500, min_samples=1)
    assert zones


def test_build_to_conquer_zones_basic():
    to_conquer = [
        {"lat": -22.2, "lng": -43.2, "acc": 50},
        {"lat": -22.2001, "lng": -43.2001, "acc": 50},
    ]
    zones = build_to_conquer_zones([], to_conquer, eps_m=500, min_samples=1)
    assert zones


def test_build_to_conquer_zones_filters_small_components_by_min_zone_points(monkeypatch):
    monkeypatch.setattr(
        tc_module,
        "cluster_points",
        lambda _pts, eps_m, min_samples: [
            {
                "id": 7,
                "center": {},
                "points": [
                    {"lat": 0.0, "lng": 0.0, "acc": 40},
                    {"lat": 0.0001, "lng": 0.0001, "acc": 40},
                ],
            }
        ],
    )
    monkeypatch.setattr(
        tc_module,
        "_build_overlap_polys",
        lambda *args, **kwargs: [
            (Polygon([(0, 0), (0, 1), (1, 0)]), 2),
            (Polygon([(2, 2), (2, 3), (3, 2)]), 5),
        ],
    )

    zones = build_to_conquer_zones(
        conquered_points=[],
        to_conquer_points=[{"lat": 1.0, "lng": 1.0, "acc": 40}],
        eps_m=500,
        min_samples=1,
        min_zone_points=5,
    )

    assert len(zones) == 1
    assert zones[0]["count"] == 5


def test_expand_points_by_accuracy_handles_empty_invalid_and_min_segments():
    assert expand_points_by_accuracy([], acc_segments=2) == []

    points = [
        {"lat": 1.0, "lng": 2.0, "acc": 10},
        {"lat": None, "lng": 2.1, "acc": 10},
        {"lat": 1.1, "lng": None, "acc": 10},
    ]
    expanded = expand_points_by_accuracy(points, acc_segments=1)
    # 1 centro + 4 pontos (segments mínimo = 4)
    assert len(expanded) == 5


def test_build_hull_returns_none_for_insufficient_or_invalid_points():
    assert build_hull([]) is None
    assert build_hull([{"lat": 0.0, "lng": 0.0}, {"lat": 0.1, "lng": 0.1}]) is None
    assert (
        build_hull(
            [
                {"lat": 0.0, "lng": 0.0},
                {"lat": 0.1},
                {"lng": 0.1},
            ]
        )
        is None
    )


def test_polygon_helpers_cover_none_multipolygon_and_filter(monkeypatch):
    poly_a = Polygon([(0, 0), (1, 0), (0, 1)])
    poly_b = Polygon([(2, 2), (3, 2), (2, 3)])
    multi = MultiPolygon([poly_a, poly_b])
    parts = polygon_to_parts(multi)
    assert len(parts) == 2
    assert polygon_to_zone_parts(None) == []

    monkeypatch.setattr(
        tc_module,
        "polygon_to_parts",
        lambda _p: [
            {"ring": [{"lat": 1.0, "lng": 1.0}], "holes": []},
            {
                "ring": [
                    {"lat": 0.0, "lng": 0.0},
                    {"lat": 0.1, "lng": 0.1},
                    {"lat": 0.2, "lng": 0.2},
                ],
                "holes": [],
            },
        ],
    )
    filtered = polygon_to_zone_parts(poly_a)
    assert len(filtered) == 1
    assert len(filtered[0]["ring"]) == 3


def test_split_parts_and_metric_roundtrip_helpers():
    assert _split_parts_to_zones([], base_id=5, count=2) == []
    one_zone = _split_parts_to_zones(
        [
            {
                "ring": [
                    {"lat": 0.0, "lng": 0.0},
                    {"lat": 0.1, "lng": 0.1},
                    {"lat": 0.2, "lng": 0.2},
                ],
                "holes": [],
            }
        ],
        base_id=7,
        count=3,
    )
    assert one_zone == [
        {
            "id": 7,
            "count": 3,
            "parts": [
                [
                    {"lat": 0.0, "lng": 0.0},
                    {"lat": 0.1, "lng": 0.1},
                    {"lat": 0.2, "lng": 0.2},
                ]
            ],
        }
    ]
    many = _split_parts_to_zones(
        [
            {
                "ring": [
                    {"lat": 1.0, "lng": 1.0},
                    {"lat": 1.1, "lng": 1.1},
                    {"lat": 1.2, "lng": 1.2},
                ],
                "holes": [],
            },
            {
                "ring": [
                    {"lat": 2.0, "lng": 2.0},
                    {"lat": 2.1, "lng": 2.1},
                    {"lat": 2.2, "lng": 2.2},
                ],
                "holes": [],
            },
        ],
        base_id=9,
        count=4,
    )
    assert [z["id"] for z in many] == [900, 901]

    scale = _meters_scale(100.0)
    assert scale["m_per_deg_lng"] == scale["m_per_deg_lat"]

    x, y = _to_local_meters(
        lat=-22.0,
        lng=-43.0,
        lat0=-22.1,
        lng0=-43.1,
        m_per_deg_lat=scale["m_per_deg_lat"],
        m_per_deg_lng=scale["m_per_deg_lng"],
    )
    lng, lat = _local_meters_to_latlng(
        x,
        y,
        lat0=-22.1,
        lng0=-43.1,
        m_per_deg_lat=scale["m_per_deg_lat"],
        m_per_deg_lng=scale["m_per_deg_lng"],
    )
    assert round(lat, 4) == -22.0
    assert round(lng, 4) == -43.0


def test_overlap_builders_with_overlapping_and_isolated_components():
    points_local = [
        {"x": 0.0, "y": 0.0, "acc": 50.0, "lat": 0.0, "lng": 0.0},
        {"x": 30.0, "y": 10.0, "acc": 50.0, "lat": 0.0001, "lng": 0.0001},
        {"x": 500.0, "y": 500.0, "acc": 10.0, "lat": 0.01, "lng": 0.01},
    ]
    components = _build_components(points_local)
    assert len(components) == 2
    assert any(len(comp) == 2 and has_overlap for comp, has_overlap in components)

    polys = _build_overlap_polys(
        points_local,
        center_lat=0.0,
        center_lng=0.0,
        m_per_deg_lat=111320.0,
        m_per_deg_lng=111320.0,
    )
    assert len(polys) == 1
    assert polys[0][1] == 2


def test_build_to_conquer_zones_covers_conquered_union_and_sort(monkeypatch):
    conquered_clusters = [
        {
            "id": 9,
            "center": {},
            "points": [
                {"lat": 10.0, "lng": 10.0, "acc": 60},
                {"lat": 10.0001, "lng": 10.0001, "acc": 60},
                {"lat": 10.0002, "lng": 10.0002, "acc": 0},
            ],
        }
    ]
    to_conquer_clusters = [
        {"id": 2, "center": {}, "points": [{"lat": 0.0, "lng": 0.0, "acc": 55}]},
        {
            "id": 1,
            "center": {},
            "points": [
                {"lat": 0.1, "lng": 0.1, "acc": 55},
                {"lat": 0.1001, "lng": 0.1001, "acc": 55},
                {"lat": 0.1002, "lng": 0.1002, "acc": 0},
            ],
        },
    ]
    calls = [conquered_clusters, to_conquer_clusters]

    monkeypatch.setattr(
        tc_module,
        "cluster_points",
        lambda _pts, eps_m, min_samples: calls.pop(0),
    )
    zones = build_to_conquer_zones(
        conquered_points=[{"lat": 1.0, "lng": 1.0}],
        to_conquer_points=[{"lat": 2.0, "lng": 2.0}],
        eps_m=400,
        min_samples=1,
    )
    assert zones
    assert zones == sorted(zones, key=lambda z: z["id"])


def test_build_conquered_zones_covers_empty_and_non_empty_components(monkeypatch):
    clusters = [
        {"id": 3, "center": {}, "points": [{"lat": -1.0, "lng": -1.0, "acc": 40}]},
        {
            "id": 2,
            "center": {},
            "points": [
                {"lat": -1.1, "lng": -1.1, "acc": 40},
                {"lat": -1.1001, "lng": -1.1001, "acc": 40},
            ],
        },
        {
            "id": 1,
            "center": {},
            "points": [
                {"lat": -1.2, "lng": -1.2, "acc": 0},
                {"lat": -1.2001, "lng": -1.2001, "acc": 0},
            ],
        },
    ]
    monkeypatch.setattr(
        tc_module,
        "cluster_points",
        lambda _pts, eps_m, min_samples: clusters,
    )
    zones = build_conquered_zones(
        conquered_points=[{"lat": -1.0, "lng": -1.0}],
        eps_m=300,
        min_samples=1,
    )
    assert zones
    assert zones == sorted(zones, key=lambda z: z["id"])


def test_build_to_conquer_zones_clips_with_lower_min_samples(monkeypatch):
    """When min_samples > 3 (e.g. discovery uses 5), conquered clusters must
    still be built with min_samples=3 so that higher-priority zones rendered
    with min_samples=3 are correctly reproduced for clipping."""
    recorded_calls = []

    original_cluster = tc_module.cluster_points

    def tracking_cluster(pts, eps_m, min_samples):
        recorded_calls.append({"min_samples": min_samples, "n_pts": len(pts)})
        return original_cluster(pts, eps_m=eps_m, min_samples=min_samples)

    monkeypatch.setattr(tc_module, "cluster_points", tracking_cluster)

    conquered = [
        {"lat": -22.0, "lng": -43.0, "acc": 50},
        {"lat": -22.0001, "lng": -43.0001, "acc": 50},
        {"lat": -22.0002, "lng": -43.0002, "acc": 50},
    ]
    to_conquer = [
        {"lat": -22.1, "lng": -43.1, "acc": 50},
        {"lat": -22.1001, "lng": -43.1001, "acc": 50},
        {"lat": -22.1002, "lng": -43.1002, "acc": 50},
        {"lat": -22.1003, "lng": -43.1003, "acc": 50},
        {"lat": -22.1004, "lng": -43.1004, "acc": 50},
    ]

    build_to_conquer_zones(
        conquered_points=conquered,
        to_conquer_points=to_conquer,
        eps_m=500,
        min_samples=5,
    )

    # First call (conquered) should use min(5, 3) = 3
    assert recorded_calls[0]["min_samples"] == 3
    # Second call (to_conquer) should keep min_samples=5
    assert recorded_calls[1]["min_samples"] == 5
