from app.tools import build_demo_v3_routes


def test_cap_seed_points_preserves_endpoints():
    points = [(-22.91 + (index * 0.0001), -43.18) for index in range(140)]

    capped = build_demo_v3_routes._cap_seed_points(points, max_points=40)

    assert len(capped) == 40
    assert capped[0] == points[0]
    assert capped[-1] == points[-1]


def test_densify_geometry_and_validate_route_rows():
    geometry = [
        (-22.918500, -43.183000),
        (-22.909000, -43.183000),
        (-22.898700, -43.183000),
    ]

    route_rows = build_demo_v3_routes._densify_geometry(
        geometry,
        start_time="2026-04-11T00:15:00Z",
        points_per_km=282.42,
    )
    stats = build_demo_v3_routes._validate_route_rows(route_rows)

    assert len(route_rows) >= 500
    assert 1.8 <= stats["distance_km"] <= 2.6
    assert 240.0 <= stats["points_per_km"] <= 300.0
    assert stats["step_distance_m"]["max"] <= 18.0


def test_write_and_read_gpx_roundtrip(tmp_path):
    seed_points = [
        (-22.918300, -43.185100),
        (-22.917900, -43.184500),
        (-22.917400, -43.183700),
    ]
    output_path = tmp_path / "route.gpx"

    build_demo_v3_routes._write_gpx(
        seed_points,
        output_path=output_path,
        start_time="2026-04-11T00:15:00Z",
    )
    payload = build_demo_v3_routes._read_gpx(output_path)

    assert len(payload) == 3
    assert payload[0]["lat"] == seed_points[0][0]
    assert payload[-1]["lng"] == seed_points[-1][1]
