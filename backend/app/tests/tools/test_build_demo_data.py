import json
from pathlib import Path

import pytest

from app.tools import build_demo_data


def test_build_demo_data_generates_v4_pack(tmp_path):
    pack_root = tmp_path / "showcase-core-v4"
    source_root = (
        Path(build_demo_data.__file__).resolve().parents[2]
        / "demo_data_sources"
        / "showcase-core-v4"
        / "routes"
    )

    assert (
        build_demo_data.build_pack(
            validate=True,
            pack_root=pack_root,
            source_root=source_root,
        )
        == 0
    )

    manifest_path = pack_root / "manifest.json"
    assert manifest_path.exists()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    summary = manifest["summary"]
    assert summary["networks_total"] >= 2000
    assert summary["wardrive_sessions"] == 11
    assert summary["wardrive_networks_observed"] >= 3500
    assert summary["cross_source_capture_networks"] >= 2
    assert summary["combined_candidate_networks"] >= 2
    assert summary["wardrive_handshake_networks"] >= 6
    assert summary["wardrive_handshake_raw_networks"] >= 3
    assert summary["session_count_by_transport_mode"] == {
        "bike": 1,
        "boat": 1,
        "car": 3,
        "metro": 1,
        "motorcycle": 1,
        "train": 2,
        "walk": 2,
    }

    wardrive_dir = pack_root / "runtime" / "wardrive"
    assert len(list(wardrive_dir.glob("*.csv"))) == 11
    session_tags = json.loads(
        (wardrive_dir / "session_tags.json").read_text(encoding="utf-8")
    )
    assert len(session_tags) == 11
    assert session_tags["20260411_001500_wardriving"] == "car"
    assert session_tags["20260411_044500_urca_botafogo_shore_boat"] == "boat"

    for session in manifest["wardrive_sessions"]:
        multiplier = float(session["density_multiplier"])
        assert 1.7 <= float(session["route_distance_km"]) <= 5.8
        assert int(session["route_points"]) >= 420
        assert int(session["scan_points"]) >= 420
        assert int(session["csv_rows"]) >= 9000
        assert int(session["networks_observed"]) >= 700
        assert float(session["rows_per_km"]) >= 12555.66 * multiplier * 0.84
        assert float(session["rows_per_km"]) <= 12555.66 * multiplier * 1.12
        assert float(session["rows_per_point"]) >= 44.46 * multiplier * 0.8
        assert float(session["rows_per_point"]) <= 44.46 * multiplier * 1.2
        assert (
            float(session["unique_bssids_per_km"])
            >= 658.11 * max(0.42, multiplier) * 0.8
        )
        assert (
            float(session["unique_bssids_per_km"])
            <= 658.11 * max(0.42, multiplier) * 1.25
        )


def test_route_loader_rejects_wifi_identity_columns(tmp_path):
    bad_route = tmp_path / "bad_route.csv"
    bad_route.write_text(
        "timestamp,lat,lng,altitude_m,speed_kmh,accuracy_m,ssid\n"
        "2026-04-11T00:15:00Z,-22.90,-43.18,5,20,4,REAL_NET\n",
        encoding="utf-8",
    )

    with pytest.raises(AssertionError):
        build_demo_data._load_route_waypoints(bad_route)
