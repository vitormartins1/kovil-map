import json
from collections import Counter
from pathlib import Path

import pytest

from app.tools import build_demo_data


def test_build_demo_data_generates_v5_pack(tmp_path, monkeypatch):
    pack_root = tmp_path / "showcase-core-v5"
    source_root = (
        Path(build_demo_data.__file__).resolve().parents[2]
        / "demo_data_sources"
        / "showcase-core-v5"
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
    assert summary["wardrive_sessions"] == 4
    assert summary["wardrive_networks_observed"] >= 2500
    assert summary["cross_source_capture_networks"] >= 2
    assert summary["combined_candidate_networks"] >= 2
    assert summary["wardrive_handshake_networks"] >= 260
    assert summary["wardrive_handshake_raw_networks"] >= 8
    assert summary["handshake_captures"] >= 320
    assert summary["gps_backed_locked_networks"] >= 250
    assert summary["no_gps_locked_networks"] >= 4
    assert summary["cracked_networks"] >= 50
    assert summary["not_ready_networks"] >= 3
    assert summary["pwnagotchi_promoted_wardrive_networks"] == 240
    assert summary["pwnagotchi_promoted_locked_networks"] == 208
    assert summary["pwnagotchi_promoted_cracked_networks"] == 32
    assert summary["pwnagotchi_promoted_convertible_networks"] == 24
    assert summary["session_count_by_transport_mode"] == {
        "car": 3,
        "motorcycle": 1,
    }

    wardrive_dir = pack_root / "runtime" / "wardrive"
    assert len(list(wardrive_dir.glob("*.csv"))) == 4
    session_tags = json.loads(
        (wardrive_dir / "session_tags.json").read_text(encoding="utf-8")
    )
    assert len(session_tags) == 4
    assert session_tags["20260411_001500_wardriving"] == "car"
    handshakes_dir = pack_root / "runtime" / "handshakes"
    sample_pcap = next(handshakes_dir.glob("*.pcap"))
    sample_base = sample_pcap.stem
    assert (handshakes_dir / f"{sample_base}.details").exists()
    assert (handshakes_dir / f"{sample_base}.try").exists()
    assert not (handshakes_dir / "captures").exists()

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

    from app.services import data_loader as dl_module
    from app.services import handshake_catalog as hc_module
    from app.services.to_conquer_service import (
        build_conquered_zones,
        build_to_conquer_zones,
    )

    runtime_root = pack_root / "runtime"
    runtime_paths = {
        "HANDSHAKES_DIR": str(runtime_root / "handshakes"),
        "WARDRIVE_DIR": str(runtime_root / "wardrive"),
        "BRUCE_PCAP_DIR": str(runtime_root / "BrucePCAP"),
        "BRUCE_HANDSHAKES_DIR": str(runtime_root / "BrucePCAP" / "handshakes"),
        "M5EVIL_DIR": str(runtime_root / "m5evil"),
        "M5EVIL_HANDSHAKES_DIR": str(runtime_root / "m5evil" / "handshakes"),
    }
    for name, value in runtime_paths.items():
        if hasattr(dl_module, name):
            monkeypatch.setattr(dl_module, name, value)
    for name in (
        "HANDSHAKES_DIR",
        "BRUCE_PCAP_DIR",
        "BRUCE_HANDSHAKES_DIR",
        "M5EVIL_HANDSHAKES_DIR",
    ):
        monkeypatch.setattr(hc_module, name, runtime_paths[name])
    monkeypatch.setattr(dl_module, "_DATA_CACHE", None)
    monkeypatch.setattr(dl_module, "_WARDRIVE_SESSION_TAGS", None)
    monkeypatch.setattr(dl_module, "_WARDRIVE_MANIFEST", None)
    monkeypatch.setattr(dl_module, "_WARDRIVE_MANIFEST_PATH", None)

    data = dl_module.reload_data()
    state_counts = Counter(
        str(item.get("network_state") or "") for item in data.values()
    )
    assert state_counts["locked"] >= 250
    assert state_counts["cracked"] >= 50

    locked_points = [
        {
            "lat": item["lat"],
            "lng": item["lng"],
            "acc": item.get("acc", item.get("accuracy", 0)) or 0,
        }
        for item in data.values()
        if item.get("network_state") == "locked"
        and item.get("lat") is not None
        and item.get("lng") is not None
    ]
    cracked_points = [
        {
            "lat": item["lat"],
            "lng": item["lng"],
            "acc": item.get("acc", item.get("accuracy", 0)) or 0,
        }
        for item in data.values()
        if item.get("network_state") == "cracked"
        and item.get("lat") is not None
        and item.get("lng") is not None
    ]
    to_conquer_zones = build_to_conquer_zones(
        cracked_points,
        locked_points,
        eps_m=200,
        min_samples=5,
        min_zone_points=2,
    )
    conquered_zones = build_conquered_zones(
        cracked_points,
        eps_m=200,
        min_samples=3,
    )
    assert len(to_conquer_zones) >= 10
    assert len(conquered_zones) >= 4


def test_route_loader_rejects_wifi_identity_columns(tmp_path):
    bad_route = tmp_path / "bad_route.csv"
    bad_route.write_text(
        "timestamp,lat,lng,altitude_m,speed_kmh,accuracy_m,ssid\n"
        "2026-04-11T00:15:00Z,-22.90,-43.18,5,20,4,REAL_NET\n",
        encoding="utf-8",
    )

    with pytest.raises(AssertionError):
        build_demo_data._load_route_waypoints(bad_route)
