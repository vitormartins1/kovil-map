import json
from pathlib import Path

from app.tools import build_demo_v4_routes


def test_build_demo_v4_routes_generates_expected_mix(tmp_path):
    repo_root = Path(build_demo_v4_routes.__file__).resolve().parents[2]
    v3_routes = repo_root / "demo_data_sources" / "showcase-core-v3" / "routes"
    v3_seeds = repo_root / "demo_data_sources" / "showcase-core-v3" / "seeds"
    v4_routes = tmp_path / "routes"
    v4_seeds = tmp_path / "seeds"
    metadata_path = tmp_path / "route_build_report.json"

    results = build_demo_v4_routes.build_routes(
        v3_source_root=v3_routes,
        v3_seed_root=v3_seeds,
        v4_source_root=v4_routes,
        v4_seed_root=v4_seeds,
        metadata_path=metadata_path,
    )

    assert len(results) == 11
    assert metadata_path.exists()
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata == results

    assert results["centro_lapa_santa_teresa.csv"]["transport_mode"] == "car"
    assert results["aterro_promenade_walk.csv"]["transport_mode"] == "walk"
    assert results["lagoa_jardim_botanico_bike.csv"]["transport_mode"] == "bike"
    assert results["urca_botafogo_shore_boat.csv"]["route_family"] == "water"
    assert (
        results["maracana_sao_cristovao_praca_maua_train.csv"]["transport_mode"]
        == "train"
    )
    assert (
        results["centro_historico_museu_amanha_metro.csv"]["transport_mode"] == "metro"
    )

    for route_asset, payload in results.items():
        assert (v4_routes / route_asset).exists()
        assert (v4_seeds / str(payload["seed_asset"])).exists()
        assert 240.0 <= float(payload["points_per_km"]) <= 300.0
        assert float(payload["step_distance_m"]["max"]) <= 18.0
        assert float(payload["distance_km"]) >= 1.7
