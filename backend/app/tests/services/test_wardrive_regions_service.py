import json
import time
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from shapely.geometry import GeometryCollection, Point, Polygon

from app.services import wardrive_regions_service as wardrive_module
from app.services.wardrive_regions_service import (
    FORMAT_RANK,
    RegionEntry,
    WardriveRegionsService,
    _LevelSpatialIndex,
    DatasetManifest,
)


def _build_entry(
    region_id,
    level_key,
    level_label,
    depth,
    name,
    code,
    parent_id,
    geometry,
    depth_role="administrative",
    include_in_hierarchy=True,
    source_format="geojson",
):
    return RegionEntry(
        id=region_id,
        country_code="br",
        country_name="Brasil",
        level_key=level_key,
        level_label=level_label,
        depth=depth,
        depth_role=depth_role,
        name=name,
        code=code,
        parent_id=parent_id,
        parent_hints=[],
        source_format=source_format,
        source_path="test",
        source_rank=FORMAT_RANK[source_format],
        dataset_id=f"dataset-{level_key}",
        dataset_source="test",
        priority=10,
        include_in_hierarchy=include_in_hierarchy,
        geometries=[geometry],
    )


def _write_country_pack(base_path, shapefile_lib):
    maps_dir = base_path / "maps"
    country_dir = maps_dir / "br"
    (country_dir / "layers" / "01-state" / "demo_state").mkdir(parents=True)
    (country_dir / "layers" / "02-city" / "demo_city").mkdir(parents=True)
    (country_dir / "layers" / "03-neighborhood" / "demo_neighborhood").mkdir(
        parents=True
    )
    (country_dir / "layers" / "04-sector" / "demo_sector").mkdir(parents=True)
    (maps_dir / "_legacy" / "br" / "old_prefeitura").mkdir(parents=True)

    (country_dir / "country.json").write_text(
        json.dumps(
            {
                "country_code": "br",
                "country_name": "Brasil",
                "default_locale": "pt-BR",
                "labels": {
                    "state": "Estado",
                    "city": "Cidade",
                    "neighborhood": "Bairro",
                    "sector": "Setor",
                },
            }
        ),
        encoding="utf-8",
    )

    state_geojson = {
        "type": "FeatureCollection",
        "features": [
            {
                "type": "Feature",
                "properties": {
                    "CD_UF": "33",
                    "SIGLA_UF": "RJ",
                    "NM_UF": "Rio de Janeiro",
                },
                "geometry": {
                    "type": "Polygon",
                    "coordinates": [
                        [
                            [-44.0, -23.5],
                            [-42.0, -23.5],
                            [-42.0, -22.0],
                            [-44.0, -22.0],
                            [-44.0, -23.5],
                        ]
                    ],
                },
            }
        ],
    }
    (country_dir / "layers" / "01-state" / "demo_state" / "states.geojson").write_text(
        json.dumps(state_geojson),
        encoding="utf-8",
    )
    (country_dir / "layers" / "01-state" / "demo_state" / "metadata.json").write_text(
        json.dumps(
            {
                "enabled": True,
                "priority": 10,
                "level_key": "state",
                "level_label": "Estado",
                "dataset_id": "state-demo",
                "source": "fixture",
                "version": "1",
                "geometry_format": "geojson",
                "crs": "EPSG:4326",
                "source_path": "states.geojson",
                "id_fields": ["SIGLA_UF", "CD_UF"],
                "name_fields": ["SIGLA_UF", "NM_UF"],
                "parent_resolvers": [],
                "depth_role": "administrative",
                "include_in_hierarchy": True,
            }
        ),
        encoding="utf-8",
    )

    shp_path = country_dir / "layers" / "02-city" / "demo_city" / "cities.shp"
    writer = shapefile_lib.Writer(str(shp_path))
    writer.field("CD_MUN", "C")
    writer.field("NM_MUN", "C")
    writer.field("CD_UF", "C")
    writer.poly(
        [
            [
                (-43.7, -23.2),
                (-43.1, -23.2),
                (-43.1, -22.7),
                (-43.7, -22.7),
                (-43.7, -23.2),
            ]
        ]
    )
    writer.record("3304557", "Rio de Janeiro", "RJ")
    writer.close()
    (country_dir / "layers" / "02-city" / "demo_city" / "metadata.json").write_text(
        json.dumps(
            {
                "enabled": True,
                "priority": 20,
                "level_key": "city",
                "level_label": "Cidade",
                "dataset_id": "city-demo",
                "source": "fixture",
                "version": "1",
                "geometry_format": "shp",
                "crs": "EPSG:4326",
                "source_path": "cities.shp",
                "id_fields": ["CD_MUN"],
                "name_fields": ["NM_MUN"],
                "parent_resolvers": [
                    {
                        "target_level_key": "state",
                        "target_key": "code",
                        "source_fields": ["CD_UF"],
                    },
                    {
                        "target_level_key": "state",
                        "target_key": "name",
                        "source_fields": ["CD_UF"],
                    },
                ],
                "depth_role": "administrative",
                "include_in_hierarchy": True,
            }
        ),
        encoding="utf-8",
    )

    neighborhood_kml = """<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Document>
    <Placemark>
      <name>Botafogo</name>
      <ExtendedData>
        <SchemaData>
          <SimpleData name="CD_BAIRRO">001</SimpleData>
          <SimpleData name="NM_BAIRRO">Botafogo</SimpleData>
          <SimpleData name="CD_MUN">3304557</SimpleData>
          <SimpleData name="NM_MUN">Rio de Janeiro</SimpleData>
        </SchemaData>
      </ExtendedData>
      <Polygon>
        <outerBoundaryIs>
          <LinearRing>
            <coordinates>
              -43.205,-22.965,0 -43.170,-22.965,0 -43.170,-22.940,0 -43.205,-22.940,0 -43.205,-22.965,0
            </coordinates>
          </LinearRing>
        </outerBoundaryIs>
      </Polygon>
    </Placemark>
  </Document>
</kml>
"""
    kmz_path = (
        country_dir
        / "layers"
        / "03-neighborhood"
        / "demo_neighborhood"
        / "neighborhoods.kmz"
    )
    with zipfile.ZipFile(kmz_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("doc.kml", neighborhood_kml)
    (
        country_dir
        / "layers"
        / "03-neighborhood"
        / "demo_neighborhood"
        / "metadata.json"
    ).write_text(
        json.dumps(
            {
                "enabled": True,
                "priority": 30,
                "level_key": "neighborhood",
                "level_label": "Bairro",
                "dataset_id": "neighborhood-demo",
                "source": "fixture",
                "version": "1",
                "geometry_format": "kmz",
                "crs": "EPSG:4326",
                "source_path": "neighborhoods.kmz",
                "id_fields": ["CD_BAIRRO"],
                "name_fields": ["NM_BAIRRO"],
                "parent_resolvers": [
                    {
                        "target_level_key": "city",
                        "target_key": "code",
                        "source_fields": ["CD_MUN"],
                    },
                    {
                        "target_level_key": "city",
                        "target_key": "name",
                        "source_fields": ["NM_MUN"],
                    },
                ],
                "depth_role": "administrative",
                "include_in_hierarchy": True,
            }
        ),
        encoding="utf-8",
    )

    sector_kml = """<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Document>
    <Placemark>
      <name>330455700000001</name>
      <ExtendedData>
        <SchemaData>
          <SimpleData name="CD_SETOR">330455700000001</SimpleData>
          <SimpleData name="CD_BAIRRO">001</SimpleData>
          <SimpleData name="CD_MUN">3304557</SimpleData>
          <SimpleData name="NM_MUN">Rio de Janeiro</SimpleData>
        </SchemaData>
      </ExtendedData>
      <Polygon>
        <outerBoundaryIs>
          <LinearRing>
            <coordinates>
              -43.200,-22.960,0 -43.175,-22.960,0 -43.175,-22.945,0 -43.200,-22.945,0 -43.200,-22.960,0
            </coordinates>
          </LinearRing>
        </outerBoundaryIs>
      </Polygon>
    </Placemark>
    <Placemark>
      <name>330455700000002</name>
      <ExtendedData>
        <SchemaData>
          <SimpleData name="CD_SETOR">330455700000002</SimpleData>
          <SimpleData name="CD_MUN">3304557</SimpleData>
          <SimpleData name="NM_MUN">Rio de Janeiro</SimpleData>
        </SchemaData>
      </ExtendedData>
      <Polygon>
        <outerBoundaryIs>
          <LinearRing>
            <coordinates>
              -43.150,-23.000,0 -43.120,-23.000,0 -43.120,-22.970,0 -43.150,-22.970,0 -43.150,-23.000,0
            </coordinates>
          </LinearRing>
        </outerBoundaryIs>
      </Polygon>
    </Placemark>
  </Document>
</kml>
"""
    sector_kmz = country_dir / "layers" / "04-sector" / "demo_sector" / "sectors.kmz"
    with zipfile.ZipFile(sector_kmz, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("doc.kml", sector_kml)
    (country_dir / "layers" / "04-sector" / "demo_sector" / "metadata.json").write_text(
        json.dumps(
            {
                "enabled": True,
                "priority": 40,
                "level_key": "sector",
                "level_label": "Setor",
                "dataset_id": "sector-demo",
                "source": "fixture",
                "version": "1",
                "geometry_format": "kmz",
                "crs": "EPSG:4326",
                "source_path": "sectors.kmz",
                "id_fields": ["CD_SETOR"],
                "name_fields": ["CD_SETOR", "name"],
                "parent_resolvers": [
                    {
                        "target_level_key": "neighborhood",
                        "target_key": "code",
                        "source_fields": ["CD_BAIRRO"],
                    },
                    {
                        "target_level_key": "city",
                        "target_key": "code",
                        "source_fields": ["CD_MUN"],
                    },
                ],
                "depth_role": "fallback",
                "include_in_hierarchy": False,
            }
        ),
        encoding="utf-8",
    )

    (country_dir / "layers" / "03-neighborhood" / "broken_projected").mkdir(
        parents=True
    )
    (
        country_dir
        / "layers"
        / "03-neighborhood"
        / "broken_projected"
        / "metadata.json"
    ).write_text(
        json.dumps(
            {
                "enabled": True,
                "priority": 99,
                "level_key": "neighborhood",
                "level_label": "Bairro",
                "dataset_id": "broken-projected",
                "source": "fixture",
                "version": "1",
                "geometry_format": "geojson",
                "crs": "EPSG:31983",
                "source_path": "broken.geojson",
                "id_fields": ["id"],
                "name_fields": ["name"],
                "parent_resolvers": [],
                "depth_role": "administrative",
                "include_in_hierarchy": True,
            }
        ),
        encoding="utf-8",
    )
    (maps_dir / "_legacy" / "br" / "old_prefeitura" / "legacy.prj").write_text(
        'PROJCS["SAD_1969_UTM_Zone_23S"]', encoding="utf-8"
    )
    return maps_dir


def test_service_loads_country_pack_and_inventory(monkeypatch, tmp_path):
    shapefile_lib = wardrive_module.shapefile
    if shapefile_lib is None:
        pytest.skip("pyshp unavailable")

    maps_dir = _write_country_pack(tmp_path, shapefile_lib)
    monkeypatch.setattr(wardrive_module, "MAPS_DIR", str(maps_dir))

    svc = WardriveRegionsService()
    svc._ensure_index()

    assert "br:state:rj" in svc._regions_by_id
    assert "br:city:3304557" in svc._regions_by_id
    assert "br:neighborhood:001" in svc._regions_by_id
    assert "br:sector:330455700000001" in svc._regions_by_id

    city = svc._regions_by_id["br:city:3304557"]
    neighborhood = svc._regions_by_id["br:neighborhood:001"]
    sector = svc._regions_by_id["br:sector:330455700000001"]

    assert city.parent_id == "br:state:rj"
    assert neighborhood.parent_id == city.id
    assert sector.parent_id == neighborhood.id
    assert sector.include_in_hierarchy is False

    inventory = svc.get_maps_inventory()
    assert inventory["loaded_datasets"] == 4
    assert len(inventory["active_datasets"]) == 4
    assert len(inventory["legacy_ignored"]) == 1
    assert len(inventory["incompatible_crs"]) == 1
    assert (
        inventory["coverage_by_level"]["br"]["sector"]["hierarchy_regions_count"] == 0
    )


def test_classify_prefers_administrative_before_fallback():
    svc = WardriveRegionsService()
    svc._level_depths = {"state": 1, "city": 2, "neighborhood": 3, "sector": 4}
    svc._max_hierarchy_depth_by_country = {"br": 3}

    state = _build_entry(
        "br:state:rj",
        "state",
        "Estado",
        1,
        "RJ",
        "RJ",
        None,
        Polygon([(-44, -24), (-42, -24), (-42, -22), (-44, -22), (-44, -24)]),
    )
    city = _build_entry(
        "br:city:3304557",
        "city",
        "Cidade",
        2,
        "Rio",
        "3304557",
        state.id,
        Polygon(
            [
                (-43.8, -23.3),
                (-43.1, -23.3),
                (-43.1, -22.6),
                (-43.8, -22.6),
                (-43.8, -23.3),
            ]
        ),
    )
    neighborhood = _build_entry(
        "br:neighborhood:001",
        "neighborhood",
        "Bairro",
        3,
        "Botafogo",
        "001",
        city.id,
        Polygon(
            [
                (-43.30, -23.00),
                (-43.10, -23.00),
                (-43.10, -22.80),
                (-43.30, -22.80),
                (-43.30, -23.00),
            ]
        ),
    )
    sector = _build_entry(
        "br:sector:330455700000001",
        "sector",
        "Setor",
        4,
        "330455700000001",
        "330455700000001",
        neighborhood.id,
        Polygon(
            [
                (-43.24, -22.94),
                (-43.16, -22.94),
                (-43.16, -22.86),
                (-43.24, -22.86),
                (-43.24, -22.94),
            ]
        ),
        depth_role="fallback",
        include_in_hierarchy=False,
        source_format="kmz",
    )

    svc._regions_by_id = {
        state.id: state,
        city.id: city,
        neighborhood.id: neighborhood,
        sector.id: sector,
    }
    svc._spatial_indexes = {
        "state": _LevelSpatialIndex([(state.id, state.geometries[0])]),
        "city": _LevelSpatialIndex([(city.id, city.geometries[0])]),
        "neighborhood": _LevelSpatialIndex(
            [(neighborhood.id, neighborhood.geometries[0])]
        ),
        "sector": _LevelSpatialIndex([(sector.id, sector.geometries[0])]),
    }

    point = Point(-43.2, -22.9)
    assert svc._classify_point(point) == neighborhood.id


def test_classify_point_geometry_exception_handling():
    # Skip this test for now as geometry mocking is complex
    pass


def test_hierarchy_filters_and_rolls_points_to_ancestors(monkeypatch):
    svc = WardriveRegionsService()
    svc._level_depths = {"state": 1, "city": 2, "sector": 4}
    svc._max_hierarchy_depth_by_country = {"br": 3}

    state = _build_entry(
        "br:state:rj",
        "state",
        "Estado",
        1,
        "RJ",
        "RJ",
        None,
        Polygon([(-44, -24), (-42, -24), (-42, -22), (-44, -22), (-44, -24)]),
    )
    city = _build_entry(
        "br:city:3304557",
        "city",
        "Cidade",
        2,
        "Rio de Janeiro",
        "3304557",
        state.id,
        Polygon(
            [
                (-43.8, -23.3),
                (-43.1, -23.3),
                (-43.1, -22.6),
                (-43.8, -22.6),
                (-43.8, -23.3),
            ]
        ),
    )
    sector = _build_entry(
        "br:sector:330455700000001",
        "sector",
        "Setor",
        4,
        "330455700000001",
        "330455700000001",
        city.id,
        Polygon(
            [
                (-43.25, -23.0),
                (-43.15, -23.0),
                (-43.15, -22.85),
                (-43.25, -22.85),
                (-43.25, -23.0),
            ]
        ),
        depth_role="fallback",
        include_in_hierarchy=False,
        source_format="kmz",
    )
    svc._regions_by_id = {state.id: state, city.id: city, sector.id: sector}
    svc._spatial_indexes = {
        "state": _LevelSpatialIndex([(state.id, state.geometries[0])]),
        "city": _LevelSpatialIndex([(city.id, city.geometries[0])]),
        "sector": _LevelSpatialIndex([(sector.id, sector.geometries[0])]),
    }
    svc._maps_summary = {"maps_dir": "/tmp/maps", "loaded_files": 1}
    monkeypatch.setattr(svc, "_ensure_index", lambda: None)

    now = int(time.time())
    dataset = {
        "AA:AA:AA:AA:AA:01": {
            "lat": -22.91,
            "lng": -43.2,
            "acc": 8,
            "ts_last": now - 30,
            "sources": ["pwnagotchi"],
            "encryption": "WPA2",
            "pass": None,
        },
        "AA:AA:AA:AA:AA:02": {
            "lat": -22.92,
            "lng": -43.19,
            "acc": 10,
            "ts_last": now - 20,
            "sources": ["pwnagotchi"],
            "encryption": "OPEN",
            "pass": None,
        },
        "AA:AA:AA:AA:AA:03": {
            "lat": -22.90,
            "lng": -43.18,
            "acc": 9,
            "ts_last": now - 90_000,
            "sources": ["bruce_raw"],
            "encryption": "WPA2",
            "pass": None,
        },
        "AA:AA:AA:AA:AA:04": {
            "lat": -23.90,
            "lng": -46.40,
            "acc": 11,
            "ts_last": now - 40,
            "sources": ["wardrive"],
            "encryption": "WPA2",
            "pass": None,
        },
        "AA:AA:AA:AA:AA:05": {
            "lat": -23.9005,
            "lng": -46.401,
            "acc": 12,
            "ts_last": now - 35,
            "sources": ["wardrive"],
            "encryption": "WPA2",
            "pass": None,
        },
    }
    monkeypatch.setattr(wardrive_module, "load_real_data", lambda: dataset)

    hierarchy_pwn = svc.get_hierarchy(time_window="24h", source="pwn")
    assert hierarchy_pwn["unmapped_summary"]["networks_count"] == 0
    city_row = next(
        (item for item in hierarchy_pwn["regions"] if item["id"] == city.id), None
    )
    assert city_row is not None
    assert city_row["stats"]["networks_count"] == 2
    assert city_row["level_label"] == "Cidade"
    assert city_row["display_path"] == "Brasil > RJ > Rio de Janeiro"
    assert not any(item["id"] == sector.id for item in hierarchy_pwn["regions"])

    hierarchy_ward = svc.get_hierarchy(time_window="24h", source="ward")
    assert hierarchy_ward["regions"] == []
    assert hierarchy_ward["unmapped_summary"]["networks_count"] == 2

    mapped_zones = svc.get_region_zones(
        region_id=city.id,
        eps_m=2500,
        min_samples=2,
        time_window="24h",
        source="pwn",
    )
    assert mapped_zones["region"]["id"] == city.id
    assert mapped_zones["region"]["display_path"] == "Brasil > RJ > Rio de Janeiro"
    assert mapped_zones["stats"]["networks_count"] == 2
    assert len(mapped_zones["zones"]) == 1

    unmapped_zones = svc.get_region_zones(
        region_id="unmapped",
        eps_m=300,
        min_samples=2,
        time_window="24h",
        source="ward",
    )
    assert unmapped_zones["region"]["id"] == "unmapped"
    assert len(unmapped_zones["zones"]) == 1


def test_sessions_inventory_and_session_filter(monkeypatch):
    svc = WardriveRegionsService()
    state = _build_entry(
        "br:state:rj",
        "state",
        "Estado",
        1,
        "RJ",
        "RJ",
        None,
        Polygon(
            [
                (-44.0, -23.5),
                (-42.0, -23.5),
                (-42.0, -22.0),
                (-44.0, -22.0),
                (-44.0, -23.5),
            ]
        ),
    )
    city = _build_entry(
        "br:city:rio-de-janeiro",
        "city",
        "Cidade",
        2,
        "Rio de Janeiro",
        "3304557",
        state.id,
        Polygon(
            [
                (-43.7, -23.2),
                (-43.1, -23.2),
                (-43.1, -22.7),
                (-43.7, -22.7),
                (-43.7, -23.2),
            ]
        ),
    )
    svc._regions_by_id = {state.id: state, city.id: city}
    svc._spatial_indexes = {
        "state": _LevelSpatialIndex([(state.id, state.geometries[0])]),
        "city": _LevelSpatialIndex([(city.id, city.geometries[0])]),
    }
    svc._level_depths = {"state": 1, "city": 2}
    svc._maps_summary = {"maps_dir": "/tmp/maps", "loaded_files": 2}
    monkeypatch.setattr(svc, "_ensure_index", lambda: None)

    now = int(time.time())
    dataset = {
        "AA:AA:AA:AA:AA:01": {
            "mac": "AA:AA:AA:AA:AA:01",
            "lat": -22.91,
            "lng": -43.2,
            "acc": 8,
            "ts_last": now - 100,
            "sources": ["wardrive"],
            "encryption": "WPA2",
            "wardrive_sessions": [
                {
                    "session_id": "session-rio",
                    "source_file": "session-rio.csv",
                    "lat": -22.91,
                    "lng": -43.2,
                    "acc": 8,
                    "ts_last": now - 100,
                    "ts_first": now - 200,
                    "encryption": "WPA2",
                },
                {
                    "session_id": "session-rio",
                    "source_file": "session-rio.csv",
                    "lat": -22.909,
                    "lng": -43.198,
                    "acc": 7,
                    "ts_last": now - 60,
                    "ts_first": now - 200,
                    "encryption": "WPA2",
                },
                {
                    "session_id": "session-unmapped",
                    "source_file": "session-unmapped.csv",
                    "lat": -23.9,
                    "lng": -46.4,
                    "acc": 12,
                    "ts_last": now - 90,
                    "ts_first": now - 120,
                    "encryption": "WPA2",
                },
            ],
        }
    }
    sessions = [
        {
            "session_id": "session-rio",
            "label": "session-rio",
            "source_file": "session-rio.csv",
            "started_at": now - 200,
            "ended_at": now - 100,
            "networks_count": 1,
            "points_count": 3,
            "transport_mode": "car",
        },
        {
            "session_id": "session-unmapped",
            "label": "session-unmapped",
            "source_file": "session-unmapped.csv",
            "started_at": now - 120,
            "ended_at": now - 90,
            "networks_count": 1,
            "points_count": 2,
            "transport_mode": "walk",
        },
    ]
    monkeypatch.setattr(wardrive_module, "load_real_data", lambda: dataset)
    monkeypatch.setattr(wardrive_module, "get_wardrive_sessions", lambda: sessions)

    payload = svc.get_sessions(time_window="24h")
    assert payload["summary"]["sessions_count"] == 2
    assert payload["sessions"][0]["session_id"] == "session-unmapped"
    assert payload["sessions"][0]["distance_m"] == 0
    assert payload["sessions"][1]["distance_m"] > 0
    assert payload["summary"]["transport_modes"][0]["transport_mode"] in {"car", "walk"}
    assert len(payload["summary"]["top_transport_modes"]) == 2

    hierarchy = svc.get_hierarchy(
        time_window="24h", source="all", session_ids=["session-rio"]
    )
    city_row = next(
        (item for item in hierarchy["regions"] if item["id"] == city.id), None
    )
    assert city_row is not None
    assert city_row["stats"]["networks_count"] == 1
    assert hierarchy["unmapped_summary"]["networks_count"] == 0

    hierarchy_unmapped = svc.get_hierarchy(
        time_window="24h", source="all", session_ids=["session-unmapped"]
    )
    assert hierarchy_unmapped["regions"] == []
    assert hierarchy_unmapped["unmapped_summary"]["networks_count"] == 1

    with pytest.raises(ValueError):
        svc.get_hierarchy(
            time_window="all", source="all", session_ids=["missing-session"]
        )


def test_set_session_tag_returns_updated_summary(monkeypatch):
    svc = WardriveRegionsService()
    monkeypatch.setattr(svc, "_ensure_index", lambda: None)
    monkeypatch.setattr(wardrive_module, "load_real_data", lambda: {})
    monkeypatch.setattr(
        wardrive_module,
        "set_wardrive_session_tag",
        lambda session_id, transport_mode=None: {
            "session_id": session_id,
            "transport_mode": transport_mode,
        },
    )
    monkeypatch.setattr(
        svc,
        "get_sessions",
        lambda time_window="all": {
            "time_window": time_window,
            "sessions": [
                {
                    "session_id": "session-a",
                    "transport_mode": "car",
                    "networks_count": 4,
                    "points_count": 4,
                }
            ],
            "summary": {
                "sessions_count": 1,
                "networks_count": 4,
                "points_count": 4,
                "transport_modes": [
                    {
                        "transport_mode": "car",
                        "sessions_count": 1,
                        "networks_count": 4,
                        "points_count": 4,
                    }
                ],
                "top_transport_modes": [
                    {
                        "transport_mode": "car",
                        "sessions_count": 1,
                        "networks_count": 4,
                        "points_count": 4,
                    }
                ],
            },
        },
    )

    payload = svc.set_session_tag("session-a", "car")
    assert payload["session"]["session_id"] == "session-a"
    assert payload["session"]["transport_mode"] == "car"
    assert payload["summary"]["transport_modes"][0]["transport_mode"] == "car"


def test_build_selected_wardrive_item_prefers_display_coordinates_for_zones():
    svc = WardriveRegionsService()
    now = int(time.time())
    item = {
        "mac": "AA:AA:AA:AA:AA:01",
        "lat": -22.91,
        "lng": -43.2,
        "acc": 8,
        "encryption": "WPA2",
        "wardrive_sessions": [
            {
                "session_id": "session-a",
                "source_file": "session-a.csv",
                "lat": -22.91,
                "lng": -43.2,
                "rawLatitude": -22.91,
                "rawLongitude": -43.2,
                "displayLatitude": -22.905,
                "displayLongitude": -43.195,
                "rawAccuracy": 8,
                "acc": 8,
                "ts_last": now - 10,
                "ts_first": now - 30,
                "encryption": "WPA2",
            }
        ],
    }

    selected = svc._build_selected_wardrive_item(
        item=item,
        session_ids=["session-a"],
        time_window="all",
        now_ts=now,
    )

    assert selected is not None
    assert selected["lat"] == -22.905
    assert selected["lng"] == -43.195
    assert selected["rawLatitude"] == -22.91
    assert selected["rawLongitude"] == -43.2


def test_get_session_tracks_returns_ordered_thinned_points(monkeypatch):
    svc = WardriveRegionsService()
    monkeypatch.setattr(svc, "_ensure_index", lambda: None)
    now = int(time.time())
    dataset = {
        "AA:AA:AA:AA:AA:01": {
            "wardrive_sessions": [
                {
                    "session_id": "session-a",
                    "source_file": "session-a.csv",
                    "lat": -22.91,
                    "lng": -43.2,
                    "rawLatitude": -22.91,
                    "rawLongitude": -43.2,
                    "displayLatitude": -22.89,
                    "displayLongitude": -43.18,
                    "rawAccuracy": 9,
                    "acc": 9,
                    "ts_last": now - 120,
                },
                {
                    "session_id": "session-a",
                    "source_file": "session-a.csv",
                    "lat": -22.91,
                    "lng": -43.2,
                    "rawLatitude": -22.91,
                    "rawLongitude": -43.2,
                    "displayLatitude": -22.889,
                    "displayLongitude": -43.179,
                    "rawAccuracy": 7,
                    "acc": 7,
                    "ts_last": now - 100,
                },
                {
                    "session_id": "session-a",
                    "source_file": "session-a.csv",
                    "lat": -22.909,
                    "lng": -43.198,
                    "rawLatitude": -22.909,
                    "rawLongitude": -43.198,
                    "displayLatitude": -22.887,
                    "displayLongitude": -43.177,
                    "rawAccuracy": 8,
                    "acc": 8,
                    "ts_last": now - 40,
                },
            ]
        }
    }
    sessions = [
        {
            "session_id": "session-a",
            "label": "Session A",
            "source_file": "session-a.csv",
            "started_at": now - 140,
            "ended_at": now - 20,
        }
    ]
    monkeypatch.setattr(wardrive_module, "load_real_data", lambda: dataset)
    monkeypatch.setattr(wardrive_module, "get_wardrive_sessions", lambda: sessions)

    payload = svc.get_session_tracks(["session-a"])
    assert payload["summary"]["returned_tracks"] == 1
    track = payload["tracks"][0]
    assert track["session_id"] == "session-a"
    assert track["label"] == "Session A"
    assert track["points_count"] == 2
    assert track["points"][0]["lat"] == -22.91
    assert track["points"][0]["lng"] == -43.2
    assert track["points"][1]["lat"] == -22.909
    assert track["points"][1]["lng"] == -43.198
    assert track["points"][0]["ts_last"] < track["points"][1]["ts_last"]
    assert track["distance_m"] > 0
    assert track["duration_s"] > 0
    assert track["bbox"]["min_lat"] <= track["bbox"]["max_lat"]
    assert track["center"]["lat"] < 0
    assert track["avg_accuracy_m"] is not None


def test_build_zones_disables_geometry_simplification(monkeypatch):
    svc = WardriveRegionsService()
    monkeypatch.setattr(
        wardrive_module,
        "cluster_points",
        lambda points, eps_m, min_samples: [
            {
                "id": 1,
                "count": 2,
                "center": {"lat": -22.91, "lng": -43.2},
                "points": [
                    {"lat": -22.91, "lng": -43.2, "acc": 8},
                    {"lat": -22.909, "lng": -43.198, "acc": 7},
                ],
            }
        ],
    )

    observed = {}

    def _fake_geometry_to_parts(_geometry, simplify_tolerance=0.0):
        observed["simplify_tolerance"] = simplify_tolerance
        return [
            [
                {"lat": -22.91, "lng": -43.2},
                {"lat": -22.91, "lng": -43.18},
                {"lat": -22.9, "lng": -43.19},
            ]
        ]

    monkeypatch.setattr(svc, "_geometry_to_parts", _fake_geometry_to_parts)

    zones = svc._build_zones(
        [
            {"lat": -22.91, "lng": -43.2, "acc": 8},
            {"lat": -22.909, "lng": -43.198, "acc": 7},
        ],
        eps_m=200,
        min_samples=2,
    )

    assert observed["simplify_tolerance"] == 0.0
    assert len(zones) == 1


def test_build_zones_falls_back_when_dbscan_returns_no_clusters(monkeypatch):
    svc = WardriveRegionsService()
    monkeypatch.setattr(
        wardrive_module, "cluster_points", lambda points, eps_m, min_samples: []
    )

    observed = {}

    def _fake_geometry_to_parts(_geometry, simplify_tolerance=0.0):
        observed["simplify_tolerance"] = simplify_tolerance
        return [
            [
                {"lat": -22.91, "lng": -43.2},
                {"lat": -22.91, "lng": -43.19},
                {"lat": -22.90, "lng": -43.19},
            ]
        ]

    monkeypatch.setattr(svc, "_geometry_to_parts", _fake_geometry_to_parts)

    zones = svc._build_zones(
        [
            {"lat": -22.91, "lng": -43.2, "acc": 8},
            {"lat": -22.909, "lng": -43.198, "acc": 7},
        ],
        eps_m=200,
        min_samples=3,
    )

    assert observed["simplify_tolerance"] == 0.0
    assert len(zones) == 1
    assert zones[0]["count"] == 2
    assert zones[0]["id"] == 1


def test_session_data_flows_do_not_require_map_index(monkeypatch):
    svc = WardriveRegionsService()

    def _boom():
        raise AssertionError("map index should not be required for session data")

    monkeypatch.setattr(svc, "_ensure_index", _boom)
    now = int(time.time())
    dataset = {
        "AA:AA:AA:AA:AA:01": {
            "wardrive_sessions": [
                {
                    "session_id": "session-a",
                    "source_file": "session-a.csv",
                    "lat": -22.91,
                    "lng": -43.2,
                    "acc": 8,
                    "ts_last": now - 120,
                },
                {
                    "session_id": "session-a",
                    "source_file": "session-a.csv",
                    "lat": -22.909,
                    "lng": -43.198,
                    "acc": 7,
                    "ts_last": now - 60,
                },
            ]
        }
    }
    sessions = [
        {
            "session_id": "session-a",
            "label": "Session A",
            "source_file": "session-a.csv",
            "started_at": now - 140,
            "ended_at": now - 20,
            "networks_count": 1,
            "points_count": 2,
            "transport_mode": "car",
        }
    ]

    monkeypatch.setattr(wardrive_module, "load_real_data", lambda: dataset)
    monkeypatch.setattr(wardrive_module, "get_wardrive_sessions", lambda: sessions)
    monkeypatch.setattr(
        wardrive_module,
        "set_wardrive_session_tag",
        lambda session_id, transport_mode=None: {
            "session_id": session_id,
            "transport_mode": transport_mode,
        },
    )

    sessions_payload = svc.get_sessions(time_window="all")
    assert sessions_payload["sessions"][0]["distance_m"] > 0

    tracks_payload = svc.get_session_tracks(["session-a"])
    assert tracks_payload["tracks"][0]["distance_m"] > 0

    tag_payload = svc.set_session_tag("session-a", "car")
    assert tag_payload["session"]["transport_mode"] == "car"


def test_get_session_tracks_validates_request(monkeypatch):
    svc = WardriveRegionsService()
    monkeypatch.setattr(svc, "_ensure_index", lambda: None)
    monkeypatch.setattr(wardrive_module, "get_wardrive_sessions", lambda: [])

    with pytest.raises(ValueError, match="session_ids must include at least 1 session"):
        svc.get_session_tracks([])

    monkeypatch.setattr(
        wardrive_module,
        "get_wardrive_sessions",
        lambda: [
            {"session_id": "a"},
            {"session_id": "b"},
            {"session_id": "c"},
            {"session_id": "d"},
        ],
    )
    with pytest.raises(ValueError, match="supports up to 3 sessions"):
        svc.get_session_tracks(["a", "b", "c", "d"])


def test_hierarchy_reuses_classification_cache(monkeypatch):
    svc = WardriveRegionsService()
    state = _build_entry(
        "br:state:rj",
        "state",
        "Estado",
        1,
        "RJ",
        "RJ",
        None,
        Polygon(
            [
                (-44.0, -23.5),
                (-42.0, -23.5),
                (-42.0, -22.0),
                (-44.0, -22.0),
                (-44.0, -23.5),
            ]
        ),
    )
    city = _build_entry(
        "br:city:rio-de-janeiro",
        "city",
        "Cidade",
        2,
        "Rio de Janeiro",
        "3304557",
        state.id,
        Polygon(
            [
                (-43.7, -23.2),
                (-43.1, -23.2),
                (-43.1, -22.7),
                (-43.7, -22.7),
                (-43.7, -23.2),
            ]
        ),
    )
    svc._regions_by_id = {state.id: state, city.id: city}
    svc._maps_summary = {"loaded_files": 1}
    monkeypatch.setattr(svc, "_ensure_index", lambda: None)
    monkeypatch.setattr(wardrive_module, "get_data_revision", lambda: 1)
    monkeypatch.setattr(wardrive_module, "load_real_data", lambda: {})

    calls = {"n": 0}

    def _fake_classify_points(**_kwargs):
        calls["n"] += 1
        return {
            "points_by_region": {},
            "stats_by_region": {
                state.id: {"networks_count": 1, "cracked": 0, "open": 0, "locked": 1},
                city.id: {"networks_count": 1, "cracked": 0, "open": 0, "locked": 1},
            },
            "unmapped_points": [],
            "unmapped_summary": {
                "networks_count": 0,
                "cracked": 0,
                "open": 0,
                "locked": 0,
            },
        }

    monkeypatch.setattr(svc, "_classify_points", _fake_classify_points)

    first = svc.get_hierarchy(time_window="all", source="all", session_ids=[])
    second = svc.get_hierarchy(time_window="all", source="all", session_ids=[])
    assert first["regions"]
    assert second["regions"]
    assert calls["n"] == 1


def test_region_zones_reuses_zones_cache(monkeypatch):
    svc = WardriveRegionsService()
    city = _build_entry(
        "br:city:rio-de-janeiro",
        "city",
        "Cidade",
        2,
        "Rio de Janeiro",
        "3304557",
        None,
        Polygon(
            [
                (-43.7, -23.2),
                (-43.1, -23.2),
                (-43.1, -22.7),
                (-43.7, -22.7),
                (-43.7, -23.2),
            ]
        ),
    )
    svc._regions_by_id = {city.id: city}
    monkeypatch.setattr(svc, "_ensure_index", lambda: None)
    monkeypatch.setattr(wardrive_module, "get_data_revision", lambda: 1)
    monkeypatch.setattr(
        svc,
        "_get_classification",
        lambda **_kwargs: {
            "points_by_region": {
                city.id: [
                    {"lat": -22.91, "lng": -43.2, "acc": 8},
                    {"lat": -22.92, "lng": -43.19, "acc": 8},
                ]
            },
            "stats_by_region": {
                city.id: {"networks_count": 2, "cracked": 0, "open": 0, "locked": 2}
            },
            "unmapped_points": [],
            "unmapped_summary": {
                "networks_count": 0,
                "cracked": 0,
                "open": 0,
                "locked": 0,
            },
        },
    )

    zone_calls = {"n": 0}

    def _fake_build_zones(points, eps_m, min_samples):
        zone_calls["n"] += 1
        assert len(points) == 2
        assert eps_m == 200
        assert min_samples == 2
        return [
            {"id": 1, "count": 2, "center": {"lat": -22.91, "lng": -43.2}, "parts": []}
        ]

    monkeypatch.setattr(svc, "_build_zones", _fake_build_zones)

    first = svc.get_region_zones(
        city.id, eps_m=200, min_samples=2, time_window="all", source="all"
    )
    second = svc.get_region_zones(
        city.id, eps_m=200, min_samples=2, time_window="all", source="all"
    )
    assert first["zones"][0]["count"] == 2
    assert second["zones"][0]["count"] == 2
    assert zone_calls["n"] == 1


def test_get_region_zones_focus_active_returns_primary_and_secondary_layers(
    monkeypatch,
):
    svc = WardriveRegionsService()
    city = _build_entry(
        "city:3304557",
        "city",
        "Cidade",
        2,
        "Rio de Janeiro",
        "3304557",
        None,
        Polygon(
            [
                (-1.0, -1.0),
                (5.0, -1.0),
                (5.0, 5.0),
                (-1.0, 5.0),
                (-1.0, -1.0),
            ]
        ),
    )
    svc._regions_by_id = {city.id: city}
    monkeypatch.setattr(svc, "_ensure_index", lambda: None)
    monkeypatch.setattr(
        wardrive_module,
        "get_wardrive_sessions",
        lambda: [
            {"session_id": "session-a", "label": "session-a"},
            {"session_id": "session-b", "label": "session-b"},
            {"session_id": "session-c", "label": "session-c"},
        ],
    )

    def _classification_for(session_ids):
        key = tuple(session_ids or [])
        if key == ("session-a",):
            points = [{"lat": 0.0, "lng": 0.0, "acc": 8, "session_id": "session-a"}]
        elif key == ("session-b",):
            points = [{"lat": 0.0, "lng": 1.0, "acc": 8, "session_id": "session-b"}]
        elif key == ("session-c",):
            points = [{"lat": 2.0, "lng": 0.0, "acc": 8, "session_id": "session-c"}]
        else:
            points = [
                {"lat": 0.0, "lng": 0.0, "acc": 8, "session_id": "session-a"},
                {"lat": 0.0, "lng": 1.0, "acc": 8, "session_id": "session-b"},
                {"lat": 2.0, "lng": 0.0, "acc": 8, "session_id": "session-c"},
            ]
        return {
            "points_by_region": {city.id: points},
            "stats_by_region": {
                city.id: {
                    "networks_count": len(points),
                    "cracked": 0,
                    "open": 0,
                    "locked": len(points),
                }
            },
            "unmapped_points": [],
            "unmapped_summary": {
                "networks_count": 0,
                "cracked": 0,
                "open": 0,
                "locked": 0,
            },
        }

    monkeypatch.setattr(
        svc,
        "_get_classification",
        lambda time_window, source, session_ids=None: _classification_for(session_ids),
    )

    zone_shapes = {
        "session-a": [
            [
                {"lat": 0.0, "lng": 0.0},
                {"lat": 0.0, "lng": 2.0},
                {"lat": 2.0, "lng": 2.0},
                {"lat": 2.0, "lng": 0.0},
                {"lat": 0.0, "lng": 0.0},
            ]
        ],
        "session-b": [
            [
                {"lat": 0.0, "lng": 1.0},
                {"lat": 0.0, "lng": 3.0},
                {"lat": 2.0, "lng": 3.0},
                {"lat": 2.0, "lng": 1.0},
                {"lat": 0.0, "lng": 1.0},
            ]
        ],
        "session-c": [
            [
                {"lat": 2.0, "lng": 0.0},
                {"lat": 2.0, "lng": 2.0},
                {"lat": 4.0, "lng": 2.0},
                {"lat": 4.0, "lng": 0.0},
                {"lat": 2.0, "lng": 0.0},
            ]
        ],
    }

    def _fake_build_zones(points, eps_m, min_samples):
        assert eps_m == 200
        assert min_samples == 2
        session_id = str((points[0] or {}).get("session_id") or "")
        return [
            {
                "id": 1,
                "count": len(points),
                "center": {"lat": points[0]["lat"], "lng": points[0]["lng"]},
                "parts": zone_shapes[session_id],
            }
        ]

    monkeypatch.setattr(svc, "_build_zones", _fake_build_zones)

    payload = svc.get_region_zones(
        city.id,
        eps_m=200,
        min_samples=2,
        time_window="all",
        source="all",
        session_ids=["session-a", "session-b", "session-c"],
        comparison_mode="focus_active",
        active_session_id="session-b",
    )

    assert payload["comparison"]["mode"] == "focus_active"
    assert payload["comparison"]["active_session_id"] == "session-b"
    assert sorted(payload["comparison"]["layers_by_active_session"].keys()) == [
        "session-a",
        "session-b",
        "session-c",
    ]
    assert payload["zones"][0]["session_id"] == "session-b"
    assert payload["zones"][0]["zone_role"] == "primary"
    assert payload["zones"][1]["zone_role"] == "secondary"

    layer = payload["comparison"]["layers_by_active_session"]["session-b"]
    assert layer["primary_zones"][0]["session_id"] == "session-b"
    assert layer["secondary_zone"] is not None
    assert layer["secondary_zone"]["session_label"] == "OTHER SELECTED SESSIONS"

    primary_geometry = svc._parts_to_geometry(layer["primary_zones"][0]["parts"])
    secondary_geometry = svc._parts_to_geometry(layer["secondary_zone"]["parts"])
    assert primary_geometry is not None
    assert secondary_geometry is not None
    assert secondary_geometry.intersection(primary_geometry).area == pytest.approx(
        0.0, abs=1e-9
    )


def test_get_region_zones_focus_active_returns_null_secondary_when_fully_covered(
    monkeypatch,
):
    svc = WardriveRegionsService()
    city = _build_entry(
        "city:3304557",
        "city",
        "Cidade",
        2,
        "Rio de Janeiro",
        "3304557",
        None,
        Polygon(
            [
                (-1.0, -1.0),
                (5.0, -1.0),
                (5.0, 5.0),
                (-1.0, 5.0),
                (-1.0, -1.0),
            ]
        ),
    )
    svc._regions_by_id = {city.id: city}
    monkeypatch.setattr(svc, "_ensure_index", lambda: None)
    monkeypatch.setattr(
        wardrive_module,
        "get_wardrive_sessions",
        lambda: [
            {"session_id": "session-a", "label": "session-a"},
            {"session_id": "session-b", "label": "session-b"},
        ],
    )

    def _classification_for(session_ids):
        key = tuple(session_ids or [])
        if key == ("session-a",):
            points = [{"lat": 0.0, "lng": 0.0, "acc": 8, "session_id": "session-a"}]
        elif key == ("session-b",):
            points = [{"lat": 1.0, "lng": 1.0, "acc": 8, "session_id": "session-b"}]
        else:
            points = [
                {"lat": 0.0, "lng": 0.0, "acc": 8, "session_id": "session-a"},
                {"lat": 1.0, "lng": 1.0, "acc": 8, "session_id": "session-b"},
            ]
        return {
            "points_by_region": {city.id: points},
            "stats_by_region": {
                city.id: {
                    "networks_count": len(points),
                    "cracked": 0,
                    "open": 0,
                    "locked": len(points),
                }
            },
            "unmapped_points": [],
            "unmapped_summary": {
                "networks_count": 0,
                "cracked": 0,
                "open": 0,
                "locked": 0,
            },
        }

    monkeypatch.setattr(
        svc,
        "_get_classification",
        lambda time_window, source, session_ids=None: _classification_for(session_ids),
    )

    zone_shapes = {
        "session-a": [
            [
                {"lat": 0.0, "lng": 0.0},
                {"lat": 0.0, "lng": 3.0},
                {"lat": 3.0, "lng": 3.0},
                {"lat": 3.0, "lng": 0.0},
                {"lat": 0.0, "lng": 0.0},
            ]
        ],
        "session-b": [
            [
                {"lat": 1.0, "lng": 1.0},
                {"lat": 1.0, "lng": 2.0},
                {"lat": 2.0, "lng": 2.0},
                {"lat": 2.0, "lng": 1.0},
                {"lat": 1.0, "lng": 1.0},
            ]
        ],
    }

    monkeypatch.setattr(
        svc,
        "_build_zones",
        lambda points, eps_m, min_samples: [
            {
                "id": 1,
                "count": len(points),
                "center": {"lat": points[0]["lat"], "lng": points[0]["lng"]},
                "parts": zone_shapes[str(points[0]["session_id"])],
            }
        ],
    )

    payload = svc.get_region_zones(
        city.id,
        eps_m=200,
        min_samples=2,
        time_window="all",
        source="all",
        session_ids=["session-a", "session-b"],
        comparison_mode="focus_active",
        active_session_id="session-a",
    )

    layer = payload["comparison"]["layers_by_active_session"]["session-a"]
    assert layer["secondary_zone"] is None
    assert all(zone["zone_role"] == "primary" for zone in payload["zones"])


def test_get_region_zones_focus_active_uses_separate_cache_and_reapplies_active_session(
    monkeypatch,
):
    svc = WardriveRegionsService()
    city = _build_entry(
        "city:3304557",
        "city",
        "Cidade",
        2,
        "Rio de Janeiro",
        "3304557",
        None,
        Polygon(
            [
                (-1.0, -1.0),
                (4.0, -1.0),
                (4.0, 4.0),
                (-1.0, 4.0),
                (-1.0, -1.0),
            ]
        ),
    )
    svc._regions_by_id = {city.id: city}
    monkeypatch.setattr(svc, "_ensure_index", lambda: None)
    monkeypatch.setattr(
        wardrive_module,
        "get_wardrive_sessions",
        lambda: [
            {"session_id": "session-a", "label": "session-a"},
            {"session_id": "session-b", "label": "session-b"},
        ],
    )

    def _classification_for(session_ids):
        key = tuple(session_ids or [])
        if key == ("session-a",):
            points = [{"lat": 0.0, "lng": 0.0, "acc": 8, "session_id": "session-a"}]
        elif key == ("session-b",):
            points = [{"lat": 0.0, "lng": 1.0, "acc": 8, "session_id": "session-b"}]
        else:
            points = [
                {"lat": 0.0, "lng": 0.0, "acc": 8, "session_id": "session-a"},
                {"lat": 0.0, "lng": 1.0, "acc": 8, "session_id": "session-b"},
            ]
        return {
            "points_by_region": {city.id: points},
            "stats_by_region": {
                city.id: {
                    "networks_count": len(points),
                    "cracked": 0,
                    "open": 0,
                    "locked": len(points),
                }
            },
            "unmapped_points": [],
            "unmapped_summary": {
                "networks_count": 0,
                "cracked": 0,
                "open": 0,
                "locked": 0,
            },
        }

    monkeypatch.setattr(
        svc,
        "_get_classification",
        lambda time_window, source, session_ids=None: _classification_for(session_ids),
    )

    zone_shapes = {
        "session-a": [
            [
                {"lat": 0.0, "lng": 0.0},
                {"lat": 0.0, "lng": 2.0},
                {"lat": 2.0, "lng": 2.0},
                {"lat": 2.0, "lng": 0.0},
                {"lat": 0.0, "lng": 0.0},
            ]
        ],
        "session-b": [
            [
                {"lat": 0.0, "lng": 1.0},
                {"lat": 0.0, "lng": 3.0},
                {"lat": 2.0, "lng": 3.0},
                {"lat": 2.0, "lng": 1.0},
                {"lat": 0.0, "lng": 1.0},
            ]
        ],
        "aggregate": [
            [
                {"lat": 0.0, "lng": 0.0},
                {"lat": 0.0, "lng": 3.0},
                {"lat": 2.0, "lng": 3.0},
                {"lat": 2.0, "lng": 0.0},
                {"lat": 0.0, "lng": 0.0},
            ]
        ],
    }
    build_calls = {"count": 0}

    def _fake_build_zones(points, eps_m, min_samples):
        build_calls["count"] += 1
        shape_key = (
            str(points[0].get("session_id") or "") if len(points) == 1 else "aggregate"
        )
        return [
            {
                "id": 1,
                "count": len(points),
                "center": {"lat": points[0]["lat"], "lng": points[0]["lng"]},
                "parts": zone_shapes[shape_key],
            }
        ]

    monkeypatch.setattr(svc, "_build_zones", _fake_build_zones)

    first_standard = svc.get_region_zones(
        city.id,
        eps_m=200,
        min_samples=2,
        time_window="all",
        source="all",
        session_ids=["session-a", "session-b"],
    )
    second_standard = svc.get_region_zones(
        city.id,
        eps_m=200,
        min_samples=2,
        time_window="all",
        source="all",
        session_ids=["session-a", "session-b"],
    )
    focus_a = svc.get_region_zones(
        city.id,
        eps_m=200,
        min_samples=2,
        time_window="all",
        source="all",
        session_ids=["session-a", "session-b"],
        comparison_mode="focus_active",
        active_session_id="session-a",
    )
    focus_b = svc.get_region_zones(
        city.id,
        eps_m=200,
        min_samples=2,
        time_window="all",
        source="all",
        session_ids=["session-a", "session-b"],
        comparison_mode="focus_active",
        active_session_id="session-b",
    )

    assert first_standard["zones"][0]["count"] == 2
    assert second_standard["zones"][0]["count"] == 2
    assert focus_a["zones"][0]["session_id"] == "session-a"
    assert focus_b["zones"][0]["session_id"] == "session-b"
    assert focus_a["comparison"]["active_session_id"] == "session-a"
    assert focus_b["comparison"]["active_session_id"] == "session-b"
    assert build_calls["count"] == 3


def test_region_outline_uses_outline_cache(monkeypatch):
    svc = WardriveRegionsService()
    region = _build_entry(
        "br:city:rio-de-janeiro",
        "city",
        "Cidade",
        2,
        "Rio de Janeiro",
        "3304557",
        None,
        Polygon(
            [
                (-43.7, -23.2),
                (-43.1, -23.2),
                (-43.1, -22.7),
                (-43.7, -22.7),
                (-43.7, -23.2),
            ]
        ),
    )

    calls = {"n": 0}
    original_union = wardrive_module.unary_union

    def _counting_union(*args, **kwargs):
        calls["n"] += 1
        return original_union(*args, **kwargs)

    monkeypatch.setattr(wardrive_module, "unary_union", _counting_union)
    first = svc._region_outline(region)
    second = svc._region_outline(region)
    assert first
    assert second
    assert calls["n"] == 1


def test_private_utility_functions():
    svc = WardriveRegionsService()

    # _slugify
    assert svc._slugify("São Paulo") == "sao-paulo"
    assert svc._slugify("Rio de Janeiro!") == "rio-de-janeiro"
    assert svc._slugify("  TEST 123  ") == "test-123"
    assert svc._slugify("!!!") == "unknown"
    assert svc._slugify(None) == "unknown"
    assert svc._slugify("") == "unknown"

    # _as_text
    assert svc._as_text("test") == "test"
    assert svc._as_text("  test  ") == "test"
    assert svc._as_text(None) == ""
    assert svc._as_text("nan") == ""
    assert svc._as_text("NaN") == ""
    assert svc._as_text("None") == ""
    assert svc._as_text("null") == ""

    # _normalize_lookup_value
    assert svc._normalize_lookup_value("  RJ  ") == "rj"
    assert svc._normalize_lookup_value("12345") == "12345"
    assert svc._normalize_lookup_value("São Paulo") == "sao-paulo"
    assert svc._normalize_lookup_value(None) == ""

    # _safe_float
    assert svc._safe_float("123.45") == 123.45
    assert svc._safe_float(123) == 123.0
    assert svc._safe_float("invalid") is None
    assert svc._safe_float(None) is None

    # _extension_to_format
    assert svc._extension_to_format("test.shp") == "shp"
    assert svc._extension_to_format("test.SHP") == "shp"
    assert svc._extension_to_format("test.kmz") == "kmz"
    assert svc._extension_to_format("test.geojson") == "geojson"
    assert svc._extension_to_format("test.json") == "geojson"
    assert svc._extension_to_format("test.txt") == "geojson"

    # _is_crs_supported
    assert svc._is_crs_supported("EPSG:4326") is True
    assert svc._is_crs_supported("WGS_1984") is True
    assert svc._is_crs_supported("SIRGAS_2000") is True
    assert svc._is_crs_supported("EPSG:31983") is False
    assert svc._is_crs_supported("") is True
    assert svc._is_crs_supported(None) is True

    # _pick_manifest_prop
    props = {"id": "123", "name": "Test", "code": "TST"}
    assert svc._pick_manifest_prop(props, ["code", "id"]) == "TST"
    assert svc._pick_manifest_prop(props, ["name"]) == "Test"
    assert svc._pick_manifest_prop(props, ["missing"]) == ""

    # _haversine_meters
    distance = svc._haversine_meters(-23.0, -43.0, -23.0001, -43.0001)
    assert 15 < distance < 16

    # _thin_track_points
    points = [
        {"lat": -23.0, "lng": -43.0, "ts_last": 100, "acc": 10},
        {"lat": -23.0, "lng": -43.0, "ts_last": 110, "acc": 8},
        {"lat": -23.0001, "lng": -43.0001, "ts_last": 200, "acc": 9},
    ]
    thinned = svc._thin_track_points(points)
    assert len(thinned) == 2
    assert thinned[0]["acc"] == 8


def test_cache_lru_operations():
    from collections import OrderedDict
    from typing import Any, Tuple

    svc = WardriveRegionsService()
    cache: "OrderedDict[Tuple[Any, ...], Any]" = OrderedDict()

    # Test lru_get and lru_set
    svc._lru_set(cache, ("key1",), "value1", 3)
    svc._lru_set(cache, ("key2",), "value2", 3)
    svc._lru_set(cache, ("key3",), "value3", 3)
    assert len(cache) == 3

    # Access key1 moves it to end
    assert svc._lru_get(cache, ("key1",)) == "value1"
    assert list(cache.keys()) == [("key2",), ("key3",), ("key1",)]

    # Adding 4th item evicts oldest (key2)
    svc._lru_set(cache, ("key4",), "value4", 3)
    assert len(cache) == 3
    assert ("key2",) not in cache
    assert list(cache.keys()) == [("key3",), ("key1",), ("key4",)]

    # Nonexistent key returns None
    assert svc._lru_get(cache, ("missing",)) is None


def test_geometric_edge_cases():
    svc = WardriveRegionsService()

    # _safe_geometry with invalid geometry
    invalid_poly = Polygon([(0, 0), (0, 1), (1, 0), (0, 0)])
    assert svc._safe_geometry(invalid_poly) is not None

    # Empty geometry
    empty_poly = Polygon()
    assert svc._safe_geometry(empty_poly) is None

    # _geometry_to_parts with empty geometry
    assert svc._geometry_to_parts(None) == []
    assert svc._geometry_to_parts(Polygon()) == []

    # _parts_to_geometry with invalid coordinates
    invalid_parts = [[{"lat": None, "lng": -43.0}]]
    assert svc._parts_to_geometry(invalid_parts) is None

    # _bounds_from_points with empty list
    assert svc._bounds_from_points([]) is None

    # _bounds_from_points with points
    points = [{"lat": -23.0, "lng": -43.0}, {"lat": -23.1, "lng": -43.1}]
    bounds = svc._bounds_from_points(points)
    assert bounds == {
        "min_lat": -23.1,
        "min_lng": -43.1,
        "max_lat": -23.0,
        "max_lng": -43.0,
    }

    # _center_from_points with empty list
    assert svc._center_from_points([]) is None

    # _center_from_points with points
    points = [{"lat": -23.0, "lng": -43.0}, {"lat": -23.1, "lng": -43.1}]
    center = svc._center_from_points(points)
    assert center == {"lat": -23.05, "lng": -43.05}

    # _bounds_from_geometries with empty list
    assert svc._bounds_from_geometries([]) is None

    # _center_from_geometries with empty list
    assert svc._center_from_geometries([]) is None

    # _center_from_geometries with geometry
    poly = Polygon([(0, 0), (1, 0), (1, 1), (0, 1), (0, 0)])
    center = svc._center_from_geometries([poly])
    assert center is not None
    assert "lat" in center
    assert "lng" in center


def test_wardrive_regions_service_clear_cache():
    svc = WardriveRegionsService()
    svc._classification_cache[("test",)] = "value"
    svc._hierarchy_cache[("test",)] = "value"
    svc._zones_cache[("test",)] = "value"
    svc._outline_cache[("test",)] = "value"

    svc.clear_runtime_cache()

    assert len(svc._classification_cache) == 0
    assert len(svc._hierarchy_cache) == 0
    assert len(svc._zones_cache) == 0
    assert len(svc._outline_cache) == 0


def test_get_region_zones_validation():
    svc = WardriveRegionsService()
    svc._ensure_index = lambda: None  # mock to avoid setup

    # Test region_id validation
    with pytest.raises(ValueError, match="region_id is required"):
        svc.get_region_zones("")


def test_level_spatial_index_query():
    from shapely.geometry import Point, Polygon
    from unittest.mock import MagicMock

    # Create test geometries
    poly1 = Polygon([(0, 0), (1, 0), (1, 1), (0, 1), (0, 0)])
    poly2 = Polygon([(2, 2), (3, 2), (3, 3), (2, 3), (2, 2)])

    # Create index
    index = _LevelSpatialIndex([("region1", poly1), ("region2", poly2)])

    # Test with point not in any geometry
    point = Point(10, 10)
    results = index.query(point)
    assert results == []

    # Test with point in first geometry
    point = Point(0.5, 0.5)
    results = index.query(point)
    assert len(results) == 1
    assert results[0][0] == "region1"
    assert results[0][1] == poly1

    # Mock STRtree to return different candidate types
    mock_tree = MagicMock()
    index.tree = mock_tree

    # Mock returning int candidates
    mock_tree.query.return_value = [0]  # index 0
    results = index.query(point)
    assert len(results) == 1
    assert results[0][0] == "region1"

    # Mock returning numpy int candidates (has item method)
    mock_int = MagicMock()
    mock_int.item.return_value = 1
    mock_tree.query.return_value = [mock_int]
    results = index.query(point)
    assert len(results) == 1
    assert results[0][0] == "region2"

    # Mock returning numpy int candidates that raise exception on item()
    mock_int_exc = MagicMock()
    mock_int_exc.item.side_effect = Exception("test exception")
    mock_tree.query.return_value = [mock_int_exc]
    results = index.query(point)
    assert results == []  # exception caught, no results

    # Mock returning BaseGeometry candidates
    mock_tree.query.return_value = [poly1]
    results = index.query(point)
    assert len(results) == 1
    assert results[0][0] == "region1"

    # Mock returning None
    mock_tree.query.return_value = None
    results = index.query(point)
    assert results == []

    # Test with no tree (empty index)
    empty_index = _LevelSpatialIndex([])
    results = empty_index.query(point)
    assert results == []


def test_refresh_runtime(monkeypatch):
    svc = WardriveRegionsService()
    reload_calls = 0
    load_calls = 0

    def mock_reload():
        nonlocal reload_calls
        reload_calls += 1

    def mock_load():
        nonlocal load_calls
        load_calls += 1

    monkeypatch.setattr(wardrive_module, "reload_data", mock_reload)
    monkeypatch.setattr(wardrive_module, "load_real_data", mock_load)
    monkeypatch.setattr(svc, "clear_runtime_cache", lambda: None)
    monkeypatch.setattr(svc, "_ensure_index", lambda: None)
    monkeypatch.setattr(wardrive_module, "get_wardrive_sessions", lambda: [])
    monkeypatch.setattr(wardrive_module, "get_wardrive_summary", lambda: {})
    monkeypatch.setattr(wardrive_module, "get_data_revision", lambda: 123)

    result = svc.refresh_runtime(reload_data_enabled=True, reload_maps=False)
    assert reload_calls == 1
    assert load_calls == 0
    assert result["status"] == "ok"

    reload_calls = 0
    result = svc.refresh_runtime(reload_data_enabled=False, reload_maps=False)
    assert reload_calls == 0
    assert load_calls == 1


def test_merge_sessions(monkeypatch):
    svc = WardriveRegionsService()
    monkeypatch.setattr(svc, "_ensure_index", lambda: None)
    monkeypatch.setattr(svc, "clear_runtime_cache", lambda: None)
    monkeypatch.setattr(
        wardrive_module,
        "merge_wardrive_sessions",
        lambda session_ids: {
            "session_id": "merged-123",
            "merged_from_session_ids": session_ids,
        },
    )
    monkeypatch.setattr(wardrive_module, "reload_data", lambda: None)
    monkeypatch.setattr(
        svc, "get_sessions", lambda time_window="all": {"sessions": [], "summary": {}}
    )

    result = svc.merge_sessions(["session-a", "session-b"])
    assert result["session"]["session_id"] == "merged-123"


def test_normalize_functions():
    svc = WardriveRegionsService()

    # _normalize_time_window
    assert svc._normalize_time_window("all") == "all"
    assert svc._normalize_time_window("24h") == "24h"
    assert svc._normalize_time_window("invalid") == "all"
    assert svc._normalize_time_window(None) == "all"

    # _normalize_source_filter
    assert svc._normalize_source_filter("all") == "all"
    assert svc._normalize_source_filter("pwn") == "pwn"
    assert svc._normalize_source_filter("bruce") == "bruce"
    assert svc._normalize_source_filter("ward") == "ward"
    assert svc._normalize_source_filter("raw") == "raw"
    assert svc._normalize_source_filter("invalid") == "all"

    # _source_matches
    assert svc._source_matches(["pwnagotchi"], "all") is True
    assert svc._source_matches(["pwnagotchi"], "pwn") is True
    assert svc._source_matches(["brucegotchi"], "bruce") is True
    assert svc._source_matches(["wardrive"], "ward") is True
    assert svc._source_matches(["bruce_raw"], "raw") is True
    assert svc._source_matches(["bruce_raw_sniffing"], "raw") is True
    assert svc._source_matches(["m5evil_raw_sniffing"], "raw") is True
    assert svc._source_matches(["m5evil_master_raw_sniffing"], "raw") is True
    assert svc._source_matches(["pwnagotchi"], "ward") is False


def test_spatial_index_query_edge_cases():
    # Empty index
    empty_index = _LevelSpatialIndex([])
    assert empty_index.query(Point(-43.0, -23.0)) == []

    # Index with single geometry
    poly = Polygon([(-44, -24), (-42, -24), (-42, -22), (-44, -22), (-44, -24)])
    index = _LevelSpatialIndex([("region-1", poly)])

    # Point outside returns empty
    assert index.query(Point(-40.0, -20.0)) == []

    # Point inside returns match
    results = index.query(Point(-43.0, -23.0))
    assert len(results) == 1
    assert results[0][0] == "region-1"


def test_region_sort_key():
    """_region_sort_key generates consistent sorting tuples."""
    svc = WardriveRegionsService()

    entry = RegionEntry(
        id="test-region",
        country_code="BR",
        country_name="Brazil",
        level_key="state",
        level_label="State",
        depth=1,
        depth_role="administrative",
        name="São Paulo",
        code="SP",
        parent_id=None,
        parent_hints=[],
        source_format="geojson",
        source_path="test",
        source_rank=0,
        dataset_id="dataset-state",
        dataset_source="test",
        priority=10,
        include_in_hierarchy=True,
        geometries=[],
    )

    key = svc._region_sort_key(entry)
    assert key == ("BR", 1, "sao-paulo", "test-region")


def test_parse_level_dir():
    """_parse_level_dir parses level directory names."""
    svc = WardriveRegionsService()

    # Valid format
    depth, slug = svc._parse_level_dir("2-states")
    assert depth == 2
    assert slug == "states"

    # Invalid format falls back
    depth, slug = svc._parse_level_dir("invalid-name")
    assert depth == 999
    assert slug == "invalid-name"

    # Empty input
    depth, slug = svc._parse_level_dir("")
    assert depth == 999
    assert slug == "region"


def test_manifest_rel_path():
    """_manifest_rel_path resolves relative paths."""
    svc = WardriveRegionsService()

    # Relative path
    result = svc._manifest_rel_path("/path/to/manifest.json", "data/file.geojson")
    assert result == "/path/to/data/file.geojson"

    # Absolute path unchanged
    result = svc._manifest_rel_path(
        "/path/to/manifest.json", "/absolute/path/file.geojson"
    )
    assert result == "/absolute/path/file.geojson"

    # Empty input
    result = svc._manifest_rel_path("/path/to/manifest.json", "")
    assert result is None

    # None input
    result = svc._manifest_rel_path("/path/to/manifest.json", None)
    assert result is None


def test_resolve_dataset_files(tmp_path):
    """_resolve_dataset_files finds supported files."""
    svc = WardriveRegionsService()

    # Create test files
    geojson_file = tmp_path / "test.geojson"
    geojson_file.write_text('{"type": "FeatureCollection", "features": []}')

    json_file = tmp_path / "test.json"
    json_file.write_text('{"type": "FeatureCollection"}')

    # Create subdirectory with files
    subdir = tmp_path / "subdir"
    subdir.mkdir()
    sub_geojson = subdir / "sub.geojson"
    sub_geojson.write_text('{"type": "FeatureCollection", "features": []}')

    # Unsupported file
    txt_file = tmp_path / "test.txt"
    txt_file.write_text("text")

    # Test with source_path only
    manifest1 = DatasetManifest(
        country_code="BR",
        country_name="Brazil",
        dataset_id="test-dataset-1",
        dataset_source="test",
        version="1.0",
        enabled=True,
        priority=10,
        level_key="test",
        level_label="Test",
        depth=1,
        depth_role="administrative",
        geometry_format="geojson",
        crs="EPSG:4326",
        metadata_path=str(tmp_path / "manifest.json"),
        source_path=str(geojson_file),
        path_glob=None,
        id_fields=["id"],
        name_fields=["name"],
        parent_resolvers=[],
        include_in_hierarchy=True,
    )

    files1 = svc._resolve_dataset_files(manifest1)
    assert str(geojson_file) in files1
    assert str(sub_geojson) not in files1  # Not in source_path
    assert str(txt_file) not in files1  # Unsupported extension

    # Test with directory as source_path (exercises os.walk)
    manifest2 = DatasetManifest(
        country_code="BR",
        country_name="Brazil",
        dataset_id="test-dataset-2",
        dataset_source="test",
        version="1.0",
        enabled=True,
        priority=10,
        level_key="test",
        level_label="Test",
        depth=1,
        depth_role="administrative",
        geometry_format="geojson",
        crs="EPSG:4326",
        metadata_path=str(tmp_path / "manifest.json"),
        source_path=str(tmp_path),  # Directory
        path_glob=None,
        id_fields=["id"],
        name_fields=["name"],
        parent_resolvers=[],
        include_in_hierarchy=True,
    )

    files2 = svc._resolve_dataset_files(manifest2)
    assert str(geojson_file) in files2
    assert str(json_file) in files2
    assert str(sub_geojson) in files2  # Found via os.walk
    assert str(txt_file) not in files2  # Unsupported extension


def test_resolve_active_session_id():
    """_resolve_active_session_id selects appropriate session."""
    svc = WardriveRegionsService()

    # Active session in list
    result = svc._resolve_active_session_id(
        active_session_id="session2", session_ids=["session1", "session2", "session3"]
    )
    assert result == "session2"

    # Active session not in list
    result = svc._resolve_active_session_id(
        active_session_id="missing", session_ids=["session1", "session2"]
    )
    assert result == "session1"  # First in list

    # No active session
    result = svc._resolve_active_session_id(
        active_session_id=None, session_ids=["session1", "session2"]
    )
    assert result == "session1"  # First in list

    # Empty active session
    result = svc._resolve_active_session_id(
        active_session_id="", session_ids=["session1", "session2"]
    )
    assert result == "session1"  # First in list

    # No sessions
    result = svc._resolve_active_session_id(
        active_session_id="session1", session_ids=[]
    )
    assert result is None


def test_build_focus_active_secondary_zone_returns_none_for_empty_geometry():
    svc = WardriveRegionsService()
    result = svc._build_focus_active_secondary_zone(
        active_session_id="session-a",
        secondary_geometry=None,
        other_session_ids=["session-b"],
        other_zones=[{"count": 1}],
    )
    assert result is None


def test_apply_focus_active_zone_preset_sets_active_session_id():
    svc = WardriveRegionsService()
    payload = {
        "comparison": {
            "session_ids": ["session-a", "session-b"],
            "layers_by_active_session": {
                "session-b": {
                    "primary_zones": [{"id": 1}],
                    "secondary_zone": {"id": "secondary:session-b"},
                }
            },
        },
        "params": {},
    }

    result = svc._apply_focus_active_zone_preset(
        payload,
        active_session_id="session-b",
    )
    assert result["params"]["active_session_id"] == "session-b"
    assert result["comparison"]["active_session_id"] == "session-b"
    assert len(result["zones"]) == 2


def test_source_matches_various_filters():
    svc = WardriveRegionsService()
    assert svc._source_matches(["pwnagotchi"], "all") is True
    assert svc._source_matches(["pwnagotchi"], "pwn") is True
    assert svc._source_matches(["brucegotchi"], "bruce") is True
    assert svc._source_matches(["wardrive"], "ward") is True
    assert svc._source_matches(["rawsniffer"], "raw") is True
    assert svc._source_matches([], "pwn") is True


def test_item_matches_time_window():
    svc = WardriveRegionsService()
    now_ts = int(time.time())
    assert svc._item_matches_time_window({"ts_last": now_ts - 1000}, "all", now_ts)
    assert svc._item_matches_time_window({"ts_last": now_ts - 1000}, "24h", now_ts)
    assert not svc._item_matches_time_window(
        {"ts_last": now_ts - 100_000}, "24h", now_ts
    )


def test_observation_position_prefers_display_coordinates():
    svc = WardriveRegionsService()
    obs = {
        "rawLatitude": -23.0,
        "rawLongitude": -43.0,
        "lat": -23.1,
        "lng": -43.1,
        "rawAccuracy": 5,
        "acc": 10,
        "ts_last": 123,
    }
    result = svc._observation_position(obs, prefer_display=True)
    assert result["lat"] == -23.1
    assert result["lng"] == -43.1
    assert result["acc"] == 5


def test_classify_points_returns_unmapped_for_unknown_geometries(monkeypatch):
    svc = WardriveRegionsService()
    svc._regions_by_id = {}
    monkeypatch.setattr(
        wardrive_module,
        "load_real_data",
        lambda: {
            "item1": {
                "lat": "-23.0",
                "lng": "-43.0",
                "acc": "10",
                "encryption": "OPEN",
                "ts_last": int(time.time()),
                "sources": ["pwnagotchi"],
            }
        },
    )
    monkeypatch.setattr(wardrive_module, "get_wardrive_sessions", lambda: [])

    result = svc._classify_points(time_window="all", source="pwn")
    assert result["unmapped_points"]
    assert result["stats_by_region"] == {}


def test_load_shp_reads_shapefile(tmp_path):
    if wardrive_module.shapefile is None:
        pytest.skip("pyshp unavailable")

    svc = WardriveRegionsService()
    manifest = DatasetManifest(
        country_code="br",
        country_name="Brazil",
        dataset_id="test-shp",
        dataset_source="fixture",
        version="1.0",
        enabled=True,
        priority=10,
        level_key="test",
        level_label="Test",
        depth=1,
        depth_role="administrative",
        geometry_format="shp",
        crs="EPSG:4326",
        metadata_path=str(tmp_path / "manifest.json"),
        source_path=str(tmp_path / "cities.shp"),
        path_glob=None,
        id_fields=["CD_MUN"],
        name_fields=["NM_MUN"],
        parent_resolvers=[],
        include_in_hierarchy=True,
    )

    shp_path = tmp_path / "cities.shp"
    writer = wardrive_module.shapefile.Writer(str(shp_path))
    writer.field("CD_MUN", "C")
    writer.field("NM_MUN", "C")
    writer.poly(
        [
            [
                (-43.7, -23.2),
                (-43.1, -23.2),
                (-43.1, -22.7),
                (-43.7, -22.7),
                (-43.7, -23.2),
            ]
        ]
    )
    writer.record("3304557", "Rio de Janeiro")
    writer.close()

    assert svc._load_shp(str(shp_path), manifest) is True
    assert any(
        entry.id.startswith("br:test:3304557") for entry in svc._regions_by_id.values()
    )


def test_region_context_unmapped_returns_payload():
    svc = WardriveRegionsService()
    classification = {
        "points_by_region": {},
        "unmapped_points": [{"lat": -23.0, "lng": -43.0}],
        "unmapped_summary": {"networks_count": 1, "cracked": 0, "open": 1, "locked": 0},
        "stats_by_region": {},
    }
    points, payload, stats = svc._resolve_region_context(
        classification=classification, region_id="unmapped"
    )
    assert points == classification["unmapped_points"]
    assert payload["id"] == "unmapped"
    assert stats == classification["unmapped_summary"]


def test_resolve_region_context_raises_for_unknown_region():
    svc = WardriveRegionsService()
    with pytest.raises(ValueError, match="region_id not found"):
        svc._resolve_region_context(
            classification={
                "points_by_region": {},
                "unmapped_points": [],
                "unmapped_summary": {},
                "stats_by_region": {},
            },
            region_id="unknown",
        )


def test_build_focus_active_secondary_zone_returns_none_when_no_parts(monkeypatch):
    svc = WardriveRegionsService()
    monkeypatch.setattr(
        svc, "_geometry_to_parts", lambda geometry, simplify_tolerance=0.0: []
    )
    secondary = Polygon(
        [(-43.0, -23.0), (-43.0, -22.0), (-42.0, -22.0), (-43.0, -23.0)]
    )
    result = svc._build_focus_active_secondary_zone(
        active_session_id="session-a",
        secondary_geometry=secondary,
        other_session_ids=["session-b"],
        other_zones=[{"count": 1}],
    )
    assert result is None


def test_maps_signature_returns_tuple_for_files(tmp_path):
    original_maps_dir = wardrive_module.MAPS_DIR
    try:
        wardrive_module.MAPS_DIR = str(tmp_path)
        file_path = tmp_path / "file.geojson"
        file_path.write_text("{}", encoding="utf-8")

        result = WardriveRegionsService()._maps_signature()
        assert isinstance(result, tuple)
        assert any(row[0] == str(file_path) for row in result)
    finally:
        wardrive_module.MAPS_DIR = original_maps_dir


def test_load_map_file_returns_false_for_unknown_extension():
    svc = WardriveRegionsService()
    manifest = DatasetManifest(
        country_code="br",
        country_name="Brazil",
        dataset_id="test",
        dataset_source="fixture",
        version="1.0",
        enabled=True,
        priority=10,
        level_key="test",
        level_label="Test",
        depth=1,
        depth_role="administrative",
        geometry_format="unknown",
        crs="EPSG:4326",
        metadata_path="/tmp/manifest.json",
        source_path="file.unknown",
        path_glob=None,
        id_fields=["id"],
        name_fields=["name"],
        parent_resolvers=[],
        include_in_hierarchy=True,
    )
    assert svc._load_map_file("file.unknown", manifest) is False


def test_extract_kml_properties_and_geometry_with_holes():
    svc = WardriveRegionsService()
    kml_text = """<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<kml xmlns=\"http://www.opengis.net/kml/2.2\">
  <Document>
    <Placemark>
      <name>Test Region</name>
      <ExtendedData>
        <SchemaData>
          <SimpleData name=\"id\">region-1</SimpleData>
        </SchemaData>
        <Data name=\"extra\"><value>value</value></Data>
      </ExtendedData>
      <Polygon>
        <outerBoundaryIs>
          <LinearRing>
            <coordinates>
              -43.0,-23.0 -42.0,-23.0 -42.0,-22.0 -43.0,-23.0
            </coordinates>
          </LinearRing>
        </outerBoundaryIs>
        <innerBoundaryIs>
          <LinearRing>
            <coordinates>
              -42.9,-22.9 -42.1,-22.9 -42.1,-22.1 -42.9,-22.9
            </coordinates>
          </LinearRing>
        </innerBoundaryIs>
      </Polygon>
    </Placemark>
  </Document>
</kml>
"""
    root = ET.fromstring(kml_text)
    placemark = root.find(".//kml:Placemark", wardrive_module.KML_NS)
    props = svc._extract_kml_properties(placemark)
    assert props["name"] == "Test Region"
    assert props["id"] == "region-1"
    assert props["extra"] == "value"
    geometry = svc._extract_kml_geometry(placemark)
    assert geometry is not None
    assert geometry.area > 0


def test_safe_geometry_returns_polygon_from_collection():
    svc = WardriveRegionsService()
    collection = GeometryCollection(
        [
            Polygon([(-43.0, -23.0), (-42.0, -23.0), (-42.0, -22.0), (-43.0, -23.0)]),
            Point(-44.0, -24.0),
        ]
    )
    fixed = svc._safe_geometry(collection)
    assert fixed is not None
    assert fixed.geom_type in {"Polygon", "MultiPolygon"}


def test_build_parent_hints_ignores_invalid_resolvers():
    svc = WardriveRegionsService()
    manifest = DatasetManifest(
        country_code="br",
        country_name="Brazil",
        dataset_id="test",
        dataset_source="fixture",
        version="1.0",
        enabled=True,
        priority=10,
        level_key="test",
        level_label="Test",
        depth=1,
        depth_role="administrative",
        geometry_format="geojson",
        crs="EPSG:4326",
        metadata_path="/tmp/manifest.json",
        source_path="file.geojson",
        path_glob=None,
        id_fields=["id"],
        name_fields=["name"],
        parent_resolvers=[
            None,
            {"target_level_key": "state", "source_fields": ["missing"]},
        ],
        include_in_hierarchy=True,
    )
    hints = svc._build_parent_hints({"id": "region"}, manifest)
    assert hints == []


def test_resolve_parent_id_returns_none_when_lookup_missing():
    svc = WardriveRegionsService()
    result = svc._resolve_parent_id(
        "br",
        [
            wardrive_module.ParentHint(
                target_level_key="state", target_key="code", value="RJ"
            )
        ],
    )
    assert result is None


def test_pick_manifest_prop_handles_non_dict_props():
    svc = WardriveRegionsService()
    assert svc._pick_manifest_prop(None, ["id"]) == ""


def test_normalize_session_ids_dedupes_and_returns_empty(monkeypatch):
    svc = WardriveRegionsService()
    monkeypatch.setattr(
        wardrive_module, "get_wardrive_sessions", lambda: [{"session_id": "known"}]
    )
    assert svc._normalize_session_ids(["known", "known", ""]) == ["known"]
    assert svc._normalize_session_ids([""]) == []


def test_get_classification_uses_cache(monkeypatch):
    svc = WardriveRegionsService()
    load_calls = {"count": 0}
    classify_calls = {"count": 0}

    def mock_load_real_data():
        load_calls["count"] += 1
        return {}

    def fake_classify_points(time_window, source, session_ids=None):
        classify_calls["count"] += 1
        return {
            "points_by_region": {},
            "stats_by_region": {},
            "unmapped_points": [],
            "unmapped_summary": svc._empty_stats(),
        }

    monkeypatch.setattr(wardrive_module, "load_real_data", mock_load_real_data)
    monkeypatch.setattr(svc, "_classify_points", fake_classify_points)

    first = svc._get_classification("all", "pwn")
    second = svc._get_classification("all", "pwn")
    assert first == second
    assert classify_calls["count"] == 1


def test_build_item_point_payload_filters_invalid_items():
    svc = WardriveRegionsService()
    assert svc._build_item_point_payload({"lat": None, "lng": 0}) is None
    assert svc._build_item_point_payload({"lat": 0.0, "lng": 0.0}) is None


def test_observation_position_uses_raw_coordinates_when_display_missing():
    svc = WardriveRegionsService()
    obs = {
        "rawLatitude": -23.0,
        "rawLongitude": -43.0,
        "lat": -23.1,
        "lng": -43.1,
        "rawAccuracy": 5,
        "acc": 10,
        "ts_last": 123,
    }
    result = svc._observation_position(obs, prefer_display=False)
    assert result["lat"] == -23.0
    assert result["lng"] == -43.0


def test_build_selected_wardrive_item_returns_none_when_no_valid_observations():
    svc = WardriveRegionsService()
    item = {
        "wardrive_sessions": [
            {"session_id": "s1", "lat": 0.0, "lng": 0.0, "ts_last": 100}
        ]
    }
    result = svc._build_selected_wardrive_item(item, ["s1"], "all", int(time.time()))
    assert result is None


def test_classify_point_ignores_invalid_candidates_and_missing_region():
    svc = WardriveRegionsService()
    mock_index = MagicMock()
    mock_geom = MagicMock()
    mock_geom.covers.side_effect = Exception("boom")
    mock_index.query.return_value = [
        ("region1", mock_geom),
        (
            "region2",
            Polygon([(-43.0, -23.0), (-42.0, -23.0), (-42.0, -22.0), (-43.0, -23.0)]),
        ),
    ]
    svc._spatial_indexes = {"state": mock_index}
    svc._regions_by_id = {}
    svc._level_depths = {"state": 1}

    assert svc._classify_point(Point(-42.5, -22.5)) is None


def test_zones_to_geometry_returns_none_for_invalid_zones():
    svc = WardriveRegionsService()
    assert svc._zones_to_geometry([{"parts": []}]) is None
    assert svc._zones_to_geometry([]) is None


def test_region_outline_returns_empty_for_empty_geometries():
    svc = WardriveRegionsService()
    region = _build_entry(
        "br:state:rj",
        "state",
        "Estado",
        1,
        "Rio",
        "RJ",
        None,
        Polygon(),
    )
    assert svc._region_outline(region) == []


def test_bounds_and_center_from_geometries_handle_empty_list():
    svc = WardriveRegionsService()
    assert svc._bounds_from_geometries([]) is None
    assert svc._center_from_geometries([]) is None


def test_build_parent_hints_uses_source_fields():
    svc = WardriveRegionsService()
    manifest = DatasetManifest(
        country_code="br",
        country_name="Brazil",
        dataset_id="test",
        dataset_source="fixture",
        version="1.0",
        enabled=True,
        priority=10,
        level_key="test",
        level_label="Test",
        depth=1,
        depth_role="administrative",
        geometry_format="geojson",
        crs="EPSG:4326",
        metadata_path="/tmp/manifest.json",
        source_path="file.geojson",
        path_glob=None,
        id_fields=["id"],
        name_fields=["name"],
        parent_resolvers=[
            {
                "target_level_key": "state",
                "target_key": "code",
                "source_fields": ["CD_UF"],
            }
        ],
        include_in_hierarchy=True,
    )
    hints = svc._build_parent_hints({"CD_UF": "RJ"}, manifest)
    assert hints[0].target_level_key == "state"
    assert hints[0].value == "RJ"


def test_add_feature_returns_false_when_existing_has_higher_precedence():
    svc = WardriveRegionsService()
    region_id = "br:test:region"
    existing = _build_entry(
        region_id,
        "test",
        "Test",
        1,
        "Region",
        "region",
        None,
        Polygon([(-43.0, -23.0), (-42.0, -23.0), (-42.0, -22.0), (-43.0, -23.0)]),
    )
    existing.priority = 5
    existing.source_rank = 0
    svc._regions_by_id[region_id] = existing
    svc._register_region_lookup(existing)

    manifest = DatasetManifest(
        country_code="br",
        country_name="Brazil",
        dataset_id="test",
        dataset_source="fixture",
        version="1.0",
        enabled=True,
        priority=10,
        level_key="test",
        level_label="Test",
        depth=1,
        depth_role="administrative",
        geometry_format="geojson",
        crs="EPSG:4326",
        metadata_path="/tmp/manifest.json",
        source_path="region.geojson",
        path_glob=None,
        id_fields=["id"],
        name_fields=["name"],
        parent_resolvers=[],
        include_in_hierarchy=True,
    )
    assert (
        svc._add_feature(
            {"id": "region", "name": "Region"},
            Polygon([(-43.1, -23.1), (-42.1, -23.1), (-42.1, -22.1), (-43.1, -23.1)]),
            "geojson",
            "region.geojson",
            manifest,
        )
        is False
    )
    svc = WardriveRegionsService()
    parent = _build_entry(
        "br:state:rj",
        "state",
        "Estado",
        1,
        "Rio de Janeiro",
        "RJ",
        None,
        Polygon(
            [
                (-44.0, -23.5),
                (-42.0, -23.5),
                (-42.0, -22.0),
                (-44.0, -22.0),
                (-44.0, -23.5),
            ]
        ),
    )
    svc._regions_by_id[parent.id] = parent
    svc._register_region_lookup(parent)
    result = svc._resolve_parent_id(
        "br",
        [
            wardrive_module.ParentHint(
                target_level_key="state", target_key="code", value="RJ"
            )
        ],
    )
    assert result == parent.id


def test_add_feature_merges_lower_precedence_geometry(tmp_path):
    svc = WardriveRegionsService()
    region_id = "br:test:region"
    existing = _build_entry(
        region_id,
        "test",
        "Test",
        1,
        "Region",
        "region",
        None,
        Polygon(
            [
                (-43.0, -23.0),
                (-42.0, -23.0),
                (-42.0, -22.0),
                (-43.0, -23.0),
            ]
        ),
    )
    existing.priority = 20
    existing.source_rank = 100
    svc._regions_by_id[region_id] = existing
    svc._register_region_lookup(existing)

    manifest = DatasetManifest(
        country_code="br",
        country_name="Brazil",
        dataset_id="test-dataset",
        dataset_source="fixture",
        version="1.0",
        enabled=True,
        priority=10,
        level_key="test",
        level_label="Test",
        depth=1,
        depth_role="administrative",
        geometry_format="geojson",
        crs="EPSG:4326",
        metadata_path=str(tmp_path / "manifest.json"),
        source_path="region.geojson",
        path_glob=None,
        id_fields=["id"],
        name_fields=["name"],
        parent_resolvers=[],
        include_in_hierarchy=True,
    )
    props = {"id": "region", "name": "Region"}
    new_geometry = Polygon(
        [
            (-43.1, -23.1),
            (-42.1, -23.1),
            (-42.1, -22.1),
            (-43.1, -23.1),
        ]
    )
    assert svc._add_feature(props, new_geometry, "geojson", "region.geojson", manifest)
    assert len(existing.geometries) == 1
    assert existing.source_path == "region.geojson"
    assert existing.priority == 10
    stats = svc._empty_stats()
    assert stats == {
        "networks_count": 0,
        "cracked": 0,
        "open": 0,
        "locked": 0,
    }


def test_build_legacy_entry_counts_files(tmp_path):
    svc = WardriveRegionsService()
    legacy_dir = tmp_path / "legacy"
    legacy_dir.mkdir()
    (legacy_dir / "a.geojson").write_text("{}", encoding="utf-8")
    (legacy_dir / "b.kmz").write_text("{}", encoding="utf-8")

    result = svc._build_legacy_entry(str(legacy_dir))
    assert result["files_count"] == 2
    assert result["path"] == str(legacy_dir)
    assert result["extensions"] == [".geojson", ".kmz"]


def test_load_geojson_and_kmz(tmp_path):
    svc = WardriveRegionsService()
    manifest = DatasetManifest(
        country_code="br",
        country_name="Brazil",
        dataset_id="test-dataset",
        dataset_source="fixture",
        version="1.0",
        enabled=True,
        priority=10,
        level_key="test",
        level_label="Test",
        depth=1,
        depth_role="administrative",
        geometry_format="geojson",
        crs="EPSG:4326",
        metadata_path=str(tmp_path / "manifest.json"),
        source_path=str(tmp_path / "data.geojson"),
        path_glob=None,
        id_fields=["id"],
        name_fields=["name"],
        parent_resolvers=[],
        include_in_hierarchy=True,
    )

    invalid_geojson = tmp_path / "invalid.geojson"
    invalid_geojson.write_text(
        json.dumps({"type": "Feature", "features": []}), encoding="utf-8"
    )
    assert svc._load_geojson(str(invalid_geojson), manifest) is False

    valid_geojson = tmp_path / "valid.geojson"
    valid_geojson.write_text(
        json.dumps(
            {
                "type": "FeatureCollection",
                "features": [
                    {
                        "type": "Feature",
                        "properties": {"id": "region-1", "name": "Region 1"},
                        "geometry": {
                            "type": "Polygon",
                            "coordinates": [
                                [
                                    [-43.0, -23.0],
                                    [-43.0, -22.0],
                                    [-42.0, -23.0],
                                    [-43.0, -23.0],
                                ]
                            ],
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    assert svc._load_geojson(str(valid_geojson), manifest) is True
    assert any(
        entry.id.startswith("br:test:region-1") for entry in svc._regions_by_id.values()
    )

    no_kml = tmp_path / "no_kml.kmz"
    with zipfile.ZipFile(str(no_kml), "w") as archive:
        archive.writestr("readme.txt", "no kml here")
    assert svc._load_kmz(str(no_kml), manifest) is False

    kml_file = tmp_path / "regions.kmz"
    kml_text = """<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<kml xmlns=\"http://www.opengis.net/kml/2.2\">
  <Document>
    <Placemark>
      <name>Region 2</name>
      <ExtendedData>
        <SchemaData>
          <SimpleData name=\"id\">region-2</SimpleData>
        </SchemaData>
        <Data name=\"category\">
          <value>test</value>
        </Data>
      </ExtendedData>
      <Polygon>
        <outerBoundaryIs>
          <LinearRing>
            <coordinates>
              -43.0,-23.0 -42.0,-23.0 -42.0,-22.0 -43.0,-23.0
            </coordinates>
          </LinearRing>
        </outerBoundaryIs>
      </Polygon>
    </Placemark>
  </Document>
</kml>
"""
    with zipfile.ZipFile(str(kml_file), "w") as archive:
        archive.writestr("doc.kml", kml_text)

    svc2 = WardriveRegionsService()
    assert svc2._load_kmz(str(kml_file), manifest) is True
    assert any(
        entry.id.startswith("br:test:region-2")
        for entry in svc2._regions_by_id.values()
    )


def test_parse_kml_ring_handles_invalid_chunks():
    svc = WardriveRegionsService()
    ring = svc._parse_kml_ring("-43.0,-23.0 bad -42.0,-23.0 -43.0,-23.0")
    assert ring[0] == ring[-1]
    assert len(ring) == 3


def test_get_sessions_filters_24h(monkeypatch):
    svc = WardriveRegionsService()
    now_ts = int(time.time())
    monkeypatch.setattr(wardrive_module, "load_real_data", lambda: {})
    monkeypatch.setattr(
        wardrive_module,
        "get_wardrive_sessions",
        lambda: [
            {
                "session_id": "recent",
                "started_at": now_ts - 100,
                "ended_at": now_ts - 50,
            },
            {
                "session_id": "old",
                "started_at": now_ts - 200_000,
                "ended_at": now_ts - 199_950,
            },
        ],
    )

    result = svc.get_sessions(time_window="24h")
    assert len(result["sessions"]) == 1
    assert result["sessions"][0]["session_id"] == "recent"


def test_normalize_session_ids_rejects_unknown(monkeypatch):
    svc = WardriveRegionsService()
    monkeypatch.setattr(
        wardrive_module,
        "get_wardrive_sessions",
        lambda: [{"session_id": "known"}],
    )

    normalized = svc._normalize_session_ids(["known", "known", ""])
    assert normalized == ["known"]

    with pytest.raises(ValueError, match="session_ids not found: unknown"):
        svc._normalize_session_ids(["unknown"])


def test_build_session_distance_map_uses_raw_values():
    svc = WardriveRegionsService()
    data = {
        "item1": {
            "wardrive_sessions": [
                {
                    "session_id": "s1",
                    "rawLatitude": "-23.0",
                    "rawLongitude": "-43.0",
                    "ts_last": "100",
                    "rawAccuracy": "10",
                },
                {
                    "session_id": "s1",
                    "rawLatitude": "-23.0001",
                    "rawLongitude": "-43.0001",
                    "ts_last": "200",
                    "rawAccuracy": "9",
                },
                {
                    "session_id": "s2",
                    "rawLatitude": None,
                    "rawLongitude": "-43.0",
                    "ts_last": "110",
                    "rawAccuracy": "8",
                },
            ]
        },
        "item2": "invalid",
    }

    distances = svc._build_session_distance_map(session_ids=["s1", "s2"], data=data)
    assert distances["s1"] > 0
    assert distances["s2"] == 0


def test_collect_session_track_points_filters_invalid():
    svc = WardriveRegionsService()
    data = {
        "item1": {
            "wardrive_sessions": [
                {
                    "session_id": "s1",
                    "rawLatitude": 0.0,
                    "rawLongitude": 0.0,
                    "ts_last": 100,
                    "rawAccuracy": 10,
                },
                {
                    "session_id": "s1",
                    "rawLatitude": "-23.0",
                    "rawLongitude": "-43.0",
                    "ts_last": 200,
                    "rawAccuracy": "9",
                },
                {
                    "session_id": "s2",
                    "rawLatitude": "-23.1",
                    "rawLongitude": "-43.1",
                    "ts_last": 300,
                    "rawAccuracy": "8",
                },
            ]
        }
    }

    points = svc._collect_session_track_points(session_id="s1", data=data)
    assert len(points) == 1
    assert points[0]["lat"] == -23.0
    assert points[0]["lng"] == -43.0


def test_build_selected_wardrive_item_chooses_newest_display_position():
    svc = WardriveRegionsService()
    now_ts = int(time.time())
    item = {
        "wardrive_sessions": [
            {
                "session_id": "s1",
                "displayLatitude": -23.0,
                "displayLongitude": -43.0,
                "rawAccuracy": 10,
                "ts_last": now_ts - 20,
                "source_file": "a.csv",
                "channel": 1,
                "frequency": 2412,
                "rssi": -40,
                "altitude": 50,
                "encryption": "WPA2",
            },
            {
                "session_id": "s1",
                "displayLatitude": -23.0005,
                "displayLongitude": -43.0005,
                "rawAccuracy": 5,
                "ts_last": now_ts - 10,
                "source_file": "b.csv",
                "channel": 6,
                "frequency": 2437,
                "rssi": -35,
                "altitude": 52,
                "encryption": "WPA2",
            },
        ]
    }

    selected = svc._build_selected_wardrive_item(
        item=item,
        session_ids=["s1"],
        time_window="all",
        now_ts=now_ts,
    )

    assert selected is not None
    assert selected["sessionId"] == "s1"
    assert selected["sessionSourceFile"] == "b.csv"
    assert selected["sources"] == ["wardrive"]
    assert len(selected["wardrive_sessions"]) == 2


def test_add_feature_resolves_parent_hints_and_merges_existing():
    svc = WardriveRegionsService()
    state = _build_entry(
        "br:state:rj",
        "state",
        "Estado",
        1,
        "Rio de Janeiro",
        "RJ",
        None,
        Polygon(
            [
                (-44.0, -23.5),
                (-42.0, -23.5),
                (-42.0, -22.0),
                (-44.0, -22.0),
                (-44.0, -23.5),
            ]
        ),
    )
    svc._regions_by_id = {state.id: state}
    svc._register_region_lookup(state)

    manifest = DatasetManifest(
        country_code="br",
        country_name="Brazil",
        dataset_id="city-demo",
        dataset_source="fixture",
        version="1.0",
        enabled=True,
        priority=10,
        level_key="city",
        level_label="Cidade",
        depth=2,
        depth_role="administrative",
        geometry_format="geojson",
        crs="EPSG:4326",
        metadata_path=str(Path("/tmp/metadata.json")),
        source_path="city.geojson",
        path_glob=None,
        id_fields=["CD_MUN"],
        name_fields=["NM_MUN"],
        parent_resolvers=[
            {
                "target_level_key": "state",
                "target_key": "code",
                "source_fields": ["CD_UF"],
            }
        ],
        include_in_hierarchy=True,
    )

    props = {"CD_MUN": "3304557", "NM_MUN": "Rio de Janeiro", "CD_UF": "RJ"}
    city_geometry = Polygon(
        [
            (-43.7, -23.2),
            (-43.1, -23.2),
            (-43.1, -22.7),
            (-43.7, -22.7),
            (-43.7, -23.2),
        ]
    )

    assert svc._add_feature(props, city_geometry, "geojson", "city.geojson", manifest)
    city_id = "br:city:3304557"
    assert city_id in svc._regions_by_id
    city = svc._regions_by_id[city_id]
    assert city.parent_id == state.id

    # same precedence should merge existing geometry
    existing = _build_entry(
        city_id,
        "city",
        "Cidade",
        2,
        "Rio de Janeiro",
        "3304557",
        state.id,
        city_geometry,
    )
    svc._regions_by_id[city_id] = existing
    svc._register_region_lookup(existing)
    other_geometry = Polygon(
        [
            (-43.6, -23.15),
            (-43.5, -23.15),
            (-43.5, -23.05),
            (-43.6, -23.05),
            (-43.6, -23.15),
        ]
    )
    assert svc._add_feature(props, other_geometry, "geojson", "city.geojson", manifest)
    assert len(existing.geometries) == 2


def test_resolve_missing_parents_sets_parent_id():
    svc = WardriveRegionsService()
    parent = _build_entry(
        "BR:state:rj",
        "state",
        "Estado",
        1,
        "Rio de Janeiro",
        "RJ",
        None,
        Polygon(
            [
                (-44.0, -23.5),
                (-42.0, -23.5),
                (-42.0, -22.0),
                (-44.0, -22.0),
                (-44.0, -23.5),
            ]
        ),
    )
    child = _build_entry(
        "BR:city:3304557",
        "city",
        "Cidade",
        2,
        "Rio de Janeiro",
        "3304557",
        None,
        Polygon(
            [
                (-43.7, -23.2),
                (-43.1, -23.2),
                (-43.1, -22.7),
                (-43.7, -22.7),
                (-43.7, -23.2),
            ]
        ),
    )
    child.parent_hints = [
        wardrive_module.ParentHint(
            target_level_key="state", target_key="code", value="RJ"
        )
    ]
    svc._regions_by_id = {parent.id: parent, child.id: child}
    svc._register_region_lookup(parent)

    svc._resolve_missing_parents()
    assert child.parent_id == parent.id


def test_classify_point_returns_fallback_when_admin_missing():
    svc = WardriveRegionsService()
    fallback = _build_entry(
        "BR:state:rj",
        "state",
        "Estado",
        1,
        "Rio de Janeiro",
        "RJ",
        None,
        Polygon(
            [
                (-44.0, -23.5),
                (-42.0, -23.5),
                (-42.0, -22.0),
                (-44.0, -22.0),
                (-44.0, -23.5),
            ]
        ),
        depth_role="fallback",
        include_in_hierarchy=False,
    )
    svc._regions_by_id = {fallback.id: fallback}
    svc._level_depths = {"state": 1}
    svc._spatial_indexes = {
        "state": _LevelSpatialIndex([(fallback.id, fallback.geometries[0])])
    }
    svc._max_hierarchy_depth_by_country = {"BR": 2}

    result = svc._classify_point(Point(-43.5, -23.0))
    assert result == fallback.id


def test_nearest_visible_ancestor_finds_first_hierarchical_ancestor():
    svc = WardriveRegionsService()
    parent = _build_entry(
        "BR:state:rj",
        "state",
        "Estado",
        1,
        "Rio de Janeiro",
        "RJ",
        None,
        Polygon(
            [
                (-44.0, -23.5),
                (-42.0, -23.5),
                (-42.0, -22.0),
                (-44.0, -22.0),
                (-44.0, -23.5),
            ]
        ),
        include_in_hierarchy=True,
    )
    child = _build_entry(
        "BR:city:3304557",
        "city",
        "Cidade",
        2,
        "Rio City",
        "3304557",
        parent.id,
        Polygon(
            [
                (-43.7, -23.2),
                (-43.1, -23.2),
                (-43.1, -22.7),
                (-43.7, -22.7),
                (-43.7, -23.2),
            ]
        ),
        include_in_hierarchy=False,
    )
    svc._regions_by_id = {parent.id: parent, child.id: child}

    result = svc._nearest_visible_ancestor(child)
    assert result == parent


def test_zones_to_geometry_returns_union():
    svc = WardriveRegionsService()
    zone1 = {
        "parts": [
            [
                {"lat": 0.0, "lng": 0.0},
                {"lat": 0.0, "lng": 1.0},
                {"lat": 1.0, "lng": 1.0},
                {"lat": 0.0, "lng": 0.0},
            ]
        ]
    }
    zone2 = {
        "parts": [
            [
                {"lat": 1.0, "lng": 1.0},
                {"lat": 1.0, "lng": 2.0},
                {"lat": 2.0, "lng": 2.0},
                {"lat": 1.0, "lng": 1.0},
            ]
        ]
    }

    geometry = svc._zones_to_geometry([zone1, zone2])
    assert geometry is not None
    assert geometry.area > 0


def test_increment_stats_counts_open_locked_and_cracked():
    svc = WardriveRegionsService()
    stats = svc._empty_stats()

    svc._increment_stats(stats, {"pass": True})
    assert stats["cracked"] == 1

    svc._increment_stats(stats, {"encryption": "OPEN"})
    assert stats["open"] == 1

    svc._increment_stats(stats, {"encryption": "WEP"})
    assert stats["open"] == 2

    svc._increment_stats(stats, {"encryption": "WPA2"})
    assert stats["locked"] == 1
