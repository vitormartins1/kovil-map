import pytest

from app.services import wardrive_regions_service as wrs


def _service():
    return wrs.WardriveRegionsService()


def test_normalize_time_and_source_filters():
    service = _service()
    assert service._normalize_time_window("24h") == "24h"
    assert service._normalize_time_window("invalid") == "all"
    assert service._normalize_source_filter("pwn") == "pwn"
    assert service._normalize_source_filter("unknown") == "all"


def test_session_ids_validation(monkeypatch):
    service = _service()
    monkeypatch.setattr(
        "app.services.wardrive_regions_service.get_wardrive_sessions",
        lambda: [{"session_id": "a"}, {"session_id": "b"}],
    )
    assert service._normalize_session_ids(["a", "b"]) == ["a", "b"]
    with pytest.raises(ValueError):
        service._normalize_session_ids(["missing"])


def test_runtime_cache_scope(monkeypatch):
    service = _service()
    monkeypatch.setattr(
        "app.services.wardrive_regions_service.get_data_revision", lambda: 5
    )
    scope = service._runtime_cache_scope("24h", "ward", ["a"])
    assert scope[2] == "24h"
    assert scope[4] == ("a",)


def test_slugify_lookup_value():
    service = _service()
    assert service._slugify("São Paulo") == "sao-paulo"
    assert service._normalize_lookup_value("000123") == "000123"
    assert service._normalize_lookup_value("City Name") == "city-name"


def test_pick_manifest_props():
    service = _service()
    props = {"name": "Rio", "label": "Rio Label"}
    assert service._pick_manifest_prop(props, ["label"]) == "Rio Label"
    assert service._pick_manifest_prop(None, ["label"]) == ""


def test_lru_cache_set_and_get():
    service = _service()
    from collections import OrderedDict

    od = OrderedDict()
    od[(1,)] = {"value": 1}
    assert service._lru_get(od, (1,)) == {"value": 1}
    assert service._lru_get(od, (2,)) is None
