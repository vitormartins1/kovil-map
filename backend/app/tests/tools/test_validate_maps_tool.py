import json

from app.tools import validate_maps


def test_validate_maps_cli_outputs_inventory(monkeypatch, capsys):
    monkeypatch.setattr(
        validate_maps.wardrive_regions_service,
        "get_maps_inventory",
        lambda: {"loaded_datasets": 4, "legacy_ignored": [{"path": "/tmp/legacy"}]},
    )
    monkeypatch.setattr("sys.argv", ["validate_maps", "--pretty"])

    assert validate_maps.main() == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["loaded_datasets"] == 4
    assert payload["legacy_ignored"][0]["path"] == "/tmp/legacy"


def test_validate_maps_cli_outputs_compact_json(monkeypatch, capsys):
    monkeypatch.setattr(
        validate_maps.wardrive_regions_service,
        "get_maps_inventory",
        lambda: {"loaded_datasets": 1},
    )
    monkeypatch.setattr("sys.argv", ["validate_maps"])

    assert validate_maps.main() == 0
    output = capsys.readouterr().out.strip()
    assert output == '{"loaded_datasets": 1}'
