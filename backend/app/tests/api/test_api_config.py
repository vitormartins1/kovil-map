import json

from app.api import deps
from app.core import config as config_module


class _FakeSync:
    def __init__(self):
        self.reloads = 0

    def reload_config(self):
        self.reloads += 1


def test_config_get_put(client, tmp_path, monkeypatch):
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(
        json.dumps(
            {
                "pwn_host": "10.0.0.5",
                "pwn_pass": "secret",
                "m5_web_password": "test",
            }
        )
    )

    monkeypatch.setattr(config_module, "CONFIG_FILE", str(cfg_path))

    fake = _FakeSync()
    monkeypatch.setattr(deps, "sync_service", fake)

    resp = client.get("/api/config")
    assert resp.status_code == 200
    assert resp.json()["data"]["pwn_host"] == "10.0.0.5"
    assert "pwn_pass" not in resp.json()["data"]
    assert resp.json()["data"]["pwn_pass_configured"] is True
    assert "m5_web_password" not in resp.json()["data"]
    assert resp.json()["data"]["m5_web_password_configured"] is True

    resp = client.put(
        "/api/config",
        json={
            "pwn_host": "10.0.0.9",
            "ui_hud_density": "compact",
            "ui_sidebar_preset": "narrow",
            "ui_font_scale": "90",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["data"]["pwn_host"] == "10.0.0.9"
    assert resp.json()["data"]["ui_hud_density"] == "compact"
    assert resp.json()["data"]["ui_sidebar_preset"] == "narrow"
    assert resp.json()["data"]["ui_font_scale"] == "90"
    assert "pwn_pass" not in resp.json()["data"]
    assert fake.reloads == 1


def test_config_put_rejects_unknown_key(client, tmp_path, monkeypatch):
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps({"pwn_host": "10.0.0.5"}))
    monkeypatch.setattr(config_module, "CONFIG_FILE", str(cfg_path))

    fake = _FakeSync()
    monkeypatch.setattr(deps, "sync_service", fake)

    resp = client.put("/api/config", json={"__unknown__": "value"})
    assert resp.status_code == 422
    assert fake.reloads == 0


def test_config_put_rejects_invalid_port(client, tmp_path, monkeypatch):
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps({"pwn_host": "10.0.0.5"}))
    monkeypatch.setattr(config_module, "CONFIG_FILE", str(cfg_path))

    fake = _FakeSync()
    monkeypatch.setattr(deps, "sync_service", fake)

    resp = client.put("/api/config", json={"pwn_port": 70000})
    assert resp.status_code == 422
    assert fake.reloads == 0
