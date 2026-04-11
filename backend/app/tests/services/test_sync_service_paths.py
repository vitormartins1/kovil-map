import os


from app.services.sync_service import SyncService


class _FakeKey:
    def __init__(self, name="ssh-rsa"):
        self._name = name

    def get_name(self):
        return self._name

    def asbytes(self):
        return b"fake-key-bytes"

    def get_base64(self):
        return "ZmFrZS1rZXkteWJ0ZXM="


def _with_config(monkeypatch, **config):
    default = {
        "pwn_host": "host",
        "pwn_port": 22,
        "pwn_user": "u",
        "pwn_pass": "p",
        "remote_path": "/remote",
    }
    default.update(config)
    monkeypatch.setattr("app.services.sync_service.load_config", lambda: default)
    return SyncService()


def test_known_hosts_path_override(monkeypatch, tmp_path):
    path = tmp_path / "hosts.txt"
    service = _with_config(monkeypatch, ssh_known_hosts_path=str(path))
    assert service._get_known_hosts_path() == str(path)


def test_ensure_known_hosts_file_creates_path(tmp_path):
    service = SyncService()
    target = tmp_path / "dir" / "hosts"
    service._ensure_known_hosts_file(str(target))
    assert os.path.exists(target)


def test_host_patterns_and_serialization():
    service = SyncService()
    patterns = service._host_patterns("example", 22)
    assert "[example]:22" in patterns
    serialized = service._serialize_host_key(_FakeKey(), "example", 22)
    assert serialized["host"] == "example"
    assert serialized["fingerprint_sha256"].startswith("SHA256:")


def test_trust_remote_host_key_missing_host(monkeypatch):
    service = _with_config(monkeypatch, pwn_host="")
    result = service.trust_remote_host_key()
    assert result["status"] == "error"
    assert "SSH host missing" in result["message"]


def test_perform_sync_missing_credentials(monkeypatch):
    service = _with_config(monkeypatch, pwn_host="", remote_path="/remote")
    result = service.perform_sync(force=False)
    assert result["status"] == "error"
    pwn_stage = result["details"]["pwnagotchi_remote_sync"]
    assert pwn_stage["status"] == "error"
    assert "SSH credentials missing" in str(pwn_stage.get("message") or "")


def test_perform_sync_missing_remote_path(monkeypatch):
    service = _with_config(monkeypatch, remote_path="")
    result = service.perform_sync(force=False)
    assert result["status"] == "error"
    pwn_stage = result["details"]["pwnagotchi_remote_sync"]
    assert pwn_stage["status"] == "error"
    assert "remote path missing" in str(pwn_stage.get("message") or "").lower()


def test_trust_remote_host_key_rejects_m5evil_target(monkeypatch, tmp_path):
    service = _with_config(
        monkeypatch,
        m5_sync_enabled=True,
        m5_host="10.1.1.1",
        m5_port=80,
        ssh_known_hosts_path=str(tmp_path / "known_hosts"),
    )
    result = service.trust_remote_host_key(target="m5evil")
    assert result["status"] == "error"
    assert result["code"] == "unsupported_target"


def test_build_m5evil_base_url_uses_web_config(monkeypatch):
    service = _with_config(
        monkeypatch,
        m5_sync_enabled=True,
        m5_host="192.168.4.1",
        m5_port=80,
        m5_web_protocol="http",
        m5_admin_base_path="/evil-menu",
        m5_web_user="evil",
        m5_web_password="test",
        m5_handshake_remote_path="evil/handshakes",
    )
    profile = service._get_target_profile("m5evil")
    assert service._build_m5evil_base_url(profile) == "http://192.168.4.1:80/evil-menu/"
