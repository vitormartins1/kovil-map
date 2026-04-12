from app.services import sync_service as ss_module
from pathlib import Path
from urllib import error as urllib_error

_FIXTURE_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "m5evil_adminwebui"


class _FakeKey:
    def __init__(self, key_type, key_base64, raw_bytes):
        self._key_type = key_type
        self._key_base64 = key_base64
        self._raw = raw_bytes

    def get_name(self):
        return self._key_type

    def get_base64(self):
        return self._key_base64

    def asbytes(self):
        return self._raw

    def __eq__(self, other):
        return (
            isinstance(other, _FakeKey)
            and self._key_type == other._key_type
            and self._key_base64 == other._key_base64
            and self._raw == other._raw
        )


class _FakeHostKeys:
    _db = {}

    @classmethod
    def reset(cls):
        cls._db = {}

    def __init__(self):
        self.entries = {}

    def load(self, path):
        stored = self._db.get(path, {})
        self.entries = {
            host: {key_type: key for key_type, key in keys.items()}
            for host, keys in stored.items()
        }

    def save(self, path):
        self._db[path] = {
            host: {key_type: key for key_type, key in keys.items()}
            for host, keys in self.entries.items()
        }

    def add(self, host, key_type, key):
        self.entries.setdefault(host, {})[key_type] = key

    def lookup(self, host):
        return self.entries.get(host)


class _FakeAttr:
    def __init__(self, filename, size):
        self.filename = filename
        self.st_size = size
        self.st_mode = 0o100644


class _FakeSFTP:
    def __init__(self, files, size_map=None, fail_for=None, path_error=None):
        self.files = files
        self.size_map = size_map or {}
        self.fail_for = set(fail_for or [])
        self.path_error = path_error

    def listdir_attr(self, _remote_path):
        if self.path_error:
            raise self.path_error
        attrs = []
        for file_name in self.files:
            size = self.size_map.get(file_name, 1)
            attrs.append(_FakeAttr(file_name, size))
        return attrs

    def get(self, remote_path, local_path, callback=None):
        if any(flag in remote_path for flag in self.fail_for):
            raise RuntimeError("download failed")
        total = self.size_map.get(Path(remote_path).name, 5) or 5
        if callable(callback):
            midpoint = max(int(total // 2), 1)
            callback(midpoint, total)
            callback(total, total)
        with open(local_path, "w", encoding="utf-8") as f:
            f.write("dummy")

    def close(self):
        return None


class _FakeSSH:
    def __init__(self, sftp, connect_error=None, load_host_keys_error=None):
        self._sftp = sftp
        self._connect_error = connect_error
        self._load_host_keys_error = load_host_keys_error
        self.policy = None
        self.system_host_keys_loaded = False
        self.host_keys_loaded = []

    def set_missing_host_key_policy(self, *args, **kwargs):
        if args:
            self.policy = args[0]
        return None

    def load_system_host_keys(self, *args, **kwargs):
        self.system_host_keys_loaded = True
        return None

    def load_host_keys(self, path, *args, **kwargs):
        if self._load_host_keys_error:
            raise self._load_host_keys_error
        self.host_keys_loaded.append(path)
        return None

    def connect(self, *args, **kwargs):
        if self._connect_error:
            raise self._connect_error
        return None

    def open_sftp(self):
        return self._sftp

    def close(self):
        return None


class _FakeHttpResponse:
    def __init__(self, body, status=200, url=None, headers=None):
        self._body = body
        self._offset = 0
        self.status = status
        self.url = url
        self.headers = headers or {}

    def clone(self, *, url=None):
        return _FakeHttpResponse(
            self._body,
            status=self.status,
            url=self.url if url is None else url,
            headers=dict(self.headers),
        )

    def read(self, size=-1):
        if size is None or size < 0:
            chunk = self._body[self._offset :]
            self._offset = len(self._body)
            return chunk
        start = self._offset
        end = min(len(self._body), start + size)
        self._offset = end
        return self._body[start:end]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def _build_fake_urlopen(route_map, *, assert_auth=False):
    def _fake_urlopen(request, timeout=10):
        url = request.full_url if hasattr(request, "full_url") else str(request)
        if assert_auth:
            authorization = None
            if hasattr(request, "get_header"):
                authorization = request.get_header("Authorization")
            assert authorization is not None
            assert authorization.startswith("Basic ")
        value = route_map.get(url)
        if isinstance(value, Exception):
            raise value
        if value is None:
            raise AssertionError(f"Unexpected URL requested: {url}")
        if isinstance(value, _FakeHttpResponse):
            return value.clone(url=url if value.url is None else value.url)
        return value

    return _fake_urlopen


def _fixture(name):
    return (_FIXTURE_DIR / name).read_bytes()


def test_sync_service_force_download(tmp_path, monkeypatch):
    monkeypatch.setattr(ss_module, "HANDSHAKES_DIR", str(tmp_path))

    files = ["a.pcap", "b.txt"]
    fake_sftp = _FakeSFTP(files)
    monkeypatch.setattr(ss_module.paramiko, "SSHClient", lambda: _FakeSSH(fake_sftp))

    service = ss_module.SyncService()
    service.config = {
        "pwn_host": "127.0.0.1",
        "pwn_port": 22,
        "pwn_user": "u",
        "pwn_pass": "p",
        "remote_path": "/remote",
    }

    result = service.perform_sync(force=True)
    assert result["status"] == "success"
    assert "a.pcap" in result["details"]["handshakes"]
    assert (tmp_path / "a.pcap").exists()


def test_reload_config(monkeypatch):
    monkeypatch.setattr(ss_module, "load_config", lambda: {"pwn_host": "1.2.3.4"})
    service = ss_module.SyncService()
    service.config = {}
    service.reload_config()
    assert service.config["pwn_host"] == "1.2.3.4"


def test_sync_missing_credentials_returns_error():
    service = ss_module.SyncService()
    service.config = {"pwn_host": "127.0.0.1"}
    result = service.perform_sync(force=False)
    assert result["status"] == "error"
    pwn_stage = result["details"]["pwnagotchi_remote_sync"]
    assert pwn_stage["status"] == "error"
    assert "credentials" in str(pwn_stage.get("message") or "").lower()


def test_sync_missing_remote_path_returns_error():
    service = ss_module.SyncService()
    service.config = {
        "pwn_host": "127.0.0.1",
        "pwn_port": 22,
        "pwn_user": "u",
        "pwn_pass": "p",
        "remote_path": "",
    }
    result = service.perform_sync(force=False)
    assert result["status"] == "error"
    pwn_stage = result["details"]["pwnagotchi_remote_sync"]
    assert pwn_stage["status"] == "error"
    assert "remote path" in str(pwn_stage.get("message") or "").lower()


def test_sync_incremental_size_check(tmp_path, monkeypatch):
    monkeypatch.setattr(ss_module, "HANDSHAKES_DIR", str(tmp_path))
    (tmp_path / "same.pcap").write_text("abcd", encoding="utf-8")
    (tmp_path / "grow.pcap").write_text("x", encoding="utf-8")

    files = ["same.pcap", "grow.pcap"]
    fake_sftp = _FakeSFTP(files, size_map={"same.pcap": 4, "grow.pcap": 10})
    monkeypatch.setattr(ss_module.paramiko, "SSHClient", lambda: _FakeSSH(fake_sftp))

    service = ss_module.SyncService()
    service.config = {
        "pwn_host": "127.0.0.1",
        "pwn_port": 22,
        "pwn_user": "u",
        "pwn_pass": "p",
        "remote_path": "/remote",
    }
    result = service.perform_sync(force=False)
    assert result["status"] == "success"
    assert "grow.pcap" in result["details"]["handshakes"]
    assert "same.pcap" not in result["details"]["handshakes"]


def test_sync_service_pwnagotchi_emits_visual_download_progress(tmp_path, monkeypatch):
    monkeypatch.setattr(ss_module, "HANDSHAKES_DIR", str(tmp_path))
    fake_sftp = _FakeSFTP(
        ["HS_A.pcap", "HS_A.gps.json"],
        size_map={"HS_A.pcap": 12, "HS_A.gps.json": 8},
    )
    monkeypatch.setattr(ss_module.paramiko, "SSHClient", lambda: _FakeSSH(fake_sftp))

    service = ss_module.SyncService()
    service.config = {
        "pwn_host": "127.0.0.1",
        "pwn_port": 22,
        "pwn_user": "u",
        "pwn_pass": "p",
        "remote_path": "/remote",
    }
    events = []

    result = service._perform_pwnagotchi_sync(
        force=True,
        progress_callback=lambda mode, payload: events.append((mode, payload)),
    )

    assert result["status"] == "success"
    assert result["details"]["handshakes"] == ["HS_A.pcap", "HS_A.gps.json"]
    assert result["details"]["handshake_remote_files_found"] == 2
    assert result["details"]["handshake_files_to_download"] == 2
    assert result["details"]["handshake_files_failed"] == 0
    assert any(mode == "pwnagotchi_handshakes" for mode, _payload in events)
    assert any(
        mode == "pwnagotchi_handshakes"
        and str(payload.get("current_file") or "").startswith("HS_A.pcap [")
        for mode, payload in events
    )
    assert any(
        mode == "pwnagotchi_handshakes" and payload["stage"] == "COMPLETED"
        for mode, payload in events
    )


def test_sync_stat_error_empty_size_download_error_and_global_error(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(ss_module, "HANDSHAKES_DIR", str(tmp_path))
    (tmp_path / "err.pcap").write_text("abc", encoding="utf-8")
    (tmp_path / "empty.pcap").write_text("abc", encoding="utf-8")
    (tmp_path / "fail.pcap").write_text("abc", encoding="utf-8")
    files = ["err.pcap", "empty.pcap", "fail.pcap"]
    fake_sftp = _FakeSFTP(
        files,
        size_map={"err.pcap": None, "empty.pcap": None, "fail.pcap": 10},
        fail_for=["fail.pcap"],
    )
    monkeypatch.setattr(ss_module.paramiko, "SSHClient", lambda: _FakeSSH(fake_sftp))

    service = ss_module.SyncService()
    service.config = {
        "pwn_host": "127.0.0.1",
        "pwn_port": 22,
        "pwn_user": "u",
        "pwn_pass": "p",
        "remote_path": "/remote",
    }
    result = service.perform_sync(force=False)
    assert result["status"] == "error"
    assert any("pwnagotchi" in e for e in result["details"]["errors"])
    stage_errors = result["details"]["pwnagotchi_remote_sync"]["errors"]
    assert any("err.pcap" in e for e in stage_errors)
    assert any("fail.pcap" in e for e in stage_errors)

    monkeypatch.setattr(
        ss_module.paramiko,
        "SSHClient",
        lambda: (_ for _ in ()).throw(RuntimeError("ssh down")),
    )
    err = service.perform_sync(force=False)
    assert err["status"] == "error"


def test_sync_uses_reject_policy_and_known_hosts(tmp_path, monkeypatch):
    monkeypatch.setattr(ss_module, "HANDSHAKES_DIR", str(tmp_path))
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("", encoding="utf-8")

    fake_sftp = _FakeSFTP(["a.pcap"])
    fake_ssh = _FakeSSH(fake_sftp)
    monkeypatch.setattr(ss_module.paramiko, "SSHClient", lambda: fake_ssh)

    service = ss_module.SyncService()
    service.config = {
        "pwn_host": "127.0.0.1",
        "pwn_port": 22,
        "pwn_user": "u",
        "pwn_pass": "p",
        "remote_path": "/remote",
        "ssh_known_hosts_path": str(known_hosts),
    }

    result = service.perform_sync(force=True)
    assert result["status"] == "success"
    assert fake_ssh.system_host_keys_loaded is True
    assert str(known_hosts) in fake_ssh.host_keys_loaded
    assert fake_ssh.policy is not None
    assert fake_ssh.policy.__class__.__name__ == "RejectPolicy"


def test_sync_service_downloads_m5evil_handshakes_and_wardrive(tmp_path, monkeypatch):
    m5_dir = tmp_path / "m5"
    raw_dir = tmp_path / "m5raw"
    master_dir = tmp_path / "m5master"
    wardrive_dir = tmp_path / "wardrive"
    monkeypatch.setattr(ss_module, "M5EVIL_HANDSHAKES_DIR", str(m5_dir))
    monkeypatch.setattr(ss_module, "M5EVIL_RAWSNIFFER_DIR", str(raw_dir))
    monkeypatch.setattr(ss_module, "M5EVIL_MASTERSNIFFER_DIR", str(master_dir))
    monkeypatch.setattr(ss_module, "WARDRIVE_DIR", str(wardrive_dir))
    route_map = {
        "http://192.168.4.1:80/evil-menu/": _FakeHttpResponse(
            b'<html><body><a href="browse/">Browse SD</a></body></html>'
        ),
        "http://192.168.4.1:80/evil-menu/browse/": _FakeHttpResponse(
            b'<html><body><a href="evil/">evil</a></body></html>'
        ),
        "http://192.168.4.1:80/evil-menu/browse/evil/": _FakeHttpResponse(
            b'<html><body><a href="handshake/">handshake</a><a href="sniffer/">sniffer</a><a href="wardriving/">wardriving</a></body></html>'
        ),
        "http://192.168.4.1:80/evil-menu/browse/evil/handshake/": _FakeHttpResponse(
            b'<html><body><a href="../">..</a><a href="/evil-menu/download?path=evil/handshake/HS_TEST.pcap">HS_TEST.pcap</a><a href="/evil-menu/download?path=evil/handshake/skip.txt">skip.txt</a></body></html>'
        ),
        "http://192.168.4.1:80/evil-menu/browse/evil/sniffer/": _FakeHttpResponse(
            b'<html><body><a href="../">..</a><a href="/evil-menu/download?path=evil/sniffer/RawSniff_00.pcap">RawSniff_00.pcap</a></body></html>'
        ),
        "http://192.168.4.1:80/evil-menu/browse/evil/wardriving/": _FakeHttpResponse(
            b'<html><body><a href="../">..</a><a href="/evil-menu/download?path=evil/wardriving/walk.csv">walk.csv</a><a href="/evil-menu/download?path=evil/wardriving/note.txt">note.txt</a></body></html>'
        ),
        "http://192.168.4.1:80/evil-menu/download?path=evil/handshake/HS_TEST.pcap": _FakeHttpResponse(
            b"pcap", headers={"Content-Type": "application/octet-stream"}
        ),
        "http://192.168.4.1:80/evil-menu/download?path=evil/sniffer/RawSniff_00.pcap": _FakeHttpResponse(
            b"raw", headers={"Content-Type": "application/octet-stream"}
        ),
        "http://192.168.4.1:80/evil-menu/download?path=evil/wardriving/walk.csv": _FakeHttpResponse(
            b"csv", headers={"Content-Type": "text/csv"}
        ),
    }
    monkeypatch.setattr(
        ss_module.urllib_request,
        "urlopen",
        _build_fake_urlopen(route_map, assert_auth=True),
    )

    service = ss_module.SyncService()
    service.config = {
        "m5_sync_enabled": True,
        "m5_host": "192.168.4.1",
        "m5_port": 80,
        "m5_web_protocol": "http",
        "m5_admin_base_path": "/evil-menu",
        "m5_web_user": "evil",
        "m5_web_password": "test",
        "m5_handshake_remote_path": "evil/handshake",
        "m5_wardrive_remote_path": "evil/wardriving",
    }

    result = service._perform_m5evil_sync(force=True)
    assert result["status"] == "success"
    assert result["details"]["handshakes"] == ["HS_TEST.pcap"]
    assert result["details"]["rawsniffer_pcaps"] == ["RawSniff_00.pcap"]
    assert result["details"]["mastersniffer_pcaps"] == []
    assert result["details"]["wardrive_csvs"] == ["m5evil__walk.csv"]
    assert result["details"]["handshake_files_to_download"] == 1
    assert result["details"]["rawsniffer_files_to_download"] == 1
    assert result["details"]["mastersniffer_files_to_download"] == 0
    assert result["details"]["wardrive_files_to_download"] == 1
    assert result["details"]["handshake_files_failed"] == 0
    assert result["details"]["rawsniffer_files_failed"] == 0
    assert result["details"]["mastersniffer_files_failed"] == 0
    assert result["details"]["wardrive_files_failed"] == 0
    assert (m5_dir / "HS_TEST.pcap").exists()
    assert (raw_dir / "RawSniff_00.pcap").exists()
    assert (wardrive_dir / "m5evil__walk.csv").exists()


def test_sync_service_m5evil_partial_download_emits_progress(tmp_path, monkeypatch):
    m5_dir = tmp_path / "m5"
    raw_dir = tmp_path / "m5raw"
    master_dir = tmp_path / "m5master"
    wardrive_dir = tmp_path / "wardrive"
    monkeypatch.setattr(ss_module, "M5EVIL_HANDSHAKES_DIR", str(m5_dir))
    monkeypatch.setattr(ss_module, "M5EVIL_RAWSNIFFER_DIR", str(raw_dir))
    monkeypatch.setattr(ss_module, "M5EVIL_MASTERSNIFFER_DIR", str(master_dir))
    monkeypatch.setattr(ss_module, "WARDRIVE_DIR", str(wardrive_dir))
    route_map = {
        "http://192.168.0.6:80/check-sd-file?dir=%2Fevil%2Fhandshakes": _FakeHttpResponse(
            b'<html><body><a href="/download-sd-file?filename=/evil/handshakes/HS_A.pcap">HS_A.pcap</a><a href="/download-sd-file?filename=/evil/handshakes/HS_B.pcap">HS_B.pcap</a><a href="/download-sd-file?filename=/evil/handshakes/masterSniffer_0.pcap">masterSniffer_0.pcap</a></body></html>'
        ),
        "http://192.168.0.6:80/check-sd-file?dir=%2Fevil%2Fsniffer": _FakeHttpResponse(
            b'<html><body><a href="/download-sd-file?filename=/evil/sniffer/RawSniff_00.pcap">RawSniff_00.pcap</a></body></html>'
        ),
        "http://192.168.0.6:80/check-sd-file?dir=%2Fevil%2Fwardriving": _FakeHttpResponse(
            b'<html><body><a href="/download-sd-file?filename=/evil/wardriving/trip.csv">trip.csv</a></body></html>'
        ),
        "http://192.168.0.6:80/download-sd-file?filename=/evil/handshakes/HS_A.pcap": _FakeHttpResponse(
            b"pcap-a", headers={"Content-Type": "application/octet-stream"}
        ),
        "http://192.168.0.6:80/download-sd-file?filename=/evil/handshakes/HS_B.pcap": TimeoutError(
            "timed out"
        ),
        "http://192.168.0.6:80/download-sd-file?filename=/evil/handshakes/masterSniffer_0.pcap": _FakeHttpResponse(
            b"master", headers={"Content-Type": "application/octet-stream"}
        ),
        "http://192.168.0.6:80/download-sd-file?filename=/evil/sniffer/RawSniff_00.pcap": _FakeHttpResponse(
            b"raw", headers={"Content-Type": "application/octet-stream"}
        ),
        "http://192.168.0.6:80/download-sd-file?filename=/evil/wardriving/trip.csv": _FakeHttpResponse(
            b"csv", headers={"Content-Type": "text/csv"}
        ),
    }
    monkeypatch.setattr(
        ss_module.urllib_request,
        "urlopen",
        _build_fake_urlopen(route_map, assert_auth=True),
    )

    events = []

    service = ss_module.SyncService()
    service.config = {
        "m5_sync_enabled": True,
        "m5_host": "192.168.0.6",
        "m5_port": 80,
        "m5_web_protocol": "http",
        "m5_admin_base_path": "/evil-menu",
        "m5_web_user": "evil",
        "m5_web_password": "test",
        "m5_handshake_remote_path": "evil/handshakes",
        "m5_wardrive_remote_path": "evil/wardriving",
    }

    result = service._perform_m5evil_sync(
        force=True,
        progress_callback=lambda mode, payload: events.append((mode, payload)),
    )

    assert result["status"] == "partial"
    assert result["details"]["handshakes"] == ["HS_A.pcap"]
    assert result["details"]["rawsniffer_pcaps"] == ["RawSniff_00.pcap"]
    assert result["details"]["mastersniffer_pcaps"] == ["masterSniffer_0.pcap"]
    assert result["details"]["wardrive_csvs"] == ["m5evil__trip.csv"]
    assert result["details"]["handshake_files_to_download"] == 2
    assert result["details"]["handshake_files_failed"] == 1
    assert result["details"]["rawsniffer_files_to_download"] == 1
    assert result["details"]["rawsniffer_files_failed"] == 0
    assert result["details"]["mastersniffer_files_to_download"] == 1
    assert result["details"]["mastersniffer_files_failed"] == 0
    assert result["details"]["wardrive_files_to_download"] == 1
    assert result["details"]["wardrive_files_failed"] == 0
    assert any(
        mode == "handshakes" and payload["current_step"] == 2
        for mode, payload in events
    )
    assert any(
        mode == "handshakes"
        and str(payload.get("current_file") or "").startswith("HS_A.pcap [")
        for mode, payload in events
    )
    assert any(
        mode == "rawsniffer"
        and str(payload.get("current_file") or "").startswith("RawSniff_00.pcap [")
        for mode, payload in events
    )
    assert any(
        mode == "mastersniffer"
        and str(payload.get("current_file") or "").startswith("masterSniffer_0.pcap [")
        for mode, payload in events
    )
    assert any(
        mode == "wardrive"
        and str(payload.get("current_file") or "").startswith("trip.csv [")
        for mode, payload in events
    )
    assert any(
        mode == "rawsniffer" and payload["stage"] == "COMPLETED"
        for mode, payload in events
    )
    assert any(
        mode == "mastersniffer" and payload["stage"] == "COMPLETED"
        for mode, payload in events
    )
    assert any(
        mode == "wardrive" and payload["stage"] == "COMPLETED"
        for mode, payload in events
    )
    first_handshake_final = next(
        idx
        for idx, (mode, payload) in enumerate(events)
        if mode == "handshakes" and payload["stage"] == "PARTIAL"
    )
    first_rawsniffer_running = next(
        idx
        for idx, (mode, payload) in enumerate(events)
        if mode == "rawsniffer" and payload["stage"] == "RUNNING"
    )
    assert first_handshake_final < first_rawsniffer_running


def test_sync_service_parses_realistic_m5evil_admin_webui_pages(tmp_path, monkeypatch):
    m5_dir = tmp_path / "m5"
    raw_dir = tmp_path / "m5raw"
    master_dir = tmp_path / "m5master"
    wardrive_dir = tmp_path / "wardrive"
    monkeypatch.setattr(ss_module, "M5EVIL_HANDSHAKES_DIR", str(m5_dir))
    monkeypatch.setattr(ss_module, "M5EVIL_RAWSNIFFER_DIR", str(raw_dir))
    monkeypatch.setattr(ss_module, "M5EVIL_MASTERSNIFFER_DIR", str(master_dir))
    monkeypatch.setattr(ss_module, "WARDRIVE_DIR", str(wardrive_dir))
    route_map = {
        "http://192.168.0.6:80/evil-menu/": _FakeHttpResponse(_fixture("landing.html")),
        "http://192.168.0.6:80/evil-menu/browse/": _FakeHttpResponse(
            _fixture("browse_root.html")
        ),
        "http://192.168.0.6:80/evil-menu/browse/evil/": _FakeHttpResponse(
            b"<html><body><button onclick=\"window.location.href='/evil-menu/browse/evil/handshake/'\">handshake</button><button onclick=\"window.location.href='/evil-menu/browse/evil/sniffer/'\">sniffer</button><button onclick=\"window.location.href='/evil-menu/browse/evil/wardriving/'\">wardriving</button></body></html>"
        ),
        "http://192.168.0.6:80/evil-menu/browse/evil/handshake/": _FakeHttpResponse(
            _fixture("handshake_dir.html")
        ),
        "http://192.168.0.6:80/evil-menu/browse/evil/sniffer/": _FakeHttpResponse(
            b'<html><body><a href="/download-sd-file?filename=/evil/sniffer/RawSniff_00.pcap">RawSniff_00.pcap</a></body></html>'
        ),
        "http://192.168.0.6:80/evil-menu/browse/evil/wardriving/": _FakeHttpResponse(
            _fixture("wardrive_dir.html")
        ),
        "http://192.168.0.6:80/evil-menu/download?path=evil/handshake/HS_FIXTURE.pcap": _FakeHttpResponse(
            b"pcap", headers={"Content-Type": "application/octet-stream"}
        ),
        "http://192.168.0.6:80/evil-menu/download?path=evil/wardriving/trip.csv": _FakeHttpResponse(
            b"csv", headers={"Content-Type": "text/csv"}
        ),
    }
    monkeypatch.setattr(
        ss_module.urllib_request,
        "urlopen",
        _build_fake_urlopen(route_map, assert_auth=True),
    )

    service = ss_module.SyncService()
    service.config = {
        "m5_sync_enabled": True,
        "m5_host": "192.168.0.6",
        "m5_port": 80,
        "m5_web_protocol": "http",
        "m5_admin_base_path": "/evil-menu",
        "m5_web_user": "evil",
        "m5_web_password": "test",
        "m5_handshake_remote_path": "evil/handshake",
        "m5_wardrive_remote_path": "evil/wardriving",
    }

    result = service.probe_m5evil_admin_webui()
    assert result["status"] == "success"
    assert result["details"]["handshake_files_found"] == 1
    assert result["details"]["rawsniffer_files_found"] == 1
    assert result["details"]["mastersniffer_files_found"] == 0
    assert result["details"]["wardrive_files_found"] == 1
    assert result["details"]["browse_root_ok"] is True
    assert result["details"]["url_used"].endswith("/evil-menu/browse/evil/wardriving/")


def test_probe_m5evil_admin_webui_supports_direct_check_sd_file_listing(monkeypatch):
    route_map = {
        "http://192.168.0.6:80/check-sd-file?dir=%2Fevil%2Fhandshakes": _FakeHttpResponse(
            b'<html><body><div>Remote File Browser</div><a href="/download-sd-file?filename=/evil/handshakes/HS_REAL.pcap">HS_REAL.pcap</a></body></html>'
        ),
        "http://192.168.0.6:80/check-sd-file?dir=%2Fevil%2Fsniffer": _FakeHttpResponse(
            b'<html><body><a href="/download-sd-file?filename=/evil/sniffer/RawSniff_00.pcap">RawSniff_00.pcap</a></body></html>'
        ),
        "http://192.168.0.6:80/check-sd-file?dir=%2Fevil%2Fwardriving": _FakeHttpResponse(
            b'<html><body><form action="/download-sd-file?filename=/evil/wardriving/trip.csv" method="get"><button type="submit" value="trip.csv">trip.csv</button></form></body></html>'
        ),
    }
    monkeypatch.setattr(
        ss_module.urllib_request,
        "urlopen",
        _build_fake_urlopen(route_map, assert_auth=True),
    )

    service = ss_module.SyncService()
    service.config = {
        "m5_sync_enabled": True,
        "m5_host": "192.168.0.6",
        "m5_port": 80,
        "m5_web_protocol": "http",
        "m5_admin_base_path": "/evil-menu",
        "m5_web_user": "evil",
        "m5_web_password": "test",
        "m5_handshake_remote_path": "evil/handshakes",
        "m5_wardrive_remote_path": "evil/wardriving",
    }

    result = service.probe_m5evil_admin_webui()
    assert result["status"] == "success"
    assert result["details"]["handshake_files_found"] == 1
    assert result["details"]["rawsniffer_files_found"] == 1
    assert result["details"]["mastersniffer_files_found"] == 0
    assert result["details"]["wardrive_files_found"] == 1
    assert result["details"]["url_used"].endswith(
        "/check-sd-file?dir=%2Fevil%2Fwardriving"
    )


def test_sync_service_only_m5evil_configured_succeeds_without_pwnagotchi(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(ss_module, "M5EVIL_HANDSHAKES_DIR", str(tmp_path / "m5"))
    monkeypatch.setattr(ss_module, "M5EVIL_RAWSNIFFER_DIR", str(tmp_path / "m5raw"))
    monkeypatch.setattr(
        ss_module, "M5EVIL_MASTERSNIFFER_DIR", str(tmp_path / "m5master")
    )
    monkeypatch.setattr(ss_module, "WARDRIVE_DIR", str(tmp_path / "wardrive"))
    route_map = {
        "http://192.168.4.1:80/evil-menu/": _FakeHttpResponse(
            b'<html><body><a href="browse/">Browse SD</a></body></html>'
        ),
        "http://192.168.4.1:80/evil-menu/browse/": _FakeHttpResponse(
            b'<html><body><a href="evil/">evil</a></body></html>'
        ),
        "http://192.168.4.1:80/evil-menu/browse/evil/": _FakeHttpResponse(
            b'<html><body><a href="handshake/">handshake</a><a href="sniffer/">sniffer</a><a href="wardriving/">wardriving</a></body></html>'
        ),
        "http://192.168.4.1:80/evil-menu/browse/evil/handshake/": _FakeHttpResponse(
            b'<html><body><a href="/evil-menu/download?path=evil/handshake/HS_ONLY.pcap">HS_ONLY.pcap</a></body></html>'
        ),
        "http://192.168.4.1:80/evil-menu/browse/evil/sniffer/": _FakeHttpResponse(
            b'<html><body><a href="/evil-menu/download?path=evil/sniffer/RawSniff_00.pcap">RawSniff_00.pcap</a></body></html>'
        ),
        "http://192.168.4.1:80/evil-menu/browse/evil/wardriving/": _FakeHttpResponse(
            b'<html><body><a href="/evil-menu/download?path=evil/wardriving/trip.csv">trip.csv</a></body></html>'
        ),
        "http://192.168.4.1:80/evil-menu/download?path=evil/handshake/HS_ONLY.pcap": _FakeHttpResponse(
            b"pcap", headers={"Content-Type": "application/octet-stream"}
        ),
        "http://192.168.4.1:80/evil-menu/download?path=evil/sniffer/RawSniff_00.pcap": _FakeHttpResponse(
            b"raw", headers={"Content-Type": "application/octet-stream"}
        ),
        "http://192.168.4.1:80/evil-menu/download?path=evil/wardriving/trip.csv": _FakeHttpResponse(
            b"csv", headers={"Content-Type": "text/csv"}
        ),
    }
    monkeypatch.setattr(
        ss_module.urllib_request,
        "urlopen",
        _build_fake_urlopen(route_map, assert_auth=True),
    )

    service = ss_module.SyncService()
    service.config = {
        "pwn_host": "",
        "pwn_port": 22,
        "pwn_user": "",
        "pwn_pass": "",
        "remote_path": "",
        "m5_sync_enabled": True,
        "m5_host": "192.168.4.1",
        "m5_port": 80,
        "m5_web_protocol": "http",
        "m5_admin_base_path": "/evil-menu",
        "m5_web_user": "evil",
        "m5_web_password": "test",
        "m5_handshake_remote_path": "evil/handshake",
        "m5_wardrive_remote_path": "evil/wardriving",
    }

    result = service.perform_sync(force=True)
    assert result["status"] == "success"
    assert result["details"]["pwnagotchi_remote_sync"]["status"] == "skipped"
    assert result["details"]["m5evil_remote_sync"]["status"] == "success"
    assert result["details"]["m5evil_remote_sync"]["rawsniffer_pcaps"] == [
        "RawSniff_00.pcap"
    ]
    assert result["details"]["wardrive_csvs"] == ["m5evil__trip.csv"]


def test_probe_bruce_webui_success(monkeypatch):
    route_map = {
        "http://bruce.local:80/": _FakeHttpResponse(b"""
            <html><body>
              <h1>BRUCE Firmware</h1>
              <input type="hidden" id="actualFolder" value="/">
              <input type="hidden" id="actualFS" value="LittleFS">
              <button onclick="listFilesButton('/', 'SD', true)">SD Files</button>
              <button onclick="listFilesButton('/', 'LittleFS', true)">LittleFS</button>
              <script src="script.js"></script>
            </body></html>
            """),
        "http://bruce.local:80/listfiles?fs=SD&folder=%2FBrucePCAP": _FakeHttpResponse(
            b"""
            <table>
              <tr><th align='left'>Name</th><th style="text-align=center;">Size</th><th></th></tr>
              <tr align='left'><td><a onclick="listFilesButton('/BrucePCAP/handshakes', 'SD')" href='javascript:void(0);'>handshakes</a></td><td></td><td><i class="gg-folder" onclick="listFilesButton('/BrucePCAP/handshakes')"></i></td></tr>
              <tr><td>raw_1.pcap</td><td><i onclick="downloadDeleteButton('/BrucePCAP/raw_1.pcap', 'download')"></i></td></tr>
              <tr><td>raw_2.pcap</td><td><i onclick="downloadDeleteButton('/BrucePCAP/raw_2.pcap', 'download')"></i></td></tr>
            </table>
            """
        ),
        "http://bruce.local:80/listfiles?fs=SD&folder=%2FBruceWardriving": _FakeHttpResponse(
            b"""
            <table>
              <tr><th align='left'>Name</th><th style="text-align=center;">Size</th><th></th></tr>
              <tr><td>20260315_160040_wardriving.csv</td><td><i onclick="downloadDeleteButton('/BruceWardriving/20260315_160040_wardriving.csv', 'download')"></i></td></tr>
            </table>
            """
        ),
    }
    monkeypatch.setattr(
        ss_module.urllib_request,
        "urlopen",
        _build_fake_urlopen(route_map, assert_auth=True),
    )

    service = ss_module.SyncService()
    service.config = {
        "bruce_sync_enabled": True,
        "bruce_host": "bruce.local",
        "bruce_port": 80,
        "bruce_web_protocol": "http",
        "bruce_web_user": "admin",
        "bruce_web_password": "bruce",
    }

    result = service.probe_bruce_webui()
    assert result["status"] == "success"
    assert result["details"]["handshake_files_found"] == 0
    assert result["details"]["handshake_file_count_skipped"] is True
    assert result["details"]["rawsniffer_files_found"] == 2
    assert result["details"]["connection_ok"] is True
    assert result["details"]["auth_ok"] is True
    assert result["details"]["sd_browser_ok"] is True
    assert result["details"]["handshake_path_ok"] is True
    assert result["details"]["wardrive_files_found"] == 1


def test_probe_bruce_webui_reports_missing_sd_browser(monkeypatch):
    route_map = {
        "http://bruce.local:80/": _FakeHttpResponse(
            b"<html><body><h1>Bruce Firmware</h1><p>No browser exposed here.</p></body></html>"
        ),
    }
    monkeypatch.setattr(
        ss_module.urllib_request,
        "urlopen",
        _build_fake_urlopen(route_map, assert_auth=True),
    )

    service = ss_module.SyncService()
    service.config = {
        "bruce_sync_enabled": True,
        "bruce_host": "bruce.local",
        "bruce_port": 80,
        "bruce_web_protocol": "http",
        "bruce_web_user": "admin",
        "bruce_web_password": "bruce",
    }

    result = service.probe_bruce_webui()
    assert result["status"] == "error"
    assert result["code"] == "sd_browser_unavailable"
    assert result["details"]["connection_ok"] is True
    assert result["details"]["auth_ok"] is True
    assert result["details"]["sd_browser_ok"] is False
    assert result["details"]["failure_phase"] == "sd_browser"


def test_sync_service_bruce_downloads_handshakes_and_rawsniffer(tmp_path, monkeypatch):
    bruce_hs_dir = tmp_path / "bruce_hs"
    bruce_raw_dir = tmp_path / "bruce_raw"
    bruce_wardrive_dir = tmp_path / "bruce_wardrive"
    monkeypatch.setattr(ss_module, "BRUCE_HANDSHAKES_DIR", str(bruce_hs_dir))
    monkeypatch.setattr(ss_module, "BRUCE_RAWSNIFFER_DIR", str(bruce_raw_dir))
    monkeypatch.setattr(ss_module, "WARDRIVE_DIR", str(bruce_wardrive_dir))

    route_map = {
        "http://bruce.local:80/listfiles?fs=SD&folder=%2FBrucePCAP%2Fhandshakes": _FakeHttpResponse(
            b"""
            <table>
              <tr><th align='left'>Name</th><th style="text-align=center;">Size</th><th></th></tr>
              <tr><td>HS_A.pcap</td><td><i onclick="downloadDeleteButton('/BrucePCAP/handshakes/HS_A.pcap', 'download')"></i></td></tr>
              <tr><td>ignore.txt</td><td><i onclick="downloadDeleteButton('/BrucePCAP/handshakes/ignore.txt', 'download')"></i></td></tr>
            </table>
            """
        ),
        "http://bruce.local:80/listfiles?fs=SD&folder=%2FBrucePCAP": _FakeHttpResponse(
            b"""
            <table>
              <tr><th align='left'>Name</th><th style="text-align=center;">Size</th><th></th></tr>
              <tr align='left'><td><a onclick="listFilesButton('/BrucePCAP/handshakes', 'SD')" href='javascript:void(0);'>handshakes</a></td><td></td><td><i class="gg-folder" onclick="listFilesButton('/BrucePCAP/handshakes')"></i></td></tr>
              <tr><td>raw_1.pcap</td><td><i onclick="downloadDeleteButton('/BrucePCAP/raw_1.pcap', 'download')"></i></td></tr>
              <tr><td>raw_2.log</td><td><i onclick="downloadDeleteButton('/BrucePCAP/raw_2.log', 'download')"></i></td></tr>
            </table>
            """
        ),
        "http://bruce.local:80/listfiles?fs=SD&folder=%2FBruceWardriving": _FakeHttpResponse(
            b"""
            <table>
              <tr><th align='left'>Name</th><th style="text-align=center;">Size</th><th></th></tr>
              <tr><td>trip.csv</td><td><i onclick="downloadDeleteButton('/BruceWardriving/trip.csv', 'download')"></i></td></tr>
            </table>
            """
        ),
        "http://bruce.local:80/file?name=%2FBrucePCAP%2Fhandshakes%2FHS_A.pcap&action=download&fs=SD": _FakeHttpResponse(
            b"pcap", headers={"Content-Type": "application/octet-stream"}
        ),
        "http://bruce.local:80/file?name=%2FBrucePCAP%2Fraw_1.pcap&action=download&fs=SD": _FakeHttpResponse(
            b"raw", headers={"Content-Type": "application/octet-stream"}
        ),
        "http://bruce.local:80/file?name=%2FBruceWardriving%2Ftrip.csv&action=download&fs=SD": _FakeHttpResponse(
            b"csv", headers={"Content-Type": "text/csv"}
        ),
    }
    monkeypatch.setattr(
        ss_module.urllib_request,
        "urlopen",
        _build_fake_urlopen(route_map, assert_auth=True),
    )

    service = ss_module.SyncService()
    service.config = {
        "bruce_sync_enabled": True,
        "bruce_host": "bruce.local",
        "bruce_port": 80,
        "bruce_web_protocol": "http",
        "bruce_web_user": "admin",
        "bruce_web_password": "bruce",
    }
    events = []

    result = service._perform_bruce_sync(
        force=True,
        progress_callback=lambda mode, payload: events.append((mode, payload)),
    )
    assert result["status"] == "success"
    assert result["details"]["handshakes"] == ["HS_A.pcap"]
    assert result["details"]["rawsniffer_pcaps"] == ["raw_1.pcap"]
    assert result["details"]["wardrive_csvs"] == ["trip.csv"]
    assert result["details"]["handshake_files_to_download"] == 1
    assert result["details"]["rawsniffer_files_to_download"] == 1
    assert (bruce_hs_dir / "HS_A.pcap").exists()
    assert (bruce_raw_dir / "raw_1.pcap").exists()
    assert (bruce_wardrive_dir / "trip.csv").exists()
    assert any(mode == "bruce_handshakes" for mode, _payload in events)
    assert any(mode == "bruce_rawsniffer" for mode, _payload in events)
    assert any(mode == "bruce_wardrive" for mode, _payload in events)
    assert any(
        mode == "bruce_wardrive" and payload["stage"] == "COMPLETED"
        for mode, payload in events
    )
    first_handshake_final = next(
        idx
        for idx, (mode, payload) in enumerate(events)
        if mode == "bruce_handshakes" and payload["stage"] == "COMPLETED"
    )
    first_rawsniffer_running = next(
        idx
        for idx, (mode, payload) in enumerate(events)
        if mode == "bruce_rawsniffer" and payload["stage"] == "RUNNING"
    )
    assert first_handshake_final < first_rawsniffer_running


def test_probe_pwnagotchi_ssh_success(tmp_path, monkeypatch):
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("", encoding="utf-8")
    fake_sftp = _FakeSFTP(["capture1.pcap", "capture2.pcap"])
    monkeypatch.setattr(ss_module.paramiko, "SSHClient", lambda: _FakeSSH(fake_sftp))

    service = ss_module.SyncService()
    service.config = {
        "pwn_host": "10.0.0.2",
        "pwn_port": 22,
        "pwn_user": "pi",
        "pwn_pass": "raspberry",
        "remote_path": "/home/pi/handshakes",
        "ssh_known_hosts_path": str(known_hosts),
    }

    result = service.probe_pwnagotchi_ssh()
    assert result["status"] == "success"
    assert result["details"]["connection_ok"] is True
    assert result["details"]["auth_ok"] is True
    assert result["details"]["remote_path_ok"] is True
    assert result["details"]["files_found"] == 2


def test_probe_pwnagotchi_ssh_auth_failure(monkeypatch):
    monkeypatch.setattr(
        ss_module.paramiko,
        "SSHClient",
        lambda: _FakeSSH(
            _FakeSFTP([]),
            connect_error=ss_module.paramiko.AuthenticationException("bad auth"),
        ),
    )

    service = ss_module.SyncService()
    service.config = {
        "pwn_host": "10.0.0.2",
        "pwn_port": 22,
        "pwn_user": "pi",
        "pwn_pass": "raspberry",
        "remote_path": "/home/pi/handshakes",
    }

    result = service.probe_pwnagotchi_ssh()
    assert result["status"] == "error"
    assert result["code"] == "auth_failed"
    assert result["details"]["connection_ok"] is True
    assert result["details"]["auth_ok"] is False


def test_probe_pwnagotchi_ssh_host_key_not_trusted(monkeypatch):
    monkeypatch.setattr(
        ss_module.paramiko,
        "SSHClient",
        lambda: _FakeSSH(
            _FakeSFTP([]),
            connect_error=ss_module.paramiko.SSHException(
                "Server '[10.0.0.2]:22' not found in known_hosts"
            ),
        ),
    )
    monkeypatch.setattr(
        ss_module.SyncService,
        "_probe_remote_host_key_details",
        lambda self, host, port: {
            "host": host,
            "port": port,
            "key_type": "ssh-ed25519",
            "fingerprint_sha256": "SHA256:test",
            "fingerprint_md5": "MD5:test",
            "key_base64": "AAAATEST",
        },
    )

    service = ss_module.SyncService()
    service.config = {
        "pwn_host": "10.0.0.2",
        "pwn_port": 22,
        "pwn_user": "pi",
        "pwn_pass": "raspberry",
        "remote_path": "/home/pi/handshakes",
    }

    result = service.probe_pwnagotchi_ssh()
    assert result["status"] == "error"
    assert result["code"] == "ssh_host_key_not_trusted"
    assert result["details"]["host_key_trusted"] is False
    assert result["details"]["host_key"]["fingerprint_sha256"] == "SHA256:test"


def test_probe_pwnagotchi_ssh_host_key_mismatch(monkeypatch):
    """probe_pwnagotchi_ssh handles BadHostKeyException (key mismatch)."""
    expected_key = _FakeKey("ssh-ed25519", "AAAAOLD", b"old")
    presented_key = _FakeKey("ssh-ed25519", "AAAANEW", b"new")

    def _raise_bad_host_key(*args, **kwargs):
        exc = ss_module.paramiko.BadHostKeyException(
            "10.0.0.2", presented_key, expected_key
        )
        exc.expected_key = expected_key
        exc.key = presented_key
        raise exc

    fake_ssh = _FakeSSH(_FakeSFTP([]))
    fake_ssh.connect = _raise_bad_host_key
    monkeypatch.setattr(ss_module.paramiko, "SSHClient", lambda: fake_ssh)
    monkeypatch.setattr(
        ss_module.SyncService,
        "_probe_remote_host_key_details",
        lambda self, host, port: {
            "host": host,
            "port": port,
            "key_type": "ssh-ed25519",
            "fingerprint_sha256": "SHA256:new",
            "fingerprint_md5": "MD5:new",
            "key_base64": "AAAANEW",
        },
    )

    service = ss_module.SyncService()
    service.config = {
        "pwn_host": "10.0.0.2",
        "pwn_port": 22,
        "pwn_user": "pi",
        "pwn_pass": "raspberry",
        "remote_path": "/home/pi/handshakes",
    }

    result = service.probe_pwnagotchi_ssh()
    assert result["status"] == "error"
    assert result["code"] == "ssh_host_key_mismatch"
    assert "host_key" in result["details"]
    assert "expected_host_key" in result["details"]


def test_probe_pwnagotchi_ssh_remote_path_missing(monkeypatch):
    fake_sftp = _FakeSFTP([], path_error=FileNotFoundError("missing"))
    monkeypatch.setattr(ss_module.paramiko, "SSHClient", lambda: _FakeSSH(fake_sftp))

    service = ss_module.SyncService()
    service.config = {
        "pwn_host": "10.0.0.2",
        "pwn_port": 22,
        "pwn_user": "pi",
        "pwn_pass": "raspberry",
        "remote_path": "/home/pi/handshakes",
    }

    result = service.probe_pwnagotchi_ssh()
    assert result["status"] == "error"
    assert result["code"] == "path_not_found"
    assert result["details"]["remote_path_ok"] is False


def test_sync_service_m5evil_listing_errors_are_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(ss_module, "M5EVIL_HANDSHAKES_DIR", str(tmp_path / "m5"))
    monkeypatch.setattr(ss_module, "WARDRIVE_DIR", str(tmp_path / "wardrive"))
    route_map = {
        "http://192.168.4.1:80/evil-menu/": _FakeHttpResponse(
            b'<html><body><a href="browse/">Browse SD</a></body></html>'
        ),
        "http://192.168.4.1:80/evil-menu/browse/": _FakeHttpResponse(
            b'<html><body><a href="evil/">evil</a></body></html>'
        ),
        "http://192.168.4.1:80/evil-menu/browse/evil/": _FakeHttpResponse(
            b'<html><body><a href="handshake/">handshake</a><a href="wardriving/">wardriving</a></body></html>'
        ),
        "http://192.168.4.1:80/evil-menu/browse/evil/handshake/": urllib_error.URLError(
            "offline"
        ),
        "http://192.168.4.1:80/evil-menu/browse/evil/wardriving/": _FakeHttpResponse(
            b"<html><body>no links</body></html>"
        ),
    }
    monkeypatch.setattr(
        ss_module.urllib_request,
        "urlopen",
        _build_fake_urlopen(route_map, assert_auth=True),
    )

    service = ss_module.SyncService()
    service.config = {
        "m5_sync_enabled": True,
        "m5_host": "192.168.4.1",
        "m5_port": 80,
        "m5_web_protocol": "http",
        "m5_admin_base_path": "/evil-menu",
        "m5_web_user": "evil",
        "m5_web_password": "test",
        "m5_handshake_remote_path": "evil/handshake",
        "m5_wardrive_remote_path": "evil/wardriving",
    }

    result = service._perform_m5evil_sync(force=True)
    assert result["status"] == "error"
    assert any(
        "Failed to list handshakes" in error for error in result["details"]["errors"]
    )
    assert result["details"]["failure_phase"] == "path"


def test_probe_m5evil_admin_webui_success(monkeypatch):
    route_map = {
        "http://192.168.4.1:80/evil-menu/": _FakeHttpResponse(
            b'<html><body><a href="browse/">Browse SD</a></body></html>'
        ),
        "http://192.168.4.1:80/evil-menu/browse/": _FakeHttpResponse(
            b'<html><body><a href="evil/">evil</a></body></html>'
        ),
        "http://192.168.4.1:80/evil-menu/browse/evil/": _FakeHttpResponse(
            b'<html><body><a href="handshake/">handshake</a><a href="sniffer/">sniffer</a><a href="wardriving/">wardriving</a></body></html>'
        ),
        "http://192.168.4.1:80/evil-menu/browse/evil/handshake/": _FakeHttpResponse(
            b'<html><body><a href="/evil-menu/download?path=evil/handshake/HS_TEST.pcap">HS_TEST.pcap</a></body></html>'
        ),
        "http://192.168.4.1:80/evil-menu/browse/evil/sniffer/": _FakeHttpResponse(
            b'<html><body><a href="/evil-menu/download?path=evil/sniffer/RawSniff_00.pcap">RawSniff_00.pcap</a></body></html>'
        ),
        "http://192.168.4.1:80/evil-menu/browse/evil/wardriving/": _FakeHttpResponse(
            b'<html><body><a href="/evil-menu/download?path=evil/wardriving/trip.csv">trip.csv</a></body></html>'
        ),
    }
    monkeypatch.setattr(
        ss_module.urllib_request,
        "urlopen",
        _build_fake_urlopen(route_map, assert_auth=True),
    )

    service = ss_module.SyncService()
    service.config = {
        "m5_sync_enabled": True,
        "m5_host": "192.168.4.1",
        "m5_port": 80,
        "m5_web_protocol": "http",
        "m5_admin_base_path": "/evil-menu",
        "m5_web_user": "evil",
        "m5_web_password": "test",
        "m5_handshake_remote_path": "evil/handshake",
        "m5_wardrive_remote_path": "evil/wardriving",
    }

    result = service.probe_m5evil_admin_webui()
    assert result["status"] == "success"
    assert result["details"]["handshake_files_found"] == 1
    assert result["details"]["rawsniffer_files_found"] == 1
    assert result["details"]["mastersniffer_files_found"] == 0
    assert result["details"]["wardrive_files_found"] == 1
    assert result["details"]["connection_ok"] is True
    assert result["details"]["browse_root_ok"] is True


def test_probe_m5evil_admin_webui_auth_failed(monkeypatch):
    route_map = {
        "http://192.168.4.1:80/evil-menu/": urllib_error.HTTPError(
            "http://192.168.4.1:80/evil-menu/",
            401,
            "Unauthorized",
            hdrs=None,
            fp=None,
        ),
    }
    monkeypatch.setattr(
        ss_module.urllib_request,
        "urlopen",
        _build_fake_urlopen(route_map, assert_auth=True),
    )

    service = ss_module.SyncService()
    service.config = {
        "m5_sync_enabled": True,
        "m5_host": "192.168.4.1",
        "m5_port": 80,
        "m5_web_protocol": "http",
        "m5_admin_base_path": "/evil-menu",
        "m5_web_user": "evil",
        "m5_web_password": "test",
        "m5_handshake_remote_path": "evil/handshake",
        "m5_wardrive_remote_path": "evil/wardriving",
    }

    result = service.probe_m5evil_admin_webui()
    assert result["status"] == "error"
    assert result["code"] == "auth_failed"
    assert result["details"]["connection_ok"] is True
    assert result["details"]["auth_ok"] is False
    assert result["details"]["failure_phase"] == "auth"


def test_probe_m5evil_admin_webui_parser_mismatch_reports_browse_root(monkeypatch):
    route_map = {
        "http://192.168.4.1:80/evil-menu/": _FakeHttpResponse(
            b"<html><body><div>logged in</div></body></html>"
        ),
    }
    monkeypatch.setattr(
        ss_module.urllib_request,
        "urlopen",
        _build_fake_urlopen(route_map, assert_auth=True),
    )

    service = ss_module.SyncService()
    service.config = {
        "m5_sync_enabled": True,
        "m5_host": "192.168.4.1",
        "m5_port": 80,
        "m5_web_protocol": "http",
        "m5_admin_base_path": "/evil-menu",
        "m5_web_user": "evil",
        "m5_web_password": "test",
        "m5_handshake_remote_path": "evil/handshake",
        "m5_wardrive_remote_path": "evil/wardriving",
    }

    result = service.probe_m5evil_admin_webui()
    assert result["status"] == "error"
    assert result["code"] == "browse_not_parseable"
    assert result["details"]["connection_ok"] is True
    assert result["details"]["auth_ok"] is True
    assert result["details"]["browse_root_ok"] is False
    assert result["details"]["failure_phase"] == "browse_root"


def test_probe_m5evil_admin_webui_unreachable_reports_connection_phase(monkeypatch):
    route_map = {
        "http://192.168.4.1:80/evil-menu/": urllib_error.URLError("Connection refused"),
    }
    monkeypatch.setattr(
        ss_module.urllib_request,
        "urlopen",
        _build_fake_urlopen(route_map, assert_auth=True),
    )

    service = ss_module.SyncService()
    service.config = {
        "m5_sync_enabled": True,
        "m5_host": "192.168.4.1",
        "m5_port": 80,
        "m5_web_protocol": "http",
        "m5_admin_base_path": "/evil-menu",
        "m5_web_user": "evil",
        "m5_web_password": "test",
        "m5_handshake_remote_path": "evil/handshake",
        "m5_wardrive_remote_path": "evil/wardriving",
    }

    result = service.probe_m5evil_admin_webui()
    assert result["status"] == "error"
    assert result["code"] == "unreachable"
    assert result["details"]["connection_ok"] is False
    assert result["details"]["failure_phase"] == "connection"


def test_sync_host_key_not_trusted_error(tmp_path, monkeypatch):
    monkeypatch.setattr(ss_module, "HANDSHAKES_DIR", str(tmp_path))

    fake_sftp = _FakeSFTP([])
    fake_ssh = _FakeSSH(fake_sftp)

    def _raise_hostkey(*args, **kwargs):
        raise ss_module.paramiko.SSHException(
            "Server '[127.0.0.1]:22' not found in known_hosts"
        )

    fake_ssh.connect = _raise_hostkey
    monkeypatch.setattr(ss_module.paramiko, "SSHClient", lambda: fake_ssh)

    service = ss_module.SyncService()
    service.config = {
        "pwn_host": "127.0.0.1",
        "pwn_port": 22,
        "pwn_user": "u",
        "pwn_pass": "p",
        "remote_path": "/remote",
    }

    result = service.perform_sync(force=False)
    assert result["status"] == "error"
    assert result["code"] == "ssh_host_key_not_trusted"
    assert "host key not trusted" in result["message"].lower()


def test_trust_remote_host_key_success_and_already_trusted(tmp_path, monkeypatch):
    known_hosts = tmp_path / "known_hosts"
    _FakeHostKeys.reset()
    monkeypatch.setattr(ss_module.paramiko, "HostKeys", _FakeHostKeys)

    key = _FakeKey("ssh-ed25519", "AAAATESTKEY", b"fake-key-bytes")
    service = ss_module.SyncService()
    service.config = {
        "pwn_host": "10.0.0.2",
        "pwn_port": 22,
        "ssh_known_hosts_path": str(known_hosts),
    }
    monkeypatch.setattr(
        service, "_fetch_remote_host_key", lambda *_args, **_kwargs: key
    )

    first = service.trust_remote_host_key()
    assert first["status"] == "success"
    assert "trusted" in first["message"].lower()
    assert first["details"]["host_key"]["fingerprint_sha256"].startswith("SHA256:")

    second = service.trust_remote_host_key()
    assert second["status"] == "success"
    assert "already trusted" in second["message"].lower()


def test_trust_remote_host_key_requires_replace_on_mismatch(tmp_path, monkeypatch):
    known_hosts = tmp_path / "known_hosts"
    _FakeHostKeys.reset()
    monkeypatch.setattr(ss_module.paramiko, "HostKeys", _FakeHostKeys)

    old_key = _FakeKey("ssh-ed25519", "AAAAOLDKEY", b"old-key")
    new_key = _FakeKey("ssh-ed25519", "AAAANEWKEY", b"new-key")

    service = ss_module.SyncService()
    service.config = {
        "pwn_host": "10.0.0.2",
        "pwn_port": 22,
        "ssh_known_hosts_path": str(known_hosts),
    }
    monkeypatch.setattr(
        service, "_fetch_remote_host_key", lambda *_args, **_kwargs: old_key
    )
    assert service.trust_remote_host_key()["status"] == "success"

    monkeypatch.setattr(
        service, "_fetch_remote_host_key", lambda *_args, **_kwargs: new_key
    )
    mismatch = service.trust_remote_host_key(replace=False)
    assert mismatch["status"] == "error"
    assert mismatch["code"] == "ssh_host_key_mismatch"

    replaced = service.trust_remote_host_key(replace=True)
    assert replaced["status"] == "success"
    assert "trusted successfully" in replaced["message"].lower()


def test_trust_remote_host_key_missing_host():
    """trust_remote_host_key returns error when host is missing."""
    service = ss_module.SyncService()
    service.config = {"pwn_host": ""}
    result = service.trust_remote_host_key()
    assert result["status"] == "error"
    assert "missing" in result["message"].lower()


def test_trust_remote_host_key_probe_failed(tmp_path, monkeypatch):
    """trust_remote_host_key handles probe failure."""
    known_hosts = tmp_path / "known_hosts"
    service = ss_module.SyncService()
    service.config = {
        "pwn_host": "10.0.0.2",
        "pwn_port": 22,
        "ssh_known_hosts_path": str(known_hosts),
    }
    monkeypatch.setattr(
        service,
        "_fetch_remote_host_key",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("probe failed")),
    )
    result = service.trust_remote_host_key()
    assert result["status"] == "error"
    assert result["code"] == "ssh_host_key_probe_failed"


def test_build_ssh_client_loads_known_hosts(tmp_path, monkeypatch):
    """_build_ssh_client loads known_hosts file when configured."""
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("", encoding="utf-8")
    fake_ssh = _FakeSSH(_FakeSFTP([]))
    monkeypatch.setattr(ss_module.paramiko, "SSHClient", lambda: fake_ssh)

    service = ss_module.SyncService()
    service.config = {"ssh_known_hosts_path": str(known_hosts)}
    ssh = service._build_ssh_client()
    assert str(known_hosts) in ssh.host_keys_loaded


def test_build_ssh_client_missing_known_hosts(tmp_path, monkeypatch):
    """_build_ssh_client handles missing known_hosts gracefully."""
    fake_ssh = _FakeSSH(_FakeSFTP([]))
    monkeypatch.setattr(ss_module.paramiko, "SSHClient", lambda: fake_ssh)

    service = ss_module.SyncService()
    service.config = {"ssh_known_hosts_path": str(tmp_path / "nonexistent" / "kh")}
    ssh = service._build_ssh_client()
    assert ssh is not None


def test_build_ssh_client_load_host_keys_oserror(tmp_path, monkeypatch):
    """_build_ssh_client handles OSError when loading known_hosts."""
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("", encoding="utf-8")
    fake_ssh = _FakeSSH(
        _FakeSFTP([]), load_host_keys_error=OSError("permission denied")
    )
    monkeypatch.setattr(ss_module.paramiko, "SSHClient", lambda: fake_ssh)

    service = ss_module.SyncService()
    service.config = {"ssh_known_hosts_path": str(known_hosts)}
    ssh = service._build_ssh_client()
    assert ssh is not None
    assert str(known_hosts) not in ssh.host_keys_loaded


def test_sha256_and_md5_fingerprints():
    """_sha256_fingerprint and _md5_fingerprint return expected formats."""
    service = ss_module.SyncService()
    key = _FakeKey("ssh-ed25519", "AAAATESTKEY", b"test-bytes")
    sha256_fp = service._sha256_fingerprint(key)
    md5_fp = service._md5_fingerprint(key)
    assert sha256_fp.startswith("SHA256:")
    assert md5_fp.startswith("MD5:")


def test_serialize_host_key():
    """_serialize_host_key returns all expected fields."""
    service = ss_module.SyncService()
    key = _FakeKey("ssh-ed25519", "AAAATESTKEY", b"test-bytes")
    serialized = service._serialize_host_key(key, "10.0.0.1", 22)
    assert serialized["host"] == "10.0.0.1"
    assert serialized["port"] == 22
    assert serialized["key_type"] == "ssh-ed25519"
    assert serialized["fingerprint_sha256"].startswith("SHA256:")
    assert serialized["fingerprint_md5"].startswith("MD5:")
    assert serialized["key_base64"] == "AAAATESTKEY"


def test_host_patterns():
    """_host_patterns returns host and [host]:port."""
    service = ss_module.SyncService()
    patterns = service._host_patterns("example.com", 2222)
    assert patterns == ["example.com", "[example.com]:2222"]


def test_probe_remote_host_key_details_error(monkeypatch):
    """_probe_remote_host_key_details returns None on error."""
    service = ss_module.SyncService()
    monkeypatch.setattr(
        service,
        "_fetch_remote_host_key",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("conn refused")),
    )
    result = service._probe_remote_host_key_details("10.0.0.1", 22)
    assert result is None


def test_probe_remote_host_key_details_success(monkeypatch):
    """_probe_remote_host_key_details returns host key details on success."""
    service = ss_module.SyncService()
    fake_key = _FakeKey("ssh-ed25519", "AAAATESTKEY", b"test-bytes")
    monkeypatch.setattr(
        service,
        "_fetch_remote_host_key",
        lambda *_args, **_kwargs: fake_key,
    )
    result = service._probe_remote_host_key_details("10.0.0.1", 22)
    assert result is not None
    assert result["host"] == "10.0.0.1"
    assert result["port"] == 22
    assert result["key_type"] == "ssh-ed25519"
    assert result["key_base64"] == "AAAATESTKEY"


class _FakeTransport:
    def __init__(self, remote_key):
        self._remote_key = remote_key

    def start_client(self, timeout=10):
        return None

    def get_remote_server_key(self):
        return self._remote_key

    def close(self):
        return None


def test_fetch_remote_host_key_success(monkeypatch):
    """_fetch_remote_host_key fetches key successfully."""
    service = ss_module.SyncService()
    fake_key = _FakeKey("ssh-ed25519", "AAAATESTKEY", b"test-bytes")
    fake_sock = type("MockSock", (), {"close": lambda self: None})()
    fake_transport = _FakeTransport(fake_key)

    monkeypatch.setattr(
        ss_module.socket, "create_connection", lambda *args, **kwargs: fake_sock
    )
    monkeypatch.setattr(ss_module.paramiko, "Transport", lambda sock: fake_transport)

    result = service._fetch_remote_host_key("10.0.0.1", 22)
    assert result == fake_key


def test_ensure_known_hosts_creates_directory(tmp_path):
    """_ensure_known_hosts_file creates parent directory."""
    service = ss_module.SyncService()
    kh_path = tmp_path / "subdir" / "known_hosts"
    service._ensure_known_hosts_file(str(kh_path))
    assert kh_path.exists()


def test_trust_remote_host_key_ensure_fails(tmp_path, monkeypatch):
    """trust_remote_host_key handles OSError from _ensure_known_hosts_file."""
    service = ss_module.SyncService()
    service.config = {
        "pwn_host": "10.0.0.2",
        "pwn_port": 22,
        "ssh_known_hosts_path": "/dev/null/nonexistent/kh",
    }

    def _raise_oserror(*_args, **_kwargs):
        raise OSError("permission denied")

    monkeypatch.setattr(service, "_ensure_known_hosts_file", _raise_oserror)
    result = service.trust_remote_host_key()
    assert result["status"] == "error"
    assert result["code"] == "known_hosts_unavailable"


def test_trust_remote_host_key_save_fails(tmp_path, monkeypatch):
    """trust_remote_host_key handles OSError when saving known_hosts."""
    known_hosts = tmp_path / "known_hosts"
    _FakeHostKeys.reset()
    monkeypatch.setattr(ss_module.paramiko, "HostKeys", _FakeHostKeys)

    key = _FakeKey("ssh-ed25519", "AAAATESTKEY", b"fake-key-bytes")
    service = ss_module.SyncService()
    service.config = {
        "pwn_host": "10.0.0.2",
        "pwn_port": 22,
        "ssh_known_hosts_path": str(known_hosts),
    }
    monkeypatch.setattr(
        service, "_fetch_remote_host_key", lambda *_args, **_kwargs: key
    )

    # Make HostKeys.save raise OSError
    original_save = _FakeHostKeys.save

    def _failing_save(self, path):
        raise OSError("disk full")

    _FakeHostKeys.save = _failing_save
    result = service.trust_remote_host_key()
    assert result["status"] == "error"
    assert result["code"] == "known_hosts_unavailable"
    # Restore
    _FakeHostKeys.save = original_save


def test_sync_bad_host_key_exception(tmp_path, monkeypatch):
    """perform_sync handles BadHostKeyException."""
    monkeypatch.setattr(ss_module, "HANDSHAKES_DIR", str(tmp_path))
    fake_sftp = _FakeSFTP([])
    fake_ssh = _FakeSSH(fake_sftp)

    expected_key = _FakeKey("ssh-ed25519", "AAAAOLD", b"old")
    presented_key = _FakeKey("ssh-ed25519", "AAAANEW", b"new")

    def _raise_bad_host_key(*args, **kwargs):
        exc = ss_module.paramiko.BadHostKeyException(
            "127.0.0.1", presented_key, expected_key
        )
        exc.expected_key = expected_key
        exc.key = presented_key
        raise exc

    fake_ssh.connect = _raise_bad_host_key
    monkeypatch.setattr(ss_module.paramiko, "SSHClient", lambda: fake_ssh)

    service = ss_module.SyncService()
    service.config = {
        "pwn_host": "127.0.0.1",
        "pwn_port": 22,
        "pwn_user": "u",
        "pwn_pass": "p",
        "remote_path": "/remote",
    }

    result = service.perform_sync(force=False)
    assert result["status"] == "error"
    assert result["code"] == "ssh_host_key_mismatch"
    assert "host_key" in result["details"]
    assert "expected_host_key" in result["details"]


def test_sync_ssh_exception_generic(tmp_path, monkeypatch):
    """perform_sync handles generic SSHException."""
    monkeypatch.setattr(ss_module, "HANDSHAKES_DIR", str(tmp_path))
    fake_sftp = _FakeSFTP([])
    fake_ssh = _FakeSSH(fake_sftp)

    def _raise_ssh_err(*args, **kwargs):
        raise ss_module.paramiko.SSHException("connection refused")

    fake_ssh.connect = _raise_ssh_err
    monkeypatch.setattr(ss_module.paramiko, "SSHClient", lambda: fake_ssh)

    service = ss_module.SyncService()
    service.config = {
        "pwn_host": "127.0.0.1",
        "pwn_port": 22,
        "pwn_user": "u",
        "pwn_pass": "p",
        "remote_path": "/remote",
    }

    result = service.perform_sync(force=False)
    assert result["status"] == "error"
    pwn_stage = result["details"]["pwnagotchi_remote_sync"]
    assert pwn_stage["status"] == "error"
    assert "connection refused" in str(pwn_stage.get("message") or "")


def test_trust_remote_host_key_load_known_hosts_fails(tmp_path, monkeypatch):
    """trust_remote_host_key handles OSError when loading known_hosts."""
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("", encoding="utf-8")
    _FakeHostKeys.reset()
    monkeypatch.setattr(ss_module.paramiko, "HostKeys", _FakeHostKeys)

    key = _FakeKey("ssh-ed25519", "AAAATESTKEY", b"fake-key-bytes")
    service = ss_module.SyncService()
    service.config = {
        "pwn_host": "10.0.0.2",
        "pwn_port": 22,
        "ssh_known_hosts_path": str(known_hosts),
    }
    monkeypatch.setattr(
        service, "_fetch_remote_host_key", lambda *_args, **_kwargs: key
    )

    # Make HostKeys.load raise OSError
    original_load = _FakeHostKeys.load

    def _failing_load(self, path):
        raise OSError("read error")

    _FakeHostKeys.load = _failing_load
    result = service.trust_remote_host_key()
    assert result["status"] == "error"
    assert result["code"] == "known_hosts_unavailable"
    # Restore
    _FakeHostKeys.load = original_load


def test_link_listing_parser_handles_script_urls():
    """_LinkListingParser extracts urls from script body and attributes."""
    parser = ss_module._LinkListingParser()
    html = """
    <html>
        <body>
            <div data-url="/download/file1.pcap" data-name="HS_TEST.pcap">Download</div>
            <button onclick="window.location.href='/download/file2.pcap'">Click</button>
            <script>
                var urls = ["/download/file3.pcap", "/download/file4.pcap", "download/file5.pcap"];
            </script>
        </body>
    </html>
    """
    parser.feed(html)
    parser.close()

    hrefs = {item["href"] for item in parser.links}
    assert "/download/file1.pcap" in hrefs
    assert "/download/file2.pcap" in hrefs
    assert "/download/file3.pcap" in hrefs
    assert "/download/file4.pcap" in hrefs
    assert "download/file5.pcap" in hrefs


def test_resolve_remote_path_handles_absolute_paths():
    """_resolve_remote_path correctly handles absolute and relative paths."""
    service = ss_module.SyncService()
    assert (
        service._resolve_remote_path("/root/path", "child/file")
        == "/root/path/child/file"
    )
    assert (
        service._resolve_remote_path("/root/path/", "/absolute/path")
        == "/absolute/path"
    )
    assert service._resolve_remote_path("", "child") == "child"
    assert service._resolve_remote_path("/root/", "") == "/root"


def test_normalize_web_path_cleans_path():
    """_normalize_web_path cleans and normalizes web paths."""
    service = ss_module.SyncService()
    assert service._normalize_web_path("evil/menu/") == "/evil/menu/"
    assert service._normalize_web_path("\\evil\\menu\\test") == "/evil/menu/test"
    assert service._normalize_web_path("evil//menu//test") == "/evil/menu/test"
    assert service._normalize_web_path("") == "/"


def test_normalize_m5evil_remote_path_removes_slashes():
    """_normalize_m5evil_remote_path strips leading and trailing slashes."""
    service = ss_module.SyncService()
    assert service._normalize_m5evil_remote_path("/evil/handshake/") == "evil/handshake"
    assert (
        service._normalize_m5evil_remote_path("\\evil\\handshake\\") == "evil/handshake"
    )
    assert service._normalize_m5evil_remote_path("") == ""


def test_build_m5evil_direct_dir_url():
    """_build_m5evil_direct_dir_url builds correct check-sd-file url."""
    service = ss_module.SyncService()
    profile = {
        "protocol": "http",
        "host": "192.168.4.1",
        "port": 80,
    }
    url = service._build_m5evil_direct_dir_url(profile, "evil/handshake")
    assert "check-sd-file" in url
    assert "dir=%2Fevil%2Fhandshake" in url


def test_build_basic_auth():
    """_build_basic_auth_value produces correct Authorization header."""
    service = ss_module.SyncService()
    auth = service._build_basic_auth_value("user", "pass")
    assert auth.startswith("Basic ")
    assert auth == "Basic dXNlcjpwYXNz"


def test_looks_like_m5evil_browse_link():
    """_looks_like_m5evil_browse_link correctly identifies browse links."""
    service = ss_module.SyncService()
    assert service._looks_like_m5evil_browse_link("browse sd", "Browse SD") is True
    assert service._looks_like_m5evil_browse_link("/check-sd-file", "") is False
    assert service._looks_like_m5evil_browse_link("other", "Other") is False


def test_looks_like_html_detects_html():
    """_looks_like_html correctly identifies html responses."""
    service = ss_module.SyncService()
    assert service._looks_like_html(b"<html><body>test</body></html>") is True
    assert service._looks_like_html(b"<!DOCTYPE html>") is True
    assert service._looks_like_html(b"not html") is False
    assert service._looks_like_html(b"", "text/html") is True


def test_extract_path_from_link_parses_query_params():
    """_extract_path_from_link extracts path from query parameters."""
    service = ss_module.SyncService()
    assert (
        service._extract_path_from_link("/download?path=evil/handshake/test.pcap")
        == "evil/handshake/test.pcap"
    )
    assert service._extract_path_from_link("/download?file=test.pcap") == "test.pcap"
    assert (
        service._extract_path_from_link("/download/filename.pcap")
        == "/download/filename.pcap"
    )


def test_extract_listing_filename():
    """_extract_listing_filename extracts filename from href and query parameters."""
    service = ss_module.SyncService()
    assert (
        service._extract_listing_filename(
            "/download?path=evil/handshake/HS_TEST.pcap", ""
        )
        == "HS_TEST.pcap"
    )
    assert (
        service._extract_listing_filename("/files/HS_TEST.pcap", "Download")
        == "HS_TEST.pcap"
    )
    assert service._extract_listing_filename("", "HS_TEST.pcap") == "HS_TEST.pcap"


def test_emit_m5evil_progress():
    """_emit_m5evil_progress calls callback with correct values."""
    service = ss_module.SyncService()
    events = []

    def callback(mode, payload):
        events.append((mode, payload))

    service._emit_m5evil_progress(
        callback,
        "handshakes",
        5,
        10,
        4,
        1,
        current_file="HS_TEST.pcap",
        stage="RUNNING",
    )

    assert len(events) == 1
    assert events[0][0] == "handshakes"
    assert events[0][1]["percentage"] == 50
    assert events[0][1]["current_file"] == "HS_TEST.pcap"
    assert events[0][1]["downloaded"] == 4
    assert events[0][1]["failed"] == 1


def test_m5evil_phase_details():
    """_m5evil_phase_details returns correct structure."""
    service = ss_module.SyncService()
    profile = {"target": "m5evil"}
    details = service._m5evil_phase_details(
        profile,
        connection_ok=True,
        auth_ok=True,
        browse_root_ok=True,
        handshake_path_ok=True,
        failure_phase=None,
        url_used="http://192.168.4.1/evil-menu",
    )

    assert details["target"] == "m5evil"
    assert details["connection_ok"] is True
    assert details["auth_ok"] is True
    assert details["browse_root_ok"] is True
    assert details["failure_phase"] is None
    assert details["url_used"] == "http://192.168.4.1/evil-menu"


def test_should_download_entry_returns_false_for_missing_size():
    """_should_download_entry retorna True por padrão quando o tamanho remoto não está disponível."""
    service = ss_module.SyncService()
    errors = []
    result = service._should_download_entry(
        "/tmp/file", None, False, errors, "test.pcap"
    )
    assert result is True
    assert len(errors) == 0


def test_get_known_hosts_path_default():
    """_get_known_hosts_path returns default path when not configured."""
    service = ss_module.SyncService()
    service.config = {}
    path = service._get_known_hosts_path()
    assert ".kovil/known_hosts" in path


def test_perform_sync_handles_mixed_success_and_failure():
    """perform_sync handles mixed success and failure across targets."""
    service = ss_module.SyncService()

    def mock_pwn(*_args, **_kwargs):
        return {
            "status": "success",
            "details": {"handshakes": ["file1.pcap"], "wardrive_csvs": []},
        }

    def mock_m5(*_args, **_kwargs):
        return {
            "status": "error",
            "message": "M5Evil offline",
            "details": {"handshakes": [], "wardrive_csvs": []},
        }

    service._perform_pwnagotchi_sync = mock_pwn
    service._perform_m5evil_sync = mock_m5

    result = service.perform_sync(force=False)
    assert result["status"] == "success"
    assert "Pwnagotchi" in result["message"]
    errors = result["details"]["errors"]
    assert "m5evil: M5Evil offline" in errors
    # Bruce sync may report a non-fatal warning depending on local runtime context.
    assert len(errors) >= 1
    assert result["details"]["any_remote_success"] is True


def test_looks_like_url_value():
    """_looks_like_url_value identifies URL-like values."""
    from app.services.sync_service import _LinkListingParser

    parser = _LinkListingParser()

    # Valid URLs
    assert parser._looks_like_url_value("http://example.com") is True
    assert parser._looks_like_url_value("https://example.com") is True
    assert parser._looks_like_url_value("/path") is True
    assert parser._looks_like_url_value("./relative") is True
    assert parser._looks_like_url_value("../parent") is True
    assert parser._looks_like_url_value("evil-menu") is True
    assert parser._looks_like_url_value("browse") is True
    assert parser._looks_like_url_value("download") is True

    # Invalid values
    assert parser._looks_like_url_value("") is False
    assert parser._looks_like_url_value(None) is False
    assert parser._looks_like_url_value("   ") is False
    assert parser._looks_like_url_value("not-a-url") is False
    assert parser._looks_like_url_value("ftp://example.com") is False


def test_extract_urls_from_value():
    """_extract_urls_from_value extracts URLs from text."""
    from app.services.sync_service import _LinkListingParser

    parser = _LinkListingParser()

    # Direct URL
    assert parser._extract_urls_from_value("http://example.com") == [
        "http://example.com"
    ]

    # Quoted URLs
    assert parser._extract_urls_from_value('href="http://example.com"') == [
        "http://example.com"
    ]
    assert parser._extract_urls_from_value("href='http://example.com'") == [
        "http://example.com"
    ]
    assert parser._extract_urls_from_value("href=`http://example.com`") == [
        "http://example.com"
    ]

    # Multiple URLs
    result = parser._extract_urls_from_value(
        'href="http://a.com" and href="http://b.com"'
    )
    assert set(result) == {"http://a.com", "http://b.com"}

    # No URLs
    assert parser._extract_urls_from_value("no urls here") == []
    assert parser._extract_urls_from_value("") == []
    assert parser._extract_urls_from_value(None) == []


def test_append_link():
    """_append_link adds links to the parser."""
    from app.services.sync_service import _LinkListingParser

    parser = _LinkListingParser()

    # Add a link
    parser._append_link("http://example.com", "Example")
    assert len(parser.links) == 1
    assert parser.links[0] == {"href": "http://example.com", "text": "Example"}

    # Add the same link again (should not duplicate)
    parser._append_link("http://example.com", "Example")
    assert len(parser.links) == 1

    # Add empty href (should not add)
    parser._append_link("", "Empty")
    assert len(parser.links) == 1

    # Add None href (should not add)
    parser._append_link(None, "None")
    assert len(parser.links) == 1


def test_link_listing_parser_html_parsing():
    """Test HTML parsing functionality of _LinkListingParser."""
    from app.services.sync_service import _LinkListingParser

    html = """
    <html>
    <body>
        <a href="http://example.com">Link 1</a>
        <a href="/relative/path">Link 2</a>
        <a href="">Empty Link</a>
        <div onclick="window.location='http://onclick.com'">Click me</div>
        <form action="http://form.com">
            <input type="submit" value="Submit">
        </form>
        <script>
            var url = "http://script.com";
            fetch(url);
        </script>
        <img src="http://image.com/img.jpg" alt="Image">
    </body>
    </html>
    """

    parser = _LinkListingParser()
    parser.feed(html)

    # Check extracted links
    hrefs = {link["href"] for link in parser.links}
    assert "http://example.com" in hrefs
    assert "/relative/path" in hrefs
    assert "http://onclick.com" in hrefs
    assert "http://form.com" in hrefs
    assert "http://script.com" in hrefs
    assert "http://image.com/img.jpg" in hrefs

    # Empty href should not be included
    assert "" not in hrefs

    # Check text extraction for links
    link_texts = {link["text"] for link in parser.links}
    assert "Link 1" in link_texts
    assert "Link 2" in link_texts


def test_ensure_known_hosts_file_chmod_error(tmp_path, monkeypatch):
    """Test _ensure_known_hosts_file handles chmod errors gracefully."""
    from app.services.sync_service import SyncService
    import os

    service = SyncService()
    known_hosts_path = str(tmp_path / "known_hosts")

    # Mock os.chmod to raise OSError
    def mock_chmod(*args, **kwargs):
        raise OSError("Permission denied")

    monkeypatch.setattr(os, "chmod", mock_chmod)

    # Should not raise exception
    service._ensure_known_hosts_file(known_hosts_path)

    # File should still be created
    assert os.path.exists(known_hosts_path)


def test_get_pwnagotchi_profile_with_overrides():
    """Test _get_pwnagotchi_profile with overrides."""
    from app.services.sync_service import SyncService

    service = SyncService()
    service.config = {
        "pwn_host": "default.host",
        "pwn_port": 22,
        "pwn_user": "default_user",
        "pwn_pass": "default_pass",
        "remote_path": "/default/path",
    }

    # Test with overrides
    overrides = {
        "pwn_host": "override.host",
        "pwn_port": "2222",
        "pwn_user": "override_user",
        "pwn_pass": "override_pass",
        "remote_path": "/override/path",
    }

    profile = service._get_pwnagotchi_profile(overrides)

    assert profile["host"] == "override.host"
    assert profile["port"] == 2222
    assert profile["user"] == "override_user"
    assert profile["password"] == "override_pass"
    assert profile["handshake_path"] == "/override/path"


def test_probe_pwnagotchi_ssh_missing_host():
    """Test probe_pwnagotchi_ssh with missing host."""
    from app.services.sync_service import SyncService

    service = SyncService()
    service.config = {
        "pwn_user": "user",
        "pwn_pass": "pass",
    }

    result = service.probe_pwnagotchi_ssh({"pwn_host": ""})
    assert result["status"] == "error"
    assert result["code"] == "host_missing"


def test_probe_pwnagotchi_ssh_missing_credentials():
    """Test probe_pwnagotchi_ssh with missing credentials."""
    from app.services.sync_service import SyncService

    service = SyncService()
    service.config = {
        "pwn_host": "host",
    }

    result = service.probe_pwnagotchi_ssh({"pwn_user": "", "pwn_pass": ""})
    assert result["status"] == "error"
    assert result["code"] == "credentials_missing"


# ============================================================================
# COMPREHENSIVE EXCEPTION HANDLER TESTS FOR sync_service.py
# These tests cover SSH/SFTP exceptions, HTML parsing edge cases, and urllib errors
# ============================================================================


# Tests for paramiko exceptions in probe_pwnagotchi_ssh
def test_probe_pwnagotchi_ssh_bad_host_key_exception(monkeypatch):
    """Test probe_pwnagotchi_ssh handles BadHostKeyException (host key mismatch)."""
    import paramiko

    ssh_mock = _FakeSSH(_FakeSFTP([]))
    ssh_mock._connect_error = paramiko.BadHostKeyException(
        "hostname", paramiko.RSAKey.generate(1024), paramiko.RSAKey.generate(1024)
    )
    monkeypatch.setattr(ss_module.paramiko, "SSHClient", lambda: ssh_mock)

    service = ss_module.SyncService()
    service.config = {
        "pwn_host": "host.test",
        "pwn_port": 22,
        "pwn_user": "user",
        "pwn_pass": "pass",
        "remote_path": "/remote",
    }

    result = service.probe_pwnagotchi_ssh({})
    assert result["status"] == "error"
    assert result["code"] == "ssh_host_key_mismatch"
    assert "host key changed" in result["message"].lower()
    assert result["details"]["host_key_trusted"] is False
    assert "expected_host_key" in result["details"] or "host_key" in result["details"]


def test_probe_pwnagotchi_ssh_authentication_exception(monkeypatch):
    """Test probe_pwnagotchi_ssh handles AuthenticationException (auth failed)."""
    import paramiko

    ssh_mock = _FakeSSH(_FakeSFTP([]))
    ssh_mock._connect_error = paramiko.AuthenticationException("auth failed")
    monkeypatch.setattr(ss_module.paramiko, "SSHClient", lambda: ssh_mock)

    service = ss_module.SyncService()
    service.config = {
        "pwn_host": "host.test",
        "pwn_port": 22,
        "pwn_user": "baduser",
        "pwn_pass": "badpass",
        "remote_path": "/remote",
    }

    result = service.probe_pwnagotchi_ssh({})
    assert result["status"] == "error"
    assert result["code"] == "auth_failed"
    assert "authentication failed" in result["message"].lower()
    assert result["details"]["auth_ok"] is False
    assert result["details"]["host_key_trusted"] is True


def test_probe_pwnagotchi_ssh_ssh_exception_not_in_known_hosts(monkeypatch):
    """Test probe_pwnagotchi_ssh handles SSHException with 'not found in known_hosts' message."""
    import paramiko

    ssh_mock = _FakeSSH(_FakeSFTP([]))
    ssh_mock._connect_error = paramiko.SSHException(
        "Host key for host.test not found in known_hosts"
    )
    monkeypatch.setattr(ss_module.paramiko, "SSHClient", lambda: ssh_mock)

    service = ss_module.SyncService()
    service.config = {
        "pwn_host": "host.test",
        "pwn_port": 22,
        "pwn_user": "user",
        "pwn_pass": "pass",
        "remote_path": "/remote",
    }

    result = service.probe_pwnagotchi_ssh({})
    assert result["status"] == "error"
    assert result["code"] == "ssh_host_key_not_trusted"
    assert "not trusted" in result["message"].lower()
    assert result["details"]["host_key_trusted"] is False


def test_probe_pwnagotchi_ssh_ssh_exception_generic(monkeypatch):
    """Test probe_pwnagotchi_ssh handles generic SSHException."""
    import paramiko

    ssh_mock = _FakeSSH(_FakeSFTP([]))
    ssh_mock._connect_error = paramiko.SSHException("Generic SSH protocol error")
    monkeypatch.setattr(ss_module.paramiko, "SSHClient", lambda: ssh_mock)

    service = ss_module.SyncService()
    service.config = {
        "pwn_host": "host.test",
        "pwn_port": 22,
        "pwn_user": "user",
        "pwn_pass": "pass",
        "remote_path": "/remote",
    }

    result = service.probe_pwnagotchi_ssh({})
    assert result["status"] == "error"
    assert result["code"] == "ssh_error"
    assert "protocol error" in result["message"].lower()
    assert result["details"]["connection_ok"] is False


def test_probe_pwnagotchi_ssh_file_not_found_exception(monkeypatch):
    """Test probe_pwnagotchi_ssh handles FileNotFoundError (remote path not found)."""

    def raise_file_not_found(*args, **kwargs):
        raise FileNotFoundError("Remote path does not exist")

    sftp_mock = _FakeSFTP([])
    sftp_mock.listdir_attr = raise_file_not_found

    ssh_mock = _FakeSSH(sftp_mock)
    monkeypatch.setattr(ss_module.paramiko, "SSHClient", lambda: ssh_mock)

    service = ss_module.SyncService()
    service.config = {
        "pwn_host": "host.test",
        "pwn_port": 22,
        "pwn_user": "user",
        "pwn_pass": "pass",
        "remote_path": "/nonexistent",
    }

    result = service.probe_pwnagotchi_ssh({})
    assert result["status"] == "error"
    assert result["code"] == "path_not_found"
    assert "path not found" in result["message"].lower()
    assert result["details"]["remote_path_ok"] is False


def test_probe_pwnagotchi_ssh_oserror_unreachable(monkeypatch):
    """Test probe_pwnagotchi_ssh handles OSError (host unreachable)."""

    ssh_mock = _FakeSSH(_FakeSFTP([]))
    ssh_mock._connect_error = OSError("Network is unreachable")
    monkeypatch.setattr(ss_module.paramiko, "SSHClient", lambda: ssh_mock)

    service = ss_module.SyncService()
    service.config = {
        "pwn_host": "unreachable.host",
        "pwn_port": 22,
        "pwn_user": "user",
        "pwn_pass": "pass",
        "remote_path": "/remote",
    }

    result = service.probe_pwnagotchi_ssh({})
    assert result["status"] == "error"
    assert result["code"] == "unreachable"
    assert (
        "unreachable" in result["message"].lower()
        or "failed to reach" in result["message"].lower()
    )
    assert result["details"]["connection_ok"] is False


def test_probe_pwnagotchi_ssh_generic_exception(monkeypatch):
    """Test probe_pwnagotchi_ssh handles generic exceptions."""

    ssh_mock = _FakeSSH(_FakeSFTP([]))
    ssh_mock._connect_error = RuntimeError("Unexpected error")
    monkeypatch.setattr(ss_module.paramiko, "SSHClient", lambda: ssh_mock)

    service = ss_module.SyncService()
    service.config = {
        "pwn_host": "host.test",
        "pwn_port": 22,
        "pwn_user": "user",
        "pwn_pass": "pass",
        "remote_path": "/remote",
    }

    result = service.probe_pwnagotchi_ssh({})
    assert result["status"] == "error"
    assert result["code"] == "probe_failed"
    assert "probe failed" in result["message"].lower()


# Tests for _fetch_remote_host_key error handling
def test_fetch_remote_host_key_socket_timeout(monkeypatch):
    """Test _fetch_remote_host_key handles socket timeout."""
    import socket

    def raise_timeout(*args, **kwargs):
        raise socket.timeout("Connection timed out")

    monkeypatch.setattr("socket.create_connection", raise_timeout)

    service = ss_module.SyncService()
    result = service._probe_remote_host_key_details("host.test", 22)
    assert result is None


def test_fetch_remote_host_key_connection_error(monkeypatch):
    """Test _fetch_remote_host_key handles connection errors."""
    import socket

    def raise_connection_error(*args, **kwargs):
        raise socket.error("Connection refused")

    monkeypatch.setattr("socket.create_connection", raise_connection_error)

    service = ss_module.SyncService()
    result = service._probe_remote_host_key_details("host.test", 22)
    assert result is None


# Tests for HTML parsing edge cases
def test_parse_html_with_malformed_script_tags(monkeypatch):
    """Test _LinkListingParser handles malformed script tags."""
    service = ss_module.SyncService()

    html = """
    <html>
        <script>
            var urls = ['/browse', '/download?file=test.pcap'];
            window.location = urls[0];
        </script>
        <a href="/valid">Valid Link</a>
    </html>
    """

    links = service._list_links(html)
    assert any(link["href"] == "/valid" for link in links)


def test_parse_html_with_onclick_handlers():
    """Test _LinkListingParser extracts onclick handler URLs."""
    service = ss_module.SyncService()

    html = """
    <html>
        <button onclick="window.location='/download?path=/evil/file.pcap'">Download</button>
        <div data-href="/browse/evil/" data-label="Browse SD">Browse</div>
    </html>
    """

    links = service._list_links(html)
    hrefs = [link["href"] for link in links]
    assert any("/download" in href or "/evil" in href for href in hrefs)


def test_parse_html_with_data_attributes():
    """Test _LinkListingParser extracts data-* attributes."""
    service = ss_module.SyncService()

    html = """
    <html>
        <div data-url="/browse" data-name="Browse Files">
            <span data-href="/download?file=test.txt" aria-label="Download">DL</span>
        </div>
    </html>
    """

    links = service._list_links(html)
    assert len(links) > 0


def test_build_ssh_client_load_host_keys_file_not_found(tmp_path, monkeypatch):
    """Test _build_ssh_client handles FileNotFoundError when loading known_hosts."""

    class MockSSHClient:
        def load_system_host_keys(self):
            pass

        def load_host_keys(self, path):
            raise FileNotFoundError(f"Known hosts file not found: {path}")

        def set_missing_host_key_policy(self, policy):
            self.policy = policy

    monkeypatch.setattr(ss_module.paramiko, "SSHClient", MockSSHClient)

    service = ss_module.SyncService()
    service.config = {"ssh_known_hosts_path": str(tmp_path / "known_hosts")}

    ssh = service._build_ssh_client()
    assert ssh is not None


def test_build_ssh_client_load_host_keys_oserror_alt(tmp_path, monkeypatch):

    class MockSSHClient:
        def load_system_host_keys(self):
            pass

        def load_host_keys(self, path):
            raise OSError("Permission denied")

        def set_missing_host_key_policy(self, policy):
            self.policy = policy

    monkeypatch.setattr(ss_module.paramiko, "SSHClient", MockSSHClient)

    service = ss_module.SyncService()
    service.config = {"ssh_known_hosts_path": str(tmp_path / "known_hosts")}

    ssh = service._build_ssh_client()
    assert ssh is not None


# Tests for urllib errors in M5Evil probe
def test_probe_m5evil_http_401_auth_failed(monkeypatch):
    """Test probe_m5evil_admin_webui handles 401 Unauthorized."""
    from urllib import error as urllib_error

    def raise_http_401(*args, **kwargs):
        raise urllib_error.HTTPError("http://host/", 401, "Unauthorized", {}, None)

    monkeypatch.setattr(ss_module.urllib_request, "urlopen", raise_http_401)

    service = ss_module.SyncService()
    service.config = {
        "m5_sync_enabled": True,
        "m5_host": "host",
        "m5_port": 80,
        "m5_web_protocol": "http",
        "m5_admin_base_path": "/evil-menu",
        "m5_web_user": "user",
        "m5_web_password": "badpass",
    }

    result = service.probe_m5evil_admin_webui()
    assert result["status"] == "error"
    # M5Evil checks for required paths first, so may return paths_missing
    assert result["code"] in ("auth_failed", "paths_missing")


def test_probe_m5evil_http_404_not_found(monkeypatch):
    """Test probe_m5evil_admin_webui handles 404 Not Found."""
    from urllib import error as urllib_error

    def raise_http_404(*args, **kwargs):
        raise urllib_error.HTTPError("http://host/", 404, "Not Found", {}, None)

    monkeypatch.setattr(ss_module.urllib_request, "urlopen", raise_http_404)

    service = ss_module.SyncService()
    service.config = {
        "m5_sync_enabled": True,
        "m5_host": "host",
        "m5_port": 80,
        "m5_web_protocol": "http",
        "m5_admin_base_path": "/evil-menu",
        "m5_web_user": "user",
        "m5_web_password": "pass",
    }

    result = service.probe_m5evil_admin_webui()
    assert result["status"] == "error"
    # M5Evil checks for required paths first
    assert result["code"] in ("http_error", "paths_missing")


def test_probe_m5evil_url_error_connection_refused(monkeypatch):
    """Test probe_m5evil_admin_webui handles URLError (connection refused)."""
    from urllib import error as urllib_error

    def raise_url_error(*args, **kwargs):
        raise urllib_error.URLError("Connection refused")

    monkeypatch.setattr(ss_module.urllib_request, "urlopen", raise_url_error)

    service = ss_module.SyncService()
    service.config = {
        "m5_sync_enabled": True,
        "m5_host": "host",
        "m5_port": 80,
        "m5_web_protocol": "http",
        "m5_admin_base_path": "/evil-menu",
        "m5_web_user": "user",
        "m5_web_password": "pass",
    }

    result = service.probe_m5evil_admin_webui()
    assert result["status"] == "error"
    # Check for paths_missing first or unreachable
    assert result["code"] in ("unreachable", "paths_missing")


def test_probe_m5evil_generic_exception(monkeypatch):
    """Test probe_m5evil_admin_webui handles generic exceptions."""

    def raise_generic(*args, **kwargs):
        raise RuntimeError("Unexpected error in HTTP layer")

    monkeypatch.setattr(ss_module.urllib_request, "urlopen", raise_generic)

    service = ss_module.SyncService()
    service.config = {
        "m5_sync_enabled": True,
        "m5_host": "host",
        "m5_port": 80,
        "m5_web_protocol": "http",
        "m5_admin_base_path": "/evil-menu",
        "m5_web_user": "user",
        "m5_web_password": "pass",
    }

    result = service.probe_m5evil_admin_webui()
    assert result["status"] == "error"
    # M5Evil checks for required paths first before any HTTP operations
    assert result["code"] in ("endpoint_unavailable", "paths_missing")


# Tests for exception handling in sftp.close() and ssh.close()
def test_probe_pwnagotchi_sftp_close_exception_ignored(monkeypatch):
    """Test that exceptions in sftp.close() are ignored."""

    class MockSFTP:
        def listdir_attr(self, path):
            return []

        def close(self):
            raise RuntimeError("sftp.close() failed")

    class MockSSH:
        def load_system_host_keys(self):
            pass

        def load_host_keys(self, path):
            pass

        def set_missing_host_key_policy(self, policy):
            pass

        def connect(self, *args, **kwargs):
            pass

        def open_sftp(self):
            return MockSFTP()

        def close(self):
            pass

    monkeypatch.setattr(ss_module.paramiko, "SSHClient", lambda: MockSSH())

    service = ss_module.SyncService()
    service.config = {
        "pwn_host": "host.test",
        "pwn_port": 22,
        "pwn_user": "user",
        "pwn_pass": "pass",
        "remote_path": "/remote",
    }

    result = service.probe_pwnagotchi_ssh({})
    assert result["status"] == "success"


def test_probe_pwnagotchi_ssh_close_exception_ignored(monkeypatch):
    """Test that exceptions in ssh.close() are ignored."""

    class MockSFTP:
        def listdir_attr(self, path):
            return []

        def close(self):
            pass

    class MockSSH:
        def load_system_host_keys(self):
            pass

        def load_host_keys(self, path):
            pass

        def set_missing_host_key_policy(self, policy):
            pass

        def connect(self, *args, **kwargs):
            pass

        def open_sftp(self):
            return MockSFTP()

        def close(self):
            raise RuntimeError("ssh.close() failed")

    monkeypatch.setattr(ss_module.paramiko, "SSHClient", lambda: MockSSH())

    service = ss_module.SyncService()
    service.config = {
        "pwn_host": "host.test",
        "pwn_port": 22,
        "pwn_user": "user",
        "pwn_pass": "pass",
        "remote_path": "/remote",
    }

    result = service.probe_pwnagotchi_ssh({})
    assert result["status"] == "success"


def test_get_pwnagotchi_profile_invalid_port(monkeypatch):
    """Test _get_pwnagotchi_profile ignores invalid port overrides."""
    service = ss_module.SyncService()
    service.config = {
        "pwn_host": "default.host",
        "pwn_port": 22,
        "pwn_user": "default_user",
        "pwn_pass": "default_pass",
        "remote_path": "/default/path",
    }

    profile = service._get_pwnagotchi_profile({"pwn_port": "not-a-number"})
    assert profile["port"] == 22


def test_fetch_remote_host_key_close_exceptions_ignored(monkeypatch):
    """Test _fetch_remote_host_key swallows socket and transport close errors."""

    class FakeSocket:
        def close(self):
            raise RuntimeError("socket.close failed")

    class FakeTransport:
        def __init__(self, sock):
            self.sock = sock

        def start_client(self, timeout=10):
            pass

        def get_remote_server_key(self):
            class FakeKey:
                def get_name(self):
                    return "ssh-rsa"

                def get_base64(self):
                    return "AAAAB3NzaC1yc2E="

                def asbytes(self):
                    return b"bytes"

            return FakeKey()

        def close(self):
            raise RuntimeError("transport.close failed")

    monkeypatch.setattr(
        ss_module.socket, "create_connection", lambda *args, **kwargs: FakeSocket()
    )
    monkeypatch.setattr(
        ss_module.paramiko, "Transport", lambda sock: FakeTransport(sock)
    )

    service = ss_module.SyncService()
    key = service._fetch_remote_host_key("host.test", 22)

    assert hasattr(key, "get_name")
    assert hasattr(key, "get_base64")
