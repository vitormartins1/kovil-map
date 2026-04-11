from app.services.base_service import BaseService


def test_to_wsl_path_converts_windows_path():
    svc = BaseService()
    assert svc._to_wsl_path("C:\\Users\\Test") == "/mnt/c/Users/Test"


def test_to_wsl_path_handles_relative_and_empty():
    svc = BaseService()
    assert svc._to_wsl_path("") == ""
    assert svc._to_wsl_path("relative\\path") == "relative/path"


def test_should_use_wsl_respects_windows_binary(monkeypatch):
    svc = BaseService()
    monkeypatch.setattr(svc, "_get_config", lambda: {"use_wsl": True})

    assert svc._should_use_wsl("/usr/bin/hashcat") is True
    assert svc._should_use_wsl("C:\\tools\\hashcat.exe") is False
    assert svc._should_use_wsl("/mnt/c/hashcat.exe") is False


def test_should_use_wsl_returns_false_when_disabled(monkeypatch):
    svc = BaseService()
    monkeypatch.setattr(svc, "_get_config", lambda: {"use_wsl": False})

    assert svc._should_use_wsl("/usr/bin/hashcat") is False


def test_to_wsl_path_falls_back_when_split_raises():
    svc = BaseService()

    class _BrokenPath:
        def __contains__(self, _value):
            return True

        def split(self, *_args, **_kwargs):
            raise RuntimeError("bad split")

        def replace(self, old, new):
            return f"fallback:{old}->{new}"

    path = _BrokenPath()
    assert svc._to_wsl_path(path) == "fallback:\\->/"
