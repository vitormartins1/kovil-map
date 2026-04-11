import builtins

from app.api.routers import files as files_router


def test_get_file_content_success(client, tmp_path, monkeypatch):
    monkeypatch.setattr(files_router, "HANDSHAKES_DIR", str(tmp_path))
    target = tmp_path / "notes.txt"
    target.write_text("hello world", encoding="utf-8")

    resp = client.get("/api/files/notes.txt")
    assert resp.status_code == 200
    assert resp.json()["data"] == "hello world"


def test_get_file_content_rejects_large_file(client, tmp_path, monkeypatch):
    monkeypatch.setattr(files_router, "HANDSHAKES_DIR", str(tmp_path))
    target = tmp_path / "large.txt"
    target.write_text("x", encoding="utf-8")

    monkeypatch.setattr(files_router.os.path, "getsize", lambda _path: 1024 * 1024 + 1)

    resp = client.get("/api/files/large.txt")
    assert resp.status_code == 400
    assert resp.json()["detail"]["message"] == "File too large"


def test_get_file_content_surfaces_read_error(client, tmp_path, monkeypatch):
    monkeypatch.setattr(files_router, "HANDSHAKES_DIR", str(tmp_path))
    target = tmp_path / "broken.txt"
    target.write_text("content", encoding="utf-8")

    original_open = builtins.open

    def _broken_open(path, *args, **kwargs):
        if str(path).endswith("broken.txt"):
            raise OSError("disk error")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", _broken_open)

    resp = client.get("/api/files/broken.txt")
    assert resp.status_code == 500
    assert resp.json()["detail"]["message"] == "disk error"
