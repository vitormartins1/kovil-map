from app.services import maintenance_service as ms_module
from app.services import rawsniffer_service as rs_module


def test_clear_details_files_deletes_all(tmp_path, monkeypatch):
    """clear_details_files removes *.details and reports counts."""
    monkeypatch.setattr(ms_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(ms_module.analytics_service, "clear_cache", lambda: None)
    monkeypatch.setattr(ms_module, "_clear_recon_runtime_cache", lambda: None)
    monkeypatch.setattr(ms_module, "reload_data", lambda: None)

    for i in range(3):
        (tmp_path / f"file{i}.details").write_text("{}", encoding="utf-8")

    result = ms_module.maintenance_service.clear_details_files()

    assert result["deleted_count"] == 3
    assert result["failed_count"] == 0


def test_clear_details_files_handles_delete_error(tmp_path, monkeypatch):
    """clear_details_files counts failures when delete raises."""
    import os as real_os

    monkeypatch.setattr(ms_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(ms_module.analytics_service, "clear_cache", lambda: None)
    monkeypatch.setattr(ms_module, "_clear_recon_runtime_cache", lambda: None)
    monkeypatch.setattr(ms_module, "reload_data", lambda: None)

    (tmp_path / "good.details").write_text("{}", encoding="utf-8")
    (tmp_path / "bad.details").write_text("{}", encoding="utf-8")

    original_remove = real_os.remove
    call_count = 0

    def _mock_remove(path):
        nonlocal call_count
        call_count += 1
        if call_count == 2:
            raise PermissionError("simulated failure")
        return original_remove(path)

    monkeypatch.setattr(real_os, "remove", _mock_remove)

    result = ms_module.maintenance_service.clear_details_files()

    assert result["deleted_count"] == 1
    assert result["failed_count"] == 1


def test_clear_details_files_empty_directory(tmp_path, monkeypatch):
    """clear_details_files returns zeros when no details files exist."""
    monkeypatch.setattr(ms_module, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(ms_module.analytics_service, "clear_cache", lambda: None)
    monkeypatch.setattr(ms_module, "_clear_recon_runtime_cache", lambda: None)
    monkeypatch.setattr(ms_module, "reload_data", lambda: None)

    result = ms_module.maintenance_service.clear_details_files()

    assert result["deleted_count"] == 0
    assert result["failed_count"] == 0


def test_clear_cache_returns_expected_keys(monkeypatch):
    """clear_cache returns all expected keys."""
    monkeypatch.setattr(
        rs_module.rawsniffer_service,
        "clear_metadata_cache",
        lambda remove_files=True: {"deleted_count": 5, "failed_count": 1},
    )
    monkeypatch.setattr(ms_module.analytics_service, "clear_cache", lambda: None)
    monkeypatch.setattr(ms_module.probe_service, "invalidate_cache", lambda: None)
    monkeypatch.setattr(
        ms_module.packet_analysis_service, "invalidate_cache", lambda: None
    )
    monkeypatch.setattr(ms_module, "_clear_recon_runtime_cache", lambda: None)
    monkeypatch.setattr(ms_module, "reload_data", lambda: None)

    result = ms_module.maintenance_service.clear_cache()

    assert result["raw_metadata_deleted_count"] == 5
    assert result["raw_metadata_failed_count"] == 1
    assert result["data_cache_reloaded"] is True
    assert result["analytics_cache_cleared"] is True
    assert result["probe_cache_cleared"] is True
    assert result["packet_analysis_cache_cleared"] is True
    assert result["recon_runtime_cache_cleared"] is True


def test_clear_cache_handles_missing_deleted_count(monkeypatch):
    """clear_cache defaults deleted_count to 0 when missing from metadata result."""
    monkeypatch.setattr(
        rs_module.rawsniffer_service,
        "clear_metadata_cache",
        lambda remove_files=True: {"failed_count": 0},
    )
    monkeypatch.setattr(ms_module.analytics_service, "clear_cache", lambda: None)
    monkeypatch.setattr(ms_module.probe_service, "invalidate_cache", lambda: None)
    monkeypatch.setattr(
        ms_module.packet_analysis_service, "invalidate_cache", lambda: None
    )
    monkeypatch.setattr(ms_module, "_clear_recon_runtime_cache", lambda: None)
    monkeypatch.setattr(ms_module, "reload_data", lambda: None)

    result = ms_module.maintenance_service.clear_cache()

    assert result["raw_metadata_deleted_count"] == 0
    assert result["raw_metadata_failed_count"] == 0
