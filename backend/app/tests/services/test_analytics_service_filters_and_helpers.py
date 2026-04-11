"""Analytics service tests for filters, empty states, and helper methods."""

import pytest

from app.services import analytics_service as as_module


@pytest.fixture(autouse=True)
def patch_analytics_runtime(monkeypatch):
    monkeypatch.setattr(as_module, "load_real_data", lambda: {})
    monkeypatch.setattr(as_module, "get_wardrive_sessions", lambda: [])


def test_analytics_service_clear_cache():
    """Test clear_cache resets internal state."""
    service = as_module.AnalyticsService()
    service.clear_cache()


def test_analytics_service_get_heatmap_with_filters():
    """Test get_heatmap with filter parameters."""
    service = as_module.AnalyticsService()
    result = service.get_heatmap(
        channel=6,
        device_type="router_ap",
        security="wpa2",
        metric="density",
        cell_size_m=100,
    )
    assert isinstance(result, dict)
    assert "cells" in result


def test_analytics_service_get_channel_summary_with_filters():
    """Test get_channel_summary with filter parameters."""
    service = as_module.AnalyticsService()
    result = service.get_channel_summary(
        channel=6,
        device_type="router_ap",
        security="wpa2",
        metric="density",
    )
    assert isinstance(result, dict)
    assert "channels" in result


def test_analytics_service_get_hotspots_with_filters():
    """Test get_hotspots with filter parameters."""
    service = as_module.AnalyticsService()
    result = service.get_hotspots(
        channel=6,
        device_type="router_ap",
        security="wpa2",
        limit=10,
    )
    assert isinstance(result, dict)
    assert "hotspots" in result


def test_analytics_service_get_heatmap_with_channel_filter():
    """Test get_heatmap with channel filter."""
    service = as_module.AnalyticsService()
    result = service.get_heatmap(channel=6)
    assert isinstance(result, dict)
    assert "cells" in result


def test_analytics_service_get_heatmap_with_device_type_filter():
    """Test get_heatmap with device_type filter."""
    service = as_module.AnalyticsService()
    result = service.get_heatmap(device_type="router_ap")
    assert isinstance(result, dict)
    assert "cells" in result


def test_analytics_service_get_channel_summary_with_channel_filter():
    """Test get_channel_summary with channel filter."""
    service = as_module.AnalyticsService()
    result = service.get_channel_summary(channel=1)
    assert isinstance(result, dict)
    assert "channels" in result


def test_analytics_service_get_hotspots_with_limit():
    """Test get_hotspots with limit parameter."""
    service = as_module.AnalyticsService()
    result = service.get_hotspots(limit=5)
    assert isinstance(result, dict)
    assert "hotspots" in result
    assert len(result["hotspots"]) <= 5


def test_analytics_service_get_heatmap_empty():
    """Test get_heatmap with empty data."""
    service = as_module.AnalyticsService()
    result = service.get_heatmap()
    assert isinstance(result, dict)
    assert "cells" in result
    assert isinstance(result["cells"], list)


def test_analytics_service_get_channel_summary_empty():
    """Test get_channel_summary with empty data."""
    service = as_module.AnalyticsService()
    result = service.get_channel_summary()
    assert isinstance(result, dict)
    assert "channels" in result
    assert isinstance(result["channels"], list)


def test_analytics_service_get_hotspots_empty():
    """Test get_hotspots with empty data."""
    service = as_module.AnalyticsService()
    result = service.get_hotspots()
    assert isinstance(result, dict)
    assert "hotspots" in result
    assert isinstance(result["hotspots"], list)


class TestAnalyticsServiceFilterScenarios:
    """Additional filter matrix scenarios."""

    def test_get_channel_summary_with_filters(self):
        """Test get_channel_summary with various filters."""
        service = as_module.AnalyticsService()
        result = service.get_channel_summary(
            channel=6, device_type="router_ap", security="wpa2", metric="density"
        )
        assert isinstance(result, dict)

    def test_get_hotspots_with_all_filters(self):
        """Test get_hotspots with all filter parameters."""
        service = as_module.AnalyticsService()
        result = service.get_hotspots(
            channel=1,
            device_type="router_ap",
            security="locked",
            limit=5,
            metric="density",
        )
        assert isinstance(result, dict)


class TestAnalyticsServiceHelpers:
    """Helper method behavior for analytics_service."""

    def test_is_open_encryption(self):
        """Test _is_open_encryption."""
        service = as_module.AnalyticsService()
        assert service._is_open_encryption("OPEN") is True
        assert service._is_open_encryption("WEP") is True
        assert service._is_open_encryption("WPA2") is False
        assert service._is_open_encryption(None) is False

    def test_normalize_device_type(self):
        """Test _normalize_device_type."""
        service = as_module.AnalyticsService()
        assert service._normalize_device_type("router") == "router_ap"
        assert service._normalize_device_type("hotspot") == "phone_hotspot"
        assert service._normalize_device_type("unknown") == "unknown"
        assert service._normalize_device_type(None) == "unknown"

    def test_clamp(self):
        """Test _clamp."""
        assert as_module.AnalyticsService._clamp(5, 0, 10) == 5
        assert as_module.AnalyticsService._clamp(-1, 0, 10) == 0
        assert as_module.AnalyticsService._clamp(11, 0, 10) == 10

    def test_safe_float(self):
        """Test _safe_float."""
        assert as_module.AnalyticsService._safe_float("1.5") == 1.5
        assert as_module.AnalyticsService._safe_float("invalid") is None
        assert as_module.AnalyticsService._safe_float(None) is None

    def test_safe_int(self):
        """Test _safe_int."""
        assert as_module.AnalyticsService._safe_int("5") == 5
        assert as_module.AnalyticsService._safe_int("invalid") is None
        assert as_module.AnalyticsService._safe_int(None) is None
