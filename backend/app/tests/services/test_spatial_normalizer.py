"""
Tests for spatial normalization of Wi-Fi networks.

Tests cover:
- Deterministic jitter stability
- Cluster detection
- Source priority resolution
- Raw coordinate preservation
- Display coordinate calculation
"""

import math
from app.services.spatial_normalizer import (
    calculate_deterministic_jitter,
    apply_jitter_to_position,
    detect_position_clusters,
    get_source_priority,
    resolve_source_priority,
    normalize_network_positions,
    generate_deterministic_accuracy,
    _meters_to_lat_lng_delta,
    PositionMode,
)


class TestDeterministicAccuracy:
    """Test deterministic accuracy generation for wardrive CSV"""

    def test_accuracy_is_deterministic(self):
        """Same MAC always produces same accuracy"""
        mac = "AA:BB:CC:DD:EE:11"

        acc1 = generate_deterministic_accuracy(mac)
        acc2 = generate_deterministic_accuracy(mac)

        assert acc1 == acc2, "Same MAC should produce same accuracy"

    def test_different_macs_produce_different_accuracy(self):
        """Different MACs produce different accuracy values"""
        acc1 = generate_deterministic_accuracy("AA:BB:CC:DD:EE:11")
        acc2 = generate_deterministic_accuracy("AA:BB:CC:DD:EE:22")
        acc3 = generate_deterministic_accuracy("AA:BB:CC:DD:EE:33")

        # Very unlikely all three are same
        assert not (
            acc1 == acc2 == acc3
        ), f"Different MACs should produce different accuracies: {acc1}, {acc2}, {acc3}"

    def test_accuracy_within_default_range(self):
        """Accuracy values are within expected range"""
        for i in range(10):
            mac = f"AA:BB:CC:DD:EE:{i:02X}"
            acc = generate_deterministic_accuracy(mac)

            assert (
                3.0 <= acc <= 35.0
            ), f"Accuracy {acc} should be between 3.0 and 35.0 meters"

    def test_accuracy_custom_range(self):
        """Accuracy respects custom min/max parameters"""
        mac = "AA:BB:CC:DD:EE:11"

        acc = generate_deterministic_accuracy(mac, min_accuracy=10.0, max_accuracy=20.0)

        assert (
            10.0 <= acc <= 20.0
        ), f"Accuracy {acc} should be between 10.0 and 20.0 meters"

    def test_accuracy_distribution_varies(self):
        """Accuracy values have reasonable distribution across range"""
        accuracies = [
            generate_deterministic_accuracy(f"AA:BB:CC:DD:EE:{i:02X}")
            for i in range(50)
        ]

        min_acc = min(accuracies)
        max_acc = max(accuracies)

        # Should span most of the range, not cluster at edges
        assert min_acc < 10.0, "Should have some low accuracy values"
        assert max_acc > 25.0, "Should have some high accuracy values"
        assert max_acc - min_acc > 15.0, "Should have good distribution"


class TestDeterministicJitter:
    """Test deterministic jitter calculation"""

    def test_jitter_is_deterministic(self):
        """Same inputs produce same output"""
        bssid = "AA:BB:CC:DD:EE:FF"
        session = "test-session"
        accuracy = 5.0
        rssi = -50

        jitter1 = calculate_deterministic_jitter(bssid, session, accuracy, rssi)
        jitter2 = calculate_deterministic_jitter(bssid, session, accuracy, rssi)

        assert jitter1 == jitter2, "Jitter must be deterministic"

    def test_different_bssid_produces_different_jitter(self):
        """Different BSSID should produce different jitter"""
        session = "test-session"
        accuracy = 5.0
        rssi = -50

        jitter1 = calculate_deterministic_jitter(
            "AA:BB:CC:DD:EE:11", session, accuracy, rssi
        )
        jitter2 = calculate_deterministic_jitter(
            "AA:BB:CC:DD:EE:22", session, accuracy, rssi
        )

        assert jitter1 != jitter2, "Different BSSID should produce different jitter"

    def test_different_session_produces_different_jitter(self):
        """Different session ID should produce different jitter"""
        bssid = "AA:BB:CC:DD:EE:FF"
        accuracy = 5.0
        rssi = -50

        jitter1 = calculate_deterministic_jitter(bssid, "session1", accuracy, rssi)
        jitter2 = calculate_deterministic_jitter(bssid, "session2", accuracy, rssi)

        assert jitter1 != jitter2, "Different session should produce different jitter"

    def test_jitter_respects_accuracy_bounds(self):
        """Jitter should use bounded accuracy values"""
        bssid = "AA:BB:CC:DD:EE:FF"
        session = "test"

        # Test that different accuracies produce jitter based on clamped radius
        # The clamped range is [3, 12] meters

        # Very high accuracy -> clamped to 12m
        jitter_high_acc = calculate_deterministic_jitter(bssid, session, 1000, -50)
        offset_high = math.sqrt(jitter_high_acc[0] ** 2 + jitter_high_acc[1] ** 2)

        # Very low accuracy -> clamped to 3m
        jitter_low_acc = calculate_deterministic_jitter(bssid, session, 0.1, -50)
        offset_low = math.sqrt(jitter_low_acc[0] ** 2 + jitter_low_acc[1] ** 2)

        # The ratio should reflect the bounds (max/min = 12/3 = 4)
        # Allowing some tolerance for RSSI adjustment and rounding
        ratio = offset_high / offset_low if offset_low > 0 else 1
        assert 2 < ratio < 6  # Reasonable ratio given RSSI adjustment

        # Both should be positive and reasonable
        assert 0 < offset_high < 20
        assert 0 < offset_low < 20

    def test_stronger_rssi_produces_smaller_offset(self):
        """Stronger RSSI should produce smaller jitter offsets"""
        bssid = "AA:BB:CC:DD:EE:FF"
        session = "test"
        accuracy = 5.0

        # Very strong signal
        jitter_strong = calculate_deterministic_jitter(bssid, session, accuracy, -30)
        offset_strong = math.sqrt(jitter_strong[0] ** 2 + jitter_strong[1] ** 2)

        # Very weak signal
        jitter_weak = calculate_deterministic_jitter(bssid, session, accuracy, -90)
        offset_weak = math.sqrt(jitter_weak[0] ** 2 + jitter_weak[1] ** 2)

        # Weak should have larger offset
        assert offset_weak > offset_strong


class TestMetersToLatLngDelta:
    """Test conversion of meters to lat/lng deltas"""

    def test_zero_offset_produces_zero_delta(self):
        """Zero meter offsets should produce zero lat/lng deltas"""
        delta_lat, delta_lng = _meters_to_lat_lng_delta(0, 0, -22.0)
        assert delta_lat == 0
        assert delta_lng == 0

    def test_north_offset_increases_latitude(self):
        """North offset (meters_north > 0) should increase latitude"""
        delta_lat, _ = _meters_to_lat_lng_delta(0, 100, -22.0)
        assert delta_lat > 0
        # 100 meters / 111320 meters per degree ≈ 0.0009 degrees
        assert 0.0008 < delta_lat < 0.001

    def test_east_offset_affects_longitude(self):
        """East offset should affect longitude based on latitude"""
        _, delta_lng = _meters_to_lat_lng_delta(100, 0, -22.0)
        assert delta_lng > 0
        assert delta_lng < 0.002  # Should be reasonable for 100m

    def test_longitude_delta_varies_by_latitude(self):
        """Same east offset should produce different lng delta at different latitudes"""
        _, delta_lng_eq = _meters_to_lat_lng_delta(100, 0, 0)  # Equator
        _, delta_lng_pole = _meters_to_lat_lng_delta(100, 0, 85)  # Near pole

        # At the equator, 1 degree of longitude = 111.32 km
        # Near the pole (85°), 1 degree of longitude = 111.32 * cos(85°) = 9.7 km
        # So the same 100m east offset produces a LARGER degree delta near poles
        # (because degrees are physically smaller there)
        assert delta_lng_pole > delta_lng_eq


class TestClusterDetection:
    """Test cluster detection algorithm"""

    def test_single_network_no_cluster(self):
        """Single network should produce no clusters"""
        networks = {
            "AA:BB:CC:DD:EE:FF": {
                "mac": "AA:BB:CC:DD:EE:FF",
                "lat": -22.0,
                "lng": -43.0,
            }
        }

        clusters = detect_position_clusters(networks)

        # Should have one cluster with one network (not considered a cluster)
        assert len(clusters) == 1
        values = list(clusters.values())
        assert len(values[0]) == 1

    def test_multiple_networks_same_position(self):
        """Multiple networks at exact same position should form cluster"""
        networks = {
            "AA:BB:CC:DD:EE:11": {
                "mac": "AA:BB:CC:DD:EE:11",
                "lat": -22.0,
                "lng": -43.0,
            },
            "AA:BB:CC:DD:EE:22": {
                "mac": "AA:BB:CC:DD:EE:22",
                "lat": -22.0,
                "lng": -43.0,
            },
            "AA:BB:CC:DD:EE:33": {
                "mac": "AA:BB:CC:DD:EE:33",
                "lat": -22.0,
                "lng": -43.0,
            },
        }

        clusters = detect_position_clusters(networks)

        # All three should be in same cluster
        assert len(clusters) == 1
        values = list(clusters.values())
        assert len(values[0]) == 3

    def test_different_positions_different_clusters(self):
        """Networks at different positions should form different clusters"""
        networks = {
            "AA:BB:CC:DD:EE:11": {
                "mac": "AA:BB:CC:DD:EE:11",
                "lat": -22.0,
                "lng": -43.0,
            },
            "AA:BB:CC:DD:EE:22": {
                "mac": "AA:BB:CC:DD:EE:22",
                "lat": -22.1,
                "lng": -43.1,
            },
        }

        clusters = detect_position_clusters(networks)

        # Should have two separate clusters
        assert len(clusters) == 2


class TestSourcePriority:
    """Test source priority resolution"""

    def test_handshake_gps_highest_priority(self):
        """Pwnagotchi handshake GPS should have highest priority"""
        priority, confidence = get_source_priority("pwnagotchi-handshake-gps")

        assert priority == 1
        assert confidence == "high"

    def test_wardrive_lowest_priority(self):
        """Wardriving CSV should have lowest priority"""
        priority, confidence = get_source_priority("bruce-wardriving-csv")

        assert priority == 3
        assert confidence == "low"

    def test_legacy_source_aliases(self):
        """Legacy source names should map correctly"""
        priority1, _ = get_source_priority("wardrive")
        priority2, _ = get_source_priority("bruce-wardriving-csv")

        assert priority1 == priority2  # Should be equivalent

    def test_resolve_mixed_sources(self):
        """Should pick highest priority from mixed sources"""
        sources = ["bruce-wardriving-csv", "pwnagotchi-handshake-gps", "unknown"]

        preferred, priority, confidence = resolve_source_priority(sources)

        assert preferred == "pwnagotchi-handshake-gps"
        assert priority == 1
        assert confidence == "high"


class TestNormalizeNetworkPositions:
    """Test full network position normalization"""

    def test_single_network_no_jitter(self):
        """Single non-clustered network should not get jitter"""
        networks = {
            "AA:BB:CC:DD:EE:FF": {
                "mac": "AA:BB:CC:DD:EE:FF",
                "ssid": "TestSSID",
                "lat": -22.0,
                "lng": -43.0,
                "acc": 5.0,
                "altitude": 100,
                "sources": ["wardrive"],
            }
        }

        result = normalize_network_positions(networks, apply_jitter=True)

        network = result["AA:BB:CC:DD:EE:FF"]

        # Raw coordinates should be preserved
        assert network["rawLatitude"] == -22.0
        assert network["rawLongitude"] == -43.0

        # Display should match raw (no jitter)
        assert network["displayLatitude"] == -22.0
        assert network["displayLongitude"] == -43.0

        # Position mode should indicate jitter was not applied
        assert network["positionMode"] == PositionMode.RAW.value

    def test_clustered_networks_get_jitter(self):
        """Clustered networks should have different display coordinates"""
        networks = {
            "AA:BB:CC:DD:EE:11": {
                "mac": "AA:BB:CC:DD:EE:11",
                "ssid": "TestSSID",
                "lat": -22.0,
                "lng": -43.0,
                "acc": 5.0,
                "sources": ["wardrive"],
            },
            "AA:BB:CC:DD:EE:22": {
                "mac": "AA:BB:CC:DD:EE:22",
                "ssid": "TestSSID",
                "lat": -22.0,
                "lng": -43.0,
                "acc": 5.0,
                "sources": ["wardrive"],
            },
        }

        result = normalize_network_positions(networks, apply_jitter=True)

        net1 = result["AA:BB:CC:DD:EE:11"]
        net2 = result["AA:BB:CC:DD:EE:22"]

        # Raw coordinates should be identical
        assert net1["rawLatitude"] == net2["rawLatitude"]
        assert net1["rawLongitude"] == net2["rawLongitude"]

        # Display coordinates should be different
        assert (
            net1["displayLatitude"] != net2["displayLatitude"]
            or net1["displayLongitude"] != net2["displayLongitude"]
        )

        # Both should have jitter position mode
        assert net1["positionMode"] == PositionMode.DERIVED_JITTER.value
        assert net2["positionMode"] == PositionMode.DERIVED_JITTER.value

    def test_display_coordinates_are_close_to_raw(self):
        """Display coordinates should be very close to raw (within a few meters)"""
        networks = {
            "AA:BB:CC:DD:EE:11": {
                "mac": "AA:BB:CC:DD:EE:11",
                "lat": -22.0,
                "lng": -43.0,
                "acc": 5.0,
                "sources": ["wardrive"],
            },
            "AA:BB:CC:DD:EE:22": {
                "mac": "AA:BB:CC:DD:EE:22",
                "lat": -22.0,
                "lng": -43.0,
                "acc": 5.0,
                "sources": ["wardrive"],
            },
        }

        result = normalize_network_positions(networks, apply_jitter=True)

        net1 = result["AA:BB:CC:DD:EE:11"]

        # Calculate distance between raw and display
        lat_diff = net1["displayLatitude"] - net1["rawLatitude"]
        lng_diff = net1["displayLongitude"] - net1["rawLongitude"]

        # Each difference should be small (< 0.0002 degrees, ~20 meters)
        assert abs(lat_diff) < 0.0002
        assert abs(lng_diff) < 0.0002

    def test_lat_lng_updated_with_display_coordinates(self):
        """Verify that lat/lng are updated to display coordinates for frontend"""
        networks = {
            "AA:BB:CC:DD:EE:11": {
                "mac": "AA:BB:CC:DD:EE:11",
                "lat": -22.5,
                "lng": -43.5,
                "acc": 5.0,
                "sources": ["wardrive"],
            },
            "AA:BB:CC:DD:EE:22": {
                "mac": "AA:BB:CC:DD:EE:22",
                "lat": -22.5,
                "lng": -43.5,  # Same location
                "acc": 5.0,
                "sources": ["wardrive"],
            },
        }

        result = normalize_network_positions(networks, apply_jitter=True)

        net1 = result["AA:BB:CC:DD:EE:11"]
        net2 = result["AA:BB:CC:DD:EE:22"]

        # Verify raw coordinates are preserved
        assert net1["rawLatitude"] == -22.5
        assert net1["rawLongitude"] == -43.5

        # Verify lat/lng have been updated to display coordinates
        # (this is what the frontend sees)
        assert (
            net1["lat"] != -22.5 or net1["lng"] != -43.5
        ), "lat/lng should be updated to display coordinates (with jitter)"

        # Verify lat/lng match displayLatitude/displayLongitude
        assert (
            net1["lat"] == net1["displayLatitude"]
        ), "lat should equal displayLatitude for frontend"
        assert (
            net1["lng"] == net1["displayLongitude"]
        ), "lng should equal displayLongitude for frontend"

        # Verify the two clustered networks have different lat/lng now
        assert (net1["lat"], net1["lng"]) != (
            net2["lat"],
            net2["lng"],
        ), "Clustered networks should have different lat/lng (display coordinates)"

    def test_source_priority_set_correctly(self):
        """Source priority should be set based on highest priority source"""
        networks = {
            "AA:BB:CC:DD:EE:FF": {
                "mac": "AA:BB:CC:DD:EE:FF",
                "lat": -22.0,
                "lng": -43.0,
                "sources": ["bruce-wardriving-csv", "pwnagotchi-handshake-gps"],
            }
        }

        result = normalize_network_positions(networks)

        network = result["AA:BB:CC:DD:EE:FF"]

        assert network["sourcePriority"] == 1  # Handshake GPS has priority 1
        assert network["positionConfidence"] == "high"

    def test_raw_coordinates_preserved_through_normalization(self):
        """Raw coordinates should be exactly preserved"""
        networks = {
            "AA:BB:CC:DD:EE:FF": {
                "mac": "AA:BB:CC:DD:EE:FF",
                "lat": -22.123456,
                "lng": -43.654321,
                "acc": 7.5,
                "altitude": 42.0,
                "sources": ["wardrive"],
            }
        }

        result = normalize_network_positions(networks)

        network = result["AA:BB:CC:DD:EE:FF"]

        # Raw fields should exactly match original
        assert network["rawLatitude"] == -22.123456
        assert network["rawLongitude"] == -43.654321
        assert network["rawAccuracy"] == 7.5
        assert network["rawAltitude"] == 42.0


class TestClusterIndexJitter:
    """Tests for cluster position-based jitter differentiation"""

    def test_cluster_index_affects_offset_magnitude(self):
        """Verify networks in different cluster positions get different offset magnitudes"""
        bssid = "AA:BB:CC:DD:EE:11"
        session = "test-session"
        accuracy = 10.0
        rssi = None  # No RSSI (typical for CSV)

        # Same BSSID but different cluster positions
        jitter_pos0 = calculate_deterministic_jitter(
            bssid, session, accuracy, rssi, cluster_index=0, cluster_size=3
        )
        jitter_pos1 = calculate_deterministic_jitter(
            bssid, session, accuracy, rssi, cluster_index=1, cluster_size=3
        )
        jitter_pos2 = calculate_deterministic_jitter(
            bssid, session, accuracy, rssi, cluster_index=2, cluster_size=3
        )

        # Calculate magnitudes
        magnitude0 = math.sqrt(jitter_pos0[0] ** 2 + jitter_pos0[1] ** 2)
        magnitude1 = math.sqrt(jitter_pos1[0] ** 2 + jitter_pos1[1] ** 2)
        magnitude2 = math.sqrt(jitter_pos2[0] ** 2 + jitter_pos2[1] ** 2)

        # Each position should have different magnitude (0.3 multiplier increase)
        # pos0: 1.0x, pos1: 1.3x, pos2: 1.6x
        assert (
            magnitude1 > magnitude0
        ), f"pos1 ({magnitude1:.2f}) should > pos0 ({magnitude0:.2f})"
        assert (
            magnitude2 > magnitude1
        ), f"pos2 ({magnitude2:.2f}) should > pos1 ({magnitude1:.2f})"

        # Check that magnitudes increase (cluster indices affect offset magnitude)
        # Allow some tolerance in the ratio due to hash-based computation
        ratio_10 = magnitude1 / magnitude0
        ratio_21 = magnitude2 / magnitude1

        # Both ratios should be around 1.23-1.30 (the multipliers are 1.3 apart)
        assert (
            1.1 < ratio_10 < 1.4
        ), f"pos1/pos0 ratio {ratio_10:.2f} should be in range [1.1, 1.4]"
        assert (
            1.1 < ratio_21 < 1.4
        ), f"pos2/pos1 ratio {ratio_21:.2f} should be in range [1.1, 1.4]"

    def test_single_network_no_cluster_multiplier(self):
        """Single network in 'cluster' should use base multiplier (1.0)"""
        bssid = "AA:BB:CC:DD:EE:11"
        session = "test-session"
        accuracy = 10.0
        rssi = None

        # Single network (cluster_size=1) shouldn't get multiplier
        jitter_single = calculate_deterministic_jitter(
            bssid, session, accuracy, rssi, cluster_index=0, cluster_size=1
        )

        # Same query without explicit cluster params should give same result
        jitter_default = calculate_deterministic_jitter(bssid, session, accuracy, rssi)

        assert (
            jitter_single == jitter_default
        ), f"Single network should have same jitter as default: {jitter_single} vs {jitter_default}"

    def test_apply_jitter_with_cluster_position(self):
        """Integration test: apply_jitter_to_position with cluster info"""
        lat, lng = -22.5, -43.5
        bssid = "AA:BB:CC:DD:EE:11"
        session = "test-session"
        accuracy = 10.0
        rssi = None

        # Apply jitter at different cluster positions
        display_pos0 = apply_jitter_to_position(
            lat, lng, bssid, session, accuracy, rssi, cluster_index=0, cluster_size=3
        )
        display_pos1 = apply_jitter_to_position(
            lat, lng, bssid, session, accuracy, rssi, cluster_index=1, cluster_size=3
        )
        display_pos2 = apply_jitter_to_position(
            lat, lng, bssid, session, accuracy, rssi, cluster_index=2, cluster_size=3
        )

        # All should differ from raw position
        assert display_pos0 != (lat, lng)
        assert display_pos1 != (lat, lng)
        assert display_pos2 != (lat, lng)

        # All should differ from each other (different angles)
        assert display_pos0 != display_pos1
        assert display_pos1 != display_pos2
        assert display_pos0 != display_pos2

        # Calculate distances from center
        dist0 = math.sqrt((display_pos0[0] - lat) ** 2 + (display_pos0[1] - lng) ** 2)
        dist1 = math.sqrt((display_pos1[0] - lat) ** 2 + (display_pos1[1] - lng) ** 2)
        dist2 = math.sqrt((display_pos2[0] - lat) ** 2 + (display_pos2[1] - lng) ** 2)

        # Distances should increase with cluster position
        assert (
            dist1 > dist0
        ), f"Position 1 distance {dist1:.6f} should be > position 0 {dist0:.6f}"
        assert (
            dist2 > dist1
        ), f"Position 2 distance {dist2:.6f} should be > position 1 {dist1:.6f}"


class TestIntegration:
    """Integration tests for full workflow"""

    def test_wardrive_csv_import_workflow(self):
        """Test typical wardriving CSV import with multiple networks at same location"""
        # Simulate three networks imported from Bruce wardriving CSV
        networks = {
            "AA:BB:CC:DD:EE:11": {
                "mac": "AA:BB:CC:DD:EE:11",
                "ssid": "Network1",
                "lat": -22.5,
                "lng": -43.5,
                "acc": 6.0,
                "rssi": -45,
                "altitude": 150.0,
                "sources": ["wardrive"],
                "device_type": "unknown",
                "device_confidence": 0.0,
            },
            "AA:BB:CC:DD:EE:22": {
                "mac": "AA:BB:CC:DD:EE:22",
                "ssid": "Network2",
                "lat": -22.5,
                "lng": -43.5,  # Same location!
                "acc": 6.0,
                "rssi": -65,
                "altitude": 150.0,
                "sources": ["wardrive"],
                "device_type": "unknown",
                "device_confidence": 0.0,
            },
            "AA:BB:CC:DD:EE:33": {
                "mac": "AA:BB:CC:DD:EE:33",
                "ssid": "Network3",
                "lat": -22.5,
                "lng": -43.5,  # Same location!
                "acc": 6.0,
                "rssi": -70,
                "altitude": 150.0,
                "sources": ["wardrive"],
                "device_type": "unknown",
                "device_confidence": 0.0,
            },
        }

        result = normalize_network_positions(networks, apply_jitter=True)

        # Verify all networks are present
        assert len(result) == 3

        # Verify raw coordinates are preserved for all
        for mac in networks:
            assert result[mac]["rawLatitude"] == -22.5
            assert result[mac]["rawLongitude"] == -43.5

        # Verify display coordinates are different for each
        display_coords = [
            (result[mac]["displayLatitude"], result[mac]["displayLongitude"])
            for mac in networks
        ]

        # All display coordinates should be unique
        assert len(set(display_coords)) == 3

        # Verify all have jitter position mode (since they're clustered)
        for mac in networks:
            assert result[mac]["positionMode"] == PositionMode.DERIVED_JITTER.value

    def test_mixed_networks_with_no_gps(self):
        """Test normalization with mix of GPS and no-GPS networks"""
        networks = {
            # Networks with GPS position
            "AA:BB:CC:DD:EE:11": {
                "mac": "AA:BB:CC:DD:EE:11",
                "ssid": "Network1",
                "lat": -22.5,
                "lng": -43.5,
                "acc": 6.0,
                "sources": ["wardrive"],
            },
            "AA:BB:CC:DD:EE:22": {
                "mac": "AA:BB:CC:DD:EE:22",
                "ssid": "Network2",
                "lat": -22.5,
                "lng": -43.5,  # Same location as Network1
                "acc": 6.0,
                "sources": ["wardrive"],
            },
            # No-GPS network (from Pwnagotchi without handshake GPS)
            "AA:BB:CC:DD:EE:33": {
                "mac": "AA:BB:CC:DD:EE:33",
                "ssid": "Network3",
                "lat": None,  # No GPS
                "lng": None,
                "acc": 0,
                "type": "no-gps",
                "sources": ["pwnagotchi"],
            },
        }

        # Should not raise any errors
        result = normalize_network_positions(networks, apply_jitter=True)

        # Verify all networks are still in result
        assert len(result) == 3

        # Verify no-GPS network is unchanged
        assert result["AA:BB:CC:DD:EE:33"]["lat"] is None
        assert result["AA:BB:CC:DD:EE:33"]["lng"] is None

        # Verify GPS networks have different display coordinates (jitter applied)
        net11 = result["AA:BB:CC:DD:EE:11"]
        net22 = result["AA:BB:CC:DD:EE:22"]

        assert (
            net11["displayLatitude"] != net22["displayLatitude"]
            or net11["displayLongitude"] != net22["displayLongitude"]
        )
