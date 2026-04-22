from app.services.network_state import classify_network_state, handshake_artifact_flags


def test_classify_network_state_prefers_locked_and_cracked_states():
    locked = {
        "type": "ap",
        "lat": -22.9,
        "lng": -43.2,
        "encryption": "WPA2",
        **handshake_artifact_flags(
            preferred_pcap_size=1200,
            valid_hash_lines=1,
            details_count=1,
            cracked_count=0,
            pcap_count=1,
        ),
    }
    result = classify_network_state(locked)
    assert result["network_state"] == "locked"
    assert result["locked"] is True
    assert result["attackable"] is True

    cracked = {
        "type": "ap",
        "lat": -22.9,
        "lng": -43.2,
        "encryption": "WPA2",
        "pass": "demo-pass",
        **handshake_artifact_flags(
            preferred_pcap_size=1200,
            valid_hash_lines=1,
            details_count=1,
            cracked_count=1,
            pcap_count=1,
        ),
    }
    result = classify_network_state(cracked)
    assert result["network_state"] == "cracked"
    assert result["cracked"] is True
    assert result["locked"] is False


def test_classify_network_state_separates_not_ready_and_no_gps_locked():
    not_ready = {
        "type": "ap",
        "lat": -22.9,
        "lng": -43.2,
        "encryption": "WPA2",
        **handshake_artifact_flags(
            preferred_pcap_size=90,
            valid_hash_lines=0,
            details_count=1,
            cracked_count=0,
            pcap_count=1,
            raw_eapol_count=2,
        ),
    }
    result = classify_network_state(not_ready)
    assert result["network_state"] == "not_ready"
    assert result["attackable"] is True
    assert result["locked"] is False

    no_gps_locked = {
        "type": "no-gps",
        "encryption": "WPA2",
        **handshake_artifact_flags(
            preferred_pcap_size=1200,
            valid_hash_lines=1,
            details_count=1,
            cracked_count=0,
            pcap_count=1,
        ),
    }
    result = classify_network_state(no_gps_locked)
    assert result["network_state"] == "no_gps_locked"
    assert result["attackable"] is True
    assert result["no_gps_locked"] is True
