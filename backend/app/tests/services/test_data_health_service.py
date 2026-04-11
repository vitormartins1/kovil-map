import json

from app.services import data_health_service as dh_module


def test_data_health_summary_counts(tmp_path, monkeypatch):
    hand_dir = tmp_path / "handshakes"
    hand_dir.mkdir()

    monkeypatch.setattr(dh_module, "HANDSHAKES_DIR", str(hand_dir))

    # PCAP inventory
    (hand_dir / "net1.pcap").write_text("pcap", encoding="utf-8")
    (hand_dir / "net_missing.pcap").write_text("pcap", encoding="utf-8")
    (hand_dir / "HS_AABBCCDDEEFF.pcap").write_text("pcap", encoding="utf-8")

    # Details inventory
    (hand_dir / "net1.details").write_text(
        json.dumps({"ssid": "VisibleNet"}), encoding="utf-8"
    )
    (hand_dir / "HS_AABBCCDDEEFF.details").write_text(
        json.dumps({"ssid": "   "}), encoding="utf-8"
    )
    (hand_dir / "HS_112233445566.details").write_text(
        json.dumps({"ssid": "BruceVisible"}), encoding="utf-8"
    )
    (hand_dir / "HS_776655443322.details").write_text("{", encoding="utf-8")
    (hand_dir / "ghost.details").write_text(
        json.dumps({"ssid": "GhostNet"}), encoding="utf-8"
    )

    monkeypatch.setattr(
        dh_module,
        "load_real_data",
        lambda: {
            "AA:AA:AA:AA:AA:AA": {
                "ssid": "VisibleNet",
                "lat": -22.0,
                "lng": -43.0,
                "sources": ["pwnagotchi"],
            },
            "BB:BB:BB:BB:BB:BB": {
                "ssid": "",
                "lat": None,
                "lng": None,
                "sources": ["brucegotchi", "wardrive"],
            },
        },
    )
    monkeypatch.setattr(
        dh_module,
        "list_bruce_handshake_files",
        lambda: [
            "HS_AABBCCDDEEFF.pcap",
            "HS_112233445566.pcap",
            "HS_776655443322.pcap",
            "HS_998877665544.pcap",
        ],
    )
    monkeypatch.setattr(
        dh_module,
        "list_m5evil_handshake_files",
        lambda: [
            "HS_AABBCCDDEEFF_m5.pcap",
            "HS_112233445566_m5.pcap",
            "HS_778899AABBCC_m5.pcap",
        ],
    )
    (hand_dir / "HS_AABBCCDDEEFF_m5.details").write_text(
        json.dumps({"ssid": "   "}), encoding="utf-8"
    )
    (hand_dir / "HS_112233445566_m5.details").write_text(
        json.dumps({"ssid": "M5Visible"}), encoding="utf-8"
    )
    monkeypatch.setattr(
        dh_module.rawsniffer_service,
        "list_files",
        lambda: [
            {"filename": "raw_1.pcap", "cached_up_to_date": True, "warnings_count": 0},
            {"filename": "raw_2.pcap", "cached_up_to_date": False, "warnings_count": 2},
        ],
    )
    monkeypatch.setattr(
        dh_module.rawsniffer_service, "get_pending_files", lambda: ["raw_2.pcap"]
    )

    summary = dh_module.data_health_service.get_summary()

    assert summary["schema_version"] == 1
    assert summary["dataset"]["total_networks"] == 2
    assert summary["dataset"]["with_gps"] == 1
    assert summary["dataset"]["no_gps"] == 1
    assert summary["dataset"]["hidden_networks"] == 1
    assert summary["dataset"]["source_counts"] == {
        "pwnagotchi": 1,
        "brucegotchi": 1,
        "wardrive": 1,
    }

    assert summary["handshakes"]["pcap_files"] == 3
    assert summary["handshakes"]["details_files"] == 7
    assert summary["handshakes"]["invalid_details"] == 1
    assert summary["handshakes"]["hidden_details"] == 2
    assert summary["handshakes"]["handshake_without_details"] == 1
    assert summary["handshakes"]["details_without_handshake"] == 5

    assert summary["bruce"]["handshakes_seen"] == 4
    assert summary["bruce"]["hidden_refresh_candidates"] == 1
    assert summary["bruce"]["missing_details"] == 1
    assert summary["bruce"]["invalid_details"] == 1
    assert summary["m5evil"]["handshakes_seen"] == 3
    assert summary["m5evil"]["hidden_refresh_candidates"] == 1
    assert summary["m5evil"]["missing_details"] == 1
    assert summary["m5evil"]["invalid_details"] == 0

    assert summary["rawsniffer"]["files_seen"] == 2
    assert summary["rawsniffer"]["pending_files"] == 1
    assert summary["rawsniffer"]["cached_up_to_date_files"] == 1
    assert summary["rawsniffer"]["files_with_warnings"] == 1
