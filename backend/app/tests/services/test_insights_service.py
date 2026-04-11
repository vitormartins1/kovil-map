import json

from app.services import insights_service as is_module


def test_attack_score_and_recommendation_with_valid_context(tmp_path, monkeypatch):
    hand_dir = tmp_path / "handshakes"
    hand_dir.mkdir()
    monkeypatch.setattr(is_module, "HANDSHAKES_DIR", str(hand_dir))

    hash_file = hand_dir / "Net_AABBCCDDEEFF.22000"
    hash_file.write_text(
        "WPA*02*deadbeef*aabbccddeeff*112233445566*4e65744f6e65*00\n",
        encoding="utf-8",
    )
    (hand_dir / "Net_AABBCCDDEEFF.details").write_text(
        json.dumps(
            {
                "ssid": "NetOne",
                "security": {"pmf": "None"},
                "wps": {"present": True},
            }
        ),
        encoding="utf-8",
    )
    (hand_dir / "Net_AABBCCDDEEFF.try").write_text(
        json.dumps({"entries": [{"status": "EXHAUSTED"}]}), encoding="utf-8"
    )

    monkeypatch.setattr(
        is_module,
        "load_real_data",
        lambda: {
            "AA:BB:CC:DD:EE:FF": {
                "mac": "AA:BB:CC:DD:EE:FF",
                "ssid": "NetOne",
                "encryption": "WPA2",
                "handshake": True,
                "raw_eapol_count": 1,
            }
        },
    )
    monkeypatch.setattr(
        is_module.rawsniffer_service,
        "get_aggregated_metadata_for_bssid",
        lambda _mac: {
            "present": True,
            "aggregate": {"eapol_count_total": 2, "beacon_count_total": 15},
        },
    )

    score = is_module.insights_service.get_attack_score(mac="aa:bb:cc:dd:ee:ff")
    assert score["score"] >= 60
    assert score["priority"] in {"high", "medium"}
    assert score["signals"]["hash"]["valid_hash_lines"] == 1

    recommendation = is_module.insights_service.get_attack_recommendation(
        filename="Net_AABBCCDDEEFF.22000"
    )
    assert recommendation["action"] == "run"
    assert recommendation["recommended_mode"] in {"rules", "straight", "hybrid"}
    assert recommendation["quality_gate"]["passed"] is True
    assert recommendation["handshake_readiness"]["status"] == "ready"
    assert recommendation["handshake_readiness"]["signals"]["valid_hash_lines"] == 1


def test_quality_gate_blocks_invalid_hash_file(tmp_path, monkeypatch):
    hand_dir = tmp_path / "handshakes"
    hand_dir.mkdir()
    monkeypatch.setattr(is_module, "HANDSHAKES_DIR", str(hand_dir))

    (hand_dir / "bad.22000").write_text("invalid-line\n", encoding="utf-8")
    monkeypatch.setattr(is_module, "load_real_data", lambda: {})
    monkeypatch.setattr(
        is_module.rawsniffer_service,
        "get_aggregated_metadata_for_bssid",
        lambda _mac: {"present": False},
    )

    gate = is_module.insights_service.evaluate_quality_gate("bad.22000")
    assert gate["passed"] is False
    assert gate["code"] == "quality_gate_blocked"
    assert gate["can_override"] is False


def test_quality_gate_requires_override_when_already_cracked(tmp_path, monkeypatch):
    hand_dir = tmp_path / "handshakes"
    hand_dir.mkdir()
    monkeypatch.setattr(is_module, "HANDSHAKES_DIR", str(hand_dir))
    monkeypatch.setattr(is_module, "load_real_data", lambda: {})

    (hand_dir / "good.22000").write_text(
        "WPA*02*deadbeef*aabbccddeeff*112233445566*4e65744f6e65*00\n",
        encoding="utf-8",
    )
    (hand_dir / "good.pcap.cracked").write_text("password", encoding="utf-8")
    monkeypatch.setattr(
        is_module.rawsniffer_service,
        "get_aggregated_metadata_for_bssid",
        lambda _mac: {"present": False},
    )

    gate = is_module.insights_service.evaluate_quality_gate("good.22000")
    assert gate["passed"] is False
    assert gate["code"] == "quality_gate_overrideable"
    assert gate["can_override"] is True


def test_attack_score_does_not_treat_generic_success_as_already_cracked(
    tmp_path, monkeypatch
):
    hand_dir = tmp_path / "handshakes"
    hand_dir.mkdir()
    monkeypatch.setattr(is_module, "HANDSHAKES_DIR", str(hand_dir))

    (hand_dir / "Net_AABBCCDDEEFF.22000").write_text(
        "WPA*02*deadbeef*aabbccddeeff*112233445566*4e65744f6e65*00\n",
        encoding="utf-8",
    )
    (hand_dir / "Net_AABBCCDDEEFF.try").write_text(
        json.dumps({"entries": [{"status": "SUCCESS", "tool": "fingerprint"}]}),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        is_module,
        "load_real_data",
        lambda: {
            "AA:BB:CC:DD:EE:FF": {
                "mac": "AA:BB:CC:DD:EE:FF",
                "ssid": "NetOne",
                "encryption": "WPA2",
                "handshake": True,
            }
        },
    )
    monkeypatch.setattr(
        is_module.rawsniffer_service,
        "get_aggregated_metadata_for_bssid",
        lambda _mac: {"present": False},
    )

    score = is_module.insights_service.get_attack_score(
        filename="Net_AABBCCDDEEFF.22000"
    )
    reasons = [item.get("reason") for item in score.get("score_reasons", [])]
    assert score["score"] > 0
    assert "Network already cracked." not in reasons


def test_handshake_readiness_reports_weak_ready_with_raw_eapol(tmp_path, monkeypatch):
    hand_dir = tmp_path / "handshakes"
    hand_dir.mkdir()
    monkeypatch.setattr(is_module, "HANDSHAKES_DIR", str(hand_dir))
    monkeypatch.setattr(is_module, "BRUCE_PCAP_DIR", str(tmp_path / "BrucePCAP"))
    (tmp_path / "BrucePCAP").mkdir()

    monkeypatch.setattr(
        is_module,
        "load_real_data",
        lambda: {
            "AA:BB:CC:DD:EE:FF": {
                "mac": "AA:BB:CC:DD:EE:FF",
                "ssid": "",
                "encryption": "WPA2",
                "handshake": True,
            }
        },
    )
    monkeypatch.setattr(
        is_module.rawsniffer_service,
        "get_aggregated_metadata_for_bssid",
        lambda _mac: {
            "present": True,
            "files_count": 1,
            "aggregate": {
                "eapol_count_total": 4,
                "beacon_count_total": 12,
                "warnings": [],
            },
            "files": [{"source_file": "raw_1.pcap"}],
        },
    )

    readiness = is_module.insights_service.get_handshake_readiness(
        mac="AA:BB:CC:DD:EE:FF"
    )
    assert readiness["present"] is True
    assert readiness["readiness"]["status"] == "weak_ready"
    assert readiness["readiness"]["signals"]["raw_eapol_total"] == 4
    assert readiness["readiness"]["enrichment"]["needs_enrichment"] is True


def test_attack_recommendation_includes_hashcat_attempt_feedback(tmp_path, monkeypatch):
    hand_dir = tmp_path / "handshakes"
    hand_dir.mkdir()
    monkeypatch.setattr(is_module, "HANDSHAKES_DIR", str(hand_dir))

    hash_file = hand_dir / "Net_AABBCCDDEEFF.22000"
    hash_file.write_text(
        "WPA*02*deadbeef*aabbccddeeff*112233445566*4e65744f6e65*00\n",
        encoding="utf-8",
    )

    history_payload = {
        "entries": [
            {
                "tool": "hashcat",
                "status": "EXHAUSTED",
                "start_time": "2026-03-01T10:00:00",
                "params": {
                    "attack_mode": "rules",
                    "workload": "3",
                    "wordlist": "/opt/wordlists/top.txt",
                    "rule": "/opt/rules/best64.rule",
                },
            },
            {
                "tool": "hashcat",
                "status": "FAILED",
                "start_time": "2026-03-02T10:00:00",
                "params": {
                    "attack_mode": "straight",
                    "workload": "4",
                    "device": "Device #1",
                },
            },
            {
                "tool": "fingerprint",
                "status": "FAILED",
                "start_time": "2026-03-02T12:00:00",
                "params": {},
            },
            {
                "tool": "hashcat",
                "status": "CRACKED",
                "start_time": "2026-03-03T10:00:00",
                "params": {"attack_mode": "straight", "optimized": True},
            },
            {
                "tool": "hashcat",
                "status": "RUNNING",
                "start_time": "2026-03-04T10:00:00",
                "params": {"attack_mode": "rules"},
            },
        ]
    }
    (hand_dir / "Net_AABBCCDDEEFF.try").write_text(
        json.dumps(history_payload), encoding="utf-8"
    )

    monkeypatch.setattr(
        is_module,
        "load_real_data",
        lambda: {
            "AA:BB:CC:DD:EE:FF": {
                "mac": "AA:BB:CC:DD:EE:FF",
                "ssid": "NetOne",
                "encryption": "WPA2",
                "handshake": True,
            }
        },
    )
    monkeypatch.setattr(
        is_module.rawsniffer_service,
        "get_aggregated_metadata_for_bssid",
        lambda _mac: {"present": False},
    )

    recommendation = is_module.insights_service.get_attack_recommendation(
        filename="Net_AABBCCDDEEFF.22000"
    )

    feedback = recommendation.get("attempt_feedback")
    assert feedback is not None
    assert feedback["scope"] == "hashcat"
    assert feedback["totals"]["attempts"] == 4
    assert feedback["totals"]["distinct_modes"] == 2
    assert feedback["totals"]["exhausted"] == 1
    assert feedback["totals"]["fatal"] == 1
    assert feedback["totals"]["cracked"] == 1

    assert len(feedback["recent"]) == 4
    assert feedback["recent"][0]["mode"] == "rules"
    assert feedback["recent"][0]["outcome"] == "running"
    assert feedback["recent"][-1]["mode"] == "rules"
    assert feedback["recent"][-1]["outcome"] == "exhausted"

    exhausted_item = feedback["recent"][-1]
    assert exhausted_item["params"]["wordlist"] == "top.txt"
    assert exhausted_item["params"]["rule"] == "best64.rule"


def test_attack_recommendation_combined_quality_gate_uses_mac_for_history_lookup(
    tmp_path, monkeypatch
):
    hand_dir = tmp_path / "handshakes"
    combined_dir = hand_dir / "combined" / "e01fedba23d1" / "build-abc123"
    combined_dir.mkdir(parents=True)
    monkeypatch.setattr(is_module, "HANDSHAKES_DIR", str(hand_dir))
    monkeypatch.setattr(is_module.history_service, "get_history_path", lambda *args, **kwargs: str(combined_dir / "combined.try"))

    (combined_dir / "combined.22000").write_text(
        "WPA*02*deadbeef*e01fedba23d1*112233445566*4e65744f6e65*00\n",
        encoding="utf-8",
    )
    (combined_dir / "combined.try").write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "tool": "hashcat",
                        "status": "EXHAUSTED",
                        "params": {"attack_mode": "rules"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        is_module,
        "load_real_data",
        lambda: {
            "E0:1F:ED:BA:23:D1": {
                "mac": "E0:1F:ED:BA:23:D1",
                "ssid": "NetOne",
                "encryption": "WPA2",
                "handshake": True,
            }
        },
    )
    monkeypatch.setattr(
        is_module.rawsniffer_service,
        "get_aggregated_metadata_for_bssid",
        lambda _mac: {"present": False},
    )

    recommendation = is_module.insights_service.get_attack_recommendation(
        mac="E0:1F:ED:BA:23:D1",
        filename="combined.22000",
        combined_build_id="build-abc123",
    )

    assert recommendation["recommended_mode"] == "rules"
    assert recommendation["quality_gate"]["passed"] is False
    assert recommendation["quality_gate"]["code"] == "history_exhausted"
