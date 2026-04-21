import json

from app.services import handshake_catalog
from app.tests.conftest import write_test_pcap


def test_handshake_catalog_groups_sources_and_scores_preferred_capture(
    tmp_path,
    monkeypatch,
):
    hand_dir = tmp_path / "handshakes"
    bruce_dir = tmp_path / "BrucePCAP"
    bruce_hand_dir = bruce_dir / "handshakes"
    m5evil_dir = tmp_path / "m5evil"
    m5evil_hand_dir = m5evil_dir / "handshakes"
    hand_dir.mkdir()
    bruce_dir.mkdir()
    bruce_hand_dir.mkdir()
    m5evil_dir.mkdir()
    m5evil_hand_dir.mkdir()

    monkeypatch.setattr(handshake_catalog, "HANDSHAKES_DIR", str(hand_dir))
    monkeypatch.setattr(handshake_catalog, "BRUCE_HANDSHAKES_DIR", str(bruce_hand_dir))
    monkeypatch.setattr(handshake_catalog, "BRUCE_PCAP_DIR", str(bruce_dir))
    monkeypatch.setattr(
        handshake_catalog, "M5EVIL_HANDSHAKES_DIR", str(m5evil_hand_dir)
    )

    write_test_pcap(hand_dir / "Cafe_aabbccddeeff.pcap")
    (hand_dir / "Cafe_aabbccddeeff.22000").write_text(
        "WPA*02*abc*001122334455*aabbccddeeff*74657374*00\n",
        encoding="utf-8",
    )
    (hand_dir / "Cafe_aabbccddeeff.pcap.cracked").write_text(
        "supersecret", encoding="utf-8"
    )
    (hand_dir / "Cafe_aabbccddeeff.details").write_text(
        json.dumps(
            {
                "ssid": "Cafe",
                "vendor": "Acme",
                "security": {"wpa_version": "WPA2", "akm": ["PSK"]},
                "classification": {"type": "router_ap", "confidence": 0.9},
                "radio": {"channel": 6, "band": "2.4"},
            }
        ),
        encoding="utf-8",
    )

    write_test_pcap(bruce_hand_dir / "HS_AABBCCDDEEFF.pcap")
    write_test_pcap(m5evil_hand_dir / "HS_AABBCCDDEEFF.pcap")

    catalog = handshake_catalog.build_handshake_catalog()
    handshake_set = catalog["AA:BB:CC:DD:EE:FF"]

    assert handshake_set["resolved_ssid"] == "Cafe"
    assert handshake_set["preferred_capture_id"]
    assert len(handshake_set["captures"]) == 3
    assert handshake_set["artifact_summary"]["pcap"] == 3
    assert handshake_set["artifact_summary"]["hash_22000"] == 1

    captures_by_source = {
        capture["source"]: capture for capture in handshake_set["captures"]
    }
    assert (
        captures_by_source["pwnagotchi"]["capture_id"]
        == handshake_set["preferred_capture_id"]
    )
    assert (
        captures_by_source["pwnagotchi"]["quality"]["score"]
        > captures_by_source["brucegotchi"]["quality"]["score"]
    )
    assert (
        captures_by_source["m5evil"]["quality"]["score"]
        < captures_by_source["pwnagotchi"]["quality"]["score"]
    )

    pcap_entries = [
        item
        for item in handshake_set["flat_files"]
        if item["name"] == "HS_AABBCCDDEEFF.pcap"
    ]
    assert len(pcap_entries) == 2
    assert {item["source"] for item in pcap_entries} == {"brucegotchi", "m5evil"}


def test_handshake_catalog_prefers_source_sidecars_and_lists_combined_candidates(
    tmp_path,
    monkeypatch,
):
    hand_dir = tmp_path / "handshakes"
    hand_dir.mkdir()

    monkeypatch.setattr(handshake_catalog, "HANDSHAKES_DIR", str(hand_dir))
    monkeypatch.setattr(
        handshake_catalog, "BRUCE_HANDSHAKES_DIR", str(tmp_path / "missing-bruce")
    )
    monkeypatch.setattr(
        handshake_catalog, "BRUCE_PCAP_DIR", str(tmp_path / "missing-bruce-root")
    )
    monkeypatch.setattr(
        handshake_catalog, "M5EVIL_HANDSHAKES_DIR", str(tmp_path / "missing-m5")
    )

    write_test_pcap(hand_dir / "Cafe_aabbccddeeff.pcap")

    initial_catalog = handshake_catalog.build_handshake_catalog()
    capture = initial_catalog["AA:BB:CC:DD:EE:FF"]["captures"][0]
    capture_id = capture["capture_id"]

    (hand_dir / "Cafe_aabbccddeeff.22000").write_text(
        "WPA*02*abc*001122334455*aabbccddeeff*74657374*00\n",
        encoding="utf-8",
    )
    (hand_dir / "Cafe_aabbccddeeff.details").write_text(
        json.dumps({"ssid": "Cafe", "security": {"wpa_version": "WPA2"}}),
        encoding="utf-8",
    )
    (hand_dir / "Cafe_aabbccddeeff.try").write_text(
        json.dumps([{"status": "started"}]),
        encoding="utf-8",
    )

    combined_dir = hand_dir / "combined" / "aabbccddeeff" / "build-123456"
    combined_dir.mkdir(parents=True)
    (combined_dir / "combined.22000").write_text(
        "WPA*02*abc*001122334455*aabbccddeeff*74657374*00\n",
        encoding="utf-8",
    )
    (combined_dir / "manifest.json").write_text(
        json.dumps(
            {
                "build_id": "build-123456",
                "included_capture_ids": [capture_id],
                "included_captures": [
                    {
                        "capture_id": capture_id,
                        "source": "pwnagotchi",
                        "device_label": "Pwnagotchi",
                        "source_filename": "Cafe_aabbccddeeff.pcap",
                        "source_kind": "converted_from_pcap",
                        "valid_hash_lines": 1,
                    }
                ],
                "deduped_hash_count": 1,
            }
        ),
        encoding="utf-8",
    )

    catalog = handshake_catalog.build_handshake_catalog()
    handshake_set = catalog["AA:BB:CC:DD:EE:FF"]
    pwn_capture = handshake_set["captures"][0]

    assert handshake_set["artifact_summary"]["combined"] == 1
    assert len(handshake_set["combined_candidates"]) == 1
    assert handshake_set["combined_candidates"][0]["build_id"] == "build-123456"
    assert handshake_set["combined_candidates"][0]["artifact_scope"] == "combined"
    assert (
        handshake_set["combined_candidates"][0]["included_captures"][0]["capture_id"]
        == capture_id
    )
    assert (
        handshake_set["combined_candidates"][0]["included_captures"][0]["source_kind"]
        == "converted_from_pcap"
    )

    details_entry = pwn_capture["artifacts"]["details"][0]
    hash_entry = pwn_capture["artifacts"]["hash_22000"][0]
    history_entry = pwn_capture["artifacts"]["history"][0]
    assert details_entry["artifact_scope"] == "capture"
    assert details_entry["artifact_owner_capture_id"] == capture_id
    assert hash_entry["name"] == "Cafe_aabbccddeeff.22000"
    assert hash_entry["artifact_scope"] == "capture"
    assert hash_entry["valid_hash_lines"] == 1
    assert history_entry["name"] == "Cafe_aabbccddeeff.try"

    flat_names = {
        (
            item["name"],
            item.get("artifact_scope"),
            item.get("artifact_owner_capture_id"),
        )
        for item in handshake_set["flat_files"]
    }
    assert ("Cafe_aabbccddeeff.22000", "capture", capture_id) in flat_names


def test_handshake_catalog_falls_back_to_legacy_capture_artifacts_with_source_names(
    tmp_path,
    monkeypatch,
):
    hand_dir = tmp_path / "handshakes"
    hand_dir.mkdir()

    monkeypatch.setattr(handshake_catalog, "HANDSHAKES_DIR", str(hand_dir))
    monkeypatch.setattr(
        handshake_catalog, "BRUCE_HANDSHAKES_DIR", str(tmp_path / "missing-bruce")
    )
    monkeypatch.setattr(
        handshake_catalog, "BRUCE_PCAP_DIR", str(tmp_path / "missing-bruce-root")
    )
    monkeypatch.setattr(
        handshake_catalog, "M5EVIL_HANDSHAKES_DIR", str(tmp_path / "missing-m5")
    )

    write_test_pcap(hand_dir / "Cafe_aabbccddeeff.pcap")
    initial_catalog = handshake_catalog.build_handshake_catalog()
    capture_id = initial_catalog["AA:BB:CC:DD:EE:FF"]["captures"][0]["capture_id"]

    capture_dir = hand_dir / "captures" / capture_id
    capture_dir.mkdir(parents=True)
    (capture_dir / "capture.details").write_text(
        json.dumps({"ssid": "Cafe"}), encoding="utf-8"
    )
    (capture_dir / "capture.try").write_text(
        json.dumps({"entries": [{"status": "started"}]}), encoding="utf-8"
    )

    catalog = handshake_catalog.build_handshake_catalog()
    capture = catalog["AA:BB:CC:DD:EE:FF"]["captures"][0]
    assert capture["artifacts"]["details"][0]["name"] == "Cafe_aabbccddeeff.details"
    assert capture["artifacts"]["history"][0]["name"] == "Cafe_aabbccddeeff.try"


def test_resolve_capture_pcap_returns_none_for_invalid_id(monkeypatch, tmp_path):
    hand_dir = tmp_path / "handshakes"
    hand_dir.mkdir()
    monkeypatch.setattr(handshake_catalog, "HANDSHAKES_DIR", str(hand_dir))

    assert handshake_catalog.resolve_capture_pcap("nonexistent-capture-id") is None


def test_build_handshake_catalog_empty_directories(tmp_path, monkeypatch):
    monkeypatch.setattr(handshake_catalog, "HANDSHAKES_DIR", str(tmp_path))
    monkeypatch.setattr(
        handshake_catalog, "BRUCE_HANDSHAKES_DIR", str(tmp_path / "missing")
    )
    monkeypatch.setattr(
        handshake_catalog, "M5EVIL_HANDSHAKES_DIR", str(tmp_path / "missing")
    )

    catalog = handshake_catalog.build_handshake_catalog()
    assert catalog == {}


def test_safe_stat_with_existing_file(tmp_path):
    """Test _safe_stat with an existing file."""
    test_file = tmp_path / "test.txt"
    test_file.write_text("content")

    result = handshake_catalog._safe_stat(str(test_file))
    assert result is not None
    assert result.st_size > 0


def test_safe_stat_with_nonexistent_file(tmp_path):
    """Test _safe_stat with a nonexistent file."""
    nonexistent = str(tmp_path / "does_not_exist.txt")
    result = handshake_catalog._safe_stat(nonexistent)
    assert result is None


def test_safe_read_json_with_valid_file(tmp_path):
    """Test _safe_read_json with a valid JSON file."""
    json_file = tmp_path / "test.json"
    json_file.write_text('{"key": "value"}')

    result = handshake_catalog._safe_read_json(str(json_file))
    assert result == {"key": "value"}


def test_safe_read_json_with_nonexistent_file(tmp_path):
    """Test _safe_read_json with a nonexistent file."""
    result = handshake_catalog._safe_read_json(str(tmp_path / "missing.json"))
    assert result is None


def test_safe_read_json_with_invalid_json(tmp_path):
    """Test _safe_read_json with invalid JSON content."""
    json_file = tmp_path / "bad.json"
    json_file.write_text("not valid json {[")

    result = handshake_catalog._safe_read_json(str(json_file))
    assert result is None


def test_safe_read_json_with_non_dict_content(tmp_path):
    """Test _safe_read_json with non-dict JSON content."""
    json_file = tmp_path / "array.json"
    json_file.write_text('["array", "not", "dict"]')

    result = handshake_catalog._safe_read_json(str(json_file))
    assert result is None


def test_infer_ssid_from_legacy_filename():
    """Test _infer_ssid_from_legacy_filename utility."""
    # Valid SSID with MAC (12 hex chars without separators)
    result = handshake_catalog._infer_ssid_from_legacy_filename(
        "MyNetwork_AABBCCDDEEFF.22000"
    )
    assert result == "MyNetwork"

    # Without MAC should return empty
    result = handshake_catalog._infer_ssid_from_legacy_filename("NoMacHere.22000")
    assert result == ""

    # Empty filename
    result = handshake_catalog._infer_ssid_from_legacy_filename("")
    assert result == ""


def test_extract_mac_and_ssid_prefixed_and_trailing():
    result_prefixed = handshake_catalog._extract_mac_and_ssid(
        "HS_AABBCCDDEEFF.pcap", "prefixed"
    )
    assert result_prefixed == ("AA:BB:CC:DD:EE:FF", "")

    result_trailing = handshake_catalog._extract_mac_and_ssid(
        "Cafe_AABBCCDDEEFF.22000", "legacy"
    )
    assert result_trailing == ("AA:BB:CC:DD:EE:FF", "Cafe")

    result_invalid = handshake_catalog._extract_mac_and_ssid(
        "invalid_file.txt", "legacy"
    )
    assert result_invalid == (None, "")


def test_make_capture_id_is_deterministic():
    capture_id1 = handshake_catalog._make_capture_id(
        "pwnagotchi", "handshakes", "Cafe_aabbccddeeff.pcap"
    )
    capture_id2 = handshake_catalog._make_capture_id(
        "pwnagotchi", "handshakes", "Cafe_aabbccddeeff.pcap"
    )
    assert capture_id1 == capture_id2
    assert capture_id1.startswith("pwnagotchi-handshakes-")


def test_classify_file_type_extensions():
    assert handshake_catalog._classify_file_type("file.pcap") == "pcap"
    assert handshake_catalog._classify_file_type("file.pcapng") == "pcap"
    assert handshake_catalog._classify_file_type("file.details") == "details"
    assert handshake_catalog._classify_file_type("file.22000") == "22000"
    assert handshake_catalog._classify_file_type("file.pcap.cracked") == "cracked"
    assert handshake_catalog._classify_file_type("file.try") == "try"
    assert handshake_catalog._classify_file_type("file.unknown") == "unknown"


def test_should_ignore_handshake_list_file():
    assert handshake_catalog._should_ignore_handshake_list_file("")
    assert handshake_catalog._should_ignore_handshake_list_file("Network.gps.json")
    assert handshake_catalog._should_ignore_handshake_list_file(
        "raw_001122334455.22000"
    )
    assert handshake_catalog._should_ignore_handshake_list_file("file.wdrs.json")
    assert handshake_catalog._should_ignore_handshake_list_file("__wdrs__raw_foo.pcap")
    assert not handshake_catalog._should_ignore_handshake_list_file("capture.pcap")


def test_build_artifact_entry_empty_22000(tmp_path):
    file_path = tmp_path / "artifact.22000"
    file_path.write_text("", encoding="utf-8")

    result = handshake_catalog._build_artifact_entry(
        path=str(file_path),
        role="handshakes",
        capture_id="capture1",
        source="pwnagotchi",
        device_label="Pwnagotchi",
        artifact_kind="pcap",
    )
    assert result is None


def test_build_artifact_entry_returns_none_for_missing_file():
    result = handshake_catalog._build_artifact_entry(
        path="/does/not/exist.pcap",
        role="handshakes",
        capture_id="capture1",
        source="pwnagotchi",
        device_label="Pwnagotchi",
        artifact_kind="legacy",
    )
    assert result is None
