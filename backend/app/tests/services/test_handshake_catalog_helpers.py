from app.services import handshake_catalog


def test_classify_file_type():
    assert handshake_catalog._classify_file_type("test.pcap") == "pcap"
    assert handshake_catalog._classify_file_type("test.pcapng") == "pcap"
    assert handshake_catalog._classify_file_type("test.details") == "details"
    assert handshake_catalog._classify_file_type("test.22000") == "22000"
    assert handshake_catalog._classify_file_type("test.cracked") == "cracked"
    assert handshake_catalog._classify_file_type("test.pcap.cracked") == "cracked"
    assert handshake_catalog._classify_file_type("test.try") == "try"
    assert handshake_catalog._classify_file_type("test.txt") == "txt"
    # Case insensitive
    assert handshake_catalog._classify_file_type("TEST.PCAP") == "pcap"
    assert handshake_catalog._classify_file_type("Test.22000") == "22000"


def test_should_ignore_handshake_list_file():
    # Files to ignore (checking actual implementation logic)
    # Only files with _IGNORED_EXTENSIONS or matching patterns are ignored
    assert handshake_catalog._should_ignore_handshake_list_file("test.gps.json")
    assert handshake_catalog._should_ignore_handshake_list_file("test.geo.json")
    assert handshake_catalog._should_ignore_handshake_list_file("test.paw-gps.json")
    assert handshake_catalog._should_ignore_handshake_list_file("raw_data.22000")
    assert handshake_catalog._should_ignore_handshake_list_file("test.wdrs.json")
    assert handshake_catalog._should_ignore_handshake_list_file("__wdrs__raw_test.pcap")
    assert handshake_catalog._should_ignore_handshake_list_file("")
    assert handshake_catalog._should_ignore_handshake_list_file(None)

    # Files to keep
    assert not handshake_catalog._should_ignore_handshake_list_file(
        "net_aabbccddeeff.pcap"
    )
    assert not handshake_catalog._should_ignore_handshake_list_file(
        "HS_AABBCCDDEEFF.pcap"
    )
    assert not handshake_catalog._should_ignore_handshake_list_file(".gitignore")


def test_normalize_mac_token():
    # Valid MAC addresses
    assert handshake_catalog.normalize_mac_token("aa:bb:cc:dd:ee:ff") == "aabbccddeeff"
    assert handshake_catalog.normalize_mac_token("AA:BB:CC:DD:EE:FF") == "aabbccddeeff"
    assert handshake_catalog.normalize_mac_token("aabbccddeeff") == "aabbccddeeff"

    # Invalid MAC addresses
    assert handshake_catalog.normalize_mac_token("not:a:mac") is None
    assert handshake_catalog.normalize_mac_token("") is None
    assert handshake_catalog.normalize_mac_token(None) is None


def test_normalize_mac():
    # Valid MAC addresses
    assert handshake_catalog.normalize_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"
    assert handshake_catalog.normalize_mac("aabbccddeeff") == "AA:BB:CC:DD:EE:FF"

    # Invalid MAC addresses
    assert handshake_catalog.normalize_mac("not:a:mac") is None
    assert handshake_catalog.normalize_mac("") is None
    assert handshake_catalog.normalize_mac(None) is None


def test_infer_ssid_from_legacy_filename():
    # Standard SSID_MAC format
    assert (
        handshake_catalog._infer_ssid_from_legacy_filename("Cafe_aabbccddeeff.pcap")
        == "Cafe"
    )
    assert (
        handshake_catalog._infer_ssid_from_legacy_filename(
            "MyNetwork_112233445566.22000"
        )
        == "MyNetwork"
    )

    # Complex SSIDs with underscores (last underscore is MAV separator)
    assert (
        handshake_catalog._infer_ssid_from_legacy_filename(
            "My_Network_Test_aabbccddeeff.pcap"
        )
        == "My_Network_Test"
    )

    # HS_ prefixed files extract "HS" as SSID (before the mac)
    assert (
        handshake_catalog._infer_ssid_from_legacy_filename("HS_AABBCCDDEEFF.pcap")
        == "HS"
    )

    # No MAC match
    assert handshake_catalog._infer_ssid_from_legacy_filename("test.pcap") == ""
    assert handshake_catalog._infer_ssid_from_legacy_filename("") == ""


def test_extract_mac_and_ssid():
    # HS_ prefixed format
    mac, ssid = handshake_catalog._extract_mac_and_ssid(
        "HS_AABBCCDDEEFF.pcap", "prefixed"
    )
    assert mac == "AA:BB:CC:DD:EE:FF"
    assert ssid == ""

    # Invalid HS_ format
    mac, ssid = handshake_catalog._extract_mac_and_ssid("INVALID.pcap", "prefixed")
    assert mac is None
    assert ssid == ""

    # Legacy SSID_MAC format
    mac, ssid = handshake_catalog._extract_mac_and_ssid(
        "Cafe_aabbccddeeff.pcap", "legacy"
    )
    assert mac == "AA:BB:CC:DD:EE:FF"
    assert ssid == "Cafe"

    # Invalid legacy format
    mac, ssid = handshake_catalog._extract_mac_and_ssid("nofile.pcap", "legacy")
    assert mac is None
    assert ssid == ""
