from types import SimpleNamespace

from app.utils import rawsniffer_parser as parser


def test_decode_ssid_branches():
    assert parser.decode_ssid(None) == ("", None)
    assert parser.decode_ssid("<hidden>") == ("", None)
    assert parser.decode_ssid("4d7957694669") == ("MyWiFi", "4d7957694669")
    # invalid hex path should fall back to original text
    assert parser.decode_ssid("zzzz") == ("zzzz", None)


def test_numeric_parsers_and_channel_frequency():
    assert parser.channel_to_frequency(14) == 2484
    assert parser.channel_to_frequency(36) == 5180
    assert parser.channel_to_frequency(999) is None
    assert parser.to_int("12.8") == 12
    assert parser.to_int("bad") is None
    assert parser.to_float("1.25") == 1.25
    assert parser.to_float("bad") is None
    assert parser.parse_subtype(None) is None
    assert parser.parse_subtype("  ") is None
    assert parser.parse_subtype("0x08") == 8
    assert parser.parse_subtype("bad") is None


def test_parse_output_handles_short_lines_and_missing_fields():
    source_stat = SimpleNamespace(st_size=10, st_mtime=20.0)
    output = "\n".join(
        [
            "",  # empty line ignored
            "1700000000\t0x08\t\t\t\t\t6",  # beacon without bssid -> continue
            "1700000001\t0x04\t\t\t\t",  # probe with missing sa -> continue
            "1700000002\t0x28\t\t\t\t\t\t1\t",  # eapol with no candidate -> continue
            "1700000003\t0x08\t001122334455\t\t\t4d7957694669\t6\t\t",  # valid beacon
            "1700000004\t0x04\tFFFFFFFFFFFF\tAABBCCDDEEFF\t001122334455\t\t\t\t",  # probe mapped to target
            "1700000005\t0x28\t001122334455\t\t\t\t\t1\t",  # eapol increments target
        ]
    )

    parsed = parser.parse_output(
        output,
        warnings=["warn"],
        source_file="capture.pcap",
        source_stat=source_stat,
        schema_version=7,
    )

    assert parsed["schema_version"] == 7
    assert parsed["stats"]["parsed_lines"] == 6
    assert parsed["stats"]["beacon_frames"] >= 1
    assert parsed["stats"]["probe_requests"] >= 1
    assert parsed["stats"]["eapol_frames"] >= 1
    assert parsed["stats"]["networks_count"] == 1
    net = parsed["networks"][0]
    assert net["bssid"] == "00:11:22:33:44:55"
    assert net["ssid"] == "MyWiFi"
    assert net["probe_client_count"] == 1
    assert net["eapol_count"] == 1
