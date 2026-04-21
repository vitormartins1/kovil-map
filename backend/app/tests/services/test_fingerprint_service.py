import json

from app.services import fingerprint_service as fs_module


def test_extract_returns_error_when_tshark_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(fs_module, "HANDSHAKES_DIR", str(tmp_path))
    service = fs_module.FingerprintService()
    monkeypatch.setattr(service, "_check_tshark", lambda: None)

    result = service.extract("Any_aabbccddeeff.pcap")
    assert result["status"] == "error"
    assert "tshark" in result["message"]


def test_extract_returns_error_when_tshark_filenotfound(tmp_path, monkeypatch):
    monkeypatch.setattr(fs_module, "HANDSHAKES_DIR", str(tmp_path))
    (tmp_path / "Any_aabbccddeeff.pcap").write_text("pcap", encoding="utf-8")
    service = fs_module.FingerprintService()
    monkeypatch.setattr(service, "_check_tshark", lambda: "tshark")
    monkeypatch.setattr(
        fs_module.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            FileNotFoundError("tshark not found")
        ),
    )

    result = service.extract("Any_aabbccddeeff.pcap")
    assert result["status"] == "error"
    assert "tshark not found" in result["message"]


def test_extract_uses_cached_details_when_present(tmp_path, monkeypatch):
    monkeypatch.setattr(fs_module, "HANDSHAKES_DIR", str(tmp_path))

    pcap_name = "Test_aabbccddeeff.pcap"
    (tmp_path / pcap_name).write_text("pcap", encoding="utf-8")
    cached_content = {"ssid": "Cached", "meta": {"timestamp": "2026-01-01T00:00:00Z"}}
    (tmp_path / "Test_aabbccddeeff.details").write_text(
        json.dumps(cached_content), encoding="utf-8"
    )

    service = fs_module.FingerprintService()
    monkeypatch.setattr(service, "_check_tshark", lambda: "tshark")

    result = service.extract(pcap_name, force=False)
    assert result["status"] == "success"
    assert result["cached"] is True
    assert result["details"]["ssid"] == "Cached"


def test_extract_uses_capture_id_resolution_when_present(tmp_path, monkeypatch):
    hand_dir = tmp_path / "handshakes"
    hand_dir.mkdir()
    external_dir = tmp_path / "external"
    external_dir.mkdir()
    external_pcap = external_dir / "Alias.pcap"
    external_pcap.write_text("pcap", encoding="utf-8")

    monkeypatch.setattr(fs_module, "HANDSHAKES_DIR", str(hand_dir))
    (external_dir / "Alias.details").write_text(
        json.dumps(
            {"ssid": "CaptureAlias", "meta": {"timestamp": "2026-01-01T00:00:00Z"}}
        ),
        encoding="utf-8",
    )

    service = fs_module.FingerprintService()
    monkeypatch.setattr(service, "_check_tshark", lambda: "tshark")
    monkeypatch.setattr(
        fs_module,
        "resolve_pcap_reference",
        lambda filename, capture_id=None, search_roots=None: {
            "path": str(external_pcap),
            "filename": "Alias.pcap",
            "capture_id": capture_id,
            "basename": "Alias",
        },
    )

    result = service.extract("", force=False, capture_id="cap-123")
    assert result["status"] == "success"
    assert result["cached"] is True
    assert result["details"]["ssid"] == "CaptureAlias"
    assert result["saved_path"].endswith("external/Alias.details")


def test_extract_uses_raw_item_id_resolution_and_raw_safe_details_name(
    tmp_path, monkeypatch
):
    hand_dir = tmp_path / "handshakes"
    hand_dir.mkdir()
    external_dir = tmp_path / "external"
    external_dir.mkdir()
    raw_pcap = external_dir / "raw_1.pcap"
    raw_pcap.write_text("pcap", encoding="utf-8")

    monkeypatch.setattr(fs_module, "HANDSHAKES_DIR", str(hand_dir))

    service = fs_module.FingerprintService()
    monkeypatch.setattr(service, "_check_tshark", lambda: "tshark")
    monkeypatch.setattr(service, "_should_use_wsl", lambda *_: False)
    monkeypatch.setattr(
        fs_module.rawsniffer_service,
        "resolve_raw_pcap_item",
        lambda raw_item_id: {
            "raw_item_id": raw_item_id,
            "filename": "raw_1.pcap",
            "path": str(raw_pcap),
            "source": "m5evil",
            "device_label": "M5Evil",
        },
    )

    outputs = [
        ("AA:BB:CC:DD:EE:FF\t5261774e6574\n", []),
        ("AA:BB:CC:DD:EE:FF\t5261774e6574\t2\t5\t4\t0\t1\n", []),
        ("", []),
        (
            "AA:BB:CC:DD:EE:FF\t5261774e6574\t6\t1,2,5.5\t11,54\t1\t1\t1\t1\t0\t1\t1\t2\t1\t5\t30\t100\t-40\t54\t2412\n",
            [],
        ),
    ]
    monkeypatch.setattr(service, "_run_tshark", lambda _cmd: outputs.pop(0))

    class _FakeManuf:
        def get_manuf(self, _mac):
            return "Espressif"

    monkeypatch.setattr(fs_module.deps, "manuf_parser", _FakeManuf())
    monkeypatch.setattr(fs_module.deps.mac_lookup, "lookup", lambda _mac: "Unknown")
    monkeypatch.setattr(
        fs_module.history_service, "add_entry", lambda *a, **k: "entry-raw"
    )
    monkeypatch.setattr(fs_module.history_service, "update_entry", lambda *a, **k: None)
    monkeypatch.setattr(fs_module, "reload_data", lambda: None)

    result = service.extract(
        "", force=True, raw_item_id="raw::pcap::abc123", bssid="AA:BB:CC:DD:EE:FF"
    )
    assert result["status"] == "success"
    saved_name = result["saved_path"].split("/")[-1]
    assert saved_name == "__rawdetails__raw_1_aabbccddeeff.details"
    assert result["details"]["meta"]["raw_item_id"] == "raw::pcap::abc123"
    assert result["details"]["meta"]["raw_target_bssid"] == "AA:BB:CC:DD:EE:FF"


def test_extract_raw_item_id_filters_to_requested_bssid(tmp_path, monkeypatch):
    hand_dir = tmp_path / "handshakes"
    hand_dir.mkdir()
    external_dir = tmp_path / "external"
    external_dir.mkdir()
    raw_pcap = external_dir / "HAL_22.pcap"
    raw_pcap.write_text("pcap", encoding="utf-8")

    monkeypatch.setattr(fs_module, "HANDSHAKES_DIR", str(hand_dir))

    service = fs_module.FingerprintService()
    monkeypatch.setattr(service, "_check_tshark", lambda: "tshark")
    monkeypatch.setattr(service, "_should_use_wsl", lambda *_: False)
    monkeypatch.setattr(
        fs_module.rawsniffer_service,
        "resolve_raw_pcap_item",
        lambda raw_item_id: {
            "raw_item_id": raw_item_id,
            "filename": "HAL_22.pcap",
            "path": str(raw_pcap),
            "source": "brucegotchi",
            "device_label": "Bruce",
        },
    )

    outputs = [
        (
            "\n".join(
                [
                    "11:22:33:44:55:66\t4f74686572",
                    "AA:BB:CC:DD:EE:FF\t546172676574",
                ]
            ),
            [],
        ),
        (
            "\n".join(
                [
                    "11:22:33:44:55:66\t4f74686572\t2\t5\t4\t0\t1",
                    "AA:BB:CC:DD:EE:FF\t546172676574\t8\t5\t4\t1\t1",
                ]
            ),
            [],
        ),
        ("", []),
        (
            "\n".join(
                [
                    "11:22:33:44:55:66\t4f74686572\t1\t1,2\t11\t1\t1\t1\t0\t0\t1\t1\t2\t1\t5\t30\t100\t-50\t24\t2412\t001122",
                    "AA:BB:CC:DD:EE:FF\t546172676574\t6\t1,2,5.5\t11,54\t1\t1\t1\t1\t0\t1\t1\t2\t1\t5\t30\t100\t-40\t54\t2437\tAABBCC",
                ]
            ),
            [],
        ),
    ]
    monkeypatch.setattr(service, "_run_tshark", lambda _cmd: outputs.pop(0))

    class _FakeManuf:
        def get_manuf(self, mac):
            return "TargetVendor" if mac == "AA:BB:CC:DD:EE:FF" else "OtherVendor"

    monkeypatch.setattr(fs_module.deps, "manuf_parser", _FakeManuf())
    monkeypatch.setattr(fs_module.deps.mac_lookup, "lookup", lambda _mac: "Unknown")
    monkeypatch.setattr(
        fs_module.history_service, "add_entry", lambda *a, **k: "entry-target"
    )
    monkeypatch.setattr(fs_module.history_service, "update_entry", lambda *a, **k: None)
    monkeypatch.setattr(fs_module, "reload_data", lambda: None)

    result = service.extract(
        "",
        force=True,
        raw_item_id="raw::pcap::target123",
        bssid="AA:BB:CC:DD:EE:FF",
    )
    assert result["status"] == "success"
    assert result["details"]["bssid"] == "AA:BB:CC:DD:EE:FF"
    assert result["details"]["ssid"] == "Target"
    assert result["details"]["vendor"] == "TargetVendor"
    assert result["saved_path"].endswith("__rawdetails__HAL_22_aabbccddeeff.details")


def test_extract_success_generates_details(tmp_path, monkeypatch):
    monkeypatch.setattr(fs_module, "HANDSHAKES_DIR", str(tmp_path))
    pcap_name = "Sheila_aabbccddeeff.pcap"
    (tmp_path / pcap_name).write_text("pcap", encoding="utf-8")

    service = fs_module.FingerprintService()
    monkeypatch.setattr(service, "_check_tshark", lambda: "tshark")
    monkeypatch.setattr(service, "_should_use_wsl", lambda *_: False)

    outputs = [
        # SSID/BSSID
        ("AA:BB:CC:DD:EE:FF\t536865696c61\n", []),
        # RSN
        ("AA:BB:CC:DD:EE:FF\t536865696c61\t2\t5\t4\t0\t1\n", []),
        # WPS
        ("", []),
        # Extras
        (
            "AA:BB:CC:DD:EE:FF\t536865696c61\t6\t1,2,5.5\t11,54\t1\t1\t1\t1\t0\t1\t1\t2\t1\t5\t30\t100\t-40\t54\t2412\n",
            [],
        ),
    ]

    def _fake_run(_):
        return outputs.pop(0)

    monkeypatch.setattr(service, "_run_tshark", _fake_run)

    class _FakeManuf:
        def get_manuf(self, _mac):
            return "TP-Link"

    monkeypatch.setattr(fs_module.deps, "manuf_parser", _FakeManuf())
    monkeypatch.setattr(fs_module.deps.mac_lookup, "lookup", lambda _mac: "Unknown")
    monkeypatch.setattr(
        fs_module.history_service, "add_entry", lambda *a, **k: "entry-1"
    )
    monkeypatch.setattr(fs_module.history_service, "update_entry", lambda *a, **k: None)
    monkeypatch.setattr(fs_module, "reload_data", lambda: None)

    result = service.extract(pcap_name, force=True)
    assert result["status"] == "success"
    assert result["cached"] is False
    assert result["details"]["ssid"] == "Sheila"
    assert result["details"]["security"]["wpa_version"] == "WPA2"
    assert result["details"]["security"]["group_cipher"] == "WRAP"
    assert result["details"]["security"]["pmf"] == "Capable"
    assert result["details"]["vendor"] == "TP-Link"
    assert result["details"]["radio"]["channel"] == 6
    assert result["details"]["radio"]["band"] == "2.4"
    assert result["details"]["radio"]["datarate_mbps_max"] == 54
    assert result["details"]["rates"]["max_rate_mbps"] == 54
    assert result["details"]["capabilities"]["privacy"] is True
    assert result["details"]["phy"]["ht_present"] is True
    assert result["details"]["qbss"]["station_count"] == 5
    assert result["details"]["classification"]["version"] == "v2"
    assert "scores" in result["details"]["classification"]
    assert "signals" in result["details"]["classification"]
    assert result["details"]["classification"]["type"] in {
        "router_ap",
        "phone_hotspot",
        "iot_ap",
        "unknown",
        "camera_ap",
        "printer_ap",
    }
    assert (tmp_path / "Sheila_aabbccddeeff.details").exists()


def test_extract_resolves_pcap_from_m5evil_handshakes_dir(tmp_path, monkeypatch):
    hand_dir = tmp_path / "handshakes"
    m5evil_dir = tmp_path / "m5evil" / "handshakes"
    hand_dir.mkdir()
    m5evil_dir.mkdir(parents=True)
    monkeypatch.setattr(fs_module, "HANDSHAKES_DIR", str(hand_dir))
    monkeypatch.setattr(fs_module, "M5EVIL_HANDSHAKES_DIR", str(m5evil_dir))

    pcap_name = "HS_AABBCCDDEEFF.pcap"
    (m5evil_dir / pcap_name).write_text("pcap", encoding="utf-8")

    service = fs_module.FingerprintService()
    monkeypatch.setattr(service, "_check_tshark", lambda: "tshark")
    monkeypatch.setattr(service, "_should_use_wsl", lambda *_: False)

    outputs = [
        ("AA:BB:CC:DD:EE:FF\t4d354576696c\n", []),
        ("AA:BB:CC:DD:EE:FF\t4d354576696c\t8\t5\t4\t0\t1\n", []),
        ("", []),
        (
            "AA:BB:CC:DD:EE:FF\t4d354576696c\t6\t1,2,5.5\t11,54\t1\t1\t1\t1\t0\t1\t1\t2\t1\t5\t30\t100\t-40\t54\t2412\n",
            [],
        ),
    ]
    monkeypatch.setattr(service, "_run_tshark", lambda _cmd: outputs.pop(0))

    class _FakeManuf:
        def get_manuf(self, _mac):
            return "Espressif"

    monkeypatch.setattr(fs_module.deps, "manuf_parser", _FakeManuf())
    monkeypatch.setattr(fs_module.deps.mac_lookup, "lookup", lambda _mac: "Unknown")
    monkeypatch.setattr(
        fs_module.history_service, "add_entry", lambda *a, **k: "entry-m5"
    )
    monkeypatch.setattr(fs_module.history_service, "update_entry", lambda *a, **k: None)
    monkeypatch.setattr(fs_module, "reload_data", lambda: None)

    result = service.extract(pcap_name, force=True)
    assert result["status"] == "success"
    assert result["details"]["ssid"] == "M5Evil"
    assert (hand_dir / "HS_AABBCCDDEEFF.details").exists()


def test_fingerprint_helpers_and_parsers():
    service = fs_module.FingerprintService()

    rows = service._parse_rows("aa\tbb\ncc\n", 2)
    assert rows == [["aa", "bb"], ["cc", ""]]

    dec, raw = service._decode_ssid("536865696c61")
    assert dec == "Sheila"
    assert raw == "536865696c61"
    dec2, raw2 = service._decode_ssid("MySSID")
    assert dec2 == "MySSID"
    assert raw2 is None

    bssid, ssid, ssid_hex = service._first_network([["aa:bb", "536865696c61"]])
    assert bssid == "AA:BB"
    assert ssid == "Sheila"
    assert ssid_hex == "536865696c61"
    assert service._first_network([]) == ("", "", None)

    labels = service._label_list(["2", "2", "99"], fs_module.AKM_MAP)
    assert labels == ["PSK", "99"]
    assert service._derive_wpa_version(["SAE"], []) == "WPA3"
    assert service._derive_wpa_version([], ["CCMP"]) == "WPA2"
    assert service._derive_wpa_version([], []) == "Unknown"
    assert service._derive_pmf("1", "0") == "Required"
    assert service._derive_pmf("0", "1") == "Capable"
    assert service._derive_pmf("", "") == "Unknown"
    assert service._derive_pmf("0", "0") == "None"


def test_classification_paths():
    service = fs_module.FingerprintService()
    camera = service._classify(
        {
            "vendor": "Unknown",
            "ssid": "test",
            "wps": {
                "present": True,
                "device_name": "IP Camera",
                "model_name": "",
                "manufacturer": "",
            },
        }
    )
    assert camera["type"] == "camera_ap"
    assert camera["version"] == "v2"
    assert camera["tier"] in {"high", "medium", "low"}
    assert "scores" in camera
    printer = service._classify(
        {
            "vendor": "Unknown",
            "ssid": "test",
            "wps": {
                "present": True,
                "device_name": "HP Printer",
                "model_name": "",
                "manufacturer": "",
            },
        }
    )
    assert printer["type"] == "printer_ap"
    hotspot = service._classify(
        {"vendor": "Unknown", "ssid": "iPhone Hotspot", "wps": {"present": False}}
    )
    assert hotspot["type"] == "phone_hotspot"
    unknown = service._classify(
        {"vendor": "Generic Corp", "ssid": "abc", "wps": {"present": False}}
    )
    assert unknown["type"] in {"unknown", "router_ap"}


def test_run_tshark_error_and_warning_paths(monkeypatch):
    service = fs_module.FingerprintService()
    monkeypatch.setattr(service, "_build_command", lambda _cmd: (["tshark"], "tshark"))

    class _ProcWarn:
        returncode = 0
        stdout = "ok"
        stderr = "warn"

    monkeypatch.setattr(fs_module.subprocess, "run", lambda *_a, **_k: _ProcWarn())
    out, warnings = service._run_tshark(["-r", "a.pcap"])
    assert out == "ok"
    assert warnings == ["warn"]

    class _ProcErr:
        returncode = 2
        stdout = ""
        stderr = "bad field"

    monkeypatch.setattr(fs_module.subprocess, "run", lambda *_a, **_k: _ProcErr())
    try:
        service._run_tshark(["-r", "a.pcap"])
        assert False
    except RuntimeError as exc:
        assert "bad field" in str(exc)

    monkeypatch.setattr(
        fs_module.subprocess,
        "run",
        lambda *_a, **_k: (_ for _ in ()).throw(FileNotFoundError()),
    )
    try:
        service._run_tshark(["-r", "a.pcap"])
        assert False
    except RuntimeError as exc:
        assert "not found" in str(exc)


def test_extract_invalid_cache_vendor_fallback_and_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(fs_module, "HANDSHAKES_DIR", str(tmp_path))
    pcap_name = "X_aabbccddeeff.pcap"
    (tmp_path / pcap_name).write_text("pcap", encoding="utf-8")
    (tmp_path / "X_aabbccddeeff.details").write_text("{", encoding="utf-8")
    service = fs_module.FingerprintService()
    monkeypatch.setattr(service, "_check_tshark", lambda: "tshark")
    monkeypatch.setattr(service, "_should_use_wsl", lambda *_: False)

    outputs = [
        ("AA:BB:CC:DD:EE:FF\tX\n", []),
        ("AA:BB:CC:DD:EE:FF\tX\t2\t5\t5\t1\t0\n", []),
        ("AA:BB:CC:DD:EE:FF\tX\tM\tModel\t1\tDevice\n", []),
        (
            "AA:BB:CC:DD:EE:FF\tX\t11\t1,2,5.5\t11\t1\t0\t1\t0\t0\t1\t1\t0\t0\t\t\t\t-33\t24\t2462\n",
            [],
        ),
    ]
    monkeypatch.setattr(service, "_run_tshark", lambda _cmd: outputs.pop(0))
    monkeypatch.setattr(fs_module.deps, "manuf_parser", None)
    monkeypatch.setattr(
        fs_module.deps.mac_lookup, "lookup", lambda _mac: "FallbackVendor"
    )
    monkeypatch.setattr(
        fs_module.history_service, "add_entry", lambda *a, **k: "entry-2"
    )
    monkeypatch.setattr(fs_module.history_service, "update_entry", lambda *a, **k: None)
    monkeypatch.setattr(fs_module, "reload_data", lambda: None)

    result = service.extract(pcap_name, force=False)
    assert result["status"] == "success"
    assert result["details"]["vendor"] == "FallbackVendor"
    assert result["details"]["wps"]["present"] is True

    calls = []
    monkeypatch.setattr(
        fs_module.history_service, "update_entry", lambda *a, **k: calls.append((a, k))
    )
    monkeypatch.setattr(
        service, "_run_tshark", lambda _cmd: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    failed = service.extract(pcap_name, force=True)
    assert failed["status"] == "error"
    assert calls


def test_normalize_oui():
    """_normalize_oui cleans and normalizes OUI strings."""
    service = fs_module.FingerprintService()
    assert service._normalize_oui("00:11:22") == "001122"
    assert service._normalize_oui("00-11-22") == "001122"
    assert service._normalize_oui("001122") == "001122"
    assert service._normalize_oui("") is None
    assert service._normalize_oui(None) is None
    assert service._normalize_oui("12") is None


def test_collect_ouis():
    """_collect_ouis collects unique OUIs from rows."""
    service = fs_module.FingerprintService()
    rows = [["", "00:11:22:33:44:55"], ["", "00:11:22,aa:bb:cc"]]
    ouis = service._collect_ouis(rows, 1)
    assert "001122" in ouis
    assert "AABBCC" in ouis


def test_derive_band():
    """_derive_band derives band from frequency or channel."""
    service = fs_module.FingerprintService()
    assert service._derive_band(2437, None) == "2.4"
    assert service._derive_band(5180, None) == "5"
    assert service._derive_band(5955, None) == "6"
    assert service._derive_band(None, 6) == "2.4"
    assert service._derive_band(None, 36) == "5"
    assert service._derive_band(None, None) is None


def test_any_flag():
    """_any_flag detects truthy values in rows."""
    service = fs_module.FingerprintService()
    assert service._any_flag([["", "1"]], 1) is True
    assert service._any_flag([["", "true"]], 1) is True
    assert service._any_flag([["", "0"]], 1) is False
    assert service._any_flag([], 1) is False


def test_stats_empty():
    """_stats returns empty dict for empty list."""
    service = fs_module.FingerprintService()
    assert service._stats([]) == {}


def test_unique_numbers():
    """_unique_numbers deduplicates rounded values."""
    service = fs_module.FingerprintService()
    # Test with values that round to the same key
    result = service._unique_numbers([1.0, 1.0, 2.0])
    assert len(result) == 2
    assert result[0] == 1.0
    assert result[1] == 2.0
    # Test with empty list
    result2 = service._unique_numbers([])
    assert result2 == []


def test_derive_pmf_all_cases():
    """_derive_pmf handles all cases."""
    service = fs_module.FingerprintService()
    assert service._derive_pmf("1", "1") == "Required"
    assert service._derive_pmf("0", "1") == "Capable"
    assert service._derive_pmf("", "") == "Unknown"
    assert service._derive_pmf("0", "0") == "None"


def test_check_tshark_absolute_path(tmp_path, monkeypatch):
    """_check_tshark handles absolute path."""
    service = fs_module.FingerprintService()
    monkeypatch.setattr(service, "conf", {"tshark_path": "/usr/bin/tshark"})
    monkeypatch.setattr(fs_module.os.path, "exists", lambda p: p == "/usr/bin/tshark")
    assert service._check_tshark() == "/usr/bin/tshark"


def test_check_tshark_relative_path(monkeypatch):
    """_check_tshark handles relative path."""
    service = fs_module.FingerprintService()
    monkeypatch.setattr(service, "conf", {"tshark_path": "tshark"})
    monkeypatch.setattr(
        fs_module.shutil,
        "which",
        lambda p: "/usr/bin/tshark" if p == "tshark" else None,
    )
    assert service._check_tshark() == "tshark"


def test_build_command_wsl(monkeypatch):
    """_build_command prepends wsl when needed."""
    service = fs_module.FingerprintService()
    monkeypatch.setattr(service, "conf", {"tshark_path": "tshark"})
    monkeypatch.setattr(service, "_should_use_wsl", lambda _: True)
    cmd, cmd_str = service._build_command(["-r", "file.pcap"])
    assert cmd[0] == "wsl"
    assert "wsl" in cmd_str


def test_parse_number_list():
    """_parse_number_list extracts numbers from strings."""
    service = fs_module.FingerprintService()
    assert service._parse_number_list("1,2,3") == [1.0, 2.0, 3.0]
    assert service._parse_number_list("1.5, 2.5") == [1.5, 2.5]
    assert service._parse_number_list("") == []
    assert service._parse_number_list("abc") == []


def test_collect_numbers():
    """_collect_numbers gathers numbers from rows."""
    service = fs_module.FingerprintService()
    rows = [["", "1,2"], ["", "3"]]
    result = service._collect_numbers(rows, 1)
    assert result == [1.0, 2.0, 3.0]


def test_clamp():
    """_clamp constrains values to range."""
    service = fs_module.FingerprintService()
    assert service._clamp(5.0, 0.0, 10.0) == 5.0
    assert service._clamp(-5.0, 0.0, 10.0) == 0.0
    assert service._clamp(15.0, 0.0, 10.0) == 10.0


def test_rows_for_bssid():
    """_rows_for_bssid filters or returns all rows."""
    service = fs_module.FingerprintService()
    rows = [["AA:BB:CC:DD:EE:FF", "x"], ["11:22:33:44:55:66", "y"]]
    result = service._rows_for_bssid(rows, "aa:bb:cc:dd:ee:ff")
    assert len(result) == 1
    assert result[0][1] == "x"
    assert service._rows_for_bssid(rows, "") == rows
    assert service._rows_for_bssid([], "aa:bb:cc:dd:ee:ff") == []
    assert (
        service._rows_for_bssid(rows, "22:22:22:22:22:22", allow_fallback=False) == []
    )


def test_first_non_empty():
    """_first_non_empty returns first non-empty value."""
    service = fs_module.FingerprintService()
    rows = [["", ""], ["", "value"]]
    assert service._first_non_empty(rows, 1) == "value"
    assert service._first_non_empty([], 1) == ""


def test_extract_pcap_not_found(tmp_path, monkeypatch):
    """extract returns error when PCAP not found."""

    monkeypatch.setattr(fs_module, "HANDSHAKES_DIR", str(tmp_path))
    service = fs_module.FingerprintService()
    monkeypatch.setattr(service, "_check_tshark", lambda: "tshark")
    monkeypatch.setattr(
        "app.utils.pcap.resolve_pcap_reference", lambda *args, **kwargs: None
    )
    result = service.extract("nonexistent.pcap")
    assert result["status"] == "error"
    assert "not found" in result["message"].lower()
