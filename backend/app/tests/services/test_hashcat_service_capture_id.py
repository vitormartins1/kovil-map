from app.services import hashcat_service as hs_module


def test_convert_pcap_uses_capture_id_resolution(tmp_path, monkeypatch):
    hand_dir = tmp_path / "handshakes"
    hand_dir.mkdir()
    external_dir = tmp_path / "external"
    external_dir.mkdir()
    external_pcap = external_dir / "CaptureA.pcap"
    external_pcap.write_text("pcap", encoding="utf-8")

    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(hand_dir))

    service = hs_module.HashcatService()
    monkeypatch.setattr(
        service, "_get_config", lambda: {"hcxpcapngtool_path": "hcxpcapngtool"}
    )
    monkeypatch.setattr(service, "_should_use_wsl", lambda _bin: False)
    monkeypatch.setattr(
        hs_module,
        "resolve_pcap_reference",
        lambda filename, capture_id=None, raw_item_id=None, search_roots=None: {
            "path": str(external_pcap),
            "filename": "CaptureA.pcap",
            "capture_id": capture_id,
            "raw_item_id": raw_item_id,
            "basename": "CaptureA",
        },
    )
    monkeypatch.setattr(
        hs_module.history_service, "add_entry", lambda *args, **kwargs: "entry-cap"
    )
    monkeypatch.setattr(
        hs_module.history_service, "update_entry", lambda *args, **kwargs: None
    )

    captured = {}

    def _start_job(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return "job-cap"

    monkeypatch.setattr(hs_module.job_manager, "start_job", _start_job)

    result = service.convert_pcap(None, capture_id="cap-123")
    assert result == {
        "status": "started",
        "job_id": "job-cap",
        "output_file": "capture.22000",
    }
    assert captured["command"][0] == "hcxpcapngtool"
    assert str(external_pcap) in captured["command"]
    assert (
        str(hand_dir / "captures" / "cap-123" / "capture.22000") in captured["command"]
    )


def test_convert_pcap_uses_raw_item_id_resolution(tmp_path, monkeypatch):
    hand_dir = tmp_path / "handshakes"
    hand_dir.mkdir()
    external_dir = tmp_path / "raw"
    external_dir.mkdir()
    external_pcap = external_dir / "raw_1.pcap"
    external_pcap.write_text("pcap", encoding="utf-8")

    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(hand_dir))

    service = hs_module.HashcatService()
    monkeypatch.setattr(
        service, "_get_config", lambda: {"hcxpcapngtool_path": "hcxpcapngtool"}
    )
    monkeypatch.setattr(service, "_should_use_wsl", lambda _bin: False)
    monkeypatch.setattr(
        hs_module,
        "resolve_pcap_reference",
        lambda filename, capture_id=None, raw_item_id=None, search_roots=None: {
            "path": str(external_pcap),
            "filename": "raw_1.pcap",
            "capture_id": capture_id,
            "raw_item_id": raw_item_id,
            "basename": "raw_1",
        },
    )
    monkeypatch.setattr(
        hs_module.history_service, "add_entry", lambda *args, **kwargs: "entry-raw"
    )
    monkeypatch.setattr(
        hs_module.history_service, "update_entry", lambda *args, **kwargs: None
    )

    captured = {}

    def _start_job(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return "job-raw"

    monkeypatch.setattr(hs_module.job_manager, "start_job", _start_job)

    result = service.convert_pcap(None, raw_item_id="raw::pcap::abc123")
    assert result == {
        "status": "started",
        "job_id": "job-raw",
        "output_file": "raw_1.22000",
    }
    assert str(external_pcap) in captured["command"]
    assert str(hand_dir / "raw_1.22000") in captured["command"]


def test_build_combined_candidate_writes_deduped_capture_group_artifact(
    tmp_path, monkeypatch
):
    hand_dir = tmp_path / "handshakes"
    hand_dir.mkdir()
    monkeypatch.setattr(hs_module, "HANDSHAKES_DIR", str(hand_dir))

    capture_a_dir = hand_dir / "captures" / "cap-a"
    capture_b_dir = hand_dir / "captures" / "cap-b"
    capture_a_dir.mkdir(parents=True)
    capture_b_dir.mkdir(parents=True)
    (capture_a_dir / "capture.22000").write_text(
        "WPA*02*abc*001122334455*aabbccddeeff*74657374*00\n"
        "WPA*02*def*001122334455*aabbccddeeff*74657374*00\n",
        encoding="utf-8",
    )
    (capture_b_dir / "capture.22000").write_text(
        "WPA*02*abc*001122334455*aabbccddeeff*74657374*00\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        hs_module.handshake_catalog_service,
        "get_handshake_set",
        lambda mac: {
            "mac": "AA:BB:CC:DD:EE:FF",
            "captures": [
                {
                    "capture_id": "cap-a",
                    "source": "pwnagotchi",
                    "device_label": "Pwnagotchi",
                    "source_filename": "Cafe_aabbccddeeff.pcap",
                    "artifacts": {
                        "hash_22000": [
                            {
                                "path": str(capture_a_dir / "capture.22000"),
                                "valid_hash_lines": 2,
                            }
                        ]
                    },
                },
                {
                    "capture_id": "cap-b",
                    "source": "brucegotchi",
                    "device_label": "Brucegotchi",
                    "source_filename": "HS_AABBCCDDEEFF.pcap",
                    "artifacts": {
                        "hash_22000": [
                            {
                                "path": str(capture_b_dir / "capture.22000"),
                                "valid_hash_lines": 1,
                            }
                        ]
                    },
                },
            ],
        },
    )

    service = hs_module.HashcatService()
    result = service.build_combined_candidate("AA:BB:CC:DD:EE:FF", ["cap-a", "cap-b"])

    assert result["status"] == "success"
    assert result["included_capture_ids"] == ["cap-a", "cap-b"]
    assert result["deduped_hash_count"] == 2

    output_path = (
        hand_dir / "combined" / "aabbccddeeff" / result["build_id"] / "combined.22000"
    )
    manifest_path = (
        hand_dir / "combined" / "aabbccddeeff" / result["build_id"] / "manifest.json"
    )
    assert output_path.exists()
    assert manifest_path.exists()
    lines = [
        line.strip()
        for line in output_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(lines) == 2
