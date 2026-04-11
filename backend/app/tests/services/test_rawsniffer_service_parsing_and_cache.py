"""Rawsniffer service tests for parsing, file scanning, and metadata cache."""

import json
from app.services import rawsniffer_service as rs_module
from app.utils import rawsniffer_parser as rp_module
from app.tests.conftest import write_test_pcap


def _set_bruce_layout(tmp_path, monkeypatch):
    bruce_dir = tmp_path / "BrucePCAP"
    raw_dir = bruce_dir / "rawsniffer"
    raw_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(rs_module, "BRUCE_PCAP_DIR", str(bruce_dir))
    return bruce_dir, raw_dir


def test_rawsniffer_list_files_filters_non_pcap(tmp_path, monkeypatch):
    """Test list_files filters non-pcap files."""
    _bruce_dir, raw_dir = _set_bruce_layout(tmp_path, monkeypatch)
    monkeypatch.setattr(
        rs_module, "M5EVIL_RAWSNIFFER_DIR", str(tmp_path / "nonexistent_m5evil_raw")
    )
    monkeypatch.setattr(
        rs_module,
        "M5EVIL_MASTERSNIFFER_DIR",
        str(tmp_path / "nonexistent_m5evil_master"),
    )

    write_test_pcap(raw_dir / "test.pcap")
    (raw_dir / "test.txt").write_text("not a pcap")
    (raw_dir / "test.pdf").write_bytes(b"pdf")

    service = rs_module.RawSnifferService()
    files = service.list_files()
    assert len(files) == 1
    assert files[0]["filename"] == "test.pcap"


def test_rawsniffer_list_files_skips_hs_prefix(tmp_path, monkeypatch):
    """Test list_files skips HS_ prefixed files."""
    _bruce_dir, raw_dir = _set_bruce_layout(tmp_path, monkeypatch)
    monkeypatch.setattr(
        rs_module, "M5EVIL_RAWSNIFFER_DIR", str(tmp_path / "nonexistent_m5evil_raw")
    )
    monkeypatch.setattr(
        rs_module,
        "M5EVIL_MASTERSNIFFER_DIR",
        str(tmp_path / "nonexistent_m5evil_master"),
    )

    write_test_pcap(raw_dir / "test.pcap")
    write_test_pcap(raw_dir / "HS_aabbccddeeff.pcap")

    service = rs_module.RawSnifferService()
    files = service.list_files()
    assert len(files) == 1
    assert files[0]["filename"] == "test.pcap"


def test_rawsniffer_list_files_handles_directory(tmp_path, monkeypatch):
    """Test list_files skips directories."""
    _bruce_dir, raw_dir = _set_bruce_layout(tmp_path, monkeypatch)
    monkeypatch.setattr(
        rs_module, "M5EVIL_RAWSNIFFER_DIR", str(tmp_path / "nonexistent_m5evil_raw")
    )
    monkeypatch.setattr(
        rs_module,
        "M5EVIL_MASTERSNIFFER_DIR",
        str(tmp_path / "nonexistent_m5evil_master"),
    )

    write_test_pcap(raw_dir / "test.pcap")
    (raw_dir / "subdir.pcap").mkdir()

    service = rs_module.RawSnifferService()
    files = service.list_files()
    assert len(files) == 1
    assert files[0]["filename"] == "test.pcap"


def test_rawsniffer_list_files_nonexistent_dir(monkeypatch):
    """Test list_files with non-existent directory."""
    monkeypatch.setattr(rs_module, "BRUCE_PCAP_DIR", "/nonexistent/path")
    monkeypatch.setattr(rs_module, "M5EVIL_RAWSNIFFER_DIR", "/nonexistent/m5evil_raw")
    monkeypatch.setattr(
        rs_module, "M5EVIL_MASTERSNIFFER_DIR", "/nonexistent/m5evil_master"
    )

    service = rs_module.RawSnifferService()
    files = service.list_files()
    assert files == []


def test_rawsniffer_get_metadata_nonexistent(tmp_path, monkeypatch):
    """Test get_metadata returns None for non-existent file."""
    _set_bruce_layout(tmp_path, monkeypatch)

    service = rs_module.RawSnifferService()
    metadata = service.get_metadata("nonexistent.pcap")
    assert metadata is None


def test_rawsniffer_get_metadata_corrupt_json(tmp_path, monkeypatch):
    """Test get_metadata returns None for corrupt JSON."""
    bruce_dir, _raw_dir = _set_bruce_layout(tmp_path, monkeypatch)

    meta_dir = bruce_dir / ".metadata"
    meta_dir.mkdir()
    (meta_dir / "brucegotchi__rawsniffer__test.pcap.json").write_text("{invalid json", encoding="utf-8")

    service = rs_module.RawSnifferService()
    metadata = service.get_metadata("test.pcap")
    assert metadata is None


def test_rawsniffer_clear_metadata_cache(tmp_path, monkeypatch):
    """Test clear_metadata_cache removes cache files."""
    bruce_dir, _raw_dir = _set_bruce_layout(tmp_path, monkeypatch)

    meta_dir = bruce_dir / ".metadata"
    meta_dir.mkdir()
    (meta_dir / "brucegotchi__rawsniffer__test1.pcap.json").write_text("{}", encoding="utf-8")
    (meta_dir / "brucegotchi__rawsniffer__test2.pcap.json").write_text("{}", encoding="utf-8")

    service = rs_module.RawSnifferService()
    result = service.clear_metadata_cache()
    assert result["deleted_count"] == 2
    assert result["failed_count"] == 0


def test_rawsniffer_get_pending_files(tmp_path, monkeypatch):
    """Test get_pending_files returns files needing processing."""
    bruce_dir, raw_dir = _set_bruce_layout(tmp_path, monkeypatch)

    write_test_pcap(raw_dir / "cached.pcap")
    write_test_pcap(raw_dir / "pending.pcap")

    meta_dir = bruce_dir / ".metadata"
    meta_dir.mkdir()
    stat = (raw_dir / "cached.pcap").stat()
    (meta_dir / "brucegotchi__rawsniffer__cached.pcap.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_file": "cached.pcap",
                "source_size": stat.st_size,
                "source_mtime": stat.st_mtime,
            }
        ),
        encoding="utf-8",
    )

    service = rs_module.RawSnifferService()
    pending = service.get_pending_files()
    assert "pending.pcap" in pending
    assert "cached.pcap" not in pending


def test_rawsniffer_parse_output_with_multiple_networks(tmp_path):
    """Test parse_output with multiple networks."""
    pcap_file = tmp_path / "test.pcap"
    write_test_pcap(pcap_file)
    stat = pcap_file.stat()
    output = (
        "10.0\t0x0008\taa:bb:cc:dd:ee:ff\taa:bb:cc:dd:ee:ff\tff:ff:ff:ff:ff:ff\t4e65744f6e65\t6\t\t\n"
        "10.1\t0x0008\t11:22:33:44:55:66\t11:22:33:44:55:66\tff:ff:ff:ff:ff:ff\t4e657454776f\t11\t\t"
    )
    result = rp_module.parse_output(output, [], "test.pcap", stat)
    assert result["stats"]["networks_count"] == 2
    assert result["stats"]["beacon_frames"] == 2


def test_rawsniffer_parse_output_with_probe_request(tmp_path):
    """Test parse_output with probe request frame."""
    pcap_file = tmp_path / "test.pcap"
    write_test_pcap(pcap_file)
    stat = pcap_file.stat()
    output = "10.0\t0x0004\taa:bb:cc:dd:ee:ff\t11:22:33:44:55:66\tff:ff:ff:ff:ff:ff\t4e65744f6e65\t6\t\t"
    from app.utils import rawsniffer_parser as rp_module

    result = rp_module.parse_output(output, [], "test.pcap", stat)
    assert result["stats"]["probe_requests"] == 1
    # Probe requests don't create network entries - only beacons do
    assert result["stats"]["networks_count"] == 0


def test_rawsniffer_parse_output_with_deauth(tmp_path):
    """Test parse_output with deauth frame - counts as parsed line."""
    pcap_file = tmp_path / "test.pcap"
    write_test_pcap(pcap_file)
    stat = pcap_file.stat()
    output = (
        "10.0\t0x000c\taa:bb:cc:dd:ee:ff\t11:22:33:44:55:66\tff:ff:ff:ff:ff:ff\t\t\t\t"
    )
    from app.utils import rawsniffer_parser as rp_module

    result = rp_module.parse_output(output, [], "test.pcap", stat)
    assert result["stats"]["parsed_lines"] == 1
    assert result["stats"]["networks_count"] == 0


def test_rawsniffer_parse_output_with_disassoc(tmp_path):
    """Test parse_output with disassociation frame - counts as parsed line."""
    pcap_file = tmp_path / "test.pcap"
    write_test_pcap(pcap_file)
    stat = pcap_file.stat()
    output = (
        "10.0\t0x000a\taa:bb:cc:dd:ee:ff\t11:22:33:44:55:66\tff:ff:ff:ff:ff:ff\t\t\t\t"
    )
    from app.utils import rawsniffer_parser as rp_module

    result = rp_module.parse_output(output, [], "test.pcap", stat)
    assert result["stats"]["parsed_lines"] == 1
    assert result["stats"]["networks_count"] == 0


def test_rawsniffer_parse_output_empty(tmp_path):
    """Test parse_output with empty output."""
    pcap_file = tmp_path / "test.pcap"
    write_test_pcap(pcap_file)
    stat = pcap_file.stat()
    result = rp_module.parse_output("", [], "test.pcap", stat)
    assert result["source_file"] == "test.pcap"
    assert result["stats"]["networks_count"] == 0
    assert result["stats"]["beacon_frames"] == 0


def test_rawsniffer_parse_output_with_beacons(tmp_path):
    """Test parse_output with beacon frames."""
    pcap_file = tmp_path / "test.pcap"
    write_test_pcap(pcap_file)
    stat = pcap_file.stat()
    output = "10.0\t0x0008\taa:bb:cc:dd:ee:ff\taa:bb:cc:dd:ee:ff\tff:ff:ff:ff:ff:ff\t4e65744f6e65\t6\t\t"
    result = rp_module.parse_output(output, [], "test.pcap", stat)
    assert result["stats"]["beacon_frames"] == 1
    assert result["stats"]["networks_count"] == 1


def test_rawsniffer_parse_output_with_eapol(tmp_path):
    """Test parse_output with EAPOL frames."""
    pcap_file = tmp_path / "test.pcap"
    write_test_pcap(pcap_file)
    stat = pcap_file.stat()
    output = "12.5\t0x0028\taa:bb:cc:dd:ee:ff\t11:22:33:44:55:66\taa:bb:cc:dd:ee:ff\t\t\t2\t3"
    result = rp_module.parse_output(output, [], "test.pcap", stat)
    assert result["stats"]["eapol_frames"] == 1


def test_rawsniffer_parse_output_with_probe(tmp_path):
    """Test parse_output with probe request frames."""
    pcap_file = tmp_path / "test.pcap"
    write_test_pcap(pcap_file)
    stat = pcap_file.stat()
    output = "11.0\t0x0004\tff:ff:ff:ff:ff:ff\t11:22:33:44:55:66\taa:bb:cc:dd:ee:ff\t4e65744f6e65\t6\t\t"
    result = rp_module.parse_output(output, [], "test.pcap", stat)
    assert result["stats"]["probe_requests"] == 1


class TestRawsnifferServiceCacheScenarios:
    """Extra cache and pending-file scenarios."""

    def test_list_files_skips_hs_prefix(self, tmp_path, monkeypatch):
        """Test list_files skips HS_ prefixed files."""
        bruce_dir, raw_dir = _set_bruce_layout(tmp_path, monkeypatch)
        monkeypatch.setattr(rs_module, "M5EVIL_RAWSNIFFER_DIR", str(tmp_path / "nonexistent_m5evil_raw"))
        monkeypatch.setattr(rs_module, "M5EVIL_MASTERSNIFFER_DIR", str(tmp_path / "nonexistent_m5evil_master"))

        pcap1 = raw_dir / "test.pcap"
        write_test_pcap(pcap1)

        hs_file = raw_dir / "HS_aabbccddeeff.pcap"
        write_test_pcap(hs_file)

        service = rs_module.RawSnifferService()
        files = service.list_files()
        filenames = [f["filename"] for f in files]
        assert "test.pcap" in filenames
        assert "HS_aabbccddeeff.pcap" not in filenames

    def test_get_pending_files(self, tmp_path, monkeypatch):
        """Test get_pending_files returns files needing processing."""
        bruce_dir, raw_dir = _set_bruce_layout(tmp_path, monkeypatch)
        monkeypatch.setattr(rs_module, "M5EVIL_RAWSNIFFER_DIR", str(tmp_path / "nonexistent_m5evil_raw"))
        monkeypatch.setattr(rs_module, "M5EVIL_MASTERSNIFFER_DIR", str(tmp_path / "nonexistent_m5evil_master"))

        pcap1 = raw_dir / "pending.pcap"
        write_test_pcap(pcap1)

        pcap2 = raw_dir / "processed.pcap"
        write_test_pcap(pcap2)

        meta_dir = bruce_dir / ".metadata"
        meta_dir.mkdir()
        meta_file = meta_dir / "brucegotchi__rawsniffer__processed.pcap.json"
        # Create metadata with proper cache-fresh fields
        stat = pcap2.stat()
        meta_file.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "source_file": "processed.pcap",
                    "source_size": stat.st_size,
                    "source_mtime": stat.st_mtime,
                }
            ),
            encoding="utf-8",
        )

        service = rs_module.RawSnifferService()
        pending = service.get_pending_files()
        assert "pending.pcap" in pending
        assert "processed.pcap" not in pending

    def test_clear_metadata_cache(self, tmp_path, monkeypatch):
        """Test clear_metadata_cache removes metadata files."""
        bruce_dir, _raw_dir = _set_bruce_layout(tmp_path, monkeypatch)

        meta_dir = bruce_dir / ".metadata"
        meta_dir.mkdir()
        meta_file = meta_dir / "brucegotchi__rawsniffer__test.pcap.json"
        meta_file.write_text("{}", encoding="utf-8")

        service = rs_module.RawSnifferService()
        result = service.clear_metadata_cache()
        assert result["deleted_count"] == 1
        assert not meta_file.exists()
