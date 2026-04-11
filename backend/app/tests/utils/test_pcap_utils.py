from app.utils import pcap as pcap_utils
from app.utils.pcap import validate_pcap_file


# ── validate_pcap_file ────────────────────────────────────────────────


class TestValidatePcapFile:
    """Tests for the PCAP integrity validator."""

    def test_empty_path(self):
        ok, reason = validate_pcap_file("")
        assert not ok
        assert "empty path" in reason

    def test_missing_file(self, tmp_path):
        ok, reason = validate_pcap_file(str(tmp_path / "nope.pcap"))
        assert not ok
        assert "does not exist" in reason

    def test_not_a_file(self, tmp_path):
        d = tmp_path / "subdir"
        d.mkdir()
        ok, reason = validate_pcap_file(str(d))
        assert not ok
        assert "not a regular file" in reason

    def test_zero_byte_file(self, tmp_path):
        f = tmp_path / "empty.pcap"
        f.write_bytes(b"")
        ok, reason = validate_pcap_file(str(f))
        assert not ok
        assert "empty (0 bytes)" in reason

    def test_too_small(self, tmp_path):
        f = tmp_path / "tiny.pcap"
        f.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 10)  # 14 bytes
        ok, reason = validate_pcap_file(str(f))
        assert not ok
        assert "too small" in reason

    def test_bad_magic(self, tmp_path):
        f = tmp_path / "notpcap.pcap"
        f.write_bytes(b"RIFF" + b"\x00" * 40)
        ok, reason = validate_pcap_file(str(f))
        assert not ok
        assert "invalid magic" in reason

    def test_valid_pcap_le(self, tmp_path):
        """Little-endian PCAP with valid global header."""
        import struct
        # Global header: magic(4) + ver_major(2) + ver_minor(2) + thiszone(4)
        #   + sigfigs(4) + snaplen(4) + network(4) = 24 bytes
        ghdr = (
            b"\xd4\xc3\xb2\xa1"  # magic LE
            + struct.pack("<HH", 2, 4)  # version 2.4
            + struct.pack("<i", 0)  # thiszone
            + struct.pack("<I", 0)  # sigfigs
            + struct.pack("<I", 262144)  # snaplen
            + struct.pack("<I", 1)  # network (LINKTYPE_ETHERNET)
        )
        f = tmp_path / "good.pcap"
        f.write_bytes(ghdr)
        ok, reason = validate_pcap_file(str(f))
        assert ok
        assert reason == "ok"

    def test_valid_pcap_be(self, tmp_path):
        """Big-endian PCAP with valid global header."""
        import struct
        ghdr = (
            b"\xa1\xb2\xc3\xd4"
            + struct.pack(">HH", 2, 4)
            + struct.pack(">i", 0)
            + struct.pack(">I", 0)
            + struct.pack(">I", 262144)
            + struct.pack(">I", 1)
        )
        f = tmp_path / "good_be.pcap"
        f.write_bytes(ghdr)
        ok, reason = validate_pcap_file(str(f))
        assert ok

    def test_valid_pcapng(self, tmp_path):
        """Minimal valid pcapng section header block."""
        # SHB: magic(4) + block_total_len(4) + byte_order_magic(4) + ...
        block = (
            b"\x0a\x0d\x0d\x0a"  # block type
            + b"\x1c\x00\x00\x00"  # block total length = 28
            + b"\x1a\x2b\x3c\x4d"  # byte-order magic
            + b"\x01\x00"  # major version
            + b"\x00\x00"  # minor version
            + b"\xff\xff\xff\xff\xff\xff\xff\xff"  # section length = -1
            + b"\x1c\x00\x00\x00"  # block total length repeated
        )
        f = tmp_path / "good.pcapng"
        f.write_bytes(block)
        ok, reason = validate_pcap_file(str(f))
        assert ok

    def test_snaplen_zero_is_corrupt(self, tmp_path):
        """PCAP with snaplen == 0 should be flagged as corrupt."""
        import struct
        ghdr = (
            b"\xd4\xc3\xb2\xa1"
            + struct.pack("<HH", 2, 4)
            + struct.pack("<i", 0)
            + struct.pack("<I", 0)
            + struct.pack("<I", 0)  # snaplen = 0 → corrupt
            + struct.pack("<I", 1)
        )
        f = tmp_path / "bad_snaplen.pcap"
        f.write_bytes(ghdr)
        ok, reason = validate_pcap_file(str(f))
        assert not ok
        assert "snaplen" in reason

    def test_truncated_global_header(self, tmp_path):
        """File with valid magic but truncated global header."""
        f = tmp_path / "truncated.pcap"
        f.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 19)  # Only 23 bytes
        ok, reason = validate_pcap_file(str(f))
        assert not ok
        assert "too small" in reason

    def test_nsec_pcap_valid(self, tmp_path):
        """Nanosecond-resolution PCAP."""
        import struct
        ghdr = (
            b"\x4d\x3c\xb2\xa1"  # nsec LE magic
            + struct.pack("<HH", 2, 4)
            + struct.pack("<i", 0)
            + struct.pack("<I", 0)
            + struct.pack("<I", 262144)
            + struct.pack("<I", 1)
        )
        f = tmp_path / "nsec.pcap"
        f.write_bytes(ghdr)
        ok, reason = validate_pcap_file(str(f))
        assert ok


# ── Existing tests ────────────────────────────────────────────────────


def test_normalize_search_roots_removes_empty_and_duplicates():
    roots = pcap_utils._normalize_search_roots(["/a", "", "/a", "/b"])
    assert roots == ("/a", "/b")


def test_build_pcap_search_roots_uses_defaults_and_dedupes():
    roots = pcap_utils.build_pcap_search_roots("/a", "/b", "/a")
    assert roots == ("/a", "/b")

    assert pcap_utils.build_pcap_search_roots() == pcap_utils.DEFAULT_PCAP_SEARCH_ROOTS


def test_resolve_pcap_path_handles_absent_and_absolute(tmp_path):
    assert pcap_utils.resolve_pcap_path("") is None
    absolute = tmp_path / "capture.pcap"
    absolute.write_text("x", encoding="utf-8")
    assert pcap_utils.resolve_pcap_path(str(absolute)) == str(absolute)
    assert pcap_utils.resolve_pcap_path(str(tmp_path / "missing.pcap")) is None


def test_resolve_pcap_path_searches_roots(tmp_path):
    root_a = tmp_path / "a"
    root_b = tmp_path / "b"
    root_a.mkdir()
    root_b.mkdir()
    capture = root_b / "found.pcap"
    capture.write_text("data", encoding="utf-8")
    resolved = pcap_utils.resolve_pcap_path("found.pcap", [str(root_a), str(root_b)])
    assert resolved == str(capture)


def test_resolve_pcap_reference_uses_raw_item_id(monkeypatch):
    monkeypatch.setattr(
        "app.services.rawsniffer_service.rawsniffer_service.resolve_raw_pcap_item",
        lambda raw_item_id: {
            "path": "/tmp/raw_1.pcap",
            "filename": "raw_1.pcap",
            "raw_item_id": raw_item_id,
        },
    )

    resolved = pcap_utils.resolve_pcap_reference(
        None,
        raw_item_id="raw::pcap::abc123",
    )

    assert resolved == {
        "path": "/tmp/raw_1.pcap",
        "filename": "raw_1.pcap",
        "capture_id": "",
        "raw_item_id": "raw::pcap::abc123",
        "basename": "raw_1",
    }


def test_resolve_pcap_reference_uses_capture_id(monkeypatch):
    # Importante: temos que dar patch na referência que já foi importada no módulo pcap
    # e não na original no handshake_catalog
    monkeypatch.setattr(
        "app.utils.pcap.resolve_capture_pcap",
        lambda capture_id: {
            "path": "/tmp/capture_123.pcap",
            "filename": "handshake_2025.pcap",
            "capture_id": capture_id,
            "basename": "handshake_2025",
            "raw_item_id": "",
        },
    )

    resolved = pcap_utils.resolve_pcap_reference(
        None,
        capture_id="cap::abc123",
    )

    assert resolved == {
        "path": "/tmp/capture_123.pcap",
        "filename": "handshake_2025.pcap",
        "capture_id": "cap::abc123",
        "basename": "handshake_2025",
    }


def test_resolve_pcap_reference_falls_back_to_filename(tmp_path):
    test_file = tmp_path / "test_capture.pcap"
    test_file.write_text("dummy content", encoding="utf-8")

    resolved = pcap_utils.resolve_pcap_reference(
        test_file.name, search_roots=[str(tmp_path)]
    )

    assert resolved is not None
    assert resolved["path"] == str(test_file)
    assert resolved["filename"] == "test_capture.pcap"
    assert resolved["basename"] == "test_capture"
    assert resolved["capture_id"] == ""
    assert resolved["raw_item_id"] == ""


def test_resolve_pcap_reference_returns_none_for_not_found():
    assert pcap_utils.resolve_pcap_reference("nonexistent_file_999.pcap") is None
    assert pcap_utils.resolve_pcap_reference(None) is None
