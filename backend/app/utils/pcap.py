import logging
import os
import struct
from typing import Iterable

from app.core.config import (
    HANDSHAKES_DIR,
    BRUCE_HANDSHAKES_DIR,
    BRUCE_PCAP_DIR,
    M5EVIL_HANDSHAKES_DIR,
)
from app.services.handshake_catalog import resolve_capture_pcap

logger = logging.getLogger(__name__)

# PCAP / pcapng magic bytes
_PCAP_LE_MAGIC = b"\xd4\xc3\xb2\xa1"
_PCAP_BE_MAGIC = b"\xa1\xb2\xc3\xd4"
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
_PCAP_NSEC_LE_MAGIC = b"\x4d\x3c\xb2\xa1"
_PCAP_NSEC_BE_MAGIC = b"\xa1\xb2\x3c\x4d"

_VALID_MAGICS = (
    _PCAP_LE_MAGIC,
    _PCAP_BE_MAGIC,
    _PCAPNG_MAGIC,
    _PCAP_NSEC_LE_MAGIC,
    _PCAP_NSEC_BE_MAGIC,
)

# Minimum valid PCAP: 24-byte global header + at least 1 packet header (16 bytes)
_MIN_PCAP_SIZE = 24
# pcapng section header block minimum: 28 bytes
_MIN_PCAPNG_SIZE = 28


def validate_pcap_file(path: str) -> tuple[bool, str]:
    """Validate a PCAP/pcapng file before processing.

    Returns (is_valid, reason).  When *is_valid* is ``True`` the file
    passed all sanity checks.  When ``False``, *reason* is a short
    human-readable explanation suitable for logging.
    """
    if not path:
        return False, "empty path"

    if not os.path.exists(path):
        return False, "file does not exist"

    if not os.path.isfile(path):
        return False, "not a regular file"

    try:
        size = os.path.getsize(path)
    except OSError as exc:
        return False, f"cannot stat file: {exc}"

    if size == 0:
        return False, "file is empty (0 bytes)"

    is_pcapng = path.lower().endswith(".pcapng")
    min_size = _MIN_PCAPNG_SIZE if is_pcapng else _MIN_PCAP_SIZE
    if size < min_size:
        return False, f"file too small ({size} bytes, minimum {min_size})"

    try:
        with open(path, "rb") as fh:
            header = fh.read(4)
    except OSError as exc:
        return False, f"cannot read file: {exc}"

    if len(header) < 4:
        return False, "file too small to contain a valid header"

    if header not in _VALID_MAGICS:
        return False, (
            f"invalid magic bytes ({header.hex()}), "
            "not a recognized PCAP/pcapng format"
        )

    # For classic PCAP, do a lightweight truncation check: verify the
    # global header is complete and (optionally) that the first packet
    # record header fits within the file.
    if header in (_PCAP_LE_MAGIC, _PCAP_BE_MAGIC,
                  _PCAP_NSEC_LE_MAGIC, _PCAP_NSEC_BE_MAGIC):
        try:
            with open(path, "rb") as fh:
                ghdr = fh.read(24)
            if len(ghdr) < 24:
                return False, "PCAP global header truncated"
            # Read snaplen from global header (bytes 16-20)
            endian = "<" if header in (_PCAP_LE_MAGIC, _PCAP_NSEC_LE_MAGIC) else ">"
            snaplen = struct.unpack(f"{endian}I", ghdr[16:20])[0]
            if snaplen == 0:
                return False, "PCAP snaplen is 0 (corrupt header)"
        except OSError as exc:
            return False, f"error reading PCAP header: {exc}"

    return True, "ok"

DEFAULT_PCAP_SEARCH_ROOTS = (
    HANDSHAKES_DIR,
    BRUCE_HANDSHAKES_DIR,
    BRUCE_PCAP_DIR,
    M5EVIL_HANDSHAKES_DIR,
)


def _normalize_search_roots(search_roots: Iterable[str] | None) -> tuple[str, ...]:
    roots = search_roots if search_roots is not None else DEFAULT_PCAP_SEARCH_ROOTS
    normalized: list[str] = []
    seen = set()
    for root in roots:
        if not root:
            continue
        if root in seen:
            continue
        seen.add(root)
        normalized.append(root)
    return tuple(normalized)


def build_pcap_search_roots(*roots: str) -> tuple[str, ...]:
    if roots:
        return _normalize_search_roots(roots)
    return _normalize_search_roots(DEFAULT_PCAP_SEARCH_ROOTS)


def resolve_pcap_path(
    filename: str, search_roots: Iterable[str] | None = None
) -> str | None:
    if not filename:
        return None
    if os.path.isabs(filename):
        return filename if os.path.exists(filename) else None

    for root in _normalize_search_roots(search_roots):
        candidate = os.path.join(root, filename)
        if os.path.exists(candidate):
            return candidate
    return None


def resolve_pcap_reference(
    filename: str | None = None,
    *,
    capture_id: str | None = None,
    raw_item_id: str | None = None,
    search_roots: Iterable[str] | None = None,
) -> dict[str, str] | None:
    if capture_id:
        capture = resolve_capture_pcap(capture_id)
        if capture and capture.get("path"):
            return {
                "path": capture["path"],
                "filename": str(capture.get("filename") or filename or ""),
                "capture_id": str(capture.get("capture_id") or capture_id),
                "basename": str(
                    capture.get("basename")
                    or os.path.basename(
                        str(capture.get("filename") or filename or "")
                    ).rsplit(".", 1)[0]
                ),
            }

    if raw_item_id:
        from app.services.rawsniffer_service import rawsniffer_service

        raw_record = rawsniffer_service.resolve_raw_pcap_item(raw_item_id)
        if raw_record and raw_record.get("path"):
            raw_filename = str(raw_record.get("filename") or filename or "")
            return {
                "path": str(raw_record["path"]),
                "filename": raw_filename,
                "capture_id": str(capture_id or ""),
                "raw_item_id": str(raw_record.get("raw_item_id") or raw_item_id),
                "basename": os.path.basename(raw_filename).rsplit(".", 1)[0],
            }

    resolved_path = resolve_pcap_path(str(filename or ""), search_roots=search_roots)
    if not resolved_path:
        return None

    resolved_name = os.path.basename(str(filename or resolved_path))
    return {
        "path": resolved_path,
        "filename": resolved_name,
        "capture_id": str(capture_id or ""),
        "raw_item_id": str(raw_item_id or ""),
        "basename": os.path.basename(resolved_name).rsplit(".", 1)[0],
    }
