import struct

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routers import ALL_ROUTERS
from app.api.ws.handlers import router as ws_router


# Valid PCAP LE global header (24 bytes)
VALID_PCAP_HEADER = (
    b"\xd4\xc3\xb2\xa1"
    + struct.pack("<HH", 2, 4)
    + struct.pack("<i", 0)
    + struct.pack("<I", 0)
    + struct.pack("<I", 262144)
    + struct.pack("<I", 1)
)

# Valid pcapng Section Header Block (28 bytes)
VALID_PCAPNG_HEADER = (
    b"\x0a\x0d\x0d\x0a"
    + b"\x1c\x00\x00\x00"
    + b"\x1a\x2b\x3c\x4d"
    + b"\x01\x00\x00\x00"
    + b"\xff\xff\xff\xff\xff\xff\xff\xff"
    + b"\x1c\x00\x00\x00"
)


def write_test_pcap(path, *, pcapng: bool = False):
    """Write a minimal valid PCAP/pcapng file at *path* (str or Path)."""
    from pathlib import Path

    p = Path(path)
    p.write_bytes(VALID_PCAPNG_HEADER if pcapng else VALID_PCAP_HEADER)
    return str(p)


@pytest.fixture()
def app():
    app = FastAPI()
    for r in ALL_ROUTERS:
        app.include_router(r)
    app.include_router(ws_router)
    return app


@pytest.fixture()
def client(app):
    with TestClient(app) as client:
        yield client
