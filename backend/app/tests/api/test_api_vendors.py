from app.api import deps


class _FakeMacLookup:
    def lookup(self, mac):
        return "VendorX"


class _FakeManuf:
    def get_manuf(self, mac):
        return "VendorY"


def test_vendors_endpoint(client, monkeypatch):
    monkeypatch.setattr(deps, "mac_lookup", _FakeMacLookup())
    monkeypatch.setattr(deps, "manuf_parser", _FakeManuf())

    resp = client.get("/api/vendors/aa:bb:cc")
    assert resp.status_code == 200
    assert resp.json()["data"]["vendor"] == "VendorX"

    resp = client.get("/api/vendors/aa:bb:cc?source=manuf")
    assert resp.status_code == 200
    assert resp.json()["data"]["vendor"] == "VendorY"


def test_vendors_manuf_parser_error_and_exception(client, monkeypatch):
    class _BrokenManuf:
        def get_manuf(self, _mac):
            raise RuntimeError("boom")

    monkeypatch.setattr(deps, "manuf_parser", None)
    resp = client.get("/api/vendors/aa:bb:cc?source=manuf")
    assert resp.status_code == 200
    assert resp.json()["data"]["vendor"] == "Parser Error"

    monkeypatch.setattr(deps, "manuf_parser", _BrokenManuf())
    resp = client.get("/api/vendors/aa:bb:cc?source=manuf")
    assert resp.status_code == 200
    assert resp.json()["data"]["vendor"] == "Error"


def test_vendors_mac_lookup_keyerror_and_exception(client, monkeypatch):
    class _KeyErrorLookup:
        def lookup(self, _mac):
            raise KeyError("missing")

    class _ExceptionLookup:
        def lookup(self, _mac):
            raise RuntimeError("unexpected")

    monkeypatch.setattr(deps, "mac_lookup", _KeyErrorLookup())
    resp = client.get("/api/vendors/aa:bb:cc")
    assert resp.status_code == 200
    assert resp.json()["data"]["vendor"] == "Unknown"

    monkeypatch.setattr(deps, "mac_lookup", _ExceptionLookup())
    resp = client.get("/api/vendors/aa:bb:cc")
    assert resp.status_code == 200
    assert resp.json()["data"]["vendor"] == "Unknown"
