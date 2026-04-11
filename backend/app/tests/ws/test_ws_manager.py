import asyncio

from app.api.ws.manager import ConnectionManager


def test_connection_manager_broadcast_removes_failures():
    manager = ConnectionManager()

    class _WS:
        def __init__(self, should_fail=False):
            self.should_fail = should_fail
            self.accepted = False
            self.sent = []

        async def accept(self):
            self.accepted = True

        async def send_json(self, message):
            if self.should_fail:
                raise RuntimeError("fail")
            self.sent.append(message)

    ws_ok = _WS()
    ws_bad = _WS(should_fail=True)

    asyncio.run(manager.connect(ws_ok))
    asyncio.run(manager.connect(ws_bad))

    asyncio.run(manager.broadcast({"hello": "world"}))

    assert ws_ok in manager.active_connections
    assert ws_bad not in manager.active_connections
    assert ws_ok.sent


def test_websocket_ping_pong(client, monkeypatch):
    monkeypatch.delenv("KOVIL_API_TOKEN", raising=False)
    with client.websocket_connect("/ws") as ws:
        ws.send_text("ping")
        msg = ws.receive_text()
        assert msg == "pong"
