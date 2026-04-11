import asyncio

from fastapi import WebSocketDisconnect, status

from app.api.ws import handlers as ws_handlers


class _FakeWebSocket:
    def __init__(self, events):
        self._events = iter(events)
        self.closed_code = None
        self.sent_texts = []

    async def close(self, code):
        self.closed_code = code

    async def receive_text(self):
        event = next(self._events)
        if isinstance(event, Exception):
            raise event
        return event

    async def send_text(self, text):
        self.sent_texts.append(text)


def test_job_event_callback_broadcasts_payload(monkeypatch):
    captured = {}

    async def _broadcast(message):
        captured["message"] = message

    monkeypatch.setattr(ws_handlers.manager, "broadcast", _broadcast)
    asyncio.run(ws_handlers.job_event_callback("job_update", {"id": "1"}))

    assert captured["message"] == {"type": "job_update", "payload": {"id": "1"}}


def test_websocket_endpoint_rejects_unauthorized(monkeypatch):
    ws = _FakeWebSocket([])
    state = {"connected": False}

    async def _connect(_ws):
        state["connected"] = True

    monkeypatch.setattr(ws_handlers, "is_api_token_enabled", lambda: True)
    monkeypatch.setattr(ws_handlers, "is_websocket_authorized", lambda _ws: False)
    monkeypatch.setattr(ws_handlers.manager, "connect", _connect)

    asyncio.run(ws_handlers.websocket_endpoint(ws))

    assert ws.closed_code == status.WS_1008_POLICY_VIOLATION
    assert state["connected"] is False


def test_websocket_endpoint_disconnects_on_runtime_error(monkeypatch):
    ws = _FakeWebSocket(["hello", RuntimeError("boom")])
    state = {"connected": 0, "disconnected": 0}

    async def _connect(_ws):
        state["connected"] += 1

    def _disconnect(_ws):
        state["disconnected"] += 1

    monkeypatch.setattr(ws_handlers, "is_api_token_enabled", lambda: False)
    monkeypatch.setattr(ws_handlers, "is_websocket_authorized", lambda _ws: True)
    monkeypatch.setattr(ws_handlers.manager, "connect", _connect)
    monkeypatch.setattr(ws_handlers.manager, "disconnect", _disconnect)

    asyncio.run(ws_handlers.websocket_endpoint(ws))

    assert state["connected"] == 1
    assert state["disconnected"] == 1
    assert ws.sent_texts == []


def test_websocket_endpoint_disconnects_on_websocket_disconnect(monkeypatch):
    ws = _FakeWebSocket([WebSocketDisconnect()])
    state = {"disconnected": 0}

    async def _connect(_ws):
        return None

    def _disconnect(_ws):
        state["disconnected"] += 1

    monkeypatch.setattr(ws_handlers, "is_api_token_enabled", lambda: False)
    monkeypatch.setattr(ws_handlers, "is_websocket_authorized", lambda _ws: True)
    monkeypatch.setattr(ws_handlers.manager, "connect", _connect)
    monkeypatch.setattr(ws_handlers.manager, "disconnect", _disconnect)

    asyncio.run(ws_handlers.websocket_endpoint(ws))
    assert state["disconnected"] == 1
