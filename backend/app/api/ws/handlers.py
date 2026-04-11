from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from app.api.ws.manager import ConnectionManager
from app.core.auth import is_api_token_enabled, is_websocket_authorized

router = APIRouter()
manager = ConnectionManager()


async def job_event_callback(event_type, data):
    await manager.broadcast({"type": event_type, "payload": data})


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    if is_api_token_enabled() and not is_websocket_authorized(websocket):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)
