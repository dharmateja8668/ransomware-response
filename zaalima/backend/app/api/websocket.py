"""WebSocket for real-time SOC notifications."""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import asyncio
import json
from datetime import datetime, timezone

router = APIRouter()

# Connected WebSocket clients
connected_clients: list[WebSocket] = []


@router.websocket("/ws/notifications")
async def websocket_notifications(websocket: WebSocket):
    await websocket.accept()
    connected_clients.append(websocket)
    try:
        # Send welcome message
        await websocket.send_json({
            "type": "connected",
            "message": "Connected to ZAALIMA SOC real-time feed",
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        # Keep alive and listen
        while True:
            data = await websocket.receive_text()
            # Echo ping
            if data == "ping":
                await websocket.send_json({"type": "pong", "timestamp": datetime.now(timezone.utc).isoformat()})
    except WebSocketDisconnect:
        connected_clients.remove(websocket)


async def broadcast_notification(event_type: str, message: str, data: dict = None):
    """Broadcast a notification to all connected WebSocket clients."""
    payload = {
        "type": event_type,
        "message": message,
        "data": data or {},
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    disconnected = []
    for client in connected_clients:
        try:
            await client.send_json(payload)
        except Exception:
            disconnected.append(client)
    for c in disconnected:
        if c in connected_clients:
            connected_clients.remove(c)

