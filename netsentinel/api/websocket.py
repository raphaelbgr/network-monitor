"""WebSocket connection manager for real-time event broadcasting."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect

from netsentinel.core.events import EventBus
from netsentinel.core.models import DeviceEvent

logger = logging.getLogger(__name__)


class WebSocketManager:
    """Manages WebSocket connections and broadcasts events from the event bus."""

    def __init__(self, event_bus: EventBus) -> None:
        self._event_bus = event_bus
        self._connections: list[WebSocket] = []
        self._task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        """Start listening to the event bus and broadcasting to clients."""
        self._queue = self._event_bus.subscribe()
        self._task = asyncio.create_task(self._broadcast_loop())
        logger.info("WebSocket manager started")

    async def stop(self) -> None:
        """Stop the broadcast loop."""
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._event_bus.unsubscribe(self._queue)
        logger.info("WebSocket manager stopped")

    async def connect(self, websocket: WebSocket) -> None:
        """Accept a new WebSocket connection."""
        await websocket.accept()
        self._connections.append(websocket)
        logger.info("WebSocket client connected (total: %d)", len(self._connections))

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a disconnected WebSocket client."""
        try:
            self._connections.remove(websocket)
        except ValueError:
            pass
        logger.info("WebSocket client disconnected (total: %d)", len(self._connections))

    async def _broadcast_loop(self) -> None:
        """Continuously read events from the bus and send to all clients."""
        while True:
            try:
                event: DeviceEvent = await self._queue.get()
                message = self._serialize_event(event)
                await self._broadcast(message)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Broadcast loop error: %s", exc)
                await asyncio.sleep(1)

    async def _broadcast(self, message: str) -> None:
        """Send a message to all connected WebSocket clients."""
        dead: list[WebSocket] = []
        for ws in self._connections:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    def _serialize_event(self, event: DeviceEvent) -> str:
        """Serialize a DeviceEvent to JSON for WebSocket transmission."""
        data: dict[str, Any] = {
            "event": event.event_type.value,
            "timestamp": event.timestamp.isoformat(),
        }
        if event.device:
            data["device"] = json.loads(
                event.device.model_dump_json()
            )
            data["device"]["display_name"] = event.device.display_name
        if event.details:
            data["details"] = event.details
        return json.dumps(data)
