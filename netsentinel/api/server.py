"""FastAPI application factory for NetSentinel API."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from netsentinel.api.routes import create_routes
from netsentinel.api.websocket import WebSocketManager
from netsentinel.core.db import DeviceDatabase
from netsentinel.core.events import EventBus
from netsentinel.core.scanner import NetworkScanner

logger = logging.getLogger(__name__)

_STATIC_DIR = Path(__file__).parent.parent / "webui" / "static"


def create_app(
    db: DeviceDatabase,
    scanner: NetworkScanner,
    event_bus: EventBus,
    trigger_scan: Any,
) -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="NetSentinel API",
        description="Local network monitoring and device discovery API",
        version="0.1.0",
    )

    # CORS — allow all origins for local use
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # WebSocket manager
    ws_manager = WebSocketManager(event_bus)

    @app.on_event("startup")
    async def _startup() -> None:
        await ws_manager.start()

    @app.on_event("shutdown")
    async def _shutdown() -> None:
        await ws_manager.stop()

    # REST routes
    api_router = create_routes(db, scanner, event_bus, trigger_scan)
    app.include_router(api_router)

    # WebSocket endpoint
    @app.websocket("/ws/events")
    async def websocket_endpoint(websocket: WebSocket) -> None:
        await ws_manager.connect(websocket)
        try:
            while True:
                # Keep connection alive; handle pings from client
                data = await websocket.receive_text()
                if data == "ping":
                    await websocket.send_text("pong")
        except WebSocketDisconnect:
            ws_manager.disconnect(websocket)
        except Exception:
            ws_manager.disconnect(websocket)

    # Serve static Web UI
    if _STATIC_DIR.exists():
        app.mount("/", StaticFiles(directory=str(_STATIC_DIR), html=True), name="webui")

    return app
