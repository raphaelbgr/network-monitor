"""REST API route definitions."""

from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect

from netsentinel.api.schemas import (
    DeviceLabelRequest,
    DeviceResponse,
    EventResponse,
    HistoryEntry,
    NetworkInfo,
    PaginatedDevices,
    ScanTriggerResponse,
    StatsResponse,
)
from netsentinel.core.db import DeviceDatabase
from netsentinel.core.events import EventBus
from netsentinel.core.models import Device, DeviceType
from netsentinel.core.scanner import NetworkScanner

router = APIRouter(prefix="/api")


def _device_to_response(device: Device) -> DeviceResponse:
    return DeviceResponse(
        **device.model_dump(),
        display_name=device.display_name,
    )


def create_routes(
    db: DeviceDatabase,
    scanner: NetworkScanner,
    event_bus: EventBus,
    trigger_scan: Any,  # callable
) -> APIRouter:
    """Create the API router with injected dependencies."""

    @router.get("/devices", response_model=PaginatedDevices)
    async def list_devices(
        online: bool | None = Query(None, description="Filter by online status"),
        type: str | None = Query(None, description="Filter by device type"),
        page: int = Query(1, ge=1, description="Page number"),
        page_size: int = Query(50, ge=1, le=200, description="Items per page"),
    ) -> PaginatedDevices:
        dtype = DeviceType(type) if type else None
        all_devices = await db.get_all_devices(
            online_only=online is True,
            device_type=dtype,
        )
        # If online=False explicitly requested, filter offline only
        if online is False:
            all_devices = [d for d in all_devices if not d.is_online]

        total = len(all_devices)
        start = (page - 1) * page_size
        end = start + page_size
        page_devices = all_devices[start:end]

        return PaginatedDevices(
            devices=[_device_to_response(d) for d in page_devices],
            total=total,
            page=page,
            page_size=page_size,
        )

    @router.get("/devices/{mac}", response_model=DeviceResponse)
    async def get_device(mac: str) -> DeviceResponse:
        device = await db.get_device(mac.upper().replace("-", ":"))
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        return _device_to_response(device)

    @router.put("/devices/{mac}/label", response_model=DeviceResponse)
    async def set_label(mac: str, body: DeviceLabelRequest) -> DeviceResponse:
        mac = mac.upper().replace("-", ":")
        ok = await db.set_label(mac, name=body.name, notes=body.notes)
        if not ok:
            raise HTTPException(status_code=404, detail="Device not found")
        device = await db.get_device(mac)
        assert device is not None
        return _device_to_response(device)

    @router.get("/devices/{mac}/history", response_model=list[HistoryEntry])
    async def get_device_history(
        mac: str,
        limit: int = Query(100, ge=1, le=1000),
    ) -> list[HistoryEntry]:
        mac = mac.upper().replace("-", ":")
        history = await db.get_device_history(mac, limit=limit)
        return [HistoryEntry(**h) for h in history]

    @router.post("/scan", response_model=ScanTriggerResponse)
    async def trigger_scan_endpoint() -> ScanTriggerResponse:
        try:
            asyncio.create_task(trigger_scan())
            return ScanTriggerResponse(status="ok", message="Scan triggered")
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    @router.get("/network", response_model=NetworkInfo)
    async def get_network_info() -> NetworkInfo:
        # Attempt to get public IP
        public_ip: str | None = None
        try:
            import httpx

            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get("https://api.ipify.org?format=json")
                if resp.status_code == 200:
                    public_ip = resp.json().get("ip")
        except Exception:
            pass

        return NetworkInfo(
            interface=scanner.interface,
            gateway=scanner.gateway_ip,
            subnet=scanner.subnet,
            public_ip=public_ip,
        )

    @router.get("/stats", response_model=StatsResponse)
    async def get_stats() -> StatsResponse:
        stats = await db.get_stats()
        return StatsResponse(**stats)

    @router.get("/events", response_model=list[EventResponse])
    async def get_recent_events(
        limit: int = Query(100, ge=1, le=500),
    ) -> list[EventResponse]:
        events = event_bus.recent_events[:limit]
        return [
            EventResponse(
                event_type=e.event_type.value,
                device_mac=e.device.mac if e.device else None,
                device_ip=e.device.ipv4 if e.device else None,
                timestamp=e.timestamp.isoformat(),
                details=e.details,
            )
            for e in events
        ]

    return router
