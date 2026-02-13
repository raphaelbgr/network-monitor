"""Pydantic schemas for API request/response models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from netsentinel.core.models import DeviceType, EventType


class DeviceResponse(BaseModel):
    mac: str
    vendor: str | None = None
    ipv4: str | None = None
    ipv6: str | None = None
    hostname: str | None = None
    custom_name: str | None = None
    display_name: str
    device_type: DeviceType
    os_guess: str | None = None
    open_ports: list[int] = Field(default_factory=list)
    mdns_services: list[str] = Field(default_factory=list)
    latency_ms: float | None = None
    is_gateway: bool = False
    is_online: bool = True
    first_seen: datetime
    last_seen: datetime
    last_changed: datetime
    scan_count: int = 0
    notes: str | None = None


class DeviceLabelRequest(BaseModel):
    name: str | None = None
    notes: str | None = None


class HistoryEntry(BaseModel):
    id: int
    mac: str
    ipv4: str | None = None
    event_type: str
    timestamp: str
    details: str | None = None


class NetworkInfo(BaseModel):
    interface: str | None = None
    gateway: str | None = None
    subnet: str | None = None
    public_ip: str | None = None


class StatsResponse(BaseModel):
    total_devices: int
    online_count: int
    new_today: int
    type_breakdown: dict[str, int] = Field(default_factory=dict)


class EventResponse(BaseModel):
    event_type: str
    device_mac: str | None = None
    device_ip: str | None = None
    timestamp: str
    details: dict[str, str] = Field(default_factory=dict)


class ScanTriggerResponse(BaseModel):
    status: str
    message: str


class PaginatedDevices(BaseModel):
    devices: list[DeviceResponse]
    total: int
    page: int
    page_size: int
