"""Device models and enums for NetSentinel."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class DeviceType(str, Enum):
    ROUTER = "router"
    PHONE = "phone"
    COMPUTER = "computer"
    TABLET = "tablet"
    SMART_TV = "smart_tv"
    IOT_DEVICE = "iot_device"
    PRINTER = "printer"
    GAME_CONSOLE = "game_console"
    UNKNOWN = "unknown"


class EventType(str, Enum):
    DEVICE_ONLINE = "device_online"
    DEVICE_OFFLINE = "device_offline"
    DEVICE_NEW = "device_new"
    DEVICE_IP_CHANGED = "device_ip_changed"
    SCAN_COMPLETE = "scan_complete"


def _now() -> datetime:
    return datetime.now().astimezone()


# Keep alias so existing imports don't break
_utcnow = _now


class Device(BaseModel):
    """Represents a discovered network device."""

    mac: str  # Primary key — normalized uppercase colon-separated
    vendor: str | None = None
    ipv4: str | None = None
    ipv6: str | None = None
    hostname: str | None = None
    custom_name: str | None = None
    device_type: DeviceType = DeviceType.UNKNOWN
    os_guess: str | None = None
    open_ports: list[int] = Field(default_factory=list)
    mdns_services: list[str] = Field(default_factory=list)
    latency_ms: float | None = None
    is_gateway: bool = False
    is_online: bool = True
    first_seen: datetime = Field(default_factory=_utcnow)
    last_seen: datetime = Field(default_factory=_utcnow)
    last_changed: datetime = Field(default_factory=_utcnow)
    scan_count: int = 1
    notes: str | None = None

    @property
    def display_name(self) -> str:
        """Best available name for display purposes."""
        return self.custom_name or self.hostname or self.vendor or self.mac


class DeviceEvent(BaseModel):
    """An event related to a device state change."""

    event_type: EventType
    device: Device | None = None
    timestamp: datetime = Field(default_factory=_utcnow)
    details: dict[str, str] = Field(default_factory=dict)


class ScanResult(BaseModel):
    """Result of a single ARP scan."""

    devices: list[Device]
    duration_seconds: float
    timestamp: datetime = Field(default_factory=_utcnow)
    interface: str | None = None
    subnet: str | None = None
