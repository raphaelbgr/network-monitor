"""Async SQLite persistence layer for device data."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiosqlite

from netsentinel.core.models import Device, DeviceType

logger = logging.getLogger(__name__)

_SCHEMA_VERSION = 1

_CREATE_TABLES = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY,
    vendor TEXT,
    ipv4 TEXT,
    ipv6 TEXT,
    hostname TEXT,
    custom_name TEXT,
    device_type TEXT NOT NULL DEFAULT 'unknown',
    os_guess TEXT,
    open_ports TEXT NOT NULL DEFAULT '[]',
    mdns_services TEXT NOT NULL DEFAULT '[]',
    latency_ms REAL,
    is_gateway INTEGER NOT NULL DEFAULT 0,
    is_online INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    last_changed TEXT NOT NULL,
    scan_count INTEGER NOT NULL DEFAULT 1,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS device_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT NOT NULL,
    ipv4 TEXT,
    event_type TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    details TEXT,
    FOREIGN KEY (mac) REFERENCES devices(mac)
);

CREATE INDEX IF NOT EXISTS idx_history_mac ON device_history(mac);
CREATE INDEX IF NOT EXISTS idx_history_timestamp ON device_history(timestamp);

CREATE TABLE IF NOT EXISTS device_labels (
    mac TEXT PRIMARY KEY,
    custom_name TEXT,
    notes TEXT,
    FOREIGN KEY (mac) REFERENCES devices(mac)
);
"""


def _dt_to_str(dt: datetime) -> str:
    return dt.isoformat()


def _str_to_dt(s: str) -> datetime:
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _row_to_device(row: aiosqlite.Row) -> Device:
    """Convert a database row to a Device model."""
    return Device(
        mac=row["mac"],
        vendor=row["vendor"],
        ipv4=row["ipv4"],
        ipv6=row["ipv6"],
        hostname=row["hostname"],
        custom_name=row["custom_name"],
        device_type=DeviceType(row["device_type"]),
        os_guess=row["os_guess"],
        open_ports=json.loads(row["open_ports"]),
        mdns_services=json.loads(row["mdns_services"]),
        latency_ms=row["latency_ms"],
        is_gateway=bool(row["is_gateway"]),
        is_online=bool(row["is_online"]),
        first_seen=_str_to_dt(row["first_seen"]),
        last_seen=_str_to_dt(row["last_seen"]),
        last_changed=_str_to_dt(row["last_changed"]),
        scan_count=row["scan_count"],
        notes=row["notes"],
    )


class DeviceDatabase:
    """Async SQLite database for device persistence."""

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path
        self._db: aiosqlite.Connection | None = None

    async def initialize(self) -> None:
        """Open the database and create tables if needed."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(str(self._db_path))
        self._db.row_factory = aiosqlite.Row
        await self._db.executescript(_CREATE_TABLES)

        # Check/set schema version
        async with self._db.execute("SELECT COUNT(*) FROM schema_version") as cursor:
            count = (await cursor.fetchone())[0]
        if count == 0:
            await self._db.execute(
                "INSERT INTO schema_version (version) VALUES (?)", (_SCHEMA_VERSION,)
            )
        await self._db.commit()
        logger.info("Database initialized at %s", self._db_path)

    async def close(self) -> None:
        """Close the database connection."""
        if self._db:
            await self._db.close()
            self._db = None

    async def upsert_device(self, device: Device) -> None:
        """Insert or update a device record."""
        assert self._db is not None
        await self._db.execute(
            """
            INSERT INTO devices (
                mac, vendor, ipv4, ipv6, hostname, custom_name, device_type,
                os_guess, open_ports, mdns_services, latency_ms, is_gateway,
                is_online, first_seen, last_seen, last_changed, scan_count, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(mac) DO UPDATE SET
                vendor = COALESCE(excluded.vendor, vendor),
                ipv4 = excluded.ipv4,
                ipv6 = COALESCE(excluded.ipv6, ipv6),
                hostname = COALESCE(excluded.hostname, hostname),
                device_type = excluded.device_type,
                os_guess = COALESCE(excluded.os_guess, os_guess),
                open_ports = excluded.open_ports,
                mdns_services = excluded.mdns_services,
                latency_ms = excluded.latency_ms,
                is_gateway = excluded.is_gateway,
                is_online = excluded.is_online,
                last_seen = excluded.last_seen,
                last_changed = excluded.last_changed,
                scan_count = excluded.scan_count,
                notes = COALESCE(excluded.notes, notes)
            """,
            (
                device.mac,
                device.vendor,
                device.ipv4,
                device.ipv6,
                device.hostname,
                device.custom_name,
                device.device_type.value,
                device.os_guess,
                json.dumps(device.open_ports),
                json.dumps(device.mdns_services),
                device.latency_ms,
                int(device.is_gateway),
                int(device.is_online),
                _dt_to_str(device.first_seen),
                _dt_to_str(device.last_seen),
                _dt_to_str(device.last_changed),
                device.scan_count,
                device.notes,
            ),
        )
        await self._db.commit()

    async def get_device(self, mac: str) -> Device | None:
        """Get a single device by MAC address."""
        assert self._db is not None
        async with self._db.execute(
            "SELECT * FROM devices WHERE mac = ?", (mac.upper(),)
        ) as cursor:
            row = await cursor.fetchone()
            return _row_to_device(row) if row else None

    async def get_all_devices(
        self,
        online_only: bool = False,
        device_type: DeviceType | None = None,
    ) -> list[Device]:
        """Get all devices, optionally filtered."""
        assert self._db is not None
        query = "SELECT * FROM devices WHERE 1=1"
        params: list[Any] = []
        if online_only:
            query += " AND is_online = 1"
        if device_type:
            query += " AND device_type = ?"
            params.append(device_type.value)
        query += " ORDER BY is_online DESC, ipv4 ASC"

        async with self._db.execute(query, params) as cursor:
            rows = await cursor.fetchall()
            return [_row_to_device(row) for row in rows]

    async def set_offline(self, mac: str) -> None:
        """Mark a device as offline."""
        assert self._db is not None
        await self._db.execute(
            "UPDATE devices SET is_online = 0 WHERE mac = ?", (mac.upper(),)
        )
        await self._db.commit()

    async def set_all_offline(self) -> None:
        """Mark all devices as offline (before a scan cycle)."""
        assert self._db is not None
        await self._db.execute("UPDATE devices SET is_online = 0")
        await self._db.commit()

    async def set_label(self, mac: str, name: str | None = None, notes: str | None = None) -> bool:
        """Set a custom name and/or notes for a device."""
        assert self._db is not None
        device = await self.get_device(mac)
        if device is None:
            return False

        updates: list[str] = []
        params: list[Any] = []
        if name is not None:
            updates.append("custom_name = ?")
            params.append(name)
        if notes is not None:
            updates.append("notes = ?")
            params.append(notes)
        if not updates:
            return False

        params.append(mac.upper())
        await self._db.execute(
            f"UPDATE devices SET {', '.join(updates)} WHERE mac = ?", params
        )

        # Also upsert into device_labels
        await self._db.execute(
            """
            INSERT INTO device_labels (mac, custom_name, notes)
            VALUES (?, ?, ?)
            ON CONFLICT(mac) DO UPDATE SET
                custom_name = COALESCE(excluded.custom_name, custom_name),
                notes = COALESCE(excluded.notes, notes)
            """,
            (mac.upper(), name, notes),
        )
        await self._db.commit()
        return True

    async def add_history_event(
        self, mac: str, ipv4: str | None, event_type: str, details: str | None = None
    ) -> None:
        """Add an entry to the device history log."""
        assert self._db is not None
        now = _dt_to_str(datetime.now().astimezone())
        await self._db.execute(
            "INSERT INTO device_history (mac, ipv4, event_type, timestamp, details) VALUES (?, ?, ?, ?, ?)",
            (mac.upper(), ipv4, event_type, now, details),
        )
        await self._db.commit()

    async def get_device_history(
        self, mac: str, limit: int = 100
    ) -> list[dict[str, Any]]:
        """Get the event history for a device."""
        assert self._db is not None
        async with self._db.execute(
            "SELECT * FROM device_history WHERE mac = ? ORDER BY timestamp DESC LIMIT ?",
            (mac.upper(), limit),
        ) as cursor:
            rows = await cursor.fetchall()
            return [
                {
                    "id": row["id"],
                    "mac": row["mac"],
                    "ipv4": row["ipv4"],
                    "event_type": row["event_type"],
                    "timestamp": row["timestamp"],
                    "details": row["details"],
                }
                for row in rows
            ]

    async def get_recent_events(self, limit: int = 100) -> list[dict[str, Any]]:
        """Get the most recent events across all devices."""
        assert self._db is not None
        async with self._db.execute(
            "SELECT * FROM device_history ORDER BY timestamp DESC LIMIT ?",
            (limit,),
        ) as cursor:
            rows = await cursor.fetchall()
            return [
                {
                    "id": row["id"],
                    "mac": row["mac"],
                    "ipv4": row["ipv4"],
                    "event_type": row["event_type"],
                    "timestamp": row["timestamp"],
                    "details": row["details"],
                }
                for row in rows
            ]

    async def get_stats(self) -> dict[str, Any]:
        """Get summary statistics."""
        assert self._db is not None
        stats: dict[str, Any] = {}

        async with self._db.execute("SELECT COUNT(*) FROM devices") as cur:
            stats["total_devices"] = (await cur.fetchone())[0]

        async with self._db.execute("SELECT COUNT(*) FROM devices WHERE is_online = 1") as cur:
            stats["online_count"] = (await cur.fetchone())[0]

        # New today
        today_start = datetime.now().astimezone().replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        async with self._db.execute(
            "SELECT COUNT(*) FROM devices WHERE first_seen >= ?",
            (_dt_to_str(today_start),),
        ) as cur:
            stats["new_today"] = (await cur.fetchone())[0]

        # Device type breakdown
        async with self._db.execute(
            "SELECT device_type, COUNT(*) as cnt FROM devices GROUP BY device_type"
        ) as cur:
            rows = await cur.fetchall()
            stats["type_breakdown"] = {row["device_type"]: row["cnt"] for row in rows}

        return stats
