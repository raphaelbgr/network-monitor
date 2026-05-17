"""Integration tests for DeviceDatabase (uses in-memory SQLite)."""

from __future__ import annotations

import pytest
import pytest_asyncio

from netsentinel.core.db import DeviceDatabase
from netsentinel.core.models import Device, DeviceType
from pathlib import Path


@pytest.fixture
async def db(tmp_path: Path) -> DeviceDatabase:  # type: ignore[misc]
    db_path = tmp_path / "test.db"
    db = DeviceDatabase(db_path)
    await db.initialize()
    yield db
    await db.close()


def _make_device(mac: str = "AA:BB:CC:DD:EE:FF", ipv4: str = "192.168.1.1") -> Device:
    return Device(mac=mac, ipv4=ipv4, vendor="Test Vendor", is_online=True)


@pytest.mark.asyncio
async def test_upsert_and_get(db: DeviceDatabase) -> None:
    device = _make_device()
    await db.upsert_device(device)
    fetched = await db.get_device("AA:BB:CC:DD:EE:FF")
    assert fetched is not None
    assert fetched.mac == "AA:BB:CC:DD:EE:FF"
    assert fetched.ipv4 == "192.168.1.1"


@pytest.mark.asyncio
async def test_get_nonexistent(db: DeviceDatabase) -> None:
    result = await db.get_device("00:00:00:00:00:00")
    assert result is None


@pytest.mark.asyncio
async def test_upsert_updates_ip(db: DeviceDatabase) -> None:
    device = _make_device(ipv4="192.168.1.1")
    await db.upsert_device(device)
    updated = device.model_copy(update={"ipv4": "192.168.1.99"})
    await db.upsert_device(updated)
    fetched = await db.get_device("AA:BB:CC:DD:EE:FF")
    assert fetched is not None
    assert fetched.ipv4 == "192.168.1.99"


@pytest.mark.asyncio
async def test_set_offline(db: DeviceDatabase) -> None:
    device = _make_device()
    await db.upsert_device(device)
    await db.set_offline("AA:BB:CC:DD:EE:FF")
    fetched = await db.get_device("AA:BB:CC:DD:EE:FF")
    assert fetched is not None
    assert fetched.is_online is False


@pytest.mark.asyncio
async def test_get_all_devices(db: DeviceDatabase) -> None:
    await db.upsert_device(_make_device("AA:BB:CC:DD:EE:01", "192.168.1.1"))
    await db.upsert_device(_make_device("AA:BB:CC:DD:EE:02", "192.168.1.2"))
    devices = await db.get_all_devices()
    assert len(devices) == 2


@pytest.mark.asyncio
async def test_get_all_devices_online_only(db: DeviceDatabase) -> None:
    await db.upsert_device(_make_device("AA:BB:CC:DD:EE:01", "192.168.1.1"))
    d2 = _make_device("AA:BB:CC:DD:EE:02", "192.168.1.2")
    offline = d2.model_copy(update={"is_online": False})
    await db.upsert_device(offline)
    devices = await db.get_all_devices(online_only=True)
    assert len(devices) == 1
    assert devices[0].mac == "AA:BB:CC:DD:EE:01"


@pytest.mark.asyncio
async def test_set_label(db: DeviceDatabase) -> None:
    await db.upsert_device(_make_device())
    ok = await db.set_label("AA:BB:CC:DD:EE:FF", name="My Device", notes="test notes")
    assert ok is True
    fetched = await db.get_device("AA:BB:CC:DD:EE:FF")
    assert fetched is not None
    assert fetched.custom_name == "My Device"
    assert fetched.notes == "test notes"


@pytest.mark.asyncio
async def test_set_label_nonexistent(db: DeviceDatabase) -> None:
    ok = await db.set_label("00:00:00:00:00:00", name="Ghost")
    assert ok is False


@pytest.mark.asyncio
async def test_add_and_get_history(db: DeviceDatabase) -> None:
    await db.upsert_device(_make_device())
    await db.add_history_event("AA:BB:CC:DD:EE:FF", "192.168.1.1", "device_new")
    await db.add_history_event("AA:BB:CC:DD:EE:FF", "192.168.1.99", "device_ip_changed", "from 192.168.1.1")
    history = await db.get_device_history("AA:BB:CC:DD:EE:FF")
    assert len(history) == 2
    assert history[0]["event_type"] == "device_ip_changed"  # newest first


@pytest.mark.asyncio
async def test_get_stats(db: DeviceDatabase) -> None:
    await db.upsert_device(_make_device("AA:BB:CC:DD:EE:01", "192.168.1.1"))
    d2 = _make_device("AA:BB:CC:DD:EE:02", "192.168.1.2")
    offline = d2.model_copy(update={"is_online": False})
    await db.upsert_device(offline)
    stats = await db.get_stats()
    assert stats["total_devices"] == 2
    assert stats["online_count"] == 1
    assert "new_today" in stats
    assert "type_breakdown" in stats
