"""Unit tests for netsentinel.core.models."""

from __future__ import annotations

import pytest

from netsentinel.core.models import Device, DeviceEvent, DeviceType, EventType


class TestDevice:
    def test_display_name_custom_name_takes_priority(self) -> None:
        d = Device(mac="AA:BB:CC:DD:EE:FF", custom_name="My Router", hostname="router.local")
        assert d.display_name == "My Router"

    def test_display_name_falls_back_to_hostname(self) -> None:
        d = Device(mac="AA:BB:CC:DD:EE:FF", hostname="router.local")
        assert d.display_name == "router.local"

    def test_display_name_falls_back_to_vendor(self) -> None:
        d = Device(mac="AA:BB:CC:DD:EE:FF", vendor="TP-Link")
        assert d.display_name == "TP-Link"

    def test_display_name_falls_back_to_mac(self) -> None:
        d = Device(mac="AA:BB:CC:DD:EE:FF")
        assert d.display_name == "AA:BB:CC:DD:EE:FF"

    def test_default_device_type(self) -> None:
        d = Device(mac="AA:BB:CC:DD:EE:FF")
        assert d.device_type == DeviceType.UNKNOWN

    def test_default_is_online(self) -> None:
        d = Device(mac="AA:BB:CC:DD:EE:FF")
        assert d.is_online is True

    def test_scan_count_default(self) -> None:
        d = Device(mac="AA:BB:CC:DD:EE:FF")
        assert d.scan_count == 1

    def test_model_copy_update(self) -> None:
        d = Device(mac="AA:BB:CC:DD:EE:FF", is_online=True)
        offline = d.model_copy(update={"is_online": False})
        assert offline.is_online is False
        assert d.is_online is True  # original unchanged


class TestDeviceEvent:
    def test_event_without_device(self) -> None:
        e = DeviceEvent(event_type=EventType.SCAN_COMPLETE)
        assert e.device is None
        assert e.details == {}

    def test_event_with_device(self) -> None:
        device = Device(mac="AA:BB:CC:DD:EE:FF", ipv4="192.168.1.1")
        e = DeviceEvent(event_type=EventType.DEVICE_NEW, device=device)
        assert e.device is not None
        assert e.device.mac == "AA:BB:CC:DD:EE:FF"

    def test_event_type_values(self) -> None:
        assert EventType.DEVICE_ONLINE.value == "device_online"
        assert EventType.DEVICE_OFFLINE.value == "device_offline"
        assert EventType.DEVICE_NEW.value == "device_new"
        assert EventType.DEVICE_IP_CHANGED.value == "device_ip_changed"
        assert EventType.SCAN_COMPLETE.value == "scan_complete"
