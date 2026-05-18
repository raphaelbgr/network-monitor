"""Unit tests for netsentinel.core.fingerprint utilities."""

from __future__ import annotations

import pytest

from netsentinel.core.fingerprint import _guess_os_from_ttl, infer_device_type
from netsentinel.core.models import DeviceType


class TestGuessOsFromTtl:
    def test_linux_ttl(self) -> None:
        assert _guess_os_from_ttl(64) == "Linux/macOS/iOS/Android"

    def test_linux_ttl_low(self) -> None:
        assert _guess_os_from_ttl(50) == "Linux/macOS/iOS/Android"

    def test_windows_ttl(self) -> None:
        assert _guess_os_from_ttl(128) == "Windows"

    def test_windows_ttl_mid(self) -> None:
        assert _guess_os_from_ttl(100) == "Windows"

    def test_network_equipment_ttl(self) -> None:
        assert _guess_os_from_ttl(255) == "Network Equipment"

    def test_none_returns_none(self) -> None:
        assert _guess_os_from_ttl(None) is None


class TestInferDeviceType:
    def test_gateway_always_router(self) -> None:
        assert (
            infer_device_type(
                vendor="Apple",
                open_ports=[],
                os_guess=None,
                is_gateway=True,
                mdns_services=[],
            )
            == DeviceType.ROUTER
        )

    def test_iphone_lockdownd_port(self) -> None:
        result = infer_device_type(
            vendor="Apple",
            open_ports=[62078],
            os_guess=None,
            is_gateway=False,
            mdns_services=[],
        )
        assert result == DeviceType.PHONE

    def test_chromecast_port_8009(self) -> None:
        result = infer_device_type(
            vendor="Google",
            open_ports=[8009],
            os_guess=None,
            is_gateway=False,
            mdns_services=[],
        )
        assert result == DeviceType.SMART_TV

    def test_printer_port_9100(self) -> None:
        result = infer_device_type(
            vendor=None,
            open_ports=[9100],
            os_guess=None,
            is_gateway=False,
            mdns_services=[],
        )
        assert result == DeviceType.PRINTER

    def test_printer_port_631(self) -> None:
        result = infer_device_type(
            vendor=None,
            open_ports=[631],
            os_guess=None,
            is_gateway=False,
            mdns_services=[],
        )
        assert result == DeviceType.PRINTER

    def test_airplay_mdns_smart_tv(self) -> None:
        result = infer_device_type(
            vendor="Samsung",
            open_ports=[],
            os_guess=None,
            is_gateway=False,
            mdns_services=["_airplay._tcp"],
        )
        assert result == DeviceType.SMART_TV

    def test_printer_mdns_ipp(self) -> None:
        result = infer_device_type(
            vendor="HP",
            open_ports=[],
            os_guess=None,
            is_gateway=False,
            mdns_services=["_ipp._tcp"],
        )
        assert result == DeviceType.PRINTER

    def test_samsung_vendor_smart_tv(self) -> None:
        """Samsung/LG via vendor should classify as SMART_TV."""
        result = infer_device_type(
            vendor="Samsung Electronics",
            open_ports=[],
            os_guess=None,
            is_gateway=False,
            mdns_services=[],
        )
        assert result == DeviceType.SMART_TV

    def test_windows_os_is_computer(self) -> None:
        result = infer_device_type(
            vendor=None,
            open_ports=[],
            os_guess="Windows",
            is_gateway=False,
            mdns_services=[],
        )
        assert result == DeviceType.COMPUTER

    def test_linux_with_ssh_is_computer(self) -> None:
        result = infer_device_type(
            vendor=None,
            open_ports=[22],
            os_guess="Linux/macOS/iOS/Android",
            is_gateway=False,
            mdns_services=[],
        )
        assert result == DeviceType.COMPUTER

    def test_espressif_iot(self) -> None:
        result = infer_device_type(
            vendor="Espressif Inc.",
            open_ports=[80],
            os_guess=None,
            is_gateway=False,
            mdns_services=[],
        )
        assert result == DeviceType.IOT_DEVICE

    def test_hp_printer_vendor(self) -> None:
        result = infer_device_type(
            vendor="HP Inc.",
            open_ports=[],
            os_guess=None,
            is_gateway=False,
            mdns_services=[],
        )
        assert result == DeviceType.PRINTER

    def test_unknown_fallback(self) -> None:
        result = infer_device_type(
            vendor=None,
            open_ports=[],
            os_guess=None,
            is_gateway=False,
            mdns_services=[],
        )
        assert result == DeviceType.UNKNOWN
