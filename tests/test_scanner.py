"""Unit tests for netsentinel.core.scanner utilities."""

from __future__ import annotations

import pytest

from netsentinel.core.scanner import _normalize_mac, _parse_arp_table


class TestNormalizeMac:
    def test_colon_uppercase(self) -> None:
        assert _normalize_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"

    def test_hyphen_to_colon(self) -> None:
        assert _normalize_mac("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"

    def test_zero_padded(self) -> None:
        # Some OUI entries omit leading zero in a byte
        assert _normalize_mac("0:1:2:3:4:5") == "00:01:02:03:04:05"

    def test_already_normalized(self) -> None:
        mac = "AA:BB:CC:11:22:33"
        assert _normalize_mac(mac) == mac

    def test_windows_hyphen_format(self) -> None:
        assert _normalize_mac("AA-BB-CC-DD-EE-FF") == "AA:BB:CC:DD:EE:FF"


class TestParseArpTable:
    """Test ARP table parsing across OS output formats."""

    def _run_with_mock_output(
        self, monkeypatch: pytest.MonkeyPatch, stdout: str, gateway_ip: str | None = None
    ) -> list[dict]:
        """Patch subprocess.run to return controlled arp -a output."""
        import subprocess

        class _FakeResult:
            def __init__(self) -> None:
                self.stdout = stdout

        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *args, **kwargs: _FakeResult(),
        )
        return _parse_arp_table(gateway_ip)

    def test_windows_dynamic_entry(self, monkeypatch: pytest.MonkeyPatch) -> None:
        output = (
            "Interface: 192.168.1.100 --- 0xe\n"
            "  Internet Address      Physical Address      Type\n"
            "  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic\n"
        )
        devices = self._run_with_mock_output(monkeypatch, output)
        assert len(devices) == 1
        assert devices[0]["mac"] == "AA:BB:CC:DD:EE:FF"
        assert devices[0]["ipv4"] == "192.168.1.1"
        assert devices[0]["is_gateway"] is False

    def test_windows_static_entry_is_included(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Gateway is often listed as 'static' on Windows — must not be skipped."""
        output = (
            "Interface: 192.168.1.100 --- 0xe\n"
            "  Internet Address      Physical Address      Type\n"
            "  192.168.1.1           aa-bb-cc-dd-ee-ff     static\n"
        )
        devices = self._run_with_mock_output(monkeypatch, output, gateway_ip="192.168.1.1")
        assert len(devices) == 1
        assert devices[0]["is_gateway"] is True

    def test_gateway_flag_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        output = (
            "  192.168.1.1           aa-bb-cc-11-22-33     dynamic\n"
            "  192.168.1.42          aa-bb-cc-44-55-66     dynamic\n"
        )
        devices = self._run_with_mock_output(monkeypatch, output, gateway_ip="192.168.1.1")
        gw = next(d for d in devices if d["ipv4"] == "192.168.1.1")
        assert gw["is_gateway"] is True
        other = next(d for d in devices if d["ipv4"] == "192.168.1.42")
        assert other["is_gateway"] is False

    def test_broadcast_mac_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        output = (
            "  192.168.1.255         ff-ff-ff-ff-ff-ff     static\n"
            "  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic\n"
        )
        devices = self._run_with_mock_output(monkeypatch, output)
        assert all(d["mac"] != "FF:FF:FF:FF:FF:FF" for d in devices)

    def test_incomplete_entry_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        output = (
            "? (192.168.1.50) at <incomplete> on eth0\n"
            "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on eth0\n"
        )
        devices = self._run_with_mock_output(monkeypatch, output)
        assert len(devices) == 1

    def test_linux_format(self, monkeypatch: pytest.MonkeyPatch) -> None:
        output = (
            "? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0\n"
            "? (192.168.1.50) at 11:22:33:44:55:66 [ether] on eth0\n"
        )
        devices = self._run_with_mock_output(monkeypatch, output)
        assert len(devices) == 2

    def test_duplicate_mac_deduplicated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        output = (
            "  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic\n"
            "  192.168.1.2           aa-bb-cc-dd-ee-ff     dynamic\n"
        )
        devices = self._run_with_mock_output(monkeypatch, output)
        assert len(devices) == 1
