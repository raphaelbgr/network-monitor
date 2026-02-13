"""Textual TUI dashboard for real-time network monitoring."""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import DataTable, Footer, Header, Label, Static

from netsentinel.config import get_settings, Settings
from netsentinel.core.db import DeviceDatabase
from netsentinel.core.events import EventBus
from netsentinel.core.fingerprint import fingerprint_device
from netsentinel.core.models import Device, DeviceEvent, DeviceType, EventType, _utcnow
from netsentinel.core.scanner import NetworkScanner

logger = logging.getLogger(__name__)

_TYPE_LABEL: dict[DeviceType, str] = {
    DeviceType.ROUTER: "RTR",
    DeviceType.PHONE: "PHN",
    DeviceType.COMPUTER: "PC",
    DeviceType.TABLET: "TAB",
    DeviceType.SMART_TV: "TV",
    DeviceType.IOT_DEVICE: "IoT",
    DeviceType.PRINTER: "PRT",
    DeviceType.GAME_CONSOLE: "GME",
    DeviceType.UNKNOWN: "---",
}


def _trunc(text: str, width: int) -> str:
    if len(text) <= width:
        return text
    return text[: width - 1] + "\u2026"


def _ip_sort_key(ipv4: str | None) -> int:
    parts = (ipv4 or "0.0.0.0").split(".")
    return sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts))


class NetworkBanner(Static):
    """Top banner showing network info and stats."""

    iface: reactive[str] = reactive("detecting...")
    subnet: reactive[str] = reactive("detecting...")
    gateway: reactive[str] = reactive("detecting...")
    total: reactive[int] = reactive(0)
    online: reactive[int] = reactive(0)
    scan_info: reactive[str] = reactive("")

    def render(self) -> str:
        return (
            f" Interface [bold]{self.iface}[/]  |  "
            f"Subnet [bold]{self.subnet}[/]  |  "
            f"Gateway [bold]{self.gateway}[/]  |  "
            f"Devices [bold green]{self.online}[/]/{self.total}  "
            f"  {self.scan_info}"
        )


class EventLog(Static):
    """Bottom bar showing recent events."""

    message: reactive[str] = reactive("Waiting for scan...")

    def render(self) -> str:
        return f" {self.message}"


class NetSentinelApp(App):
    """Textual TUI application for NetSentinel live monitoring."""

    TITLE = "NetSentinel"
    SUB_TITLE = "Network Monitor"

    CSS = """
    Screen {
        background: $surface;
    }
    NetworkBanner {
        dock: top;
        height: 1;
        background: $primary-background;
        color: $text;
        padding: 0 1;
    }
    EventLog {
        dock: bottom;
        height: 1;
        background: $primary-background;
        color: $text-muted;
        padding: 0 1;
    }
    DataTable {
        height: 1fr;
    }
    DataTable > .datatable--header {
        background: $primary-background;
        color: $text;
        text-style: bold;
    }
    DataTable > .datatable--cursor {
        background: $accent 30%;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("s", "trigger_scan", "Scan Now"),
        Binding("r", "refresh_table", "Refresh"),
        Binding("d", "show_detail", "Detail"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._settings: Settings = get_settings()
        self._scanner: NetworkScanner | None = None
        self._db: DeviceDatabase | None = None
        self._event_bus = EventBus()
        self._devices: dict[str, Device] = {}
        self._scanning = False
        self._last_scan_time: datetime | None = None
        self._scan_duration: float | None = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield NetworkBanner()
        yield DataTable(zebra_stripes=True, cursor_type="row")
        yield EventLog()
        yield Footer()

    async def on_mount(self) -> None:
        """Initialize scanner, database, and start the scan loop."""
        # Set up the table columns
        table = self.query_one(DataTable)
        table.add_column("", key="status", width=2)
        table.add_column("Name", key="name", width=22)
        table.add_column("IP Address", key="ip", width=15)
        table.add_column("MAC Address", key="mac", width=17)
        table.add_column("Vendor", key="vendor", width=18)
        table.add_column("Type", key="type", width=5)
        table.add_column("RTT", key="rtt", width=7)
        table.add_column("Last Seen", key="seen", width=10)

        # Initialize core components
        self._db = DeviceDatabase(self._settings.resolved_db_path)
        await self._db.initialize()

        self._scanner = NetworkScanner(self._settings)
        await self._scanner.initialize()

        # Update banner
        banner = self.query_one(NetworkBanner)
        banner.iface = self._scanner.interface or "auto"
        banner.subnet = self._scanner.subnet or "unknown"
        banner.gateway = self._scanner.gateway_ip or "unknown"

        # Load existing devices
        for d in await self._db.get_all_devices():
            self._devices[d.mac] = d

        self._refresh_table()

        # Start background scanning
        self._run_scan_loop()

    def _refresh_table(self) -> None:
        """Rebuild the DataTable rows from current device state."""
        table = self.query_one(DataTable)
        table.clear()

        # Sort: online first, then IP numerically
        sorted_devices = sorted(
            self._devices.values(),
            key=lambda d: (0 if d.is_online else 1, _ip_sort_key(d.ipv4)),
        )

        now = _utcnow()

        for device in sorted_devices:
            status = "ON" if device.is_online else "--"
            name = _trunc(device.display_name, 22)
            vendor = _trunc(device.vendor or "Unknown", 18)
            rtt = f"{device.latency_ms:.0f}ms" if device.latency_ms else "-"
            seen = device.last_seen.strftime("%H:%M:%S")
            dev_type = _TYPE_LABEL.get(device.device_type, "?")

            table.add_row(
                status,
                name,
                device.ipv4 or "-",
                device.mac,
                vendor,
                dev_type,
                rtt,
                seen,
                key=device.mac,
            )

        # Update banner counts
        banner = self.query_one(NetworkBanner)
        banner.total = len(self._devices)
        banner.online = sum(1 for d in self._devices.values() if d.is_online)
        if self._last_scan_time and self._scan_duration is not None:
            banner.scan_info = (
                f"Last scan: {self._last_scan_time.strftime('%H:%M:%S')} "
                f"({self._scan_duration:.1f}s)"
            )

    @work(exclusive=True, thread=False)
    async def _run_scan_loop(self) -> None:
        """Background scan loop."""
        while True:
            await self._do_scan()
            await asyncio.sleep(self._settings.scan_interval)

    async def _do_scan(self) -> None:
        """Execute a single scan cycle."""
        if self._scanning or self._scanner is None or self._db is None:
            return

        self._scanning = True
        event_log = self.query_one(EventLog)
        event_log.message = "Scanning network..."

        try:
            start = time.monotonic()
            raw_devices = await self._scanner.scan()
            scan_dur = time.monotonic() - start

            seen_macs: set[str] = set()
            sem = asyncio.Semaphore(self._settings.max_concurrent_fingerprint)

            async def _fp(raw: dict) -> Device:
                async with sem:
                    existing = self._devices.get(raw["mac"])
                    return await fingerprint_device(raw, self._settings, existing=existing)

            tasks = [_fp(r) for r in raw_devices]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            new_count = 0
            for result in results:
                if isinstance(result, Exception):
                    logger.warning("Fingerprint error: %s", result)
                    continue
                assert isinstance(result, Device)
                mac = result.mac
                seen_macs.add(mac)

                if mac not in self._devices:
                    new_count += 1
                    await self._db.add_history_event(
                        mac, result.ipv4, EventType.DEVICE_NEW.value
                    )
                elif not self._devices[mac].is_online:
                    await self._db.add_history_event(
                        mac, result.ipv4, EventType.DEVICE_ONLINE.value
                    )
                elif self._devices[mac].ipv4 != result.ipv4:
                    await self._db.add_history_event(
                        mac, result.ipv4, EventType.DEVICE_IP_CHANGED.value,
                        f"from {self._devices[mac].ipv4}",
                    )

                self._devices[mac] = result
                await self._db.upsert_device(result)

            # Mark offline
            for mac, device in list(self._devices.items()):
                if mac not in seen_macs and device.is_online:
                    offline = device.model_copy(update={"is_online": False})
                    self._devices[mac] = offline
                    await self._db.set_offline(mac)
                    await self._db.add_history_event(
                        mac, device.ipv4, EventType.DEVICE_OFFLINE.value
                    )

            self._last_scan_time = _utcnow()
            self._scan_duration = scan_dur

            self._refresh_table()

            online = sum(1 for d in self._devices.values() if d.is_online)
            msg = (
                f"Scan complete: {len(raw_devices)} hosts in {scan_dur:.1f}s "
                f"| {online} online | {len(self._devices)} total"
            )
            if new_count:
                msg += f" | {new_count} NEW"
            event_log.message = msg

        except Exception as exc:
            logger.error("Scan failed: %s", exc)
            event_log.message = f"Scan error: {exc}"
        finally:
            self._scanning = False

    def action_trigger_scan(self) -> None:
        """Trigger an immediate scan (bound to 's')."""
        if not self._scanning:
            self._do_scan_once()

    @work(exclusive=True, thread=False)
    async def _do_scan_once(self) -> None:
        await self._do_scan()

    def action_refresh_table(self) -> None:
        """Refresh the table display (bound to 'r')."""
        self._refresh_table()

    def action_show_detail(self) -> None:
        """Show detail for the selected device (bound to 'd')."""
        table = self.query_one(DataTable)
        if table.cursor_row is not None:
            row_key = table.get_row_at(table.cursor_row)
            # row_key is the data; we used MAC as the key
            try:
                row_key_value = list(self._devices.keys())[table.cursor_row]
                device = self._devices.get(row_key_value)
                if device:
                    self.notify(
                        f"{device.display_name}\n"
                        f"IP: {device.ipv4}  MAC: {device.mac}\n"
                        f"Vendor: {device.vendor or 'Unknown'}\n"
                        f"OS: {device.os_guess or 'N/A'}  "
                        f"Ports: {', '.join(map(str, device.open_ports)) or 'None'}",
                        title=f"Device Detail",
                        timeout=8,
                    )
            except (IndexError, KeyError):
                pass

    async def action_quit(self) -> None:
        """Clean up and quit."""
        if self._db:
            await self._db.close()
        self.exit()
