"""CLI command implementations for NetSentinel."""

from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import sys
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from netsentinel.config import get_settings
from netsentinel.core.models import Device, DeviceType

console = Console()

# Short type labels that won't eat column space
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


def _setup_logging(level: str = "WARNING") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.WARNING),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def _check_root() -> None:
    from netsentinel.core.scanner import check_privileges

    if not check_privileges():
        console.print(
            Panel(
                "[bold red]Root/administrator privileges required for network scanning.[/]\n\n"
                "Run with:\n"
                "  [bold]sudo netsentinel scan[/]          (Linux/macOS)\n"
                "  [bold]Run as Administrator[/]            (Windows)\n\n"
                "Or use [bold]--dry-run[/] to view previously saved devices.",
                title="Insufficient Privileges",
                border_style="red",
            )
        )
        raise typer.Exit(1)


def _trunc(text: str, width: int) -> str:
    """Truncate text with ellipsis if too long."""
    if len(text) <= width:
        return text
    return text[: width - 1] + "\u2026"


def _ip_sort_key(d: Device) -> tuple[int, int]:
    """Sort key: online first, then by IP address numerically."""
    parts = (d.ipv4 or "0.0.0.0").split(".")
    ip_num = sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts))
    return (0 if d.is_online else 1, ip_num)


def _build_device_table(devices: list[Device], title: str = "Network Devices") -> Table:
    """Build a compact Rich table that adapts to terminal width."""
    term_width = console.width
    wide = term_width >= 110  # enough room for all columns

    table = Table(
        title=title,
        show_lines=False,
        expand=True,
        padding=(0, 1),
        title_style="bold cyan",
        border_style="bright_black",
    )

    # Always show these columns
    table.add_column("S", width=2, justify="center", no_wrap=True)
    table.add_column("IP Address", min_width=11, max_width=15, no_wrap=True)
    table.add_column("Name", no_wrap=True, ratio=2)
    table.add_column("MAC", width=17, no_wrap=True, style="dim")

    if wide:
        table.add_column("Vendor", no_wrap=True, ratio=1)

    table.add_column("Type", width=3, no_wrap=True, justify="center")
    table.add_column("RTT", width=6, no_wrap=True, justify="right")
    table.add_column("Seen", width=8, no_wrap=True, justify="right")

    devices.sort(key=_ip_sort_key)

    for device in devices:
        status = "[bold green]ON[/]" if device.is_online else "[red]--[/]"
        name = device.display_name
        latency = f"{device.latency_ms:.0f}ms" if device.latency_ms else "-"
        last_seen = device.last_seen.strftime("%H:%M:%S")
        dev_type = _TYPE_LABEL.get(device.device_type, "?")
        row_style = "" if device.is_online else "dim"

        row: list[str] = [
            status,
            device.ipv4 or "-",
            name,
            device.mac,
        ]
        if wide:
            row.append(device.vendor or "Unknown")
        row.extend([dev_type, latency, last_seen])

        table.add_row(*row, style=row_style)

    return table


async def _run_scan(dry_run: bool = False) -> list[Device]:
    """Execute a full scan cycle: ARP scan -> fingerprint -> persist."""
    from netsentinel.core.db import DeviceDatabase
    from netsentinel.core.fingerprint import fingerprint_device
    from netsentinel.core.scanner import NetworkScanner

    settings = get_settings()
    db = DeviceDatabase(settings.resolved_db_path)
    await db.initialize()

    if dry_run:
        devices = await db.get_all_devices()
        await db.close()
        return devices

    scanner = NetworkScanner(settings)
    await scanner.initialize()

    console.print(
        f"[bold]Scanning[/] {scanner.subnet} on {scanner.interface}...",
        highlight=False,
    )

    start = time.monotonic()
    raw_devices = await scanner.scan()
    scan_duration = time.monotonic() - start

    console.print(
        f"ARP scan found [bold]{len(raw_devices)}[/] hosts in {scan_duration:.1f}s. Fingerprinting..."
    )

    # Fingerprint all devices concurrently (with semaphore)
    sem = asyncio.Semaphore(settings.max_concurrent_fingerprint)
    devices: list[Device] = []

    async def _fingerprint_one(raw: dict) -> Device:
        async with sem:
            existing = await db.get_device(raw["mac"])
            return await fingerprint_device(raw, settings, existing=existing)

    tasks = [_fingerprint_one(r) for r in raw_devices]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, Device):
            devices.append(result)
            await db.upsert_device(result)
        elif isinstance(result, Exception):
            console.print(f"[yellow]Warning:[/] fingerprint failed: {result}")

    await db.close()
    return devices


def cmd_scan(
    dry_run: bool = typer.Option(False, "--dry-run", help="Load from DB only, no network scan."),
    log_level: str = typer.Option("WARNING", "--log-level", "-l", help="Logging level."),
) -> None:
    """Run a one-time network scan and display results."""
    _setup_logging(log_level)
    if not dry_run:
        _check_root()

    devices = asyncio.run(_run_scan(dry_run=dry_run))

    if not devices:
        console.print("[yellow]No devices found.[/]")
        raise typer.Exit(0)

    table = _build_device_table(devices)
    console.print()
    console.print(table)
    console.print(f"\n  [bold]{len(devices)}[/] devices total.\n")


def cmd_watch(
    log_level: str = typer.Option("WARNING", "--log-level", "-l"),
) -> None:
    """Start a live auto-refreshing dashboard."""
    _check_root()
    _setup_logging(log_level)
    from netsentinel.cli.dashboard import NetSentinelApp

    app = NetSentinelApp()
    app.run()


def cmd_devices(
    online: bool = typer.Option(False, "--online", help="Show only online devices."),
    device_type: Optional[str] = typer.Option(None, "--type", help="Filter by device type."),
    log_level: str = typer.Option("WARNING", "--log-level", "-l"),
) -> None:
    """List all known devices from the database."""
    _setup_logging(log_level)

    async def _list() -> list[Device]:
        from netsentinel.core.db import DeviceDatabase

        settings = get_settings()
        db = DeviceDatabase(settings.resolved_db_path)
        await db.initialize()
        dtype = DeviceType(device_type) if device_type else None
        devices = await db.get_all_devices(online_only=online, device_type=dtype)
        await db.close()
        return devices

    devices = asyncio.run(_list())

    if not devices:
        console.print("[yellow]No devices in database. Run 'netsentinel scan' first.[/]")
        raise typer.Exit(0)

    table = _build_device_table(devices, title="Known Devices")
    console.print()
    console.print(table)
    console.print(f"\n  [bold]{len(devices)}[/] devices total.\n")


def cmd_device(
    mac: str = typer.Argument(help="MAC address of the device."),
    log_level: str = typer.Option("WARNING", "--log-level", "-l"),
) -> None:
    """Show detailed info for a single device."""
    _setup_logging(log_level)

    async def _detail() -> Device | None:
        from netsentinel.core.db import DeviceDatabase

        settings = get_settings()
        db = DeviceDatabase(settings.resolved_db_path)
        await db.initialize()
        device = await db.get_device(mac.upper())
        await db.close()
        return device

    device = asyncio.run(_detail())

    if not device:
        console.print(f"[red]Device {mac} not found.[/]")
        raise typer.Exit(1)

    panel_text = (
        f"[bold]MAC:[/]         {device.mac}\n"
        f"[bold]Vendor:[/]      {device.vendor or 'Unknown'}\n"
        f"[bold]IPv4:[/]        {device.ipv4 or 'N/A'}\n"
        f"[bold]IPv6:[/]        {device.ipv6 or 'N/A'}\n"
        f"[bold]Hostname:[/]    {device.hostname or 'N/A'}\n"
        f"[bold]Custom Name:[/] {device.custom_name or 'N/A'}\n"
        f"[bold]Type:[/]        {device.device_type.value}\n"
        f"[bold]OS Guess:[/]    {device.os_guess or 'N/A'}\n"
        f"[bold]Open Ports:[/]  {', '.join(map(str, device.open_ports)) or 'None'}\n"
        f"[bold]mDNS:[/]        {', '.join(device.mdns_services) or 'None'}\n"
        f"[bold]Latency:[/]     {f'{device.latency_ms:.1f}ms' if device.latency_ms else 'N/A'}\n"
        f"[bold]Gateway:[/]     {'Yes' if device.is_gateway else 'No'}\n"
        f"[bold]Online:[/]      {'Yes' if device.is_online else 'No'}\n"
        f"[bold]First Seen:[/]  {device.first_seen.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"[bold]Last Seen:[/]   {device.last_seen.strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"[bold]Scan Count:[/]  {device.scan_count}\n"
        f"[bold]Notes:[/]       {device.notes or 'N/A'}"
    )
    console.print(Panel(panel_text, title=device.display_name, border_style="cyan"))


def cmd_label(
    mac: str = typer.Argument(help="MAC address of the device."),
    name: str = typer.Argument(help="Custom name to assign."),
    notes: Optional[str] = typer.Option(None, "--notes", "-n", help="Optional notes."),
    log_level: str = typer.Option("WARNING", "--log-level", "-l"),
) -> None:
    """Assign a custom name (and optional notes) to a device."""
    _setup_logging(log_level)

    async def _label() -> bool:
        from netsentinel.core.db import DeviceDatabase

        settings = get_settings()
        db = DeviceDatabase(settings.resolved_db_path)
        await db.initialize()
        ok = await db.set_label(mac, name=name, notes=notes)
        await db.close()
        return ok

    if asyncio.run(_label()):
        console.print(f"[green]Labeled {mac.upper()} as '{name}'.[/]")
    else:
        console.print(f"[red]Device {mac} not found in database.[/]")
        raise typer.Exit(1)


def cmd_export(
    format: str = typer.Option("json", "--format", "-f", help="Export format: json or csv."),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path."),
    log_level: str = typer.Option("WARNING", "--log-level", "-l"),
) -> None:
    """Export the device database to JSON or CSV."""
    _setup_logging(log_level)

    async def _export() -> list[Device]:
        from netsentinel.core.db import DeviceDatabase

        settings = get_settings()
        db = DeviceDatabase(settings.resolved_db_path)
        await db.initialize()
        devices = await db.get_all_devices()
        await db.close()
        return devices

    devices = asyncio.run(_export())

    if format.lower() == "json":
        data = [d.model_dump(mode="json") for d in devices]
        text = json.dumps(data, indent=2, default=str)
    elif format.lower() == "csv":
        buf = io.StringIO()
        if devices:
            fields = list(devices[0].model_dump().keys())
            writer = csv.DictWriter(buf, fieldnames=fields)
            writer.writeheader()
            for d in devices:
                row = d.model_dump(mode="json")
                row["open_ports"] = ";".join(map(str, row["open_ports"]))
                row["mdns_services"] = ";".join(row["mdns_services"])
                writer.writerow(row)
        text = buf.getvalue()
    else:
        console.print(f"[red]Unsupported format: {format}. Use json or csv.[/]")
        raise typer.Exit(1)

    if output:
        Path(output).write_text(text, encoding="utf-8")
        console.print(f"[green]Exported {len(devices)} devices to {output}[/]")
    else:
        console.print(text)


def cmd_serve(
    host: str = typer.Option("127.0.0.1", "--host", "-h", help="API server bind host."),
    port: int = typer.Option(8555, "--port", "-p", help="API server bind port."),
    with_scan: bool = typer.Option(False, "--with-scan", help="Enable background scanning."),
    log_level: str = typer.Option("INFO", "--log-level", "-l"),
) -> None:
    """Start the API server, optionally with background scanning."""
    _setup_logging(log_level)

    from netsentinel.main import run_server

    asyncio.run(run_server(host=host, port=port, with_scan=with_scan))
