"""Typer CLI application for NetSentinel."""

from __future__ import annotations

import typer

from netsentinel.cli.commands import (
    cmd_device,
    cmd_devices,
    cmd_export,
    cmd_label,
    cmd_scan,
    cmd_serve,
    cmd_watch,
)

app = typer.Typer(
    name="netsentinel",
    help="NetSentinel — comprehensive local network monitoring tool.",
    no_args_is_help=True,
    add_completion=False,
)

app.command("scan", help="Run a one-time network scan and print results.")(cmd_scan)
app.command("watch", help="Live dashboard with auto-refreshing device table.")(cmd_watch)
app.command("devices", help="List all known devices from the database.")(cmd_devices)
app.command("device", help="Show detailed info for a single device.")(cmd_device)
app.command("label", help="Assign a custom name to a device.")(cmd_label)
app.command("export", help="Export the device database to CSV or JSON.")(cmd_export)
app.command("serve", help="Start the API server (optionally with background scanning).")(cmd_serve)


if __name__ == "__main__":
    app()
