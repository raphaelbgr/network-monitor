# NetSentinel

A comprehensive local network monitoring tool — discover, fingerprint, and track every device on your LAN. An open-source alternative to Fing, running in your terminal and browser.

## Features

- **Device discovery** — scans your local network via ARP (scapy Layer 2 when available, ping sweep + ARP table fallback on Windows)
- **Device fingerprinting** — MAC vendor lookup, OS detection (TTL analysis), hostname resolution (DNS / mDNS / NetBIOS), TCP port scanning, mDNS service discovery
- **Real-time monitoring** — interactive Textual TUI dashboard with auto-refresh, plus a WebSocket-powered web UI
- **Persistent tracking** — SQLite database records first seen, last seen, IP changes, and full event history per device
- **Custom labels** — name your devices ("Dad's iPhone", "Living Room TV") with optional notes
- **REST API** — full HTTP API with auto-generated OpenAPI docs at `/docs`
- **Export** — dump your device database to JSON or CSV

## Requirements

- **Python 3.11+**
- **Windows**, Linux, or macOS
- **Administrator / root** privileges recommended for network scanning (on Windows the fallback scanner works without admin)
- Optional: [Npcap](https://npcap.com/) on Windows for native Layer 2 ARP scanning (auto-detected; not required)
- Optional: [nmap](https://nmap.org/) for enhanced OS fingerprinting

## Installation

```bash
# Clone the repository
git clone https://github.com/raphaelbgr/network-monitor.git
cd network-monitor

# Install in editable mode
pip install -e .

# Optional: nmap integration
pip install -e ".[nmap]"
```

> **Note:** If `netsentinel` is not found on your PATH after install, use `python -m netsentinel.cli.app` instead.

## Quick Start

### One-time scan

```bash
# Windows (run terminal as Administrator for best results, but works without)
python -m netsentinel.cli.app scan

# Linux / macOS
sudo netsentinel scan

# View previously scanned devices from the database (no privileges needed)
python -m netsentinel.cli.app scan --dry-run
```

Example output:

```
                                Network Devices
+-----------------------------------------------------------------------------+
| S  | IP Address    | Name     | MAC               | Type |    RTT |     Seen |
|----+---------------+----------+-------------------+------+--------+----------|
| ON | 192.168.7.1   | TP-Link~ | 30:DE:4B:E8:CE:35 | RTR  |    2ms | 16:30:50 |
| ON | 192.168.7.5   | 80:60:B~ | 80:60:B7:C6:0E:DE | PC   |   54ms | 16:30:50 |
| ON | 192.168.7.101 | windows~ | D8:5E:D3:57:3B:CA | PC   |    1ms | 16:30:44 |
| ON | 192.168.7.152 | Amazon ~ | 14:0A:C5:F0:6A:7F | IoT  |    4ms | 16:30:52 |
| ON | 192.168.7.153 | Motorol~ | EC:08:E5:74:48:39 | PHN  |   33ms | 16:30:52 |
+-----------------------------------------------------------------------------+
  19 devices total.
```

### Live TUI dashboard

```bash
python -m netsentinel.cli.app watch
```

Interactive Textual-based dashboard with:
- Auto-refreshing device table with keyboard navigation
- Background scanning at configurable intervals
- Keybindings: **s** = scan now, **r** = refresh, **d** = device detail, **q** = quit

### Web dashboard + API server

```bash
# API server only (serves previously scanned data)
python -m netsentinel.cli.app serve

# API server with background network scanning
python -m netsentinel.cli.app serve --with-scan

# Custom host/port
python -m netsentinel.cli.app serve --with-scan --host 0.0.0.0 --port 8080
```

Then open **http://127.0.0.1:8555** in your browser.

The web UI includes:
- Live-updating device table via WebSocket
- Sortable columns, search/filter bar
- Click-to-rename devices (inline edit)
- Expandable rows with full device details (ports, services, history)
- Dark theme, responsive layout

## CLI Reference

| Command | Description |
|---------|-------------|
| `scan` | One-time network scan and display results |
| `scan --dry-run` | Show devices from database without scanning |
| `watch` | Interactive Textual TUI live dashboard |
| `devices` | List all known devices from the database |
| `devices --online` | List only currently online devices |
| `devices --type phone` | Filter by device type |
| `device <MAC>` | Show detailed info for a single device |
| `label <MAC> "name"` | Assign a custom name to a device |
| `label <MAC> "name" --notes "..."` | Assign name and notes |
| `export --format json` | Export database as JSON to stdout |
| `export --format csv -o devices.csv` | Export database as CSV to file |
| `serve` | Start the REST API server |
| `serve --with-scan` | Start API server with background scanning |

All commands accept `--log-level` (`DEBUG`, `INFO`, `WARNING`, `ERROR`).

**Running commands:**

```bash
# If netsentinel is on PATH:
netsentinel <command>

# Otherwise:
python -m netsentinel.cli.app <command>
```

## REST API

With the server running, interactive docs are at **http://127.0.0.1:8555/docs** (Swagger UI).

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/devices` | List all devices (query: `?online=true`, `?type=phone`, `?page=1`, `?page_size=50`) |
| `GET` | `/api/devices/{mac}` | Get single device details |
| `PUT` | `/api/devices/{mac}/label` | Set custom name/notes — body: `{"name": "...", "notes": "..."}` |
| `GET` | `/api/devices/{mac}/history` | Get IP change history for a device |
| `POST` | `/api/scan` | Trigger an immediate network scan |
| `GET` | `/api/network` | Network info (interface, gateway, subnet, public IP) |
| `GET` | `/api/stats` | Summary stats (total, online, new today, type breakdown) |
| `GET` | `/api/events` | Recent event log (last 100) |
| `WS` | `/ws/events` | WebSocket stream of real-time events |

### WebSocket event format

```json
{
  "event": "device_new",
  "device": { "mac": "AA:BB:CC:DD:EE:FF", "ipv4": "192.168.1.42", "display_name": "...", ... },
  "timestamp": "2026-02-13T16:30:50.123456-03:00"
}
```

Event types: `device_new`, `device_online`, `device_offline`, `device_ip_changed`, `scan_complete`.

## Configuration

NetSentinel works out of the box with zero configuration. It auto-detects your network interface, subnet, and gateway.

### Config file (optional)

Create `~/.netsentinel/config.yaml` to override defaults:

```yaml
interface: null              # Network interface (auto-detect if null)
subnet: null                 # e.g. "192.168.1.0/24" (auto-detect if null)
scan_interval: 30            # Seconds between scans in watch/serve mode
scan_timeout: 3              # ARP scan timeout in seconds
max_concurrent_fingerprint: 20

api_host: "127.0.0.1"
api_port: 8555
log_level: "INFO"

offline_threshold: 300       # Seconds before a device is marked offline

# Ports checked during fingerprinting
quick_scan_ports:
  - 22    # SSH
  - 80    # HTTP
  - 443   # HTTPS
  - 445   # SMB
  - 548   # AFP
  - 8080  # HTTP alt
  - 62078 # iPhone lockdownd
  - 5353  # mDNS
```

### Environment variables

All settings can be overridden with the `NETSENTINEL_` prefix:

```bash
NETSENTINEL_INTERFACE=eth0
NETSENTINEL_SUBNET=192.168.1.0/24
NETSENTINEL_SCAN_INTERVAL=60
NETSENTINEL_API_PORT=9000
NETSENTINEL_LOG_LEVEL=DEBUG
```

## Architecture

```
netsentinel/
├── config.py              # Pydantic settings (YAML + env vars)
├── main.py                # Entry point, ScanOrchestrator, run_server()
├── core/
│   ├── scanner.py         # Network scanning (scapy L2 or ping+arp fallback)
│   ├── fingerprint.py     # OS detection, hostname, ports, mDNS, device type
│   ├── models.py          # Device / DeviceEvent Pydantic models
│   ├── db.py              # Async SQLite persistence (aiosqlite)
│   ├── events.py          # Async pub/sub event bus
│   └── vendor.py          # MAC vendor lookup (OUI database)
├── api/
│   ├── server.py          # FastAPI app factory
│   ├── routes.py          # REST endpoints
│   ├── websocket.py       # WebSocket connection manager
│   └── schemas.py         # API request/response models
├── cli/
│   ├── app.py             # Typer CLI app (7 commands)
│   ├── commands.py        # Command implementations + Rich table output
│   └── dashboard.py       # Textual TUI live dashboard
└── webui/
    └── static/
        └── index.html     # Single-file SPA (vanilla JS, dark theme)
```

### How scanning works

1. **With Npcap/libpcap** (Linux, macOS, or Windows + Npcap): uses scapy's `srp()` for fast Layer 2 ARP scanning
2. **Without Npcap** (default on Windows): performs a concurrent ping sweep to populate the OS ARP table, then parses `arp -a` output — no extra drivers needed

The scanner auto-detects which method is available at startup.

## Device Type Detection

NetSentinel infers device types by combining multiple signals:

| Type | Label | Detection Signals |
|------|-------|-------------------|
| Router | `RTR` | Gateway flag, vendor (TP-Link, Cisco, Netgear, etc.) |
| Phone | `PHN` | Port 62078 (iPhone lockdownd), mobile vendor MACs |
| Computer | `PC` | SSH/HTTP/SMB ports open, Windows TTL (~128), desktop vendors |
| Tablet | `TAB` | Tablet vendor MACs + OS signals |
| Smart TV | `TV` | AirPlay/Chromecast mDNS services, TV vendor MACs |
| IoT Device | `IoT` | ESP/Tuya/Shelly/Amazon vendor MACs |
| Printer | `PRT` | IPP/printer mDNS services, port 9100/631 |
| Game Console | `GME` | Sony/Nintendo/Microsoft + network equipment TTL |
| Unknown | `---` | No matching signals (common with MAC-randomized devices) |

## Data Storage

All data is stored locally in `~/.netsentinel/`:

| File | Purpose |
|------|---------|
| `devices.db` | SQLite database — `devices`, `device_history`, `device_labels` tables |
| `config.yaml` | User configuration overrides |

## Troubleshooting

### "No devices found"
- Verify you are connected to a local network (Wi-Fi or Ethernet)
- Try specifying the subnet explicitly: `NETSENTINEL_SUBNET=192.168.1.0/24 python -m netsentinel.cli.app scan`
- On Windows, try running the terminal as Administrator

### Vendor shows "Unknown"
Many modern devices (especially phones) use **randomized MAC addresses** that don't match any vendor in the OUI database. This is expected behavior. The vendor database is loaded from the bundled `mac-vendor-lookup` library.

### "WARNING: No libpcap provider available"
This is a harmless scapy startup message on Windows when Npcap is not installed. The fallback scanner (ping sweep + ARP table) is used automatically and works fine.

### Slow scanning
- Fingerprinting runs concurrent TCP port checks on each device. If your network has many hosts, scanning may take 10-30 seconds.
- Reduce the port list in config: `quick_scan_ports: [80, 443]`
- Increase concurrency: `max_concurrent_fingerprint: 40`

## Tech Stack

| Component | Library |
|-----------|---------|
| Network scanning | [scapy](https://scapy.net/) |
| CLI framework | [Typer](https://typer.tiangolo.com/) |
| CLI output | [Rich](https://rich.readthedocs.io/) |
| TUI dashboard | [Textual](https://textual.textualize.io/) |
| API server | [FastAPI](https://fastapi.tiangolo.com/) + [uvicorn](https://www.uvicorn.org/) |
| Database | [aiosqlite](https://github.com/omnilib/aiosqlite) (SQLite) |
| MAC vendor lookup | [mac-vendor-lookup](https://github.com/bauerj/mac_vendor_lookup) |
| Configuration | [pydantic-settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/) |
| Async runtime | asyncio + [anyio](https://anyio.readthedocs.io/) |

## License

MIT
