# NetSentinel

A comprehensive local network monitoring tool — discover, fingerprint, and track every device on your LAN. Think of it as an open-source Fing for your terminal and browser.

## Features

- **ARP-based device discovery** — fast, reliable scanning of your local network
- **Device fingerprinting** — vendor lookup, OS detection, hostname resolution, port scanning, mDNS service discovery
- **Real-time monitoring** — live terminal dashboard and WebSocket-powered web UI
- **Device tracking** — persistent SQLite database tracks first seen, last seen, IP changes, and full history
- **Custom labels** — name your devices ("Dad's iPhone", "Living Room TV")
- **REST API** — full HTTP API with OpenAPI docs for automation and integration
- **Export** — dump your device database to JSON or CSV

## Quick Start

### Requirements

- Python 3.11+
- Root/administrator privileges (required for ARP scanning)
- Optional: [nmap](https://nmap.org/) for enhanced OS fingerprinting

### Installation

```bash
# Clone and install
git clone <repo-url> && cd netsentinel
pip install -e .

# Or with uv
uv pip install -e .

# Optional: nmap integration
pip install -e ".[nmap]"
```

### First Scan

```bash
# Run a one-time scan (requires root)
sudo netsentinel scan

# View previously scanned devices (no root needed)
netsentinel scan --dry-run
```

## Usage

### CLI Commands

```bash
# One-time scan — discover and fingerprint all devices
sudo netsentinel scan

# Live dashboard — auto-refreshing terminal UI
sudo netsentinel watch

# List all known devices from the database
netsentinel devices
netsentinel devices --online          # Online only
netsentinel devices --type phone      # Filter by type

# Show detailed info for a single device
netsentinel device AA:BB:CC:DD:EE:FF

# Name a device
netsentinel label AA:BB:CC:DD:EE:FF "Dad's iPhone"
netsentinel label AA:BB:CC:DD:EE:FF "Office Printer" --notes "HP LaserJet on 2nd floor"

# Export database
netsentinel export --format json --output devices.json
netsentinel export --format csv --output devices.csv

# Start the API server
netsentinel serve
netsentinel serve --host 0.0.0.0 --port 8080

# API server with background scanning
sudo netsentinel serve --with-scan
```

### Web Dashboard

Start the server and open http://127.0.0.1:8555 in your browser:

```bash
sudo netsentinel serve --with-scan
```

The web UI features:
- Live-updating device table via WebSocket
- Sortable columns, search/filter bar
- Click-to-rename devices
- Expandable rows with full device details
- Dark theme, responsive layout

### REST API

With the server running, explore the auto-generated docs at http://127.0.0.1:8555/docs.

Key endpoints:

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/devices` | List all devices (with pagination, filters) |
| GET | `/api/devices/{mac}` | Get single device details |
| PUT | `/api/devices/{mac}/label` | Set custom name/notes |
| GET | `/api/devices/{mac}/history` | IP change history |
| POST | `/api/scan` | Trigger an immediate scan |
| GET | `/api/network` | Network info (interface, gateway, subnet) |
| GET | `/api/stats` | Summary statistics |
| GET | `/api/events` | Recent event log |
| WS | `/ws/events` | Real-time event stream |

## Configuration

NetSentinel uses sensible defaults. Override via config file or environment variables.

### Config file

Create `~/.netsentinel/config.yaml`:

```yaml
interface: eth0              # Auto-detect if null
subnet: "192.168.1.0/24"    # Auto-detect if null
scan_interval: 30            # Seconds between scans
scan_timeout: 3              # ARP scan timeout
api_host: "127.0.0.1"
api_port: 8555
log_level: "INFO"
offline_threshold: 300       # Seconds before device marked offline
```

### Environment variables

All settings can be overridden with `NETSENTINEL_` prefix:

```bash
NETSENTINEL_INTERFACE=eth0
NETSENTINEL_SCAN_INTERVAL=60
NETSENTINEL_API_PORT=9000
NETSENTINEL_LOG_LEVEL=DEBUG
```

## Architecture

```
netsentinel/
├── config.py           # Pydantic settings (YAML + env vars)
├── main.py             # Entry point, orchestrator
├── core/
│   ├── scanner.py      # ARP scanning via scapy
│   ├── fingerprint.py  # OS detection, hostname, ports, mDNS
│   ├── models.py       # Device/Event Pydantic models
│   ├── db.py           # SQLite async persistence
│   ├── events.py       # Async pub/sub event bus
│   └── vendor.py       # MAC vendor lookup
├── api/
│   ├── server.py       # FastAPI app factory
│   ├── routes.py       # REST endpoints
│   ├── websocket.py    # WebSocket manager
│   └── schemas.py      # API request/response models
├── cli/
│   ├── app.py          # Typer CLI app
│   ├── commands.py     # CLI command implementations
│   └── dashboard.py    # Rich Live dashboard
└── webui/
    └── static/
        └── index.html  # Single-file SPA dashboard
```

## Device Types

NetSentinel infers device types from multiple signals:

| Type | Detection Method |
|------|-----------------|
| Router | Gateway flag, vendor (Cisco, Netgear, etc.) |
| Phone | Port 62078 (iPhone), mobile vendors |
| Computer | SSH/HTTP ports, Windows TTL, desktop vendors |
| Smart TV | AirPlay/Chromecast mDNS, TV vendors |
| Printer | IPP/printer mDNS, port 9100, printer vendors |
| IoT Device | ESP/Tuya/Shelly vendors |
| Game Console | Sony/Nintendo/Microsoft + network TTL |

## Data Storage

All data is stored locally at `~/.netsentinel/`:

- `devices.db` — SQLite database with device records and history
- `config.yaml` — user configuration overrides

## Troubleshooting

**"Root/administrator privileges required"**
ARP scanning requires raw socket access. Run with `sudo` on Linux/macOS or as Administrator on Windows.

**No devices found**
- Check that you're connected to a local network
- Try specifying the interface: `NETSENTINEL_INTERFACE=eth0 sudo netsentinel scan`
- Try specifying the subnet: `NETSENTINEL_SUBNET=192.168.1.0/24 sudo netsentinel scan`

**Vendor shows "Unknown"**
The MAC vendor database may need updating. The library auto-updates on first use if internet is available.

## License

MIT
