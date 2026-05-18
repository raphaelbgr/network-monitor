# NetSentinel — Architecture

## Overview

NetSentinel is a Python 3.11+ application with four main entry points sharing a common core:

```
CLI (Typer)          TUI dashboard (Textual)      REST API (FastAPI)
     │                       │                           │
     └──────────────┬─────────┘              ┌───────────┘
                    │                        │
              ScanOrchestrator         WebSocketManager
                    │                        │
             ┌──────┴──────────────┐         │
             │      Core Layer     │         │
             │  NetworkScanner     │◄────────┘
             │  fingerprint_device │
             │  DeviceDatabase     │
             │  EventBus           │
             └─────────────────────┘
```

## Module Breakdown

### `netsentinel/config.py`

`Settings` (Pydantic `BaseSettings`) loads configuration from three layers with decreasing priority:

1. Environment variables (`NETSENTINEL_*`)
2. `~/.netsentinel/config.yaml` or `./config.yaml`
3. Hardcoded defaults

`get_settings(**overrides)` is the factory used everywhere to avoid a global singleton.

### `netsentinel/core/scanner.py`

`NetworkScanner` performs LAN host discovery. Two code paths:

- **Scapy Layer 2 ARP** (`_arp_scan_scapy`) — fast, reliable, requires Npcap on Windows or root on Linux/macOS.
- **Ping sweep + ARP table** (`_fallback_scan_sync`) — works on Windows without Npcap. Sends concurrent ICMP pings to populate the OS ARP cache, then reads `arp -a`. Up to 64 pings run in parallel via `subprocess.Popen`.

Auto-detection at `initialize()`: calls `_has_l2_support()` to probe the scapy socket class.

Gateway and subnet are auto-detected via scapy's routing table, then `route print` (Windows) or `ip route` (Linux/macOS).

Latency measurement (`_measure_latency`) is best-effort per-host after the scan, up to 20 concurrent.

### `netsentinel/core/fingerprint.py`

`fingerprint_device(raw, settings, existing)` enriches a raw `{mac, ipv4, latency_ms, is_gateway}` dict into a full `Device`. All five sub-tasks run concurrently via `asyncio.gather(return_exceptions=True)`:

1. `lookup_vendor(mac)` — OUI database lookup
2. `resolve_hostname(ip)` — DNS → mDNS → NetBIOS fallback chain
3. `guess_os(ip)` — ping TTL extraction → `_guess_os_from_ttl` (≤64 → Linux/Android, ≤128 → Windows, ≤255 → network equipment)
4. `scan_ports(ip, ports)` — async TCP connect scan on `quick_scan_ports`
5. `discover_ipv6(ip)` — parses `netsh interface ipv6 show neighbors` (Win) or `ip -6 neigh show`

`infer_device_type` combines all signals via priority rules: gateway flag → mDNS services → port hints → vendor strings → OS guess.

### `netsentinel/core/db.py`

`DeviceDatabase` wraps `aiosqlite`. Schema:

| Table | Purpose |
|-------|---------|
| `devices` | Primary device record (MAC primary key) |
| `device_history` | Append-only event log per device |
| `device_labels` | User-assigned names and notes |
| `schema_version` | Migration guard |

`upsert_device` uses `INSERT … ON CONFLICT(mac) DO UPDATE`. The COALESCE guards on `vendor`, `hostname`, `custom_name` etc. preserve previously enriched data when a new scan returns `None` for those fields.

### `netsentinel/core/events.py`

`EventBus` — in-memory pub/sub. Each subscriber gets its own `asyncio.Queue(maxsize=256)`. Overflow handling: drops the oldest event and retries. History buffer: last 500 events (deque-like list slice).

Event types: `device_new`, `device_online`, `device_offline`, `device_ip_changed`, `scan_complete`.

### `netsentinel/main.py`

`ScanOrchestrator` coordinates the full scan cycle:

1. Call `NetworkScanner.scan()` → raw device dicts
2. Run `fingerprint_device` for each, limited by `asyncio.Semaphore(max_concurrent_fingerprint)`
3. Compare with in-memory `_devices` dict → emit NEW / ONLINE / IP_CHANGED events
4. Mark missing MACs as OFFLINE
5. Persist all changes to `DeviceDatabase`
6. Emit `scan_complete`

`run_server()` starts uvicorn with an optional background `_scan_loop` task.

### `netsentinel/api/`

FastAPI app factory (`server.py`). Routes (`routes.py`) use injected `db`, `scanner`, `event_bus`, `trigger_scan` — no global state. WebSocket endpoint at `/ws/events` managed by `WebSocketManager`, which subscribes to `EventBus` and forwards events as JSON to all connected clients.

### `netsentinel/cli/`

Seven Typer commands: `scan`, `watch`, `devices`, `device`, `label`, `export`, `serve`. All use `asyncio.run()` with a fresh event loop. Rich tables for tabular output. `cmd_watch` launches the Textual TUI.

### `netsentinel/cli/dashboard.py`

`NetSentinelApp` (Textual `App`) embeds its own `NetworkScanner` + `DeviceDatabase` + `EventBus` instances. Background scan via `@work(exclusive=True, thread=False)`. The DataTable is rebuilt from scratch on each scan (`table.clear()` + re-add rows). Keybindings: `q` quit, `s` scan now, `r` refresh, `d` device detail notification.

### `netsentinel/webui/static/index.html`

Single-file vanilla JS SPA (no framework). Connects to the REST API for initial data load and subscribes to `/ws/events` for real-time updates. Features: search/filter bar, type filter chips, sortable table columns, inline rename (PUT `/api/devices/{mac}/label`), expandable detail rows, dark theme.

## Data Flow

```
Network → NetworkScanner.scan() → raw [{mac, ipv4, latency_ms, is_gateway}]
                                         │
                               fingerprint_device() ← vendor DB, DNS, ports, TTL
                                         │
                                    Device model
                                         │
                    ┌────────────────────┼──────────────────────┐
                    │                   │                       │
             DeviceDatabase      EventBus.publish()     in-memory dict
               upsert_device()         │
                                 WebSocketManager
                                        │
                               WS clients (browser)
```

## Configuration Priority

```
env vars (NETSENTINEL_*)
    └── config.yaml (user: ~/.netsentinel/config.yaml, fallback: ./config.yaml)
            └── Settings class defaults
```

## Concurrency Model

All I/O is async (asyncio). CPU-bound or blocking system calls (`subprocess.run`, `socket.gethostbyaddr`, OUI lookup) run in a thread pool via `asyncio.to_thread`. Concurrency for fingerprinting is bounded by `asyncio.Semaphore(max_concurrent_fingerprint)` (default: 20).
