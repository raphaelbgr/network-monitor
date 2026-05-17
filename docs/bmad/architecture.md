# Architecture Document — NetSentinel

**Status**: Active  
**Version**: 0.1.0  
**Date**: 2026-05-17

---

## 1. System Overview

NetSentinel is a single-process Python application with an asyncio event loop. It has four interfaces sharing one core library:

```
┌──────────────────────────────────────────────────────┐
│                   User Interfaces                    │
│                                                      │
│  CLI (Typer)   TUI (Textual)   Web UI (HTML/JS)      │
│      │              │               │                │
│  cmd_scan       NetSentinelApp   index.html          │
│  cmd_watch           │           (static SPA)        │
│  cmd_serve      ScanOrchestrator                     │
│  cmd_devices         │                               │
│  cmd_export          │                               │
└──────────────────────┼───────────────────────────────┘
                       │
┌──────────────────────▼───────────────────────────────┐
│                    Core Library                      │
│                                                      │
│  config.py       Settings (Pydantic)                 │
│  core/           NetworkScanner                      │
│    scanner.py    fingerprint_device()                │
│    fingerprint.py DeviceDatabase                     │
│    db.py         EventBus                            │
│    events.py     Device / DeviceEvent models         │
│    models.py     vendor lookup                       │
│    vendor.py                                         │
│  api/            FastAPI app + routes + WebSocket    │
│    server.py     WebSocketManager                    │
│    routes.py                                         │
│    websocket.py                                      │
│    schemas.py                                        │
└──────────────────────────────────────────────────────┘
```

---

## 2. Component Descriptions

### 2.1 Settings (`config.py`)

`Settings` extends Pydantic `BaseSettings`. The `_merge_yaml` model validator loads the YAML config before Pydantic processes field values, making YAML serve as a secondary source below environment variables but above class defaults.

Key settings:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `interface` | `str \| None` | `None` | Network interface (auto-detect) |
| `subnet` | `str \| None` | `None` | Subnet CIDR (auto-detect) |
| `scan_interval` | `int` | `30` | Seconds between scans |
| `scan_timeout` | `int` | `3` | ARP scan timeout |
| `max_concurrent_fingerprint` | `int` | `20` | Semaphore limit |
| `quick_scan_ports` | `list[int]` | `[22,80,443,445,548,8009,8080,62078,5353]` | TCP ports to probe |
| `api_host` | `str` | `"127.0.0.1"` | API bind address |
| `api_port` | `int` | `8555` | API bind port |

### 2.2 NetworkScanner (`core/scanner.py`)

Async scanner with automatic method selection.

**Initialization flow:**
```
NetworkScanner.initialize()
  ├── _detect_gateway()   → scapy route table | route print | ip route
  ├── _detect_subnet()    → scapy route table | ipconfig | ip addr
  └── _has_l2_support()   → probe scapy conf.L2socket class name
```

**Scan flow:**
```
NetworkScanner.scan()
  ├── [L2 available] _arp_scan_scapy(subnet, iface, timeout, gw_ip)
  │     └── scapy srp(Ether/ARP broadcast) → answered pairs
  └── [fallback] _fallback_scan_sync(subnet, timeout, gw_ip)
        ├── _ping_sweep(subnet) → spawn up to 64 parallel pings
        └── _parse_arp_table(gw_ip) → parse "arp -a" output
  └── asyncio.gather(_measure_latency) for each result (≤20 concurrent)
```

**ARP table parser** supports:
- Windows: `{ip} {mac} dynamic|static` (hyphen MAC)
- Linux: `? ({ip}) at {mac} [ether]` (colon MAC)
- macOS: `? ({ip}) at {mac} on {iface}`

Skips: broadcast MACs, multicast MACs, incomplete entries.

### 2.3 Fingerprinting Pipeline (`core/fingerprint.py`)

```python
async def fingerprint_device(raw, settings, existing=None) -> Device:
    results = await asyncio.gather(
        lookup_vendor(mac),           # MAC OUI database
        resolve_hostname(ip),         # DNS → mDNS → NetBIOS chain
        guess_os(ip),                 # ping TTL extraction
        scan_ports(ip, ports),        # async TCP connect
        discover_ipv6(ip),            # neighbor table lookup
        return_exceptions=True,       # partial results on failure
    )
    # nmap OS detection as optional enrichment
    # mDNS service discovery (best-effort)
    device_type = infer_device_type(vendor, open_ports, os_guess, is_gateway, mdns_services)
    return Device(...)  # merging with existing if provided
```

**Device type inference priority (highest to lowest):**
1. `is_gateway=True` → ROUTER
2. mDNS `_airplay._tcp` or `_googlecast._tcp` → SMART_TV
3. mDNS `_printer._tcp` or `_ipp._tcp` → PRINTER
4. Port 62078 → PHONE
5. Port 8009 → SMART_TV
6. Port 9100 or 631 → PRINTER
7. Vendor string → PRINTER, SMART_TV, IOT_DEVICE, GAME_CONSOLE
8. OS guess → COMPUTER (Windows), COMPUTER or PHONE (Linux/macOS + ports)
9. → UNKNOWN

### 2.4 Device Database (`core/db.py`)

**Schema:**

```sql
devices (
    mac TEXT PRIMARY KEY,
    vendor, ipv4, ipv6, hostname, custom_name TEXT,
    device_type TEXT DEFAULT 'unknown',
    os_guess, open_ports, mdns_services TEXT,
    latency_ms REAL,
    is_gateway, is_online INTEGER,
    first_seen, last_seen, last_changed TEXT,
    scan_count INTEGER DEFAULT 1,
    notes TEXT
)

device_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mac TEXT REFERENCES devices,
    ipv4, event_type, timestamp, details TEXT
)

device_labels (
    mac TEXT PRIMARY KEY REFERENCES devices,
    custom_name, notes TEXT
)
```

`upsert_device` uses `INSERT … ON CONFLICT(mac) DO UPDATE` with `COALESCE(excluded.field, field)` guards to preserve previously enriched data when new scan returns `NULL`.

### 2.5 Event Bus (`core/events.py`)

In-memory pub/sub. Subscribers receive `DeviceEvent` objects via per-subscriber `asyncio.Queue(maxsize=256)`. Overflow: drops oldest event and retries. History: last 500 events (list slice).

```python
queue = event_bus.subscribe()   # returns Queue
await event_bus.publish(event)  # fan-out to all queues
event_bus.unsubscribe(queue)
event_bus.recent_events         # list, newest first
```

### 2.6 ScanOrchestrator (`main.py`)

Coordinates the scan cycle. Maintains an in-memory `dict[mac → Device]` for change detection:

```
run_scan()
  ├── scanner.scan() → raw devices
  ├── asyncio.gather(fingerprint_device, semaphore=max_concurrent_fingerprint)
  ├── for each result:
  │   ├── mac not in _devices → DEVICE_NEW event
  │   ├── device was offline  → DEVICE_ONLINE event
  │   └── IP changed          → DEVICE_IP_CHANGED event
  │   └── upsert to DB + update _devices[mac]
  ├── for missing MACs: set_offline + DEVICE_OFFLINE event
  └── publish SCAN_COMPLETE
```

### 2.7 REST API (`api/`)

FastAPI application factory. All dependencies injected at factory time — no module-level globals.

**Endpoints:**

| Method | Path | Handler |
|--------|------|---------|
| GET | `/api/devices` | `list_devices` — pagination + online/type filters |
| GET | `/api/devices/{mac}` | `get_device` |
| PUT | `/api/devices/{mac}/label` | `set_label` |
| GET | `/api/devices/{mac}/history` | `get_device_history` |
| POST | `/api/scan` | `trigger_scan_endpoint` |
| GET | `/api/network` | `get_network_info` + public IP via httpx |
| GET | `/api/stats` | `get_stats` |
| GET | `/api/events` | recent events from `event_bus.recent_events` |
| WS | `/ws/events` | `WebSocketManager` → JSON event stream |

### 2.8 WebSocketManager (`api/websocket.py`)

Subscribes to `EventBus` at startup. `_broadcast_loop` reads from the subscription queue and sends serialized JSON to all connected WebSocket clients. Dead connections removed automatically.

**Event JSON schema:**
```json
{
  "event": "device_new",
  "timestamp": "2026-05-17T10:00:00.000+00:00",
  "device": {
    "mac": "AA:BB:CC:DD:EE:FF",
    "ipv4": "192.168.1.42",
    "display_name": "...",
    "device_type": "phone",
    ...
  },
  "details": {}
}
```

---

## 3. Concurrency Model

```
asyncio event loop (single thread)
  │
  ├── uvicorn ASGI server tasks
  ├── WebSocketManager._broadcast_loop task
  ├── ScanOrchestrator._scan_loop task
  │     └── asyncio.to_thread(blocking calls)  ← thread pool
  │           • scapy srp
  │           • subprocess.run (ping, arp, route)
  │           • socket.gethostbyaddr
  │           • mac_vendor_lookup
  └── asyncio TCP connect (scan_ports)  ← fully async
```

Thread pool calls are bounded: `asyncio.Semaphore(max_concurrent_fingerprint)` limits total in-flight fingerprint tasks. Within each fingerprint, the five sub-tasks run freely in parallel via `asyncio.gather(return_exceptions=True)`.

---

## 4. Configuration Loading

```
Settings(**overrides)
  └── _merge_yaml() validator
        1. Load ~/.netsentinel/config.yaml or ./config.yaml
        2. Merge: {yaml_values, **{k: v for k, v in overrides.items() if v is not None}}
        3. Pydantic processes merged dict
        4. Env vars (NETSENTINEL_*) applied by BaseSettings after __init__
```

---

## 5. File Layout

```
net-sentinel/
├── config.yaml              Default config (shipped with repo)
├── pyproject.toml           Build, deps, pytest config
├── README.md                User-facing docs
├── ARCHITECTURE.md          This document
├── CHANGELOG.md             Version history
├── PENDING.md               Prioritized work items
├── docs/
│   └── bmad/
│       ├── prd.md           Product requirements
│       └── architecture.md  This document (BMAD form)
├── tests/
│   ├── __init__.py
│   ├── test_models.py
│   ├── test_fingerprint.py
│   ├── test_scanner.py
│   └── test_db.py
└── netsentinel/
    ├── __init__.py          Version string
    ├── config.py            Pydantic settings
    ├── main.py              ScanOrchestrator, run_server()
    ├── core/
    │   ├── scanner.py       ARP scan engine
    │   ├── fingerprint.py   Device enrichment pipeline
    │   ├── models.py        Pydantic data models
    │   ├── db.py            aiosqlite persistence
    │   ├── events.py        Async event bus
    │   └── vendor.py        MAC OUI lookup
    ├── api/
    │   ├── server.py        FastAPI factory
    │   ├── routes.py        REST endpoints
    │   ├── websocket.py     WebSocket manager
    │   └── schemas.py       API request/response schemas
    ├── cli/
    │   ├── app.py           Typer app
    │   ├── commands.py      Command implementations
    │   └── dashboard.py     Textual TUI
    └── webui/
        └── static/
            └── index.html   Single-file SPA
```

---

## 6. Dependency Rationale

| Package | Role | Why |
|---------|------|-----|
| `scapy` | Layer 2 ARP scan | Industry standard; provides fallback detection too |
| `fastapi` | REST API | Auto OpenAPI, async-native, Pydantic integration |
| `uvicorn` | ASGI server | Standard FastAPI runtime |
| `typer` | CLI framework | Declarative, type-annotated, good UX |
| `rich` | Terminal output | Tables, panels, color without boilerplate |
| `textual` | TUI dashboard | Async-native, composable widgets |
| `aiosqlite` | Async SQLite | Zero deployment footprint, local-first |
| `pydantic` + `pydantic-settings` | Models + config | Type safety, validation, env var loading |
| `mac-vendor-lookup` | OUI database | Pure-Python, bundled DB, no network needed |
| `httpx` | Public IP lookup | Async HTTP client in API route |
| `pyyaml` | Config file loading | Standard YAML library |
| `anyio` | Async compatibility | Runtime-agnostic async primitives |
