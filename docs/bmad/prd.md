# Product Requirements Document — NetSentinel

**Status**: Active  
**Version**: 0.1.0  
**Date**: 2026-05-17

---

## 1. Problem Statement

Home and small-office network administrators have no reliable, local-first, open-source tool for:

1. Discovering every device on the LAN (not just currently connected)
2. Tracking when devices joined, left, or changed IP
3. Identifying device type and OS without cloud connectivity or accounts
4. Accessing this data programmatically for automation

Commercial alternatives (Fing, Angry IP Scanner) require cloud accounts, phone home telemetry, or restrict advanced features behind subscriptions. `nmap` requires technical skill and retains no history. Router admin panels show only currently connected devices and forget them on disconnect.

---

## 2. Goals

| ID | Goal |
|----|------|
| G1 | Discover all reachable LAN hosts without requiring driver installation on Windows |
| G2 | Identify devices by vendor, hostname, OS, open ports, and device type |
| G3 | Persist all device data and event history locally in SQLite |
| G4 | Expose data via REST API + WebSocket for automation and dashboards |
| G5 | Provide first-class terminal UI (CLI scan + Textual TUI) |
| G6 | Work on Windows, Linux, and macOS with zero configuration |

---

## 3. Non-Goals

- Cloud sync, remote monitoring, or multi-site support
- Deep packet inspection or traffic analysis
- Network access control (blocking/quarantining devices)
- Mobile application
- Real-time alerts (email, push) — data is available via WebSocket for external integration

---

## 4. User Stories

### US-01: Network Discovery
**As a** home user, **I want to** see every device on my LAN with its IP, MAC, vendor, and hostname **so that** I know what is connected to my network.

**Acceptance criteria:**
- `netsentinel scan` runs an ARP scan and prints a table of discovered hosts
- Scan completes within 60 seconds on a /24 subnet
- Works without Npcap on Windows (ping sweep fallback)
- Gateway device is always included and flagged

### US-02: Persistent Tracking
**As a** network admin, **I want to** know when a new device first appeared and every IP it has used **so that** I can audit changes over time.

**Acceptance criteria:**
- First-seen and last-seen timestamps persist across restarts
- Every IP change generates a `device_ip_changed` history event
- `netsentinel device <mac>` shows full event history

### US-03: Device Labeling
**As a** user, **I want to** assign human-readable names to devices **so that** I can identify them without memorizing MAC addresses.

**Acceptance criteria:**
- `netsentinel label <mac> "Dad's iPhone"` sets a persistent label
- Custom labels survive scans (not overwritten by fingerprinting)
- Labels are visible in CLI output, TUI, and web UI

### US-04: Live Dashboard
**As a** network watcher, **I want to** see device status update in real time **so that** I can observe devices coming and going.

**Acceptance criteria:**
- `netsentinel watch` opens a Textual TUI with auto-refreshing table
- `netsentinel serve --with-scan` starts the API with live WebSocket events
- Web UI at `http://127.0.0.1:8555` updates without page refresh

### US-05: REST API Access
**As a** developer, **I want to** query device data over HTTP **so that** I can build automations on top.

**Acceptance criteria:**
- `GET /api/devices` returns paginated device list with filters
- `GET /api/devices/{mac}/history` returns per-device event log
- `POST /api/scan` triggers an immediate scan
- OpenAPI docs available at `/docs`

### US-06: Export
**As a** user, **I want to** export device data as JSON or CSV **so that** I can analyze it in spreadsheets or scripts.

**Acceptance criteria:**
- `netsentinel export --format json` outputs valid JSON array
- `netsentinel export --format csv -o devices.csv` writes CSV file
- Exports include all device fields including custom labels

---

## 5. Functional Requirements

### FR-01: Scanning
- Must support scapy Layer 2 ARP scan when Npcap/libpcap is available
- Must fall back to ping sweep + `arp -a` parsing without Npcap
- Must auto-detect subnet, interface, and gateway
- Must allow manual override via environment variables or config file
- Scan interval configurable (default: 30s in watch/serve mode)

### FR-02: Fingerprinting
- Must resolve hostname via DNS, then mDNS, then NetBIOS
- Must infer OS from ping TTL (Linux ≤64, Windows ≤128, network equipment ≤255)
- Must lookup MAC OUI vendor
- Must scan configurable TCP ports to detect device type
- Must discover mDNS services
- Must classify device into: router, phone, computer, tablet, smart_tv, iot_device, printer, game_console, unknown
- All enrichment must run concurrently; any single failure must not fail the whole device

### FR-03: Persistence
- Must use SQLite via aiosqlite (no server dependency)
- Default DB path: `~/.netsentinel/devices.db`
- Must preserve custom_name, notes across scans
- Must record first_seen, last_seen, scan_count per device
- Must maintain append-only event log (device_history table)

### FR-04: API
- FastAPI with OpenAPI docs
- WebSocket live event stream at `/ws/events`
- CORS open for local use
- Static web UI served at `/`

### FR-05: Configuration
- YAML config file (user at `~/.netsentinel/config.yaml`, project at `./config.yaml`)
- Environment variable override (`NETSENTINEL_*` prefix)
- Code defaults as final fallback

---

## 6. Non-Functional Requirements

| Requirement | Target |
|-------------|--------|
| Scan latency (full /24) | ≤60s (typical 10-30s) |
| Fingerprint concurrency | Configurable, default 20 parallel tasks |
| Database size | ≤10MB for typical home networks (≤50 devices, 1 year) |
| Memory footprint | ≤200MB resident during scan |
| Python version | 3.11+ |
| Platforms | Windows 10+, Ubuntu 20.04+, macOS 12+ |
| Dependencies | No system services; pip-installable |

---

## 7. Release Milestones

| Milestone | Scope | Status |
|-----------|-------|--------|
| 0.1.0 | Core scanner, fingerprinting, DB, CLI, API, TUI, Web UI | Released |
| 0.2.0 | Tests, bug fixes (static ARP, gather exceptions, TV detection), Chromecast port | In progress |
| 0.3.0 | Dashboard detail view fix, DB pagination, alert hooks | Planned |
| 1.0.0 | Stable API, packaging (PyPI), Docker image | Planned |
