# Changelog

## [Unreleased] — 2026-05-17

### Fixed

- **`DeviceResponse.scan_count` default corrected from 0 to 1** (`netsentinel/api/schemas.py`). The API was returning `scan_count: 0` for freshly seen devices instead of `1`, disagreeing with the DB schema default and the `Device` model default. Now consistent at `1`.

- **`fingerprint_device` now uses `return_exceptions=True` in `asyncio.gather`** (`netsentinel/core/fingerprint.py`). Previously, if any enrichment sub-task (vendor lookup, hostname resolution, port scan, IPv6 discovery) raised an exception, the entire fingerprinting call would propagate the exception to the caller and the device would be dropped from the scan result. With `return_exceptions=True`, sub-task failures produce `None` / empty-list fallbacks while the rest of the fingerprint succeeds.

- **`_parse_arp_table` no longer skips "static" ARP entries** (`netsentinel/core/scanner.py`). On Windows, the default gateway is listed as `static` in `arp -a` output. The previous filter caused the gateway to always be absent from fallback scan results, so `is_gateway` was never set for any device. Static entries are now included; only `incomplete` entries are skipped.

- **Smart TV vendor detection fixed** (`netsentinel/core/fingerprint.py`). The previous condition `"smart" in vendor_lower.lower()` checked for the literal substring "smart" in the MAC OUI vendor string (e.g. "Samsung Electronics"), which never matches. Samsung, LG, Sony, Vizio, TCL, Hisense, and Roku devices are now correctly classified as `SMART_TV` via vendor alone.

### Added

- **Port 8009 (Google Cast / Chromecast) added to default quick scan ports** (`netsentinel/config.py`, `config.yaml`). Enables Chromecast-based `SMART_TV` detection without requiring mDNS discovery.

- **Port 8009 triggers `SMART_TV` classification** (`netsentinel/core/fingerprint.py`). `infer_device_type` now returns `SMART_TV` when port 8009 is open.

- **Test suite added** (`tests/`). 52 unit and integration tests covering:
  - `test_models.py` — `Device` display name priority, defaults, `model_copy`; `DeviceEvent` construction; `EventType` values
  - `test_fingerprint.py` — `_guess_os_from_ttl` for all TTL bands; `infer_device_type` for all device type classifications including the fixed Samsung/LG TV case and Chromecast port
  - `test_scanner.py` — `_normalize_mac` (colon, hyphen, zero-pad formats); `_parse_arp_table` across Windows static/dynamic, Linux, macOS formats, broadcast skip, duplicate MAC deduplication, and gateway flag assignment
  - `test_db.py` — `DeviceDatabase` CRUD: upsert, get, set_offline, get_all_devices with filters, set_label, add/get history, stats

- **`pytest` configuration added to `pyproject.toml`** (`[tool.pytest.ini_options]`). Sets `asyncio_mode = "auto"` and `testpaths = ["tests"]` so `python -m pytest` works without flags.

- **`graphify-out/` added to `.gitignore`**. Two untracked `graphify-out/` directories (repo root and `netsentinel/`) are now excluded from version control.

- **`PENDING.md`** — project purpose, current state, and 10 prioritized pending work items with file/line references.

- **`ARCHITECTURE.md`** — module breakdown, data flow diagram, concurrency model, configuration priority.

## [0.1.0] — 2026-04-27

Initial release. Features: ARP network scanning (scapy Layer 2 + ping/arp fallback), device fingerprinting (TTL OS detection, hostname resolution, port scanning, mDNS), SQLite persistence, event bus, REST API, WebSocket live events, Textual TUI dashboard, vanilla JS web UI, CLI with seven commands.
