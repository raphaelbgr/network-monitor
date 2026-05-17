# NetSentinel — Pending Work

**Project**: Local network monitoring and device fingerprinting tool (open-source Fing alternative).  
**State as of 2026-05-17**: Feature-complete initial release. Scanning, fingerprinting, SQLite persistence, REST API, WebSocket events, Textual TUI dashboard, single-file Web UI, and CLI are all implemented. No tests exist yet.

## Prioritized Pending Items

### P0 — Bugs (correctness)

1. **`DeviceResponse.scan_count` default is 0, not 1** (`netsentinel/api/schemas.py:31`). The DB schema and `Device` model both default to `1`. The schema mismatch means fresh-hit devices display `0` when served via the API until the next scan updates the value from the DB.

2. **`fingerprint_device` uses `return_exceptions=False` in `asyncio.gather`** (`netsentinel/core/fingerprint.py:321`). If any sub-task (vendor lookup, hostname resolution, port scan, IPv6 discovery) raises an exception, the entire fingerprint call propagates the exception to the caller instead of producing a partial result. The defensive `isinstance(result, BaseException)` checks that follow are dead code. Should be `return_exceptions=True`.

3. **`_parse_arp_table` skips all "static" ARP entries** (`netsentinel/core/scanner.py:322`). On Windows, the default gateway is often listed as a `static` entry in `arp -a` output. Skipping it causes the gateway device to be missed entirely in the fallback scan, so `is_gateway` is never set and the router appears absent.

4. **`infer_device_type` TV vendor check is always false** (`netsentinel/core/fingerprint.py:271`). The condition `"smart" in vendor_lower.lower()` checks for the substring "smart" in the raw MAC vendor string (e.g. "Samsung Electronics"), which never contains "smart". Samsung/LG TVs are never classified as `SMART_TV` via vendor path — only via mDNS. This should check port 8009 (Chromecast) or relax the condition.

### P1 — Missing infrastructure

5. **No tests** — zero test files exist. A `tests/` package with unit tests for `_normalize_mac`, `_guess_os_from_ttl`, `_parse_arp_table`, `infer_device_type`, and `DeviceDatabase` CRUD would catch regressions.

6. **`graphify-out/` not in `.gitignore`** — two `graphify-out/` directories (repo root and `netsentinel/`) are untracked and will be committed by accident. Should be added to `.gitignore`.

7. **`custom_name` not synced from `device_labels` on load** — the `upsert_device` ON CONFLICT clause updates `custom_name = COALESCE(excluded.custom_name, custom_name)`, but a fresh fingerprint result always has `custom_name=None` (it's not carried from the DB before upsert). This means a label set via `netsentinel label` is overwritten to `NULL` on the next scan cycle if the device is new to the in-memory dict. The `fingerprint_device` call should load `custom_name`/`notes` from `existing` unconditionally (it already does — but only when `existing` is not `None`; the orchestrator must always pass `existing` from DB before fingerprinting).

### P2 — Enhancements

8. **Port 8009 (Chromecast) missing from default quick_scan_ports** — adding it would improve SMART_TV detection without relying on mDNS.

9. **`DeviceDatabase.get_all_devices` has no search/limit** — pagination exists in the API but the DB query always fetches all rows.

10. **Dashboard `action_show_detail` uses fragile index lookup** (`netsentinel/cli/dashboard.py:327-328`). The device lookup uses `list(self._devices.keys())[table.cursor_row]` which breaks if the table is sorted differently from `_devices` insertion order.
