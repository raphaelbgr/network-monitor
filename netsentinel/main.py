"""Main entry point — bootstraps scanner, database, event bus, API server, and scheduler."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from netsentinel.config import get_settings
from netsentinel.core.db import DeviceDatabase
from netsentinel.core.events import EventBus
from netsentinel.core.fingerprint import fingerprint_device
from netsentinel.core.models import Device, DeviceEvent, EventType, _utcnow
from netsentinel.core.scanner import NetworkScanner

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """Coordinates periodic scanning, fingerprinting, and event emission."""

    def __init__(
        self,
        scanner: NetworkScanner,
        db: DeviceDatabase,
        event_bus: EventBus,
        settings: Any,
    ) -> None:
        self.scanner = scanner
        self.db = db
        self.event_bus = event_bus
        self.settings = settings
        self._devices: dict[str, Device] = {}
        self._scanning = False

    async def initialize(self) -> None:
        """Load existing devices from DB into memory."""
        for d in await self.db.get_all_devices():
            self._devices[d.mac] = d

    async def run_scan(self) -> list[Device]:
        """Execute a full scan cycle."""
        if self._scanning:
            logger.warning("Scan already in progress, skipping")
            return list(self._devices.values())

        self._scanning = True
        try:
            start = time.monotonic()
            raw_devices = await self.scanner.scan()
            scan_dur = time.monotonic() - start
            logger.info("ARP scan: %d hosts in %.1fs", len(raw_devices), scan_dur)

            seen_macs: set[str] = set()
            sem = asyncio.Semaphore(self.settings.max_concurrent_fingerprint)
            new_devices: list[Device] = []

            async def _fp(raw: dict[str, Any]) -> Device:
                async with sem:
                    existing = self._devices.get(raw["mac"])
                    return await fingerprint_device(raw, self.settings, existing=existing)

            tasks = [_fp(r) for r in raw_devices]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    logger.warning("Fingerprint error: %s", result)
                    continue
                assert isinstance(result, Device)
                mac = result.mac
                seen_macs.add(mac)

                # Emit events
                if mac not in self._devices:
                    await self.event_bus.publish(
                        DeviceEvent(event_type=EventType.DEVICE_NEW, device=result)
                    )
                    await self.db.add_history_event(
                        mac, result.ipv4, EventType.DEVICE_NEW.value
                    )
                elif not self._devices[mac].is_online:
                    await self.event_bus.publish(
                        DeviceEvent(event_type=EventType.DEVICE_ONLINE, device=result)
                    )
                    await self.db.add_history_event(
                        mac, result.ipv4, EventType.DEVICE_ONLINE.value
                    )
                elif self._devices[mac].ipv4 != result.ipv4:
                    await self.event_bus.publish(
                        DeviceEvent(
                            event_type=EventType.DEVICE_IP_CHANGED,
                            device=result,
                            details={
                                "old_ip": self._devices[mac].ipv4 or "",
                                "new_ip": result.ipv4 or "",
                            },
                        )
                    )
                    await self.db.add_history_event(
                        mac,
                        result.ipv4,
                        EventType.DEVICE_IP_CHANGED.value,
                        f"from {self._devices[mac].ipv4}",
                    )

                self._devices[mac] = result
                await self.db.upsert_device(result)
                new_devices.append(result)

            # Mark offline
            for mac, device in list(self._devices.items()):
                if mac not in seen_macs and device.is_online:
                    device_copy = device.model_copy(update={"is_online": False})
                    self._devices[mac] = device_copy
                    await self.db.set_offline(mac)
                    await self.event_bus.publish(
                        DeviceEvent(event_type=EventType.DEVICE_OFFLINE, device=device_copy)
                    )
                    await self.db.add_history_event(
                        mac, device.ipv4, EventType.DEVICE_OFFLINE.value
                    )

            await self.event_bus.publish(
                DeviceEvent(event_type=EventType.SCAN_COMPLETE)
            )

            return new_devices

        except Exception as exc:
            logger.error("Scan cycle failed: %s", exc)
            return []
        finally:
            self._scanning = False


async def run_server(
    host: str = "127.0.0.1",
    port: int = 8555,
    with_scan: bool = False,
) -> None:
    """Start the API server, optionally with background scanning."""
    import uvicorn

    from netsentinel.api.server import create_app

    settings = get_settings(api_host=host, api_port=port)

    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    db = DeviceDatabase(settings.resolved_db_path)
    await db.initialize()

    scanner = NetworkScanner(settings)
    event_bus = EventBus()

    orchestrator: ScanOrchestrator | None = None

    if with_scan:
        await scanner.initialize()
        orchestrator = ScanOrchestrator(scanner, db, event_bus, settings)
        await orchestrator.initialize()

    async def trigger_scan() -> None:
        if orchestrator:
            await orchestrator.run_scan()

    app = create_app(db, scanner, event_bus, trigger_scan)

    # Background scan loop
    async def _scan_loop() -> None:
        if not orchestrator:
            return
        while True:
            try:
                await orchestrator.run_scan()
            except Exception as exc:
                logger.error("Background scan error: %s", exc)
            await asyncio.sleep(settings.scan_interval)

    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level=settings.log_level.lower(),
    )
    server = uvicorn.Server(config)

    if with_scan:
        scan_task = asyncio.create_task(_scan_loop())
        try:
            await server.serve()
        finally:
            scan_task.cancel()
            await db.close()
    else:
        try:
            await server.serve()
        finally:
            await db.close()
