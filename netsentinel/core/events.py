"""In-memory async event bus for device state change notifications."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from netsentinel.core.models import DeviceEvent, EventType

logger = logging.getLogger(__name__)


class EventBus:
    """Async pub/sub event bus using per-subscriber queues.

    Subscribers receive DeviceEvent objects via asyncio.Queue.
    """

    def __init__(self) -> None:
        self._subscribers: list[asyncio.Queue[DeviceEvent]] = []
        self._history: list[DeviceEvent] = []
        self._max_history = 500

    def subscribe(self) -> asyncio.Queue[DeviceEvent]:
        """Create a new subscription queue and return it."""
        queue: asyncio.Queue[DeviceEvent] = asyncio.Queue(maxsize=256)
        self._subscribers.append(queue)
        logger.debug("New event subscriber (total: %d)", len(self._subscribers))
        return queue

    def unsubscribe(self, queue: asyncio.Queue[DeviceEvent]) -> None:
        """Remove a subscription queue."""
        try:
            self._subscribers.remove(queue)
            logger.debug("Subscriber removed (total: %d)", len(self._subscribers))
        except ValueError:
            pass

    async def publish(self, event: DeviceEvent) -> None:
        """Publish an event to all subscribers."""
        self._history.append(event)
        if len(self._history) > self._max_history:
            self._history = self._history[-self._max_history:]

        logger.info(
            "Event: %s | device=%s ip=%s",
            event.event_type.value,
            event.device.mac if event.device else "N/A",
            event.device.ipv4 if event.device else "N/A",
        )

        dead_queues: list[asyncio.Queue[DeviceEvent]] = []
        for queue in self._subscribers:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                # Drop oldest event and try again
                try:
                    queue.get_nowait()
                    queue.put_nowait(event)
                except (asyncio.QueueEmpty, asyncio.QueueFull):
                    dead_queues.append(queue)

        for q in dead_queues:
            self.unsubscribe(q)

    @property
    def recent_events(self) -> list[DeviceEvent]:
        """Return the most recent events (newest first)."""
        return list(reversed(self._history))
