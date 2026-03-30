"""
Yashigani Events — Lightweight in-process pub/sub event bus.
Uses asyncio.Queue per subscriber. No external broker dependency.
Thread-safe: publish() is safe to call from sync or async context.

Design constraints:
- Subscribers receive events as dicts — no serialization coupling.
- Dropped events are tolerated (maxsize=512 per subscriber; oldest evicted).
- The bus itself is a process singleton via get_event_bus().
- No persistence — events live only as long as they are in the queue.
"""
from __future__ import annotations

import asyncio
import logging
from typing import AsyncIterator, Optional

logger = logging.getLogger(__name__)

_MAX_QUEUE_SIZE = 512  # per subscriber; oldest dropped on overflow


class EventBus:
    """
    In-process publish/subscribe bus backed by asyncio.Queue.

    Usage:
        bus = EventBus()

        # Producer
        await bus.publish({"event_type": "INSPECTION_RESULT", ...})

        # Consumer (async generator)
        async for event in bus.subscribe():
            handle(event)
    """

    def __init__(self) -> None:
        self._subscribers: list[asyncio.Queue] = []
        self._lock = asyncio.Lock()

    async def publish(self, event: dict) -> None:
        """
        Broadcast event to all active subscribers.
        Non-blocking: if a subscriber queue is full, the oldest item is
        evicted and the new event is placed at the back.
        """
        async with self._lock:
            active: list[asyncio.Queue] = []
            for q in self._subscribers:
                if q.maxsize and q.full():
                    # Evict oldest — best effort, non-blocking
                    try:
                        q.get_nowait()
                    except asyncio.QueueEmpty:
                        pass
                try:
                    q.put_nowait(event)
                    active.append(q)
                except Exception as exc:
                    logger.debug("EventBus: failed to deliver to subscriber: %s", exc)
                    active.append(q)
            self._subscribers = active

    async def subscribe(self) -> AsyncIterator[dict]:
        """
        Async generator that yields events as they arrive.
        Caller must cancel / break out to unsubscribe.
        Automatically removes itself from the bus when the generator is closed.
        """
        q: asyncio.Queue = asyncio.Queue(maxsize=_MAX_QUEUE_SIZE)
        async with self._lock:
            self._subscribers.append(q)
        try:
            while True:
                event = await q.get()
                yield event
        finally:
            async with self._lock:
                try:
                    self._subscribers.remove(q)
                except ValueError:
                    pass

    def subscriber_count(self) -> int:
        """Return number of active subscribers."""
        return len(self._subscribers)


# ---------------------------------------------------------------------------
# Process singleton
# ---------------------------------------------------------------------------

_bus: Optional[EventBus] = None


def get_event_bus() -> EventBus:
    """
    Return the process-level EventBus singleton.
    Created lazily on first call; safe to call before the event loop starts.
    """
    global _bus
    if _bus is None:
        _bus = EventBus()
    return _bus
