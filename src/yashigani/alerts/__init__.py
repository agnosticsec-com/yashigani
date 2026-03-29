"""
Yashigani Alerts — Direct webhook alerting for P1/P2 events.
Supports Slack, Microsoft Teams, and PagerDuty.
Configured via gateway config [alerts] section.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

from yashigani.alerts.base import AlertPayload, AlertSink

logger = logging.getLogger(__name__)


class AlertDispatcher:
    """
    Dispatches alerts to all configured sinks.

    Usage:
        dispatcher = AlertDispatcher()
        dispatcher.add_sink(SlackSink(webhook_url="https://..."))
        await dispatcher.dispatch(AlertPayload(severity="critical", ...))

    dispatch() is fire-and-forget — failures are logged but never raised.
    """

    def __init__(self) -> None:
        self._sinks: list[AlertSink] = []

    def add_sink(self, sink: AlertSink) -> None:
        self._sinks.append(sink)
        logger.info("AlertDispatcher: added sink %s", type(sink).__name__)

    def clear_sinks(self) -> None:
        self._sinks.clear()

    @property
    def has_sinks(self) -> bool:
        return bool(self._sinks)

    async def dispatch(self, payload: AlertPayload) -> None:
        """Send payload to all configured sinks. Errors are logged, not raised."""
        if not self._sinks:
            return
        tasks = [self._send_one(sink, payload) for sink in self._sinks]
        await asyncio.gather(*tasks, return_exceptions=True)

    def dispatch_sync(self, payload: AlertPayload) -> None:
        """Synchronous wrapper — creates an event loop if none is running."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(self.dispatch(payload))
            else:
                loop.run_until_complete(self.dispatch(payload))
        except Exception as exc:
            logger.error("AlertDispatcher.dispatch_sync: %s", exc)

    async def _send_one(self, sink: AlertSink, payload: AlertPayload) -> None:
        try:
            await sink.send(payload)
        except Exception as exc:
            logger.error(
                "AlertDispatcher: sink %s failed for event %s: %s",
                type(sink).__name__,
                payload.event_id,
                exc,
            )


# Module-level singleton — populated at startup by backoffice configuration
_dispatcher: Optional[AlertDispatcher] = None


def get_dispatcher() -> AlertDispatcher:
    global _dispatcher
    if _dispatcher is None:
        _dispatcher = AlertDispatcher()
    return _dispatcher


def configure_dispatcher(dispatcher: AlertDispatcher) -> None:
    global _dispatcher
    _dispatcher = dispatcher
