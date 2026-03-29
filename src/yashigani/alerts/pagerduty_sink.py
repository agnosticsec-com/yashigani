"""
Yashigani Alerts — PagerDuty Events API v2 sink.
"""
from __future__ import annotations

import logging

import httpx

from yashigani.alerts.base import AlertPayload, AlertSink

logger = logging.getLogger(__name__)

_PD_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

_SEVERITY_MAP = {
    "critical": "critical",
    "warning": "warning",
    "info": "info",
}


class PagerDutySink(AlertSink):
    """Delivers alerts via PagerDuty Events API v2."""

    def __init__(self, routing_key: str, timeout: float = 10.0) -> None:
        self._key = routing_key
        self._timeout = timeout

    async def send(self, payload: AlertPayload) -> None:
        pd_severity = _SEVERITY_MAP.get(payload.severity, "warning")
        body = {
            "routing_key": self._key,
            "event_action": "trigger",
            "dedup_key": payload.event_id,
            "payload": {
                "summary": payload.title,
                "source": payload.source_component,
                "severity": pd_severity,
                "custom_details": {
                    "body": payload.body,
                    "agent_id": payload.agent_id or "",
                    **payload.extra,
                },
            },
        }
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(_PD_EVENTS_URL, json=body)
            resp.raise_for_status()

    async def test(self) -> bool:
        try:
            await self.send(AlertPayload(
                severity="info",
                title="Yashigani — Test Alert",
                body="This is a test notification from Yashigani Security Gateway.",
                event_id="test-000",
                source_component="yashigani.alerts.test",
            ))
            return True
        except Exception as exc:
            logger.warning("PagerDutySink.test failed: %s", exc)
            return False
