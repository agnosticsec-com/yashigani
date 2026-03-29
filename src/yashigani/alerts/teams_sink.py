"""
Yashigani Alerts — Microsoft Teams webhook sink (Adaptive Card format).
"""
from __future__ import annotations

import logging

import httpx

from yashigani.alerts.base import AlertPayload, AlertSink

logger = logging.getLogger(__name__)

_SEVERITY_COLOR = {
    "critical": "Attention",
    "warning": "Warning",
    "info": "Accent",
}


class TeamsSink(AlertSink):
    """Delivers alerts to a Microsoft Teams channel via incoming webhook."""

    def __init__(self, webhook_url: str, timeout: float = 10.0) -> None:
        self._url = webhook_url
        self._timeout = timeout

    async def send(self, payload: AlertPayload) -> None:
        color = _SEVERITY_COLOR.get(payload.severity, "Default")
        card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {
                                "type": "TextBlock",
                                "text": payload.title,
                                "weight": "Bolder",
                                "size": "Medium",
                                "color": color,
                            },
                            {
                                "type": "TextBlock",
                                "text": payload.body,
                                "wrap": True,
                            },
                            {
                                "type": "FactSet",
                                "facts": [
                                    {"title": "Severity", "value": payload.severity.upper()},
                                    {"title": "Event ID", "value": payload.event_id},
                                    {"title": "Component", "value": payload.source_component},
                                ]
                                + (
                                    [{"title": "Agent", "value": payload.agent_id}]
                                    if payload.agent_id
                                    else []
                                ),
                            },
                        ],
                    },
                }
            ],
        }
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(self._url, json=card)
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
            logger.warning("TeamsSink.test failed: %s", exc)
            return False
