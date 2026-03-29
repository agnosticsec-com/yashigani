"""
Yashigani Alerts — Slack webhook sink (Block Kit format).
"""
from __future__ import annotations

import logging

import httpx

from yashigani.alerts.base import AlertPayload, AlertSink

logger = logging.getLogger(__name__)

_SEVERITY_EMOJI = {
    "critical": ":red_circle:",
    "warning": ":large_yellow_circle:",
    "info": ":large_blue_circle:",
}
_SEVERITY_COLOR = {
    "critical": "#d32f2f",
    "warning": "#f57c00",
    "info": "#1565c0",
}


class SlackSink(AlertSink):
    """Delivers alerts to a Slack channel via incoming webhook."""

    def __init__(self, webhook_url: str, timeout: float = 10.0) -> None:
        self._url = webhook_url
        self._timeout = timeout

    async def send(self, payload: AlertPayload) -> None:
        emoji = _SEVERITY_EMOJI.get(payload.severity, ":bell:")
        color = _SEVERITY_COLOR.get(payload.severity, "#607d8b")
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} {payload.title}",
                    "emoji": True,
                },
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": payload.body},
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": (
                            f"*Severity:* {payload.severity.upper()} | "
                            f"*Event:* `{payload.event_id}` | "
                            f"*Component:* {payload.source_component}"
                            + (f" | *Agent:* `{payload.agent_id}`" if payload.agent_id else "")
                        ),
                    }
                ],
            },
        ]
        body = {"blocks": blocks, "attachments": [{"color": color}]}
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(self._url, json=body)
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
            logger.warning("SlackSink.test failed: %s", exc)
            return False
