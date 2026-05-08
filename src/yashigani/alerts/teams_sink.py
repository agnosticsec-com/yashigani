"""
Yashigani Alerts — Microsoft Teams webhook sink (Adaptive Card format).

# Last updated: 2026-05-03T00:00:00+01:00

V232-CSCAN-01b: URL guard applied at constructor time (config-write path) AND
at send-time (defence-in-depth). Teams allowlist: webhook.office.com,
outlook.office.com, outlook.office365.com, logic.azure.com (and subdomains).
Redirects disabled (follow_redirects=False) to prevent pivot chains.
"""
from __future__ import annotations

import logging

import httpx

from yashigani.alerts._url_guard import WebhookUrlForbidden, assert_webhook_url
from yashigani.alerts.base import AlertPayload, AlertSink

logger = logging.getLogger(__name__)

# Teams / Power Automate webhook hosts.
# Subdomain matching is applied: foo.webhook.office.com passes for webhook.office.com.
_TEAMS_ALLOWED_HOSTS: frozenset[str] = frozenset({
    "webhook.office.com",
    "outlook.office.com",
    "outlook.office365.com",
    "logic.azure.com",
})

_SEVERITY_COLOR = {
    "critical": "Attention",
    "warning": "Warning",
    "info": "Accent",
}


class TeamsSink(AlertSink):
    """Delivers alerts to a Microsoft Teams channel via incoming webhook.

    Raises WebhookUrlForbidden at construction time if the URL fails the SSRF
    guard — this propagates to the admin config route as a 400 error.
    """

    def __init__(self, webhook_url: str, timeout: float = 10.0) -> None:
        # V232-CSCAN-01b: validate at construction (config-write time).
        assert_webhook_url(webhook_url, allowed_hosts=_TEAMS_ALLOWED_HOSTS)
        self._url = webhook_url
        self._timeout = timeout

    async def send(self, payload: AlertPayload) -> None:
        # V232-CSCAN-01b: last-line-of-defence re-validation before network call.
        assert_webhook_url(self._url, allowed_hosts=_TEAMS_ALLOWED_HOSTS)

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
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=10.0, write=10.0, pool=5.0),
            follow_redirects=False,
        ) as client:
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
