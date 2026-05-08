"""
Yashigani Alerts — Slack webhook sink (Block Kit format).

# Last updated: 2026-05-03T00:00:00+01:00

V232-CSCAN-01b: URL guard applied at constructor time (config-write path) AND
at send-time (defence-in-depth). Slack allowlist: hooks.slack.com.
Redirects disabled (allow_redirects=False) to prevent pivot chains.
"""
from __future__ import annotations

import logging

import httpx

from yashigani.alerts._url_guard import WebhookUrlForbidden, assert_webhook_url
from yashigani.alerts.base import AlertPayload, AlertSink

logger = logging.getLogger(__name__)

# Slack incoming webhooks are only valid on this host.
_SLACK_ALLOWED_HOSTS: frozenset[str] = frozenset({"hooks.slack.com"})

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
    """Delivers alerts to a Slack channel via incoming webhook.

    Raises WebhookUrlForbidden at construction time if the URL fails the SSRF
    guard — this propagates to the admin config route as a 400 error.
    """

    def __init__(self, webhook_url: str, timeout: float = 10.0) -> None:
        # V232-CSCAN-01b: validate at construction (config-write time).
        assert_webhook_url(webhook_url, allowed_hosts=_SLACK_ALLOWED_HOSTS)
        self._url = webhook_url
        self._timeout = timeout

    async def send(self, payload: AlertPayload) -> None:
        # V232-CSCAN-01b: last-line-of-defence re-validation before network call.
        assert_webhook_url(self._url, allowed_hosts=_SLACK_ALLOWED_HOSTS)

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
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=10.0, write=10.0, pool=5.0),
            follow_redirects=False,
        ) as client:
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
