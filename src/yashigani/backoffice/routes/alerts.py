"""
Yashigani Backoffice — Alert sink configuration routes (v0.7.0).

Last updated: 2026-05-02T09:00:00+01:00

Configure Slack / Teams / PagerDuty direct webhook alerting.

Routes:
  GET  /admin/alerts/config          — current sink configuration (URLs masked)
  PUT  /admin/alerts/config          — update sink configuration
  POST /admin/alerts/test/{sink}     — send a test alert to a specific sink
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Path, status
from pydantic import BaseModel, Field

from yashigani.backoffice.middleware import AdminSession
from yashigani.backoffice.state import backoffice_state

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class AlertConfigRequest(BaseModel):
    slack_webhook_url: str = Field(
        default="",
        description="Slack incoming webhook URL. Empty = disabled.",
    )
    teams_webhook_url: str = Field(
        default="",
        description="Microsoft Teams incoming webhook URL. Empty = disabled.",
    )
    pagerduty_routing_key: str = Field(
        default="",
        description="PagerDuty Events API v2 routing key. Empty = disabled.",
    )
    # Alert trigger config
    alert_on_credential_exfil: bool = True
    alert_on_anomaly_threshold: bool = True
    license_expiry_warning_days: int = Field(default=14, ge=1, le=90)
    license_limit_warning_pct: int = Field(default=90, ge=50, le=99)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mask(value: str) -> str:
    """Mask a secret URL/key for display — show only last 6 chars."""
    if not value:
        return ""
    if len(value) <= 6:
        return "***"
    return "***" + value[-6:]


def _rebuild_dispatcher(config: AlertConfigRequest) -> None:
    """Rebuild the AlertDispatcher from the new configuration."""
    from yashigani.alerts import AlertDispatcher, configure_dispatcher
    from yashigani.alerts.slack_sink import SlackSink
    from yashigani.alerts.teams_sink import TeamsSink
    from yashigani.alerts.pagerduty_sink import PagerDutySink

    dispatcher = AlertDispatcher()
    if config.slack_webhook_url:
        dispatcher.add_sink(SlackSink(webhook_url=config.slack_webhook_url))
    if config.teams_webhook_url:
        dispatcher.add_sink(TeamsSink(webhook_url=config.teams_webhook_url))
    if config.pagerduty_routing_key:
        dispatcher.add_sink(PagerDutySink(routing_key=config.pagerduty_routing_key))
    configure_dispatcher(dispatcher)

    # Persist config to backoffice state so it survives the request
    backoffice_state.alert_config = config


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/config")
async def get_alert_config(session: AdminSession):
    """Return current alert sink configuration. URLs and keys are masked."""
    config = getattr(backoffice_state, "alert_config", None)
    if config is None:
        return {
            "configured": False,
            "sinks": [],
        }
    sinks = []
    if config.slack_webhook_url:
        sinks.append({"type": "slack", "masked_url": _mask(config.slack_webhook_url)})
    if config.teams_webhook_url:
        sinks.append({"type": "teams", "masked_url": _mask(config.teams_webhook_url)})
    if config.pagerduty_routing_key:
        sinks.append({"type": "pagerduty", "masked_key": _mask(config.pagerduty_routing_key)})
    return {
        "configured": bool(sinks),
        "sinks": sinks,
        "alert_on_credential_exfil": config.alert_on_credential_exfil,
        "alert_on_anomaly_threshold": config.alert_on_anomaly_threshold,
        "license_expiry_warning_days": config.license_expiry_warning_days,
        "license_limit_warning_pct": config.license_limit_warning_pct,
    }


@router.put("/config")
async def update_alert_config(
    body: AlertConfigRequest,
    session: AdminSession,
):
    """Update alert sink configuration and rebuild the dispatcher."""
    _rebuild_dispatcher(body)

    from yashigani.audit.schema import ConfigChangedEvent
    if backoffice_state.audit_writer is not None:
        try:
            backoffice_state.audit_writer.write(ConfigChangedEvent(
                admin_account=session.account_id,
                setting="alert_sinks",
                previous_value="(previous)",
                new_value=(
                    f"slack={'set' if body.slack_webhook_url else 'disabled'}, "
                    f"teams={'set' if body.teams_webhook_url else 'disabled'}, "
                    f"pagerduty={'set' if body.pagerduty_routing_key else 'disabled'}"
                ),
            ))
        except Exception as exc:
            logger.error("Failed to write ConfigChangedEvent for alert config: %s", exc)

    return {"status": "ok", "sinks_configured": sum([
        bool(body.slack_webhook_url),
        bool(body.teams_webhook_url),
        bool(body.pagerduty_routing_key),
    ])}


@router.post("/test/{sink_type}")
async def test_alert_sink(
    session: AdminSession,
    sink_type: str = Path(pattern="^(slack|teams|pagerduty)$"),
):
    """Send a test alert to a specific configured sink."""
    config = getattr(backoffice_state, "alert_config", None)
    if config is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "no_alert_config", "message": "No alert sinks configured yet."},
        )

    from yashigani.alerts.base import AlertPayload

    payload = AlertPayload(
        severity="info",
        title="Yashigani — Test Alert",
        body=(
            "This is a test notification from Yashigani Security Gateway backoffice. "
            f"Sent by admin: {session.account_id}"
        ),
        event_id="test-manual",
        source_component="yashigani.backoffice.alerts.test",
    )

    if sink_type == "slack":
        if not config.slack_webhook_url:
            raise HTTPException(status_code=404, detail={"error": "slack_not_configured"})
        from yashigani.alerts.slack_sink import SlackSink
        ok = await SlackSink(config.slack_webhook_url).test()
    elif sink_type == "teams":
        if not config.teams_webhook_url:
            raise HTTPException(status_code=404, detail={"error": "teams_not_configured"})
        from yashigani.alerts.teams_sink import TeamsSink
        ok = await TeamsSink(config.teams_webhook_url).test()
    else:  # pagerduty
        if not config.pagerduty_routing_key:
            raise HTTPException(status_code=404, detail={"error": "pagerduty_not_configured"})
        from yashigani.alerts.pagerduty_sink import PagerDutySink
        ok = await PagerDutySink(config.pagerduty_routing_key).test()

    if not ok:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail={"error": "delivery_failed", "sink": sink_type},
        )
    return {"status": "delivered", "sink": sink_type}
