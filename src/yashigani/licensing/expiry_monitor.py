"""
Yashigani Licensing — Licence expiry background monitor (v0.7.1).

Runs daily via APScheduler. Fires an alert to all configured sinks when the
active licence is within `license_expiry_warning_days` of expiry.

A module-level date guard ensures only one alert is sent per calendar day,
preventing alert storms on heavily-loaded or frequently-restarted instances.
"""
from __future__ import annotations

import logging
from datetime import date, datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# Guard: last calendar date on which an expiry alert was sent.
# Prevents multiple alerts on the same day if the scheduler fires more than once.
_last_alert_date: Optional[date] = None


async def check_and_alert_licence_expiry() -> None:
    """
    Check the active licence expiry and dispatch a warning alert if the
    licence is within the configured warning window.

    Safe to call when no alert sinks are configured — exits silently.
    Safe to call when no licence state is available — exits silently.
    """
    global _last_alert_date

    from yashigani.backoffice.state import backoffice_state
    from yashigani.alerts import get_dispatcher
    from yashigani.alerts.base import AlertPayload

    alert_config = getattr(backoffice_state, "alert_config", None)
    if alert_config is None:
        return  # No alert sinks configured — nothing to do

    dispatcher = get_dispatcher()
    if not dispatcher.has_sinks:
        return  # Dispatcher has no sinks — no-op

    # Fetch current licence
    try:
        from yashigani.licensing import get_license
        lic = get_license()
    except Exception as exc:
        logger.warning("expiry_monitor: could not read licence state: %s", exc)
        return

    if lic.expires_at is None:
        return  # Perpetual licence — nothing to warn about

    now = datetime.now(timezone.utc)
    delta = lic.expires_at - now
    days_remaining = delta.days

    warning_days = getattr(alert_config, "license_expiry_warning_days", 14)
    if days_remaining > warning_days:
        return  # Plenty of time — no alert needed

    today = date.today()
    if _last_alert_date == today:
        return  # Already alerted today — suppress

    severity = "critical" if days_remaining <= 3 else "warning"
    payload = AlertPayload(
        severity=severity,
        title="Yashigani — Licence Expiry Warning",
        body=(
            f"Your Yashigani licence ({lic.tier.value} tier) expires in "
            f"{days_remaining} day{'s' if days_remaining != 1 else ''} "
            f"({lic.expires_at.strftime('%Y-%m-%d')}). "
            "Renew at https://yashigani.io/pricing to avoid service interruption."
        ),
        event_id=f"licence-expiry-{today.isoformat()}",
        source_component="yashigani.licensing.expiry_monitor",
    )

    try:
        await dispatcher.dispatch(payload)
        _last_alert_date = today
        logger.info(
            "Licence expiry alert dispatched: %d days remaining (threshold %d)",
            days_remaining,
            warning_days,
        )
    except Exception as exc:
        logger.error("expiry_monitor: dispatch failed: %s", exc)
