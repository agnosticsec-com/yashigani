"""
Yashigani Backoffice — PII configuration and test routes (v2.2).

License gating:
  pii_log    — required for LOG mode (detection only).
  pii_redact — required for REDACT and BLOCK modes.

Routes:
  GET  /admin/pii/config          — current PII config (mode, enabled types)
  PUT  /admin/pii/config          — update mode and enabled types
  POST /admin/pii/test            — test PII detection against sample text
                                    (findings returned; nothing written to audit)
  GET  /admin/pii/cloud-bypass    — current cloud bypass setting
  PUT  /admin/pii/cloud-bypass    — toggle cloud bypass (requires admin session)

Cloud bypass (OFF by default):
  When enabled, PII filtering is skipped for cloud-routed requests only.
  Local (Ollama) traffic is ALWAYS filtered regardless of this setting.
  This is an explicit admin opt-in to allow PII to reach cloud LLMs.
  Enabling this requires pii_redact license tier.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from yashigani.backoffice.middleware import AdminSession
from yashigani.backoffice.state import backoffice_state
from yashigani.licensing.enforcer import LicenseFeatureGated, require_feature
from yashigani.pii.detector import PiiDetector, PiiMode, PiiType

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Module-level config store (in-process; persisted to backoffice_state attrs)
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG: dict = {
    "mode": PiiMode.LOG.value,
    "enabled_types": [t.value for t in PiiType],
}

# Cloud bypass is a separate flag — stored independently from mode/types config.
_DEFAULT_CLOUD_BYPASS: bool = False


def _get_config() -> dict:
    return getattr(backoffice_state, "pii_config", _DEFAULT_CONFIG.copy())


def _set_config(cfg: dict) -> None:
    backoffice_state.pii_config = cfg  # type: ignore[attr-defined]


def _get_cloud_bypass() -> bool:
    return getattr(backoffice_state, "pii_cloud_bypass", _DEFAULT_CLOUD_BYPASS)


def _set_cloud_bypass(enabled: bool) -> None:
    backoffice_state.pii_cloud_bypass = enabled  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class PiiConfigRequest(BaseModel):
    mode: str = Field(
        description="Detection mode: log | redact | block",
        pattern=r"^(log|redact|block)$",
    )
    enabled_types: list[str] = Field(
        description="List of PiiType values to enable. Empty list enables all.",
        default_factory=list,
    )

    @field_validator("enabled_types")
    @classmethod
    def validate_types(cls, values: list[str]) -> list[str]:
        valid = {t.value for t in PiiType}
        bad = [v for v in values if v not in valid]
        if bad:
            raise ValueError(f"Unknown PII types: {bad}. Valid: {sorted(valid)}")
        return values


class PiiTestRequest(BaseModel):
    text: str = Field(min_length=1, max_length=10_000)
    mode: Optional[str] = Field(
        default=None,
        description="Override mode for this test call (log | redact | block). "
                    "Defaults to the currently configured mode.",
        pattern=r"^(log|redact|block)$",
    )


class PiiCloudBypassRequest(BaseModel):
    enabled: bool = Field(
        description=(
            "When true, PII filtering is skipped for cloud-routed requests. "
            "Local (Ollama) traffic is ALWAYS filtered regardless of this flag. "
            "Enabling this is an explicit opt-in to allow PII to reach cloud LLMs."
        )
    )


# ---------------------------------------------------------------------------
# License helpers
# ---------------------------------------------------------------------------

def _require_pii_feature(mode: str) -> None:
    """Raise HTTP 402 if the active license does not cover the requested mode."""
    try:
        if mode in ("redact", "block"):
            require_feature("pii_redact")
        else:
            require_feature("pii_log")
    except LicenseFeatureGated as exc:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail={
                "error": "LICENSE_FEATURE_GATED",
                "feature": exc.feature,
                "message": (
                    "PII detection requires Professional Plus or higher. "
                    "Upgrade at https://agnosticsec.com/pricing"
                ),
            },
        ) from exc


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/config")
async def get_pii_config(session: AdminSession):
    """Return the current PII detection configuration."""
    _require_pii_feature("log")  # reading config also requires at minimum pii_log
    cfg = _get_config()
    return {
        "mode": cfg["mode"],
        "enabled_types": cfg.get("enabled_types", [t.value for t in PiiType]),
        "all_types": [t.value for t in PiiType],
    }


@router.put("/config")
async def update_pii_config(
    body: PiiConfigRequest,
    session: AdminSession,
):
    """Update PII detection mode and enabled types."""
    _require_pii_feature(body.mode)

    enabled = body.enabled_types if body.enabled_types else [t.value for t in PiiType]
    cfg = {"mode": body.mode, "enabled_types": enabled}
    _set_config(cfg)

    # Audit the config change
    from yashigani.audit.schema import ConfigChangedEvent
    if backoffice_state.audit_writer is not None:
        try:
            backoffice_state.audit_writer.write(ConfigChangedEvent(
                admin_account=session.account_id,
                setting="pii_config",
                previous_value="(previous)",
                new_value=f"mode={body.mode} types={enabled}",
            ))
        except Exception as exc:
            logger.error("Failed to write ConfigChangedEvent for pii_config: %s", exc)

    return {"status": "ok", "mode": body.mode, "enabled_types": enabled}


@router.post("/test")
async def test_pii_detection(
    body: PiiTestRequest,
    session: AdminSession,
):
    """Test PII detection against a sample text.

    Uses the currently configured (or override) mode.
    Results are returned to the caller; nothing is written to audit logs.
    Raw matched values are NEVER returned — only masked_value is included.
    """
    cfg = _get_config()
    test_mode_str = body.mode or cfg["mode"]
    _require_pii_feature(test_mode_str)

    try:
        test_mode = PiiMode(test_mode_str)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"error": "invalid_mode", "mode": test_mode_str},
        )

    enabled_type_values: list[str] = cfg.get("enabled_types", [t.value for t in PiiType])
    enabled_set: set[PiiType] = {PiiType(v) for v in enabled_type_values}

    detector = PiiDetector(mode=test_mode, enabled_types=enabled_set)
    output_text, result = detector.process(body.text)

    findings_out = [
        {
            "pii_type": f.pii_type.value,
            "start": f.start,
            "end": f.end,
            "masked_value": f.masked_value,  # raw value never returned
        }
        for f in result.findings
    ]

    return {
        "detected": result.detected,
        "action_taken": result.action_taken,
        "mode": result.mode.value,
        "finding_count": len(findings_out),
        "findings": findings_out,
        # Return redacted text only in REDACT mode so admins can preview output.
        "output_text": output_text if test_mode == PiiMode.REDACT else None,
    }


@router.get("/cloud-bypass")
async def get_pii_cloud_bypass(session: AdminSession):
    """Return the current PII cloud bypass setting.

    When cloud bypass is enabled, PII filtering is skipped for cloud-routed
    requests. Local (Ollama) traffic is always filtered.
    """
    _require_pii_feature("log")
    return {
        "cloud_bypass_enabled": _get_cloud_bypass(),
        "warning": (
            "When enabled, PII may reach cloud LLM providers. "
            "Local (Ollama) traffic is always filtered regardless of this setting."
        ),
    }


@router.put("/cloud-bypass")
async def update_pii_cloud_bypass(
    body: PiiCloudBypassRequest,
    session: AdminSession,
):
    """Toggle the PII cloud bypass setting.

    Requires pii_redact license tier (same as REDACT/BLOCK modes) because
    enabling bypass has equivalent data exposure implications.

    Local (Ollama) traffic is NEVER affected — it is always filtered.
    This setting only controls whether PII filtering runs for requests
    that the optimization engine routes to cloud providers.
    """
    # Enabling cloud bypass has the same data-exposure risk as BLOCK mode —
    # require pii_redact so community-tier users cannot accidentally expose PII.
    _require_pii_feature("redact" if body.enabled else "log")

    previous = _get_cloud_bypass()
    _set_cloud_bypass(body.enabled)

    logger.info(
        "PII cloud bypass changed: %s -> %s (admin=%s)",
        previous,
        body.enabled,
        session.account_id,
    )

    from yashigani.audit.schema import ConfigChangedEvent
    if backoffice_state.audit_writer is not None:
        try:
            backoffice_state.audit_writer.write(ConfigChangedEvent(
                admin_account=session.account_id,
                setting="pii_cloud_bypass",
                previous_value=str(previous),
                new_value=str(body.enabled),
            ))
        except Exception as exc:
            logger.error("Failed to write ConfigChangedEvent for pii_cloud_bypass: %s", exc)

    return {
        "status": "ok",
        "cloud_bypass_enabled": body.enabled,
        "warning": (
            "PII may now reach cloud LLM providers. "
            "Local (Ollama) traffic remains filtered at all times."
        ) if body.enabled else None,
    }
