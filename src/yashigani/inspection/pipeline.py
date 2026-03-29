"""
Yashigani Inspection — Main pipeline orchestrator.
Coordinates pre-masking → classification → disposition → audit.
"""
from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass
from typing import Optional, Callable

from yashigani.audit.masking import CredentialMasker
from yashigani.inspection.classifier import (
    PromptInjectionClassifier,
    LABEL_CLEAN,
    LABEL_CREDENTIAL_EXFIL,
    LABEL_PROMPT_INJECTION_ONLY,
)
from yashigani.inspection.sanitizer import sanitize, SanitizationResult

logger = logging.getLogger(__name__)

_DEFAULT_SANITIZE_THRESHOLD = 0.85


@dataclass
class PipelineResult:
    request_id: str
    action: str                     # PASS | SANITIZED | DISCARDED
    clean_query: Optional[str]      # forwarded content; None if discarded
    classification: str             # CLEAN | CREDENTIAL_EXFIL | PROMPT_INJECTION_ONLY
    severity: str                   # "" | HIGH | CRITICAL
    confidence: float
    admin_alert: Optional[dict]
    user_alert: Optional[dict]
    audit_fields: dict


class InspectionPipeline:
    """
    Full inspection pipeline for inbound queries.

    Flow:
    1. Pre-mask credentials in content (CHS masker)
    2. Classify with Qwen3.5 (local only) via classifier or backend_registry
    3. Apply disposition based on label + confidence threshold
    4. Build admin/user alerts and audit record

    If backend_registry is provided it takes precedence over the legacy
    classifier; the classifier is kept for backward-compat callers that
    do not use the registry.
    """

    def __init__(
        self,
        classifier: PromptInjectionClassifier,
        sanitize_threshold: float = _DEFAULT_SANITIZE_THRESHOLD,
        on_audit: Optional[Callable[[str, dict], None]] = None,
        backend_registry=None,  # Optional[BackendRegistry]
    ) -> None:
        self._classifier = classifier
        self._backend_registry = backend_registry
        self._threshold = sanitize_threshold
        self._masker = CredentialMasker()
        self._on_audit = on_audit or (lambda name, data: None)

    def process(
        self,
        raw_query: str,
        session_id: str,
        agent_id: str,
        user_id: str,
    ) -> PipelineResult:
        """
        Process an inbound query through the full inspection pipeline.
        Returns PipelineResult with the action and forwarding content.
        """
        request_id = str(uuid.uuid4())

        # Step 1: Mask credentials before sending to classifier
        masked_query = self._masker.mask_string(raw_query)

        # Step 2: Classify — use backend_registry if available, else legacy classifier
        if self._backend_registry is not None:
            backend_result = self._backend_registry.classify(masked_query, request_id=request_id)
            # Adapt BackendRegistry ClassifierResult to the legacy classifier shape
            # Pipeline disposition only needs .label and .confidence; wrap in a simple object
            result = _BackendResultAdapter(
                label=backend_result.label,
                confidence=backend_result.confidence,
            )
        else:
            result = self._classifier.classify(masked_query)

        # Step 3: Disposition
        if result.label == LABEL_CLEAN:
            return self._pass_through(request_id, raw_query, session_id, agent_id)

        if result.label == LABEL_CREDENTIAL_EXFIL:
            return self._handle_credential_exfil(
                request_id, raw_query, masked_query, result,
                session_id, agent_id, user_id,
            )

        # PROMPT_INJECTION_ONLY
        return self._handle_injection_only(
            request_id, result, session_id, agent_id, user_id,
        )

    def update_threshold(self, threshold: float) -> None:
        """Admin-configurable sanitization confidence threshold."""
        if not 0.70 <= threshold <= 0.99:
            raise ValueError("Threshold must be between 0.70 and 0.99")
        self._threshold = threshold

    def _dispatch_credential_exfil_alert(
        self,
        request_id: str,
        session_id: str,
        agent_id: str,
        action: str,
        confidence: float,
    ) -> None:
        """
        Fire-and-forget webhook alert for credential exfil detections (v0.7.1).
        Only dispatches if sinks are configured and `alert_on_credential_exfil` is True.
        Never raises — failures are logged by the dispatcher.
        """
        try:
            from yashigani.backoffice.state import backoffice_state
            from yashigani.alerts import get_dispatcher
            from yashigani.alerts.base import AlertPayload

            alert_config = getattr(backoffice_state, "alert_config", None)
            if alert_config is not None and not getattr(alert_config, "alert_on_credential_exfil", True):
                return

            dispatcher = get_dispatcher()
            if not dispatcher.has_sinks:
                return

            payload = AlertPayload(
                severity="critical",
                title="Yashigani — Credential Exfiltration Detected",
                body=(
                    f"A credential exfiltration attempt was detected and {action.lower()}. "
                    f"Request ID: {request_id} | Agent: {agent_id} | "
                    f"Session: {session_id} | Confidence: {confidence:.2f}"
                ),
                event_id=request_id,
                agent_id=agent_id,
                source_component="yashigani.inspection.pipeline",
            )
            dispatcher.dispatch_sync(payload)
        except Exception as exc:
            logger.error("_dispatch_credential_exfil_alert: unexpected error: %s", exc)

    # -- Disposition handlers ------------------------------------------------

    def _pass_through(
        self, request_id: str, raw_query: str,
        session_id: str, agent_id: str,
    ) -> PipelineResult:
        return PipelineResult(
            request_id=request_id,
            action="PASS",
            clean_query=raw_query,
            classification=LABEL_CLEAN,
            severity="",
            confidence=1.0,
            admin_alert=None,
            user_alert=None,
            audit_fields={},
        )

    def _handle_credential_exfil(
        self, request_id: str, raw_query: str, masked_query: str,
        classifier_result, session_id: str, agent_id: str, user_id: str,
    ) -> PipelineResult:
        action = "DISCARDED"
        clean_query = None
        sanitized = False

        if classifier_result.confidence >= self._threshold:
            san: SanitizationResult = sanitize(
                masked_query, classifier_result.detected_payload_spans
            )
            if san.success and san.clean_query:
                action = "SANITIZED"
                clean_query = san.clean_query
                sanitized = True

        admin_alert = {
            "alert_type": "CREDENTIAL_EXFIL_DETECTED",
            "severity": "CRITICAL",
            "request_id": request_id,
            "session_id": session_id,
            "agent_id": agent_id,
            "classifier_confidence": classifier_result.confidence,
            "threshold_applied": self._threshold,
            "action_taken": action,
            "sanitized": sanitized,
        }
        user_alert = _build_user_alert(request_id, action, sanitized)

        audit = {
            "event_type": "PROMPT_INJECTION_DETECTED",
            "classification": LABEL_CREDENTIAL_EXFIL,
            "severity": "CRITICAL",
            "request_id": request_id,
            "session_id": session_id,
            "agent_id": agent_id,
            "user_id": user_id,
            "action_taken": action,
            "sanitized": sanitized,
            "confidence_score": classifier_result.confidence,
            "threshold_applied": self._threshold,
            "admin_alerted": True,
            "user_alerted": True,
            "raw_query_logged": False,
            "content_hash": _content_hash(raw_query),
        }
        self._on_audit("PROMPT_INJECTION_DETECTED", audit)

        # Dispatch webhook alert if sinks are configured (v0.7.1 P2-3)
        self._dispatch_credential_exfil_alert(
            request_id=request_id,
            session_id=session_id,
            agent_id=agent_id,
            action=action,
            confidence=classifier_result.confidence,
        )

        return PipelineResult(
            request_id=request_id,
            action=action,
            clean_query=clean_query,
            classification=LABEL_CREDENTIAL_EXFIL,
            severity="CRITICAL",
            confidence=classifier_result.confidence,
            admin_alert=admin_alert,
            user_alert=user_alert,
            audit_fields=audit,
        )

    def _handle_injection_only(
        self, request_id: str, classifier_result,
        session_id: str, agent_id: str, user_id: str,
    ) -> PipelineResult:
        admin_alert = {
            "alert_type": "PROMPT_INJECTION_DETECTED",
            "severity": "HIGH",
            "request_id": request_id,
            "session_id": session_id,
            "agent_id": agent_id,
            "classifier_confidence": classifier_result.confidence,
            "action_taken": "DISCARDED",
            "sanitized": False,
            "admin_alerted": True,
        }
        user_alert = _build_user_alert(request_id, "DISCARDED", False)

        audit = {
            "event_type": "PROMPT_INJECTION_DETECTED",
            "classification": LABEL_PROMPT_INJECTION_ONLY,
            "severity": "HIGH",
            "request_id": request_id,
            "session_id": session_id,
            "agent_id": agent_id,
            "user_id": user_id,
            "action_taken": "DISCARDED",
            "sanitized": False,
            "confidence_score": classifier_result.confidence,
            "admin_alerted": True,
            "user_alerted": True,
            "raw_query_logged": False,
        }
        self._on_audit("PROMPT_INJECTION_DETECTED", audit)

        return PipelineResult(
            request_id=request_id,
            action="DISCARDED",
            clean_query=None,
            classification=LABEL_PROMPT_INJECTION_ONLY,
            severity="HIGH",
            confidence=classifier_result.confidence,
            admin_alert=admin_alert,
            user_alert=user_alert,
            audit_fields=audit,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_user_alert(request_id: str, action: str, sanitized: bool) -> dict:
    import datetime
    code = "QUERY_MODIFIED" if action == "SANITIZED" else "QUERY_DISCARDED"
    msg = (
        "Your query was modified before processing."
        if code == "QUERY_MODIFIED"
        else "Your query was not processed due to a policy violation."
    )
    return {
        "yashigani_alert": {
            "code": code,
            "message": msg,
            "request_id": request_id,
            "timestamp": datetime.datetime.now(
                tz=datetime.timezone.utc
            ).isoformat(),
        },
        "result": None,
    }


def _content_hash(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


# ---------------------------------------------------------------------------
# Adapter — bridges BackendRegistry ClassifierResult to the pipeline's
# internal duck-typed classifier result shape (label, confidence, and a
# no-op detected_payload_spans for the sanitizer path).
# ---------------------------------------------------------------------------

class _BackendResultAdapter:
    """Minimal adapter so BackendRegistry results work in disposition handlers."""

    def __init__(self, label: str, confidence: float) -> None:
        self.label = label
        self.confidence = confidence
        self.exfil_indicators = label == LABEL_CREDENTIAL_EXFIL
        self.detected_payload_spans: list = []
