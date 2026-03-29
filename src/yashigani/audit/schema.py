"""
Yashigani Audit — Event schema definitions.
All audit events extend AuditEvent. Fields are immutable after creation.
"""
from __future__ import annotations

import uuid
import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


def _now_iso() -> str:
    return datetime.datetime.now(tz=datetime.timezone.utc).isoformat()


def _new_uuid() -> str:
    return str(uuid.uuid4())


class AccountTier(str, Enum):
    ADMIN = "admin"
    USER = "user"
    SYSTEM = "system"


class EventType(str, Enum):
    # Security
    CREDENTIAL_LEAK_DETECTED = "CREDENTIAL_LEAK_DETECTED"
    PROMPT_INJECTION_DETECTED = "PROMPT_INJECTION_DETECTED"
    SIEM_DELIVERY_FAILED = "SIEM_DELIVERY_FAILED"
    # Auth — admin
    ADMIN_LOGIN = "ADMIN_LOGIN"
    ADMIN_SESSION_INVALIDATED = "ADMIN_SESSION_INVALIDATED"
    FULL_RESET_TOTP_FAILURE = "FULL_RESET_TOTP_FAILURE"
    ADMIN_SESSION_INVALIDATED_TOTP_LOCKOUT = "ADMIN_SESSION_INVALIDATED_TOTP_LOCKOUT"
    # Auth — user
    USER_LOGIN = "USER_LOGIN"
    TOTP_RESET_CONSOLE = "TOTP_RESET_CONSOLE"
    TOTP_PROVISION_TOKEN_ISSUED = "TOTP_PROVISION_TOKEN_ISSUED"
    TOTP_PROVISION_COMPLETED = "TOTP_PROVISION_COMPLETED"
    TOTP_PROVISION_FAILED = "TOTP_PROVISION_FAILED"
    RECOVERY_CODE_USED = "RECOVERY_CODE_USED"
    RECOVERY_CODES_ACKNOWLEDGED = "RECOVERY_CODES_ACKNOWLEDGED"
    RECOVERY_CODES_REGENERATED = "RECOVERY_CODES_REGENERATED"
    EMERGENCY_UNLOCK_EXECUTED = "EMERGENCY_UNLOCK_EXECUTED"
    # Config
    CONFIG_CHANGED = "CONFIG_CHANGED"
    MASKING_CONFIG_CHANGED = "MASKING_CONFIG_CHANGED"
    KSM_ROTATION_SUCCESS = "KSM_ROTATION_SUCCESS"
    KSM_ROTATION_FAILURE = "KSM_ROTATION_FAILURE"
    KSM_ROTATION_CRITICAL = "KSM_ROTATION_CRITICAL"
    # Self-service
    SELFSERVICE_ACTION = "SELFSERVICE_ACTION"
    SELFSERVICE_POLICY_DENY = "SELFSERVICE_POLICY_DENY"
    # User management
    USER_FULL_RESET = "USER_FULL_RESET"
    # Gateway
    GATEWAY_REQUEST = "GATEWAY_REQUEST"
    RATE_LIMIT_VIOLATION = "RATE_LIMIT_VIOLATION"
    # RBAC
    RBAC_GROUP_CREATED = "RBAC_GROUP_CREATED"
    RBAC_GROUP_UPDATED = "RBAC_GROUP_UPDATED"
    RBAC_GROUP_DELETED = "RBAC_GROUP_DELETED"
    RBAC_MEMBER_ADDED = "RBAC_MEMBER_ADDED"
    RBAC_MEMBER_REMOVED = "RBAC_MEMBER_REMOVED"
    RBAC_POLICY_PUSHED = "RBAC_POLICY_PUSHED"
    # Agent registry
    AGENT_REGISTERED = "AGENT_REGISTERED"
    AGENT_UPDATED = "AGENT_UPDATED"
    AGENT_DEACTIVATED = "AGENT_DEACTIVATED"
    AGENT_TOKEN_ROTATED = "AGENT_TOKEN_ROTATED"
    # Agent auth / routing
    AGENT_AUTH_FAILED = "AGENT_AUTH_FAILED"
    AGENT_CALL_ALLOWED = "AGENT_CALL_ALLOWED"
    AGENT_CALL_DENIED_RBAC = "AGENT_CALL_DENIED_RBAC"
    AGENT_CALL_DENIED_INSPECTION = "AGENT_CALL_DENIED_INSPECTION"
    AGENT_NOT_FOUND = "AGENT_NOT_FOUND"
    # Inspection backend management
    INSPECTION_BACKEND_CHANGED = "INSPECTION_BACKEND_CHANGED"
    INSPECTION_BACKEND_UNREACHABLE = "INSPECTION_BACKEND_UNREACHABLE"
    INSPECTION_BACKEND_FALLBACK = "INSPECTION_BACKEND_FALLBACK"
    INSPECTION_BACKEND_FALLBACK_EXHAUSTED = "INSPECTION_BACKEND_FALLBACK_EXHAUSTED"
    INSPECTION_BACKEND_CONFIG_CHANGED = "INSPECTION_BACKEND_CONFIG_CHANGED"
    INSPECTION_KMS_KEY_RETRIEVED = "INSPECTION_KMS_KEY_RETRIEVED"
    # v0.7.0 — IP allowlisting
    IP_ALLOWLIST_VIOLATION = "IP_ALLOWLIST_VIOLATION"
    # v0.7.0 — Rate limit threshold changes
    RATE_LIMIT_THRESHOLD_CHANGED = "RATE_LIMIT_THRESHOLD_CHANGED"
    # v0.7.0 — OPA Policy Assistant
    OPA_ASSISTANT_SUGGESTION_GENERATED = "OPA_ASSISTANT_SUGGESTION_GENERATED"
    OPA_ASSISTANT_SUGGESTION_APPLIED = "OPA_ASSISTANT_SUGGESTION_APPLIED"
    OPA_ASSISTANT_SUGGESTION_REJECTED = "OPA_ASSISTANT_SUGGESTION_REJECTED"


# ---------------------------------------------------------------------------
# Base event
# ---------------------------------------------------------------------------

@dataclass
class AuditEvent:
    event_type: str
    account_tier: str                       # AccountTier value
    masking_applied: bool = True
    audit_event_id: str = field(default_factory=_new_uuid)
    timestamp: str = field(default_factory=_now_iso)
    schema_version: str = "1.0"

    def to_dict(self) -> dict:
        import dataclasses
        return dataclasses.asdict(self)


# ---------------------------------------------------------------------------
# Security events
# ---------------------------------------------------------------------------

@dataclass
class CredentialLeakDetectedEvent(AuditEvent):
    event_type: str = EventType.CREDENTIAL_LEAK_DETECTED
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True            # immutable floor — always True
    session_id: str = ""
    agent_id: str = ""
    pattern_type: str = ""                  # e.g. 'jwt', 'api_key', 'bearer'
    content_hash: str = ""                  # SHA-256 of original segment
    source_component: str = ""


@dataclass
class PromptInjectionDetectedEvent(AuditEvent):
    event_type: str = EventType.PROMPT_INJECTION_DETECTED
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    session_id: str = ""
    agent_id: str = ""
    classification: str = ""               # CREDENTIAL_EXFIL | PROMPT_INJECTION_ONLY
    severity: str = ""                     # CRITICAL | HIGH
    confidence_score: float = 0.0
    action_taken: str = ""                 # sanitized | discarded
    sanitized: bool = False
    admin_alerted: bool = True             # always True — both paths alert admin
    user_alerted: bool = True
    raw_query_logged: bool = False         # always False — invariant


@dataclass
class SiemDeliveryFailedEvent(AuditEvent):
    event_type: str = EventType.SIEM_DELIVERY_FAILED
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    siem_target_name: str = ""
    siem_target_type: str = ""
    failed_audit_event_id: str = ""
    http_status: Optional[int] = None
    error: str = ""
    retry_attempted: bool = False


# ---------------------------------------------------------------------------
# Auth events — admin
# ---------------------------------------------------------------------------

@dataclass
class AdminLoginEvent(AuditEvent):
    event_type: str = EventType.ADMIN_LOGIN
    account_tier: str = AccountTier.ADMIN
    admin_account: str = ""
    outcome: str = ""                      # success | failure
    failure_reason: Optional[str] = None


@dataclass
class AdminSessionInvalidatedEvent(AuditEvent):
    event_type: str = EventType.ADMIN_SESSION_INVALIDATED
    account_tier: str = AccountTier.ADMIN
    admin_account: str = ""
    reason: str = ""


@dataclass
class FullResetTotpFailureEvent(AuditEvent):
    event_type: str = EventType.FULL_RESET_TOTP_FAILURE
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    admin_account: str = ""
    target_user_handle: str = ""
    failure_reason: str = ""               # missing | malformed | expired | invalid | replayed


@dataclass
class AdminSessionTotpLockoutEvent(AuditEvent):
    event_type: str = EventType.ADMIN_SESSION_INVALIDATED_TOTP_LOCKOUT
    account_tier: str = AccountTier.ADMIN
    admin_account: str = ""
    endpoint: str = ""
    consecutive_failures: int = 0


# ---------------------------------------------------------------------------
# Auth events — user / TOTP
# ---------------------------------------------------------------------------

@dataclass
class UserLoginEvent(AuditEvent):
    event_type: str = EventType.USER_LOGIN
    account_tier: str = AccountTier.USER
    user_handle: str = ""
    auth_mode: str = ""                    # sso | local
    outcome: str = ""
    failure_reason: Optional[str] = None


@dataclass
class TotpResetConsoleEvent(AuditEvent):
    """Written when totp-reset CLI command is executed. Immutable floor."""
    event_type: str = EventType.TOTP_RESET_CONSOLE
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True           # immutable floor
    admin_account: str = ""               # operator who ran the command
    target_account: str = ""


@dataclass
class TotpProvisionTokenIssuedEvent(AuditEvent):
    event_type: str = EventType.TOTP_PROVISION_TOKEN_ISSUED
    account_tier: str = AccountTier.USER
    user_handle: str = ""


@dataclass
class TotpProvisionCompletedEvent(AuditEvent):
    event_type: str = EventType.TOTP_PROVISION_COMPLETED
    account_tier: str = AccountTier.USER
    user_handle: str = ""


@dataclass
class TotpProvisionFailedEvent(AuditEvent):
    event_type: str = EventType.TOTP_PROVISION_FAILED
    account_tier: str = AccountTier.USER
    user_handle: str = ""
    reason: str = ""                       # expired_token | reuse | invalid_code


@dataclass
class RecoveryCodeUsedEvent(AuditEvent):
    """Code value is never logged. Immutable floor."""
    event_type: str = EventType.RECOVERY_CODE_USED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    admin_account: str = ""
    outcome: str = ""                      # success | failure
    codes_remaining: int = 0


@dataclass
class EmergencyUnlockExecutedEvent(AuditEvent):
    """SECURITY_CRITICAL — not maskable by any config. Immutable floor."""
    event_type: str = EventType.EMERGENCY_UNLOCK_EXECUTED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    severity: str = "SECURITY_CRITICAL"
    admin_account: str = ""
    target_account: str = ""


# ---------------------------------------------------------------------------
# Config events
# ---------------------------------------------------------------------------

@dataclass
class ConfigChangedEvent(AuditEvent):
    event_type: str = EventType.CONFIG_CHANGED
    account_tier: str = AccountTier.ADMIN
    admin_account: str = ""
    setting: str = ""
    previous_value: str = ""
    new_value: str = ""
    below_risk_threshold: bool = False


@dataclass
class MaskingConfigChangedEvent(AuditEvent):
    """Config changes to masking scope are themselves always masked."""
    event_type: str = EventType.MASKING_CONFIG_CHANGED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    admin_account: str = ""
    change_target: str = ""               # agent | user_session | component
    target_identifier: str = ""
    previous_value: str = ""
    new_value: str = ""


@dataclass
class KsmRotationEvent(AuditEvent):
    event_type: str = EventType.KSM_ROTATION_SUCCESS
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    outcome: str = ""                     # success | failure | critical
    rotation_type: str = ""               # scheduled | manual
    provider_name: str = ""
    new_token_handle: Optional[str] = None


# ---------------------------------------------------------------------------
# Self-service / user management
# ---------------------------------------------------------------------------

@dataclass
class SelfServiceEvent(AuditEvent):
    event_type: str = EventType.SELFSERVICE_ACTION
    account_tier: str = AccountTier.USER
    user_handle: str = ""
    action: str = ""
    outcome: str = ""
    failure_reason: Optional[str] = None


@dataclass
class UserFullResetEvent(AuditEvent):
    event_type: str = EventType.USER_FULL_RESET
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    admin_account: str = ""
    admin_totp_verified: bool = True      # always True on successful reset
    target_user_handle: str = ""


# ---------------------------------------------------------------------------
# Gateway events
# ---------------------------------------------------------------------------

@dataclass
class RateLimitViolationEvent(AuditEvent):
    """Written on every rate limit violation at the gateway."""
    event_type: str = EventType.RATE_LIMIT_VIOLATION
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    request_id: str = ""
    dimension: str = ""               # global | ip | agent | session
    client_ip_hash: str = ""          # SHA-256 prefix — never raw IP
    agent_id: str = ""
    session_id_prefix: str = ""
    retry_after_ms: int = 0
    rpi_at_time: float = 0.0
    rpi_multiplier: float = 1.0


@dataclass
class GatewayRequestEvent(AuditEvent):
    """Written for every request passing through the Yashigani gateway."""
    event_type: str = EventType.GATEWAY_REQUEST
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    request_id: str = ""
    method: str = ""
    path: str = ""
    action: str = ""                      # FORWARDED | DISCARDED | DENIED | BLOCKED
    reason: str = ""
    upstream_status: Optional[int] = None
    elapsed_ms: Optional[int] = None
    confidence_score: Optional[float] = None


# ---------------------------------------------------------------------------
# RBAC events
# ---------------------------------------------------------------------------

@dataclass
class RBACGroupEvent(AuditEvent):
    """Written when an RBAC group is created, updated, or deleted."""
    event_type: str = EventType.RBAC_GROUP_CREATED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    group_id: str = ""
    group_name: str = ""
    admin_account: str = ""
    change_detail: str = ""               # free-form summary of what changed


@dataclass
class RBACMemberEvent(AuditEvent):
    """Written when a member is added to or removed from an RBAC group."""
    event_type: str = EventType.RBAC_MEMBER_ADDED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    group_id: str = ""
    email: str = ""
    admin_account: str = ""


@dataclass
class RBACPolicyPushEvent(AuditEvent):
    """Written after every successful or failed OPA RBAC data push."""
    event_type: str = EventType.RBAC_POLICY_PUSHED
    account_tier: str = AccountTier.ADMIN
    masking_applied: bool = True
    groups_count: int = 0
    users_count: int = 0
    admin_account: str = ""
    outcome: str = "success"              # success | failure
    error: str = ""


# ---------------------------------------------------------------------------
# Agent registry events
# ---------------------------------------------------------------------------

@dataclass
class AgentRegisteredEvent(AuditEvent):
    event_type: str = EventType.AGENT_REGISTERED
    account_tier: str = AccountTier.ADMIN
    agent_id: str = ""
    agent_name: str = ""
    upstream_url: str = ""
    groups: list = field(default_factory=list)
    allowed_caller_groups: list = field(default_factory=list)
    allowed_paths: list = field(default_factory=list)
    admin_account: str = ""


@dataclass
class AgentUpdatedEvent(AuditEvent):
    event_type: str = EventType.AGENT_UPDATED
    account_tier: str = AccountTier.ADMIN
    agent_id: str = ""
    changed_fields: list = field(default_factory=list)
    admin_account: str = ""


@dataclass
class AgentDeactivatedEvent(AuditEvent):
    event_type: str = EventType.AGENT_DEACTIVATED
    account_tier: str = AccountTier.ADMIN
    agent_id: str = ""
    admin_account: str = ""
    reason: str = ""


@dataclass
class AgentTokenRotatedEvent(AuditEvent):
    event_type: str = EventType.AGENT_TOKEN_ROTATED
    account_tier: str = AccountTier.ADMIN
    agent_id: str = ""
    admin_account: str = ""


# ---------------------------------------------------------------------------
# Agent auth / routing events
# ---------------------------------------------------------------------------

@dataclass
class AgentAuthFailedEvent(AuditEvent):
    event_type: str = EventType.AGENT_AUTH_FAILED
    account_tier: str = AccountTier.SYSTEM
    agent_id_claimed: str = ""
    source_ip: str = ""
    path: str = ""
    failure_reason: str = ""


@dataclass
class AgentCallAllowedEvent(AuditEvent):
    event_type: str = EventType.AGENT_CALL_ALLOWED
    account_tier: str = AccountTier.SYSTEM
    caller_agent_id: str = ""
    target_agent_id: str = ""
    path: str = ""
    remainder_path: str = ""
    pipeline_action: str = ""
    classification: str = ""


@dataclass
class AgentCallDeniedRBACEvent(AuditEvent):
    event_type: str = EventType.AGENT_CALL_DENIED_RBAC
    account_tier: str = AccountTier.SYSTEM
    caller_agent_id: str = ""
    target_agent_id: str = ""
    path: str = ""
    opa_reason: str = ""


@dataclass
class AgentCallDeniedInspectionEvent(AuditEvent):
    event_type: str = EventType.AGENT_CALL_DENIED_INSPECTION
    account_tier: str = AccountTier.SYSTEM
    caller_agent_id: str = ""
    target_agent_id: str = ""
    path: str = ""
    classification: str = ""
    confidence: float = 0.0
    action: str = ""


@dataclass
class AgentNotFoundEvent(AuditEvent):
    event_type: str = EventType.AGENT_NOT_FOUND
    account_tier: str = AccountTier.SYSTEM
    caller_agent_id: str = ""
    target_agent_id_requested: str = ""
    path: str = ""


# ---------------------------------------------------------------------------
# Inspection backend management events
# ---------------------------------------------------------------------------

@dataclass
class InspectionBackendChangedEvent(AuditEvent):
    event_type: str = EventType.INSPECTION_BACKEND_CHANGED
    account_tier: str = AccountTier.ADMIN
    previous_backend: str = ""
    new_backend: str = ""
    admin_account: str = ""


@dataclass
class InspectionBackendUnreachableEvent(AuditEvent):
    event_type: str = EventType.INSPECTION_BACKEND_UNREACHABLE
    account_tier: str = AccountTier.SYSTEM
    backend_name: str = ""
    error_type: str = ""
    error_message: str = ""
    request_id: str = ""


@dataclass
class InspectionBackendFallbackEvent(AuditEvent):
    event_type: str = EventType.INSPECTION_BACKEND_FALLBACK
    account_tier: str = AccountTier.SYSTEM
    failed_backend: str = ""
    next_backend: str = ""
    fallback_position: int = 0
    request_id: str = ""


@dataclass
class InspectionBackendFallbackExhaustedEvent(AuditEvent):
    event_type: str = EventType.INSPECTION_BACKEND_FALLBACK_EXHAUSTED
    account_tier: str = AccountTier.SYSTEM
    backends_tried: list = field(default_factory=list)
    request_id: str = ""
    action_taken: str = "PROMPT_INJECTION_ONLY"


@dataclass
class InspectionBackendConfigChangedEvent(AuditEvent):
    event_type: str = EventType.INSPECTION_BACKEND_CONFIG_CHANGED
    account_tier: str = AccountTier.ADMIN
    backend_name: str = ""
    changed_fields: list = field(default_factory=list)
    admin_account: str = ""


@dataclass
class InspectionKMSKeyRetrievedEvent(AuditEvent):
    event_type: str = EventType.INSPECTION_KMS_KEY_RETRIEVED
    account_tier: str = AccountTier.SYSTEM
    backend_name: str = ""
    kms_key_name: str = ""


# ---------------------------------------------------------------------------
# v0.7.0 events
# ---------------------------------------------------------------------------

@dataclass
class IPAllowlistViolationEvent(AuditEvent):
    """Written when an agent request is rejected due to IP allowlist enforcement."""
    event_type: str = EventType.IP_ALLOWLIST_VIOLATION
    account_tier: str = AccountTier.SYSTEM
    masking_applied: bool = True
    agent_id: str = ""
    client_ip_hash: str = ""        # SHA-256 prefix — never raw IP
    allowed_cidrs: list = None      # configured CIDR list (no sensitive data)

    def __post_init__(self):
        if self.allowed_cidrs is None:
            self.allowed_cidrs = []


@dataclass
class RateLimitThresholdChangedEvent(AuditEvent):
    """Written when rpi_scale_* thresholds are changed via the backoffice API."""
    event_type: str = EventType.RATE_LIMIT_THRESHOLD_CHANGED
    account_tier: str = AccountTier.ADMIN
    admin_account: str = ""
    previous_rpi_scale_medium: float = 0.0
    previous_rpi_scale_high: float = 0.0
    previous_rpi_scale_critical: float = 0.0
    new_rpi_scale_medium: float = 0.0
    new_rpi_scale_high: float = 0.0
    new_rpi_scale_critical: float = 0.0


@dataclass
class OPAAssistantSuggestionGeneratedEvent(AuditEvent):
    """Written when the OPA assistant generates a suggestion (before admin review)."""
    event_type: str = EventType.OPA_ASSISTANT_SUGGESTION_GENERATED
    account_tier: str = AccountTier.ADMIN
    admin_account: str = ""
    description_length: int = 0     # length of NL description (not the text itself)
    suggestion_valid: bool = False
    validation_error: Optional[str] = None


@dataclass
class OPAAssistantSuggestionAppliedEvent(AuditEvent):
    """Written when admin approves and applies an OPA assistant suggestion."""
    event_type: str = EventType.OPA_ASSISTANT_SUGGESTION_APPLIED
    account_tier: str = AccountTier.ADMIN
    admin_account: str = ""
    groups_in_suggestion: int = 0
    users_in_suggestion: int = 0


@dataclass
class OPAAssistantSuggestionRejectedEvent(AuditEvent):
    """Written when admin explicitly rejects an OPA assistant suggestion."""
    event_type: str = EventType.OPA_ASSISTANT_SUGGESTION_REJECTED
    account_tier: str = AccountTier.ADMIN
    admin_account: str = ""
    reason: str = ""
