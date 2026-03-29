"""Backoffice route exports."""
from yashigani.backoffice.routes.auth import router as auth_router
from yashigani.backoffice.routes.accounts import router as accounts_router
from yashigani.backoffice.routes.users import router as users_router
from yashigani.backoffice.routes.kms import router as kms_router
from yashigani.backoffice.routes.audit import router as audit_router
from yashigani.backoffice.routes.inspection import router as inspection_router
from yashigani.backoffice.routes.inspection_backend import router as inspection_backend_router
from yashigani.backoffice.routes.dashboard import router as dashboard_router
from yashigani.backoffice.routes.ratelimit import router as ratelimit_router
from yashigani.backoffice.routes.rbac import router as rbac_router
from yashigani.backoffice.routes.scim import router as scim_router
from yashigani.backoffice.routes.agents import router as agents_router
from yashigani.backoffice.routes.infrastructure import router as infrastructure_router
from yashigani.backoffice.routes.jwt_config import jwt_config_router
from yashigani.backoffice.routes.cache import cache_router
from yashigani.backoffice.routes.audit_sinks import audit_sinks_router
from yashigani.backoffice.routes.kms_vault import kms_vault_router
from yashigani.backoffice.routes.license import license_router
from yashigani.backoffice.routes.opa_assistant import router as opa_assistant_router
from yashigani.backoffice.routes.alerts import router as alerts_router
from yashigani.backoffice.routes.agent_bundles import router as agent_bundles_router

__all__ = [
    "auth_router", "accounts_router", "users_router",
    "kms_router", "audit_router", "inspection_router",
    "inspection_backend_router",
    "dashboard_router", "ratelimit_router",
    "rbac_router", "scim_router", "agents_router",
    "infrastructure_router",
    "jwt_config_router", "cache_router", "audit_sinks_router", "kms_vault_router",
    "license_router", "opa_assistant_router", "alerts_router",
    "agent_bundles_router",
]
