"""
Yashigani Backoffice — FastAPI admin portal.
Isolated on port 8443. Local auth only (username + password + TOTP).
No data-plane access. TLS required.
"""
from __future__ import annotations

import os
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

try:
    from prometheus_client import (
        Counter, Histogram,
        generate_latest, CONTENT_TYPE_LATEST,
    )
    _PROM_AVAILABLE = True
except ImportError:
    _PROM_AVAILABLE = False

if _PROM_AVAILABLE:
    _bo_requests_total = Counter(
        "yashigani_backoffice_requests_total",
        "Total backoffice HTTP requests.",
        ["method", "path_prefix", "status_code"],
    )
    _bo_request_duration_seconds = Histogram(
        "yashigani_backoffice_request_duration_seconds",
        "Backoffice request latency in seconds.",
        ["method", "path_prefix"],
        buckets=[.005, .01, .025, .05, .1, .25, .5, 1.0, 2.5, 5.0],
    )
    _bo_auth_failures_total = Counter(
        "yashigani_backoffice_auth_failures_total",
        "Backoffice authentication failures by reason.",
        ["reason"],
    )

from yashigani.backoffice.routes import (
    auth_router,
    accounts_router,
    users_router,
    kms_router,
    audit_router,
    inspection_router,
    inspection_backend_router,
    dashboard_router,
    ratelimit_router,
    rbac_router,
    scim_router,
    agents_router,
    infrastructure_router,
    jwt_config_router,
    cache_router,
    audit_sinks_router,
    kms_vault_router,
    license_router,
    opa_assistant_router,
    alerts_router,
    agent_bundles_router,
    # v0.9.0 — Phase 6 + Phase 7
    webauthn_router,
    events_router,
    audit_search_router,
    # v2.1
    models_router,
    sensitivity_router,
    sso_router,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup — schedule daily licence expiry check (v0.7.1)
    scheduler = None
    try:
        from apscheduler.schedulers.asyncio import AsyncIOScheduler
        from yashigani.licensing.expiry_monitor import check_and_alert_licence_expiry

        scheduler = AsyncIOScheduler()
        # Run once at startup, then every 24 hours
        scheduler.add_job(
            check_and_alert_licence_expiry,
            trigger="interval",
            hours=24,
            id="licence_expiry_check",
            replace_existing=True,
        )
        scheduler.start()
        # Fire immediately so the first check happens at startup, not 24h later
        import asyncio
        asyncio.ensure_future(check_and_alert_licence_expiry())
    except ImportError:
        pass  # apscheduler not installed — expiry alerts disabled
    except Exception as exc:
        import logging
        logging.getLogger(__name__).warning(
            "Could not start licence expiry scheduler: %s", exc
        )

    yield

    # Shutdown
    if scheduler is not None:
        scheduler.shutdown(wait=False)


def create_backoffice_app() -> FastAPI:
    app = FastAPI(
        title="Yashigani Backoffice",
        version="2.1.0",
        docs_url=None,          # disable Swagger in production
        redoc_url=None,
        openapi_url=None,       # never expose schema externally
        lifespan=lifespan,
    )

    # CORS: backoffice serves its own frontend — no cross-origin needed
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[],       # no CORS allowed
        allow_credentials=False,
        allow_methods=[],
        allow_headers=[],
    )

    # Prometheus instrumentation middleware — must be registered before security headers
    # so we record metrics even on requests that return error responses.
    # /internal/metrics is excluded to avoid self-scrape cardinality noise.
    @app.middleware("http")
    async def prometheus_middleware(request: Request, call_next):
        if not _PROM_AVAILABLE or request.url.path == "/internal/metrics":
            return await call_next(request)
        # Collapse path to a low-cardinality prefix (first two segments)
        segments = [s for s in request.url.path.split("/") if s]
        path_prefix = "/" + "/".join(segments[:2]) if segments else "/"
        start = time.monotonic()
        response = await call_next(request)
        elapsed = time.monotonic() - start
        _bo_requests_total.labels(
            method=request.method,
            path_prefix=path_prefix,
            status_code=str(response.status_code),
        ).inc()
        _bo_request_duration_seconds.labels(
            method=request.method,
            path_prefix=path_prefix,
        ).observe(elapsed)
        return response

    # Security headers middleware
    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "no-referrer"
        # CSP: strict for all pages — no inline scripts or styles allowed
        # ASVS 3.4.3: object-src 'none' + base-uri 'none'; 3.4.7: report-uri
        _csp = "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; report-uri /admin/csp-report; report-to default"
        response.headers["Content-Security-Policy"] = _csp
        return response

    # Generic error handlers — never leak internal state
    @app.exception_handler(Exception)
    async def generic_error_handler(request: Request, exc: Exception):
        return JSONResponse(
            status_code=500,
            content={"error": "internal_error", "message": "An internal error occurred"},
        )

    # Unauthenticated health endpoint for Docker healthcheck
    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    # Internal Prometheus metrics endpoint — scraped by Prometheus on internal network only.
    # No auth required: reachable only within the internal Docker/Podman network.
    # ASVS V9.1.1: network-layer isolation replaces endpoint auth here.
    @app.get("/internal/metrics")
    async def internal_metrics():
        if not _PROM_AVAILABLE:
            return PlainTextResponse("# prometheus_client not installed\n")
        return PlainTextResponse(
            generate_latest().decode("utf-8"),
            media_type=CONTENT_TYPE_LATEST,
        )

    # Static files (CSS/JS for login pages etc.)
    import pathlib
    _static_dir = pathlib.Path(__file__).parent / "static"
    if _static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")

    # Admin UI — HTML pages
    _templates_dir = pathlib.Path(__file__).parent / "templates"
    if _templates_dir.exists():
        _templates = Jinja2Templates(directory=str(_templates_dir))

        @app.get("/login", include_in_schema=False)
        async def user_login_page(request: Request):
            return _templates.TemplateResponse(request, "user_login.html")

        @app.get("/admin/login", include_in_schema=False)
        async def admin_login_page(request: Request):
            return _templates.TemplateResponse(request, "login.html")

        @app.get("/admin/", include_in_schema=False)
        async def admin_dashboard_page(request: Request):
            return _templates.TemplateResponse(request, "dashboard.html")

    # Routers
    app.include_router(auth_router, prefix="/auth", tags=["auth"])
    app.include_router(dashboard_router, prefix="/dashboard", tags=["dashboard"])
    app.include_router(accounts_router, prefix="/admin/accounts", tags=["admin-accounts"])
    app.include_router(users_router, prefix="/admin/users", tags=["user-accounts"])
    app.include_router(kms_router, prefix="/admin/kms", tags=["kms"])
    app.include_router(audit_router, prefix="/admin/audit", tags=["audit"])
    app.include_router(inspection_router, prefix="/admin/inspection", tags=["inspection"])
    app.include_router(inspection_backend_router, prefix="/admin/inspection", tags=["inspection-backend"])
    app.include_router(ratelimit_router, prefix="/admin/ratelimit", tags=["ratelimit"])
    app.include_router(rbac_router, prefix="/admin/rbac", tags=["rbac"])
    app.include_router(scim_router, prefix="/scim/v2", tags=["scim"])
    app.include_router(agents_router, tags=["agents"])
    app.include_router(infrastructure_router, prefix="/admin/infrastructure", tags=["infrastructure"])
    app.include_router(jwt_config_router, tags=["jwt-config"])
    app.include_router(cache_router, tags=["cache"])
    app.include_router(audit_sinks_router, tags=["audit-sinks"])
    app.include_router(kms_vault_router, tags=["kms-vault"])
    app.include_router(license_router, prefix="/admin/license", tags=["license"])
    app.include_router(opa_assistant_router, prefix="/admin/opa-assistant", tags=["opa-assistant"])
    app.include_router(alerts_router, prefix="/admin/alerts", tags=["alerts"])
    app.include_router(agent_bundles_router, prefix="/admin/agent-bundles", tags=["agent-bundles"])
    # v1.0 — Budget admin API
    from yashigani.backoffice.routes.budget import router as budget_router
    app.include_router(budget_router, tags=["budget"])

    # v2.1 — Model alias management + Sensitivity patterns
    app.include_router(models_router, prefix="/admin/models", tags=["models"])
    app.include_router(sensitivity_router, prefix="/admin/sensitivity", tags=["sensitivity"])
    # v2.1 — SSO / OIDC login flow (no auth required — serves anonymous users)
    app.include_router(sso_router, prefix="/auth", tags=["sso"])

    # v2.2 — PII detection admin API
    from yashigani.backoffice.routes.pii import router as pii_router
    app.include_router(pii_router, prefix="/admin/pii", tags=["pii"])

    # v2.3 — Cryptographic inventory (ASVS 11.1.3)
    from yashigani.backoffice.routes.crypto_inventory import router as crypto_inventory_router
    app.include_router(crypto_inventory_router, prefix="/admin", tags=["crypto"])

    # ASVS 3.4.7 — CSP violation report endpoint
    from yashigani.backoffice.routes.csp_report import router as csp_report_router
    app.include_router(csp_report_router, prefix="/admin", tags=["csp"])

    # Service management — enable/disable optional compose profiles from admin panel
    from yashigani.backoffice.routes.services import router as services_router
    app.include_router(services_router, tags=["services"])

    # v0.9.0 — Phase 6: WebAuthn/Passkeys
    # webauthn_router carries its own full path segments (no prefix stripping needed)
    app.include_router(webauthn_router, tags=["webauthn"])
    # v0.9.0 — Phase 7: Operator Visibility
    app.include_router(events_router, prefix="/admin/events", tags=["events"])
    app.include_router(audit_search_router, prefix="/admin/audit", tags=["audit-search"])

    return app
