"""
Yashigani Backoffice — ASGI entrypoint.
Wires all admin-plane services and populates the singleton BackofficeState.

First-run behaviour:
  If no credentials exist, generates 36-char random passwords for:
    - Admin account
    - Grafana admin
    - Prometheus basic auth
    - Redis
  Prints all credentials once to stdout in a clearly delimited block.
  Marks bootstrap complete via sentinel file so this never repeats.
"""
from __future__ import annotations

import asyncio
import logging
import os

from yashigani.audit.config import AuditConfig
from yashigani.audit.scope import MaskingScopeConfig
from yashigani.audit.writer import AuditLogWriter
from yashigani.auth.bootstrap import (
    load_or_generate,
    print_credentials,
    write_docker_secrets,
    mark_bootstrapped,
)
from yashigani.auth.local_auth import LocalAuthService
from yashigani.auth.session import SessionStore
from yashigani.chs.handle import CredentialHandleService
from yashigani.chs.resource_monitor import ResourceMonitor
from yashigani.inspection.classifier import PromptInjectionClassifier
from yashigani.inspection.pipeline import InspectionPipeline
from yashigani.kms.factory import create_provider
from yashigani.kms.rotation import KSMRotationScheduler
from yashigani.ratelimit.config import RateLimitConfig
from yashigani.ratelimit.limiter import RateLimiter
from yashigani.rbac.store import RBACStore
from yashigani.agents.registry import AgentRegistry
from yashigani.metrics.collectors import MetricsCollector
from yashigani.backoffice.app import create_backoffice_app
from yashigani.backoffice.state import backoffice_state

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _bootstrap():
    # ── First-run credential generation ────────────────────────────────────
    admin_username = os.getenv("YASHIGANI_ADMIN_USERNAME", "admin@yashigani.local")
    secrets_dir = os.getenv("YASHIGANI_SECRETS_DIR", "/run/secrets")

    creds = load_or_generate(admin_username=admin_username, secrets_dir=secrets_dir)
    if creds is not None:
        # New deployment — print credentials and store them
        # If installer already wrote secrets, use those instead of generated ones
        redis_pwd_file = os.path.join(secrets_dir, "redis_password")
        if os.path.exists(redis_pwd_file):
            creds.redis_password = open(redis_pwd_file).read().strip()
        grafana_pwd_file = os.path.join(secrets_dir, "grafana_admin_password")
        if os.path.exists(grafana_pwd_file):
            creds.grafana_admin_password = open(grafana_pwd_file).read().strip()
        print_credentials(creds)
        write_docker_secrets(creds, secrets_dir=secrets_dir)
        mark_bootstrapped()
        initial_admin_password = creds.admin_password
        _redis_password = creds.redis_password
    else:
        # Credentials already exist — read from secret file
        admin_pwd_file = os.path.join(secrets_dir, "admin_initial_password")
        with open(admin_pwd_file) as f:
            initial_admin_password = f.read().strip()

        redis_pwd_file = os.path.join(secrets_dir, "redis_password")
        _redis_password = (
            open(redis_pwd_file).read().strip()
            if os.path.exists(redis_pwd_file)
            else os.getenv("REDIS_PASSWORD", "")
        )

    # ── KSM ────────────────────────────────────────────────────────────────
    kms_provider = create_provider()

    # ── Audit ───────────────────────────────────────────────────────────────
    audit_config = AuditConfig.from_env()
    audit_writer = AuditLogWriter(
        config=audit_config,
        masking_scope=MaskingScopeConfig(),
    )

    # ── Session store (Redis db/1) ──────────────────────────────────────────
    from urllib.parse import quote
    redis_host = os.getenv("REDIS_HOST", "redis")
    redis_port = os.getenv("REDIS_PORT", "6379")
    redis_url = f"redis://:{quote(_redis_password, safe='')}@{redis_host}:{redis_port}/1"
    session_store = SessionStore(redis_url=redis_url)

    # ── Auth service ────────────────────────────────────────────────────────
    auth_service = LocalAuthService()

    if not auth_service._accounts:
        _, _ = auth_service.create_admin(
            username=admin_username,
            auto_generate=False,
            plaintext_password=initial_admin_password,
        )
        # Pre-provision TOTP if the installer wrote a secret
        totp_file = os.path.join(secrets_dir, "admin1_totp_secret")
        if os.path.exists(totp_file):
            totp_secret = open(totp_file).read().strip()
            record = auth_service._accounts.get(admin_username)
            if record and totp_secret:
                record.totp_secret = totp_secret
                record.force_totp_provision = False
                logger.info("Bootstrap: TOTP pre-provisioned from installer secret")
        logger.info("Bootstrap: initial admin account created — %s", admin_username)

    # ── Resource monitor ───────────────────────────────────────────────────
    resource_monitor = ResourceMonitor()

    # ── CHS ─────────────────────────────────────────────────────────────────
    chs = CredentialHandleService(
        kms_provider=kms_provider,
        resource_monitor=resource_monitor,
        on_audit=audit_writer,
    )

    # ── Rotation scheduler (optional) ──────────────────────────────────────
    rotation_scheduler = None
    secret_key = os.getenv("KSM_ROTATION_SECRET_KEY", "")
    cron_expr = os.getenv("KSM_ROTATION_CRON", "0 3 * * *")
    if secret_key:
        rotation_scheduler = KSMRotationScheduler(
            provider=kms_provider,
            secret_key=secret_key,
            cron_expr=cron_expr,
        )
        rotation_scheduler.start()

    # ── Inspection pipeline ────────────────────────────────────────────────
    ollama_url = os.getenv("OLLAMA_BASE_URL", "http://ollama:11434")
    model = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")
    classifier = PromptInjectionClassifier(model=model, ollama_base_url=ollama_url)
    inspection_pipeline = InspectionPipeline(
        classifier=classifier,
        sanitize_threshold=float(os.getenv("YASHIGANI_INJECT_THRESHOLD", "0.85")),
    )

    # ── Rate limiter ─────────────────────────────────────────────────────────
    rate_limiter = None
    try:
        import redis as _redis
        redis_rl_url = f"redis://:{_redis_password}@{redis_host}:{redis_port}/2"
        redis_rl_client = _redis.from_url(redis_rl_url, decode_responses=False)
        rate_limiter = RateLimiter(
            redis_client=redis_rl_client,
            config=RateLimitConfig(),
            resource_monitor=resource_monitor,
        )
    except Exception as exc:
        logger.warning("Rate limiter Redis unavailable (%s) — rate limiting disabled", exc)

    # ── RBAC store + Agent registry (Redis db/3) ─────────────────────────────
    rbac_store = None
    agent_registry = None
    try:
        import redis as _redis
        redis_rbac_url = f"redis://:{_redis_password}@{redis_host}:{redis_port}/3"
        redis_rbac_client = _redis.from_url(redis_rbac_url, decode_responses=False)
        rbac_store = RBACStore(redis_client=redis_rbac_client)
        logger.info(
            "RBAC store initialised: %d group(s) loaded from Redis",
            len(rbac_store.list_groups()),
        )
        # Agent registry shares the same Redis db/3 instance (different key namespace)
        agent_registry = AgentRegistry(redis_client=redis_rbac_client)
        logger.info(
            "Agent registry initialised: %d agent(s) in index",
            agent_registry.count("all"),
        )
    except Exception as exc:
        logger.warning("RBAC/Agent Redis unavailable (%s) — RBAC and agent registry disabled", exc)

    # ── Backend registry + config store (Redis db/1, separate key namespace) ─
    backend_registry = None
    backend_config_store = None
    try:
        import redis as _redis
        from yashigani.inspection.backends.ollama import OllamaBackend
        from yashigani.inspection.backend_registry import BackendRegistry
        from yashigani.inspection.backend_config import BackendConfigStore

        # BackendConfigStore shares Redis db/1 (session store) — different key namespace
        redis_session_client = _redis.from_url(
            f"redis://:{_redis_password}@{redis_host}:{redis_port}/1",
            decode_responses=False,
        )
        backend_config_store = BackendConfigStore(redis_client=redis_session_client)

        # Determine default active backend from env or Redis
        default_backend_name = os.getenv(
            "YASHIGANI_INSPECTION_DEFAULT_BACKEND",
            backend_config_store.get_active(),
        )
        fallback_chain_raw = os.getenv(
            "YASHIGANI_INSPECTION_FALLBACK_CHAIN",
            "",
        )
        if fallback_chain_raw:
            fallback_chain = [b.strip() for b in fallback_chain_raw.split(",") if b.strip()]
        else:
            fallback_chain = backend_config_store.get_fallback_chain()

        # Build the initial active backend (Ollama is always available locally)
        ollama_backend = OllamaBackend(
            base_url=ollama_url,
            model=model,
        )

        backend_registry = BackendRegistry(
            active_backend=ollama_backend,
            fallback_chain=fallback_chain,
            all_backends={"ollama": ollama_backend},
            audit_writer=audit_writer,
        )

        # Inject backend_registry into the inspection pipeline
        inspection_pipeline._backend_registry = backend_registry

        logger.info(
            "Backend registry initialised: active=%s, chain=%s",
            ollama_backend.name, fallback_chain,
        )
    except Exception as exc:
        logger.warning(
            "Backend registry init failed (%s) — inspection pipeline uses legacy classifier",
            exc,
        )

    # ── OTEL tracing ───────────────────────────────────────────────────────
    try:
        from yashigani.tracing import setup_tracer
        setup_tracer("yashigani-backoffice")
    except Exception as exc:
        logger.warning("OTEL setup skipped: %s", exc)

    # ── Response cache (Redis DB 4) — for admin management (Phase 6) ──────────
    response_cache = None
    try:
        import redis as _redis
        from yashigani.gateway.response_cache import ResponseCache
        redis_cache_url = f"redis://:{_redis_password}@{redis_host}:{redis_port}/4"
        redis_cache_client = _redis.from_url(redis_cache_url, decode_responses=False)
        response_cache = ResponseCache(redis_client=redis_cache_client)
        logger.info("Backoffice: response cache client ready (Redis DB 4)")
    except Exception as exc:
        logger.warning("Response cache init failed (%s) — cache management disabled", exc)

    # ── PostgreSQL pool + inference logger + anomaly detector ───────────────
    db_pool_ready = False
    inference_logger = None
    anomaly_detector = None
    try:
        from yashigani.db import create_pool
        from yashigani.inference import InferencePayloadLogger, AnomalyDetector

        db_dsn = os.getenv("YASHIGANI_DB_DSN", "")
        if db_dsn and "${POSTGRES_PASSWORD}" in db_dsn:
            pg_pwd_file = os.path.join(secrets_dir, "postgres_password")
            try:
                with open(pg_pwd_file) as f:
                    pg_password = f.read().strip()
                db_dsn = db_dsn.replace("${POSTGRES_PASSWORD}", pg_password)
                os.environ["YASHIGANI_DB_DSN"] = db_dsn
            except OSError:
                logger.warning("postgres_password secret not found — DB DSN unresolved")
        if db_dsn and "${POSTGRES_PASSWORD}" not in db_dsn:
            loop = asyncio.get_event_loop()
            loop.run_until_complete(create_pool())
            db_pool_ready = True

            inference_logger = InferencePayloadLogger()
            asyncio.ensure_future(inference_logger.start())

            import redis as _redis
            redis_anomaly_url = f"redis://:{_redis_password}@{redis_host}:{redis_port}/2"
            redis_anomaly_client = _redis.from_url(redis_anomaly_url, decode_responses=False)
            anomaly_detector = AnomalyDetector(redis_client=redis_anomaly_client)
            logger.info("Backoffice: DB pool + inference logger + anomaly detector ready")
        else:
            logger.warning("YASHIGANI_DB_DSN not set — Postgres features disabled in backoffice")
    except Exception as exc:
        logger.warning("Backoffice DB/inference init failed (%s) — Postgres features disabled", exc)

    # ── License ──────────────────────────────────────────────────────────────
    from yashigani.licensing import load_license, set_license
    license_state = load_license()
    set_license(license_state)
    logger.info(
        "License: tier=%s agents=%s/%s expires=%s",
        license_state.tier.value,
        "?",
        license_state.max_agents if license_state.max_agents != -1 else "unlimited",
        license_state.expires_at or "never",
    )

    # ── Populate singleton state ────────────────────────────────────────────
    backoffice_state.auth_service = auth_service
    backoffice_state.session_store = session_store
    backoffice_state.audit_writer = audit_writer
    backoffice_state.kms_provider = kms_provider
    backoffice_state.rotation_scheduler = rotation_scheduler
    backoffice_state.inspection_pipeline = inspection_pipeline
    backoffice_state.chs = chs
    backoffice_state.resource_monitor = resource_monitor
    backoffice_state.rate_limiter = rate_limiter
    backoffice_state.rbac_store = rbac_store
    backoffice_state.agent_registry = agent_registry
    backoffice_state.backend_registry = backend_registry
    backoffice_state.backend_config_store = backend_config_store
    backoffice_state.opa_url = os.getenv("YASHIGANI_OPA_URL", "http://policy:8181")
    backoffice_state.admin_min_total = int(os.getenv("YASHIGANI_ADMIN_MIN_TOTAL", "2"))
    backoffice_state.admin_min_active = int(os.getenv("YASHIGANI_ADMIN_MIN_ACTIVE", "2"))
    backoffice_state.admin_soft_target = int(os.getenv("YASHIGANI_ADMIN_SOFT_TARGET", "3"))
    backoffice_state.user_min_total = int(os.getenv("YASHIGANI_USER_MIN_TOTAL", "1"))
    backoffice_state.inference_logger = inference_logger
    backoffice_state.anomaly_detector = anomaly_detector
    backoffice_state.response_cache = response_cache
    backoffice_state.license_state = license_state

    # v0.9.0 — WebAuthn + EventBus (optional, graceful degradation if unavailable)
    try:
        from yashigani.auth.webauthn import WebAuthnService
        backoffice_state.webauthn_service = WebAuthnService()
        logger.info("WebAuthn service initialized")
    except Exception as exc:
        logger.warning("WebAuthn service unavailable (%s) — passkey routes will return 503", exc)

    try:
        from yashigani.events.bus import EventBus
        backoffice_state.event_bus = EventBus()
        logger.info("EventBus initialized")
    except Exception as exc:
        logger.warning("EventBus unavailable (%s) — SSE feed will return 503", exc)

    # v2.1 — Break glass emergency access
    try:
        from yashigani.auth.break_glass import init_break_glass
        import redis as _redis
        redis_bg = _redis.from_url(f"redis://:{quote(_redis_password, safe='')}@{redis_host}:{redis_port}/0", decode_responses=True)
        redis_bg.ping()
        backoffice_state.break_glass_manager = init_break_glass(redis_bg, audit_writer)
        logger.info("Break glass manager initialized")
    except Exception as exc:
        logger.warning("Break glass unavailable (%s)", exc)


_bootstrap()
app = create_backoffice_app()

# Start background metrics collector for backoffice-side services
_collector = MetricsCollector(
    resource_monitor=backoffice_state.resource_monitor,
    rate_limiter=backoffice_state.rate_limiter,
    chs=backoffice_state.chs,
    rotation_scheduler=backoffice_state.rotation_scheduler,
    inspection_pipeline=backoffice_state.inspection_pipeline,
    rbac_store=backoffice_state.rbac_store,
    agent_registry=backoffice_state.agent_registry,
    backend_registry=backoffice_state.backend_registry,
    poll_interval_seconds=15,
)
_collector.start()
