"""
Yashigani Gateway — ASGI entrypoint.
Wires all services together and creates the FastAPI app.
Environment variables configure service endpoints and behaviour.
"""
from __future__ import annotations

import asyncio
import logging
import os

from yashigani.audit.config import AuditConfig
from yashigani.audit.scope import MaskingScopeConfig
from yashigani.audit.writer import AuditLogWriter
from yashigani.chs.handle import CredentialHandleService
from yashigani.chs.resource_monitor import ResourceMonitor
from yashigani.inspection.classifier import PromptInjectionClassifier
from yashigani.inspection.pipeline import InspectionPipeline, ResponseInspectionPipeline
from yashigani.kms.factory import create_provider
from yashigani.ratelimit.config import RateLimitConfig
from yashigani.ratelimit.limiter import RateLimiter
from yashigani.rbac.store import RBACStore
from yashigani.agents.registry import AgentRegistry
from yashigani.metrics.collectors import MetricsCollector
from yashigani.metrics.middleware import PrometheusMiddleware
from yashigani.gateway.proxy import GatewayConfig, create_gateway_app
from yashigani.gateway.agent_auth import AgentAuthMiddleware

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _build_app():
    # ── OTEL tracing — initialise before anything else ─────────────────────
    try:
        from yashigani.tracing import setup_tracer
        setup_tracer("yashigani-gateway")
    except Exception as exc:
        logger.warning("OTEL setup skipped: %s", exc)

    # KSM provider
    kms_provider = create_provider()

    # Audit
    audit_config = AuditConfig.from_env()
    audit_writer = AuditLogWriter(
        config=audit_config,
        masking_scope=MaskingScopeConfig(),
    )

    # Resource monitor (cgroup v2 for dynamic TTL)
    resource_monitor = ResourceMonitor()

    # CHS
    chs = CredentialHandleService(
        kms_provider=kms_provider,
        resource_monitor=resource_monitor,
        audit_writer=audit_writer,
    )

    # Inspection pipeline
    ollama_url = os.getenv("OLLAMA_BASE_URL", "http://ollama:11434")
    model = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")
    if "OLLAMA_MODEL" not in os.environ:
        logger.warning("OLLAMA_MODEL not set — using default '%s'", model)
    classifier = PromptInjectionClassifier(model=model, ollama_base_url=ollama_url)

    pipeline = InspectionPipeline(
        classifier=classifier,
        sanitize_threshold=float(os.getenv("YASHIGANI_INJECT_THRESHOLD", "0.85")),
    )

    # Response inspection pipeline — v0.9.0 F-01
    response_pipeline = None
    if os.getenv("YASHIGANI_INSPECT_RESPONSES", "false").lower() == "true":
        response_pipeline = ResponseInspectionPipeline(classifier=classifier)
        logger.info("Response inspection pipeline enabled")

    # FastText first-pass classifier — Phase 12
    fasttext_backend = None
    try:
        from yashigani.inspection.backends.fasttext_backend import FastTextBackend
        fasttext_backend = FastTextBackend()
        logger.info("FastText backend loaded: %s", fasttext_backend.model_path)
    except Exception as exc:
        logger.warning("FastText backend unavailable (%s) — LLM-only inspection", exc)

    # Gateway config
    upstream_url = os.environ["YASHIGANI_UPSTREAM_URL"]
    opa_url = os.getenv("YASHIGANI_OPA_URL", "http://policy:8181")

    cfg = GatewayConfig(
        upstream_base_url=upstream_url,
        opa_url=opa_url,
    )

    # Redis base URL — derived from env vars set by docker-compose
    redis_host = os.getenv("REDIS_HOST", "redis")
    redis_port = os.getenv("REDIS_PORT", "6379")
    redis_password = ""
    secrets_dir = os.getenv("YASHIGANI_SECRETS_DIR", "/run/secrets")
    redis_pwd_file = os.path.join(secrets_dir, "redis_password")
    try:
        with open(redis_pwd_file) as f:
            redis_password = f.read().strip()
    except OSError:
        redis_password = os.getenv("REDIS_PASSWORD", "")

    redis_base = f"redis://:{redis_password}@{redis_host}:{redis_port}"

    # Rate limiter — Redis DB 2
    rate_limiter = None
    try:
        import redis as _redis
        redis_client_rl = _redis.from_url(f"{redis_base}/2", decode_responses=False)
        redis_client_rl.ping()
        rate_limiter = RateLimiter(
            redis_client=redis_client_rl,
            config=RateLimitConfig(),
            resource_monitor=resource_monitor,
        )
    except Exception as exc:
        logger.warning("Rate limiter Redis unavailable (%s) — rate limiting disabled", exc)

    # Endpoint rate limiter — Redis DB 2 (same DB, different key namespace) — Phase 5
    endpoint_rate_limiter = None
    try:
        import redis as _redis
        from yashigani.gateway.endpoint_ratelimit import EndpointRateLimiter
        redis_client_ep = _redis.from_url(f"{redis_base}/2", decode_responses=False)
        redis_client_ep.ping()
        endpoint_rate_limiter = EndpointRateLimiter(redis_client=redis_client_ep)
        logger.info("Endpoint rate limiter ready")
    except Exception as exc:
        logger.warning("Endpoint rate limiter unavailable (%s) — disabled", exc)

    # Response cache — Redis DB 4 — Phase 6
    response_cache = None
    try:
        import redis as _redis
        from yashigani.gateway.response_cache import ResponseCache
        redis_client_cache = _redis.from_url(f"{redis_base}/4", decode_responses=False)
        redis_client_cache.ping()
        response_cache = ResponseCache(redis_client=redis_client_cache)
        logger.info("Response cache ready (Redis DB 4)")
    except Exception as exc:
        logger.warning("Response cache unavailable (%s) — caching disabled", exc)

    # RBAC store and Agent registry — Redis DB 3 (shared instance, separate key namespaces)
    rbac_store = None
    agent_registry = None
    try:
        import redis as _redis
        redis_client_rbac = _redis.from_url(f"{redis_base}/3", decode_responses=False)
        redis_client_rbac.ping()
        rbac_store = RBACStore(redis_client=redis_client_rbac)
        logger.info("Gateway RBAC store ready: %d group(s)", len(rbac_store.list_groups()))
        agent_registry = AgentRegistry(redis_client=redis_client_rbac)
        logger.info(
            "Gateway agent registry ready: %d agent(s)",
            agent_registry.count("all"),
        )
    except Exception as exc:
        logger.warning(
            "RBAC/Agent Redis unavailable (%s) — RBAC and agent routing disabled", exc
        )

    # JWT inspector — Phase 7
    jwt_inspector = None
    try:
        import redis as _redis
        from yashigani.gateway.jwt_inspector import JWTInspector
        redis_client_jwt = _redis.from_url(f"{redis_base}/1", decode_responses=False)
        redis_client_jwt.ping()
        jwt_inspector = JWTInspector(redis_client=redis_client_jwt)
        logger.info(
            "JWT inspector ready (stream=%s)",
            os.getenv("YASHIGANI_DEPLOYMENT_STREAM", "opensource"),
        )
    except Exception as exc:
        logger.warning("JWT inspector unavailable (%s) — JWT validation disabled", exc)

    # PostgreSQL pool + inference logger + anomaly detector — Phases 1, 2
    db_pool = None
    inference_logger = None
    anomaly_detector = None
    try:
        from yashigani.db import create_pool
        from yashigani.inference import InferencePayloadLogger, AnomalyDetector

        loop = asyncio.get_event_loop()
        db_dsn = os.getenv("YASHIGANI_DB_DSN", "")
        if db_dsn:
            loop.run_until_complete(create_pool(db_dsn))
            db_pool = True  # sentinel; pool is module-level singleton

            inference_logger = InferencePayloadLogger()
            asyncio.ensure_future(inference_logger.start())

            import redis as _redis
            redis_client_anomaly = _redis.from_url(f"{redis_base}/2", decode_responses=False)
            redis_client_anomaly.ping()
            anomaly_detector = AnomalyDetector(redis_client=redis_client_anomaly)
            logger.info("DB pool + inference logger + anomaly detector ready")
        else:
            logger.warning("YASHIGANI_DB_DSN not set — Postgres features disabled")
    except Exception as exc:
        logger.warning("DB/inference init failed (%s) — Postgres features disabled", exc)

    gateway_app = create_gateway_app(
        config=cfg,
        inspection_pipeline=pipeline,
        chs=chs,
        audit_writer=audit_writer,
        rate_limiter=rate_limiter,
        rbac_store=rbac_store,
        agent_registry=agent_registry,
        jwt_inspector=jwt_inspector,
        endpoint_rate_limiter=endpoint_rate_limiter,
        response_cache=response_cache,
        fasttext_backend=fasttext_backend,
        inference_logger=inference_logger,
        anomaly_detector=anomaly_detector,
        response_inspection_pipeline=response_pipeline,
    )

    # Agent auth middleware — must run before Prometheus middleware so agent
    # requests are authenticated before metrics are emitted.
    gateway_app.add_middleware(
        AgentAuthMiddleware,
        agent_registry=agent_registry,
        audit_writer=audit_writer,
    )

    # Add Prometheus request metrics middleware
    gateway_app.add_middleware(PrometheusMiddleware, service="gateway")

    # Start background metrics collector
    collector = MetricsCollector(
        resource_monitor=resource_monitor,
        rate_limiter=rate_limiter,
        chs=chs,
        inspection_pipeline=pipeline,
        rbac_store=rbac_store,
        agent_registry=agent_registry,
        poll_interval_seconds=15,
    )
    collector.start()

    return gateway_app


app = _build_app()
