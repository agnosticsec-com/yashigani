"""
Sliding-window repeated small-call anomaly detector.

Uses Redis ZSET keyed by (tenant_id, session_id) to count calls within a
configurable time window. If N calls with payload size < threshold_bytes
are observed within window_seconds, emits an ANOMALY_REPEATED_SMALL_CALLS
event and increments the Prometheus counter.

Redis is the correct store for this: ephemeral, fast, no durability needed.
Postgres anomaly_thresholds table is the authoritative config (per-tenant).
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Default thresholds (used when Redis or DB lookup fails)
DEFAULT_WINDOW_SECONDS = 60
DEFAULT_CALL_COUNT_N = 10
DEFAULT_PAYLOAD_THRESHOLD_BYTES = 256


@dataclass
class AnomalyConfig:
    window_seconds: int = DEFAULT_WINDOW_SECONDS
    call_count_n: int = DEFAULT_CALL_COUNT_N
    payload_threshold_bytes: int = DEFAULT_PAYLOAD_THRESHOLD_BYTES


@dataclass
class AnomalyResult:
    anomaly_detected: bool
    call_count: int
    window_seconds: int
    threshold: int


class AnomalyDetector:
    """
    Call detect() on every incoming inference request.
    Pass the Redis client for sliding window state.
    """

    def __init__(
        self,
        redis_client,
        default_config: AnomalyConfig | None = None,
    ) -> None:
        self._redis = redis_client
        self._default_config = default_config or AnomalyConfig()

    def detect(
        self,
        tenant_id: str,
        session_id: str,
        payload_size_bytes: int,
        config: AnomalyConfig | None = None,
    ) -> AnomalyResult:
        """
        Synchronous detection for use in the gateway request path.
        Returns AnomalyResult. Never raises — errors are logged.
        """
        cfg = config or self._default_config
        try:
            return self._check(tenant_id, session_id, payload_size_bytes, cfg)
        except Exception as exc:
            logger.error("AnomalyDetector error: %s", exc)
            return AnomalyResult(
                anomaly_detected=False,
                call_count=0,
                window_seconds=cfg.window_seconds,
                threshold=cfg.call_count_n,
            )

    def _check(
        self,
        tenant_id: str,
        session_id: str,
        payload_size_bytes: int,
        cfg: AnomalyConfig,
    ) -> AnomalyResult:
        if payload_size_bytes >= cfg.payload_threshold_bytes:
            # Large payload — not a small call, skip
            return AnomalyResult(
                anomaly_detected=False,
                call_count=0,
                window_seconds=cfg.window_seconds,
                threshold=cfg.call_count_n,
            )

        key = f"anomaly:{tenant_id}:{session_id}"
        now = time.time()
        window_start = now - cfg.window_seconds

        pipe = self._redis.pipeline()
        # Add current call with timestamp as score
        pipe.zadd(key, {str(now): now})
        # Remove entries older than window
        pipe.zremrangebyscore(key, "-inf", window_start)
        # Count entries in window
        pipe.zcard(key)
        # Expire key after window to avoid Redis bloat
        pipe.expire(key, cfg.window_seconds * 2)
        results = pipe.execute()
        call_count = results[2]

        anomaly = call_count >= cfg.call_count_n
        if anomaly:
            try:
                from yashigani.metrics.registry import repeated_small_calls_total
                repeated_small_calls_total.labels(tenant_id=tenant_id).inc()
            except Exception:
                pass
            logger.warning(
                "ANOMALY_REPEATED_SMALL_CALLS: tenant=%s session=%s count=%d/%d window=%ds",
                tenant_id, session_id, call_count, cfg.call_count_n, cfg.window_seconds,
            )

        return AnomalyResult(
            anomaly_detected=anomaly,
            call_count=call_count,
            window_seconds=cfg.window_seconds,
            threshold=cfg.call_count_n,
        )
