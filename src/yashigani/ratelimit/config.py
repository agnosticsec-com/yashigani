"""
Yashigani Rate Limit — Configuration dataclass.
All limits are admin-configurable at runtime via the backoffice API.
Defaults are conservative enough for a single-node deployment.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class RateLimitConfig:
    """
    Token bucket rate limit configuration.

    Each dimension has an rps (refill rate) and burst (bucket capacity).
    Effective limit = configured_rps × rpi_multiplier(current_pressure_index).

    RPI adaptive multipliers:
        index < 0.30  → ×1.00  (no reduction)
        0.30–0.60     → ×0.80  (−20%)
        0.60–0.80     → ×0.50  (−50%)
        > 0.80        → ×0.25  (−75%, critical pressure)
    """
    enabled: bool = True
    adaptive_enabled: bool = True

    # ── Global ───────────────────────────────────────────────────────────────
    # Applied to the total request rate across all clients
    global_rps: float = 1000.0
    global_burst: int = 200

    # ── Per source IP ────────────────────────────────────────────────────────
    per_ip_rps: float = 50.0
    per_ip_burst: int = 20

    # ── Per agent ID (X-Yashigani-Agent-Id header) ───────────────────────────
    per_agent_rps: float = 100.0
    per_agent_burst: int = 30

    # ── Per session token (hashed) ───────────────────────────────────────────
    per_session_rps: float = 20.0
    per_session_burst: int = 10

    # ── Adaptive RPI multiplier thresholds ───────────────────────────────────
    rpi_scale_medium: float = 0.80    # RPI 0.30–0.60
    rpi_scale_high: float = 0.50      # RPI 0.60–0.80
    rpi_scale_critical: float = 0.25  # RPI > 0.80

    # ── Redis key TTL for token bucket state (seconds) ───────────────────────
    bucket_ttl_seconds: int = 3600

    # ── Metadata ─────────────────────────────────────────────────────────────
    updated_at: float = field(default_factory=time.time)
