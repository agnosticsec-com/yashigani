"""
Yashigani Metrics — Background Prometheus metric collectors.

Polls internal service state at a configurable interval and updates
Gauge metrics. Runs as a daemon thread — safe to start and forget.

Usage:
    collector = MetricsCollector(
        resource_monitor=monitor,
        rate_limiter=limiter,
        chs=chs_service,
        rotation_scheduler=scheduler,
        backend_registry=backend_registry,
    )
    collector.start()
"""
from __future__ import annotations

import logging
import threading
import time
from typing import Optional

logger = logging.getLogger(__name__)


class MetricsCollector:
    """
    Polls all internal services and updates Prometheus Gauge metrics.
    Counter metrics are updated inline (at the point of event) — only
    Gauges need polling since they represent current state.
    """

    def __init__(
        self,
        resource_monitor=None,
        rate_limiter=None,
        chs=None,
        rotation_scheduler=None,
        inspection_pipeline=None,
        rbac_store=None,
        agent_registry=None,
        backend_registry=None,
        poll_interval_seconds: int = 15,
    ) -> None:
        self._monitor = resource_monitor
        self._limiter = rate_limiter
        self._chs = chs
        self._scheduler = rotation_scheduler
        self._pipeline = inspection_pipeline
        self._rbac_store = rbac_store
        self._agent_registry = agent_registry
        self._backend_registry = backend_registry
        self._interval = poll_interval_seconds
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="metrics-collector"
        )
        self._thread.start()
        logger.info("Metrics collector started (interval=%ds)", self._interval)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    # -- Poll loop -----------------------------------------------------------

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._collect()
            except Exception as exc:
                logger.warning("Metrics collection error: %s", exc)
            self._stop.wait(timeout=self._interval)

    def _collect(self) -> None:
        from yashigani.metrics.registry import (
            resource_pressure_index,
            resource_memory_pressure,
            resource_cpu_throttle,
            resource_gpu_pressure,
            resource_gpu_utilisation,
            resource_gpu_memory_pressure,
            resource_memory_used_bytes,
            chs_handles_active,
            chs_current_ttl_seconds,
            ratelimit_multiplier,
            ratelimit_effective_rps,
            ratelimit_config_last_updated_timestamp,
            inspection_threshold,
            inspection_model,
        )

        # ── Resource monitor ────────────────────────────────────────────────
        if self._monitor is not None:
            try:
                m = self._monitor.get_metrics()
                resource_pressure_index.set(m.pressure_index)
                resource_memory_pressure.set(m.memory_pressure)
                resource_cpu_throttle.set(m.cpu_throttle)
                resource_gpu_pressure.set(m.gpu_pressure)
                resource_memory_used_bytes.set(m.memory_used_bytes)
                chs_current_ttl_seconds.set(self._monitor.current_ttl_seconds)
            except Exception as exc:
                logger.debug("Resource monitor metrics error: %s", exc)

        # ── GPU per-device ───────────────────────────────────────────────────
        if self._monitor is not None:
            try:
                from yashigani.chs.gpu_monitor import read_gpu_metrics
                gpu = read_gpu_metrics(
                    ollama_base_url=getattr(self._monitor, "_ollama_base_url", None)
                )
                for dev in gpu.devices:
                    idx = str(dev.get("index", 0))
                    name = dev.get("name", "unknown")
                    backend = gpu.backend
                    resource_gpu_utilisation.labels(
                        device_index=idx, device_name=name, backend=backend
                    ).set(dev.get("gpu_utilisation", 0.0))
                    resource_gpu_memory_pressure.labels(
                        device_index=idx, device_name=name, backend=backend
                    ).set(dev.get("memory_pressure", 0.0))
            except Exception as exc:
                logger.debug("GPU per-device metrics error: %s", exc)

        # ── CHS handles ─────────────────────────────────────────────────────
        if self._chs is not None:
            try:
                active = len([
                    h for h in self._chs._handles.values()
                    if not h.get("revoked") and h.get("expires_at", 0) > time.time()
                ])
                chs_handles_active.set(active)
            except Exception as exc:
                logger.debug("CHS handle metrics error: %s", exc)

        # ── Rate limiter ─────────────────────────────────────────────────────
        if self._limiter is not None:
            try:
                mult = self._limiter.current_rpi_multiplier()
                ratelimit_multiplier.set(mult)
                cfg = self._limiter.current_config()
                ratelimit_effective_rps.labels(dimension="global").set(cfg.global_rps * mult)
                ratelimit_effective_rps.labels(dimension="ip").set(cfg.per_ip_rps * mult)
                ratelimit_effective_rps.labels(dimension="agent").set(cfg.per_agent_rps * mult)
                ratelimit_effective_rps.labels(dimension="session").set(cfg.per_session_rps * mult)
                updated_at = getattr(cfg, "updated_at", None)
                if updated_at is not None:
                    ratelimit_config_last_updated_timestamp.set(updated_at)
            except Exception as exc:
                logger.debug("Rate limiter metrics error: %s", exc)

        # ── Inspection pipeline ──────────────────────────────────────────────
        if self._pipeline is not None:
            try:
                inspection_threshold.set(self._pipeline._threshold)
                model_name = self._pipeline._classifier._model
                # Use info pattern: set gauge to 1 with model label
                inspection_model.labels(model=model_name).set(1)
            except Exception as exc:
                logger.debug("Inspection pipeline metrics error: %s", exc)

        # ── Backend registry — active backend info metric ────────────────────
        if self._backend_registry is not None:
            try:
                from yashigani.metrics.registry import inspection_active_backend
                active = self._backend_registry.get_active_backend_name()
                inspection_active_backend.labels(backend=active).set(1)
            except Exception as exc:
                logger.debug("Backend registry metrics error: %s", exc)

        # ── RBAC store ───────────────────────────────────────────────────────
        if self._rbac_store is not None:
            try:
                from yashigani.metrics.registry import rbac_groups_total
                rbac_groups_total.set(len(self._rbac_store.list_groups()))
            except Exception as exc:
                logger.debug("RBAC store metrics error: %s", exc)

        # ── Agent registry ───────────────────────────────────────────────────
        if self._agent_registry is not None:
            try:
                from yashigani.metrics.registry import agent_registry_size
                agent_registry_size.labels(status="active").set(
                    self._agent_registry.count("active")
                )
                agent_registry_size.labels(status="inactive").set(
                    self._agent_registry.count("inactive")
                )
            except Exception as exc:
                logger.debug("Agent registry metrics error: %s", exc)
