"""
Yashigani CHS — Container resource pressure monitor.
Reads cgroup v2 metrics (primary) or Docker/Podman stats API (fallback).

v0.2.0: GPU pressure added to RPI formula.
Updated 4-term RPI formula:
    RPI = 0.55 × memory_pressure + 0.20 × cpu_throttle + 0.25 × gpu_pressure

Weight justification:
  Memory (0.55) — memory exhaustion causes OOM kills, the most severe failure mode.
  GPU (0.25)    — GPU saturation causes classifier queuing / timeout; second most
                  impactful for an AI inspection workload.
  CPU (0.20)    — CPU throttle degrades latency but rarely causes total failure.

TTL tier table (with GPU pressure included):
    RPI < 0.30  → TTL ceiling (30 min default)   — Low pressure
    0.30–0.60   → TTL default (15 min default)   — Medium pressure
    0.60–0.80   → 5 min                          — High pressure
    > 0.80      → 2 min floor + critical alert   — Critical pressure
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

# cgroup v2 paths
_CGROUP_MEMORY_CURRENT = Path("/sys/fs/cgroup/memory.current")
_CGROUP_MEMORY_MAX = Path("/sys/fs/cgroup/memory.max")
_CGROUP_CPU_STAT = Path("/sys/fs/cgroup/cpu.stat")

# Pressure tier thresholds
_TIER_LOW = 0.3
_TIER_MEDIUM = 0.6
_TIER_HIGH = 0.8

# TTL constants (seconds)
TTL_FLOOR_SECONDS = 120        # 2 min — hard floor (critical pressure)
TTL_HIGH_SECONDS = 300         # 5 min — high pressure
TTL_DEFAULT_SECONDS = 900      # 15 min — medium pressure
TTL_MAX_SECONDS = 1800         # 30 min — low pressure

# TTL tier labels
_TTL_TIER_LABELS = {
    TTL_FLOOR_SECONDS: "critical",
    TTL_HIGH_SECONDS:  "high",
    TTL_DEFAULT_SECONDS: "medium",
    TTL_MAX_SECONDS: "low",
}


@dataclass
class ResourceMetrics:
    memory_pressure: float = 0.0        # 0.0–1.0
    cpu_throttle: float = 0.0           # 0.0–1.0 (renamed from cpu_throttle_ratio)
    gpu_pressure: float = 0.0           # 0.0–1.0 (v0.2.0)
    pressure_index: float = 0.0         # weighted blend (0.0–1.0)
    memory_used_bytes: int = 0
    memory_max_bytes: int = 0
    ttl_tier: str = "low"               # low | medium | high | critical
    source: str = "unavailable"         # cgroup_v2 | docker_api | unavailable
    gpu_backend: str = "unavailable"    # nvml | rocm_sysfs | ollama_api | unavailable
    sampled_at: Optional[datetime] = field(default=None)


class ResourceMonitor:
    """
    Polls container resource metrics at a configurable interval and
    exposes the current Resource Pressure Index.

    GPU monitoring is attempted automatically via GPUMonitor.
    Falls back gracefully when no GPU is present.
    """

    def __init__(
        self,
        poll_interval_seconds: int = 30,
        ttl_ceiling_seconds: int = TTL_MAX_SECONDS,
        ttl_default_seconds: int = TTL_DEFAULT_SECONDS,
        ollama_base_url: Optional[str] = None,
        on_critical: Optional[Callable[..., Any]] = None,
    ) -> None:
        self._poll_interval = poll_interval_seconds
        self._ttl_ceiling = ttl_ceiling_seconds
        self._ttl_default = ttl_default_seconds
        self._ollama_base_url = ollama_base_url
        self._on_critical = on_critical or (lambda m: None)
        self._metrics = ResourceMetrics()
        self._lock = threading.RLock()
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    # -- Lifecycle -----------------------------------------------------------

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._poll_loop, daemon=True, name="chs-resource-monitor"
        )
        self._thread.start()
        logger.info("Resource monitor started (interval=%ds)", self._poll_interval)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Resource monitor stopped")

    # -- Public API ----------------------------------------------------------

    def get_metrics(self) -> ResourceMetrics:
        """Return the most recently sampled ResourceMetrics snapshot."""
        with self._lock:
            return self._metrics

    @property
    def metrics(self) -> ResourceMetrics:
        return self.get_metrics()

    @property
    def current_ttl_seconds(self) -> int:
        idx = self.get_metrics().pressure_index
        if idx > _TIER_HIGH:
            return TTL_FLOOR_SECONDS
        if idx > _TIER_MEDIUM:
            return TTL_HIGH_SECONDS
        if idx > _TIER_LOW:
            return self._ttl_default
        return self._ttl_ceiling

    def update_config(
        self,
        ttl_ceiling_seconds: Optional[int] = None,
        ttl_default_seconds: Optional[int] = None,
        poll_interval_seconds: Optional[int] = None,
    ) -> None:
        """Hot-update config without restarting the monitor."""
        with self._lock:
            if ttl_ceiling_seconds is not None:
                self._ttl_ceiling = ttl_ceiling_seconds
            if ttl_default_seconds is not None:
                self._ttl_default = ttl_default_seconds
            if poll_interval_seconds is not None:
                self._poll_interval = poll_interval_seconds

    # -- Internal ------------------------------------------------------------

    def _poll_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                metrics = self._read_metrics()
                with self._lock:
                    prev_critical = self._metrics.pressure_index > _TIER_HIGH
                    self._metrics = metrics
                if metrics.pressure_index > _TIER_HIGH and not prev_critical:
                    self._on_critical(metrics)
            except Exception as exc:
                logger.warning("Resource monitor poll error: %s", exc)
            self._stop_event.wait(timeout=self._poll_interval)

    def _read_metrics(self) -> ResourceMetrics:
        # GPU — attempt regardless of CPU/memory source
        from yashigani.chs.gpu_monitor import read_gpu_metrics
        gpu = read_gpu_metrics(ollama_base_url=self._ollama_base_url)
        gpu_pressure = (
            0.6 * gpu.gpu_utilisation + 0.4 * gpu.gpu_memory_pressure
            if gpu.available else 0.0
        )

        # CPU + memory — cgroup v2 preferred
        if _CGROUP_MEMORY_CURRENT.exists() and _CGROUP_MEMORY_MAX.exists():
            base = self._read_cgroup_v2()
        else:
            try:
                base = self._read_docker_stats()
            except Exception:
                base = ResourceMetrics(source="unavailable")

        # Updated 4-term RPI formula (v0.2.0)
        index = min(1.0,
            0.55 * base.memory_pressure +
            0.20 * base.cpu_throttle +
            0.25 * gpu_pressure
        )

        ttl_secs = self.current_ttl_seconds
        tier = _TTL_TIER_LABELS.get(ttl_secs, "low")

        return ResourceMetrics(
            memory_pressure=base.memory_pressure,
            cpu_throttle=base.cpu_throttle,
            gpu_pressure=gpu_pressure,
            pressure_index=index,
            memory_used_bytes=base.memory_used_bytes,
            memory_max_bytes=base.memory_max_bytes,
            ttl_tier=tier,
            source=base.source,
            gpu_backend=gpu.backend,
            sampled_at=datetime.now(tz=timezone.utc),
        )

    def _read_cgroup_v2(self) -> ResourceMetrics:
        mem_current = int(_CGROUP_MEMORY_CURRENT.read_text(encoding="utf-8").strip())
        mem_max_raw = _CGROUP_MEMORY_MAX.read_text(encoding="utf-8").strip()

        if mem_max_raw == "max":
            mem_max = 0
            memory_pressure = 0.0
        else:
            mem_max = int(mem_max_raw)
            memory_pressure = min(1.0, mem_current / mem_max) if mem_max > 0 else 0.0

        cpu_throttle = 0.0
        if _CGROUP_CPU_STAT.exists():
            cpu_stat = _parse_cpu_stat(_CGROUP_CPU_STAT.read_text(encoding="utf-8"))
            throttled = cpu_stat.get("throttled_usec", 0)
            usage = cpu_stat.get("usage_usec", 0)
            total = throttled + usage
            cpu_throttle = (throttled / total) if total > 0 else 0.0

        return ResourceMetrics(
            memory_pressure=memory_pressure,
            cpu_throttle=cpu_throttle,
            memory_used_bytes=mem_current,
            memory_max_bytes=mem_max,
            source="cgroup_v2",
        )

    def _read_docker_stats(self) -> ResourceMetrics:
        import os
        container_id = os.environ.get("HOSTNAME", "")
        if not container_id:
            raise RuntimeError("No HOSTNAME env var — cannot query Docker stats")

        try:
            import requests  # type: ignore[import-untyped]
            resp = requests.get(
                f"http://localhost/containers/{container_id}/stats",
                params={"stream": "false"},
                timeout=5,
            )
            data = resp.json()
        except Exception:
            raise RuntimeError("Docker stats API unavailable")

        mem = data.get("memory_stats", {})
        mem_usage = mem.get("usage", 0)
        mem_limit = mem.get("limit", 0)
        memory_pressure = (mem_usage / mem_limit) if mem_limit > 0 else 0.0

        cpu = data.get("cpu_stats", {})
        pre_cpu = data.get("precpu_stats", {})
        cpu_delta = (
            cpu.get("cpu_usage", {}).get("total_usage", 0) -
            pre_cpu.get("cpu_usage", {}).get("total_usage", 0)
        )
        sys_delta = cpu.get("system_cpu_usage", 0) - pre_cpu.get("system_cpu_usage", 0)
        cpu_throttle = (cpu_delta / sys_delta) if sys_delta > 0 else 0.0

        return ResourceMetrics(
            memory_pressure=memory_pressure,
            cpu_throttle=cpu_throttle,
            memory_used_bytes=mem_usage,
            memory_max_bytes=mem_limit,
            source="docker_api",
        )


def _parse_cpu_stat(text: str) -> dict[str, int]:
    result = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2:
            try:
                result[parts[0]] = int(parts[1])
            except ValueError:
                pass
    return result
