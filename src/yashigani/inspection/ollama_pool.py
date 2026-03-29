"""
Yashigani Inspection — Ollama pool for StatefulSet failover.

Maintains a list of Ollama replica endpoints and distributes classify()
calls via round-robin. Automatically removes unhealthy members and
re-adds them after recovery (liveness_check_interval seconds).

In K8s: endpoints are the per-pod DNS names from the headless Service:
  ollama-0.ollama-headless.yashigani.svc.cluster.local:11434
  ollama-1.ollama-headless.yashigani.svc.cluster.local:11434
"""
from __future__ import annotations
import itertools
import logging
import os
import threading
import time
import urllib.request
import urllib.error
from typing import Optional

from yashigani.inspection.backend_base import ClassifierBackend, ClassifierResult, BackendUnavailableError
from yashigani.inspection.backends.ollama import OllamaBackend

logger = logging.getLogger(__name__)

_GPU_UNAVAILABLE_SIGNAL = threading.Event()


class OllamaPool(ClassifierBackend):
    """
    Round-robin pool across multiple Ollama replicas.

    Emits GPU_UNAVAILABLE signal when all active pool members are CPU-only.
    The BackendRegistry reads this signal and applies the configured gpu_failover_policy.
    """
    name = "ollama_pool"

    def __init__(
        self,
        endpoints: list[str],
        model: str = "qwen2.5:3b",
        liveness_check_interval: int = 30,
    ) -> None:
        self._all_endpoints = list(endpoints)
        self._model = model
        self._liveness_interval = liveness_check_interval
        self._lock = threading.Lock()
        self._active: list[OllamaBackend] = [
            OllamaBackend(base_url=ep, model=model) for ep in endpoints
        ]
        self._inactive: list[tuple[OllamaBackend, float]] = []  # (backend, removed_at)
        self._cycle = itertools.cycle(self._active)
        self._stop = threading.Event()
        self._health_thread = threading.Thread(
            target=self._health_loop, daemon=True, name="ollama-pool-health"
        )
        self._health_thread.start()

    @classmethod
    def from_env(cls) -> "OllamaPool":
        """
        Build pool from environment variables.
        OLLAMA_POOL_ENDPOINTS: comma-separated URLs (e.g. http://ollama-0:11434,http://ollama-1:11434)
        Falls back to single OLLAMA_BASE_URL if OLLAMA_POOL_ENDPOINTS not set.
        """
        pool_env = os.getenv("OLLAMA_POOL_ENDPOINTS", "")
        if pool_env:
            endpoints = [ep.strip() for ep in pool_env.split(",") if ep.strip()]
        else:
            endpoints = [os.getenv("OLLAMA_BASE_URL", "http://ollama:11434")]
        model = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")
        return cls(endpoints=endpoints, model=model)

    def classify(self, content: str) -> ClassifierResult:
        with self._lock:
            if not self._active:
                raise BackendUnavailableError("All Ollama pool members are unhealthy")
            backend = next(self._cycle)
        try:
            return backend.classify(content)
        except BackendUnavailableError:
            self._mark_inactive(backend)
            # Try next member
            return self.classify(content)

    def health_check(self) -> bool:
        with self._lock:
            return len(self._active) > 0

    def _mark_inactive(self, backend: OllamaBackend) -> None:
        with self._lock:
            if backend in self._active:
                self._active.remove(backend)
                self._inactive.append((backend, time.time()))
                self._cycle = itertools.cycle(self._active) if self._active else iter([])
                logger.warning(
                    "Ollama pool member removed: %s (active=%d)",
                    backend._base_url, len(self._active),
                )
                if not self._active:
                    _GPU_UNAVAILABLE_SIGNAL.set()
                    logger.error("All Ollama pool members offline — GPU_UNAVAILABLE signal emitted")

    def _health_loop(self) -> None:
        while not self._stop.is_set():
            self._stop.wait(timeout=self._liveness_interval)
            self._check_inactive_members()

    def _check_inactive_members(self) -> None:
        recovered = []
        with self._lock:
            for backend, removed_at in list(self._inactive):
                if backend.health_check():
                    recovered.append((backend, removed_at))

        if recovered:
            with self._lock:
                for backend, _ in recovered:
                    self._inactive = [(b, t) for b, t in self._inactive if b is not backend]
                    self._active.append(backend)
                    self._cycle = itertools.cycle(self._active)
                    logger.info(
                        "Ollama pool member recovered: %s (active=%d)",
                        backend._base_url, len(self._active),
                    )
                if self._active and _GPU_UNAVAILABLE_SIGNAL.is_set():
                    _GPU_UNAVAILABLE_SIGNAL.clear()
                    logger.info("GPU_UNAVAILABLE signal cleared — pool has active members")

    def stop(self) -> None:
        self._stop.set()
