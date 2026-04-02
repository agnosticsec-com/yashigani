"""
Yashigani Pool Manager — Background health monitor.

Runs as a daemon thread in the gateway. Periodically:
  1. Checks health of all managed containers
  2. Replaces unhealthy containers (postmortem + new instance)
  3. Tears down idle containers past timeout
  4. Reports metrics to Prometheus
"""
from __future__ import annotations

import logging
import threading
import time

logger = logging.getLogger(__name__)

_DEFAULT_CHECK_INTERVAL = 30  # seconds
_DEFAULT_IDLE_TIMEOUT = 1800  # 30 minutes


class PoolHealthMonitor:
    """
    Background thread that monitors Pool Manager containers.

    Start with .start(), stop with .stop().
    Thread-safe — uses the Pool Manager's internal lock.
    """

    def __init__(
        self,
        pool_manager,
        check_interval: int = _DEFAULT_CHECK_INTERVAL,
        idle_timeout: int = _DEFAULT_IDLE_TIMEOUT,
    ) -> None:
        self._pool = pool_manager
        self._interval = check_interval
        self._idle_timeout = idle_timeout
        self._running = False
        self._thread: threading.Thread | None = None
        logger.info(
            "PoolHealthMonitor: interval=%ds, idle_timeout=%ds",
            check_interval, idle_timeout,
        )

    def start(self) -> None:
        """Start the background health monitor."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(
            target=self._run,
            name="pool-health-monitor",
            daemon=True,
        )
        self._thread.start()
        logger.info("PoolHealthMonitor: started")

    def stop(self) -> None:
        """Stop the background health monitor."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=self._interval + 5)
        logger.info("PoolHealthMonitor: stopped")

    def _run(self) -> None:
        """Main loop — runs in daemon thread."""
        while self._running:
            try:
                self._check_cycle()
            except Exception as exc:
                logger.error("PoolHealthMonitor: check cycle failed: %s", exc)
            time.sleep(self._interval)

    def _check_cycle(self) -> None:
        """One health check cycle."""
        containers = self._pool.list_all()
        if not containers:
            return

        now = time.time()
        replaced = 0
        torn_down = 0

        for info in containers:
            # Check idle timeout
            if (now - info.last_active) > self._idle_timeout:
                self._pool.teardown(info.identity_id, info.service_slug, "idle_timeout")
                torn_down += 1
                continue

            # Check health (only if we have a Docker client)
            if self._pool._docker:
                try:
                    container = self._pool._docker.containers.get(info.container_id)
                    health = container.attrs.get("State", {}).get("Health", {}).get("Status", "none")
                    if health == "unhealthy":
                        self._pool.mark_unhealthy(info.identity_id, info.service_slug)
                        if info.health_failures >= 3:
                            self._pool.replace(info.identity_id, info.service_slug, "unhealthy")
                            replaced += 1
                    elif health == "healthy":
                        self._pool.mark_healthy(info.identity_id, info.service_slug)
                except Exception as exc:
                    logger.warning(
                        "PoolHealthMonitor: failed to check %s: %s",
                        info.container_name, exc,
                    )
                    self._pool.mark_unhealthy(info.identity_id, info.service_slug)

        if replaced or torn_down:
            logger.info(
                "PoolHealthMonitor: cycle complete — %d replaced, %d torn down, %d active",
                replaced, torn_down, len(self._pool.list_all()),
            )
