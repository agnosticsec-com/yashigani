"""
Yashigani Pool Manager — Universal container lifecycle management.

Manages per-identity service containers, Ollama scaling, and self-healing
for all core services. Every identity gets a dedicated container for every
service it invokes — no shared instances.

Modules:
  pool.manager     -- Container creation, routing, health, teardown
  pool.health      -- Health monitoring and self-healing
  pool.postmortem  -- Forensic evidence collection from dead containers
"""

from yashigani.pool.manager import PoolManager, ContainerInfo

__all__ = ["PoolManager", "ContainerInfo"]
