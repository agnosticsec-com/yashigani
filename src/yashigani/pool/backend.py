"""
Yashigani Pool Manager — Container backend abstraction.

Provides a unified interface for container lifecycle operations
across Docker SDK and Podman SDK. Falls back gracefully:
  1. Docker SDK (docker-py) — if Docker daemon is available
  2. Podman SDK (podman-py) — if Podman socket is available
  3. Stub mode — in-memory tracking only (no real isolation)

Security: container-per-identity isolation is a CIAA compliance
requirement. Stub mode should only be used in tests.
"""
from __future__ import annotations

import logging
from typing import Optional, Protocol

logger = logging.getLogger(__name__)


class ContainerHandle:
    """Wrapper around a container object from either Docker or Podman SDK."""

    def __init__(self, raw, backend_name: str):
        self._raw = raw
        self._backend = backend_name

    @property
    def id(self) -> str:
        return self._raw.id

    @property
    def attrs(self) -> dict:
        if self._backend == "podman":
            # podman-py uses inspect() to get full attrs
            try:
                return self._raw.inspect()
            except Exception:
                return getattr(self._raw, "attrs", {})
        return getattr(self._raw, "attrs", {})

    def reload(self) -> None:
        self._raw.reload()

    def logs(self, tail: int = 500) -> bytes:
        return self._raw.logs(tail=tail)

    def diff(self) -> list[dict]:
        try:
            return self._raw.diff()
        except Exception:
            return []

    def kill(self) -> None:
        self._raw.kill()

    def remove(self, force: bool = False) -> None:
        self._raw.remove(force=force)

    def get_network_ip(self, network_name: str) -> str:
        """Extract the container's IP on a given network."""
        self.reload()
        if self._backend == "podman":
            # Podman network info is in a different structure
            try:
                inspect = self._raw.inspect()
                networks = inspect.get("NetworkSettings", {}).get("Networks", {})
                if network_name in networks:
                    return networks[network_name].get("IPAddress", "127.0.0.1")
                # Podman may use different network naming
                for net_name, net_info in networks.items():
                    ip = net_info.get("IPAddress", "")
                    if ip:
                        return ip
            except Exception:
                pass
            return "127.0.0.1"
        else:
            networks = self.attrs.get("NetworkSettings", {}).get("Networks", {})
            if network_name in networks:
                return networks[network_name].get("IPAddress", "127.0.0.1")
            return "127.0.0.1"


class ContainerBackend:
    """Unified container backend for Docker and Podman."""

    def __init__(self, client, backend_name: str):
        self._client = client
        self.name = backend_name

    def run(
        self,
        image: str,
        name: str,
        environment: dict,
        network: str,
        labels: dict,
        detach: bool = True,
    ) -> ContainerHandle:
        """Create and start a container."""
        if self.name == "podman":
            container = self._client.containers.run(
                image=image,
                name=name,
                environment=environment,
                detach=detach,
                remove=False,
                labels=labels,
            )
            # Podman: connect to network after creation
            try:
                net = self._client.networks.get(network)
                net.connect(container)
            except Exception as exc:
                logger.warning("Podman: failed to connect %s to network %s: %s", name, network, exc)
            return ContainerHandle(container, self.name)
        else:
            container = self._client.containers.run(
                image=image,
                name=name,
                environment=environment,
                network=network,
                detach=detach,
                remove=False,
                labels=labels,
            )
            return ContainerHandle(container, self.name)

    def get(self, container_id: str) -> ContainerHandle:
        """Get an existing container by ID."""
        return ContainerHandle(
            self._client.containers.get(container_id),
            self.name,
        )

    def ping(self) -> bool:
        """Check if the backend is reachable."""
        try:
            self._client.ping()
            return True
        except Exception:
            return False


def create_backend() -> Optional[ContainerBackend]:
    """
    Auto-detect and create the best available container backend.

    Returns None if no backend is available (stub mode).
    """
    # Try Docker SDK first
    try:
        import docker
        client = docker.from_env()
        client.ping()
        logger.info("Pool Manager: Docker SDK connected")
        return ContainerBackend(client, "docker")
    except Exception:
        pass

    # Try Podman SDK
    try:
        from podman import PodmanClient
        client = PodmanClient()
        client.ping()
        logger.info("Pool Manager: Podman SDK connected")
        return ContainerBackend(client, "podman")
    except Exception:
        pass

    # Try Podman via explicit socket paths (including mounted socket from compose)
    for sock in [
        "unix:///var/run/container.sock",  # Mounted by docker-compose.yml
        f"unix:///run/user/{_get_uid()}/podman/podman.sock",
        "unix:///run/podman/podman.sock",
        "unix:///var/run/podman/podman.sock",
        "unix:///var/run/docker.sock",  # Docker socket fallback
    ]:
        try:
            from podman import PodmanClient
            client = PodmanClient(base_url=sock)
            client.ping()
            logger.info("Pool Manager: Podman SDK connected via %s", sock)
            return ContainerBackend(client, "podman")
        except Exception:
            continue

    logger.warning("Pool Manager: no Docker or Podman SDK available — stub mode")
    return None


def _get_uid() -> int:
    """Get current user ID for Podman rootless socket path."""
    import os
    return os.getuid()
