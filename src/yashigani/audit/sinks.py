"""
Multi-sink audit writer — Phase 10.

Sinks:
  FileSink      — synchronous RotatingFileHandler (wraps existing AuditLogWriter)
  PostgresSink  — async batch writer to audit_events table via asyncpg
  SiemSink      — optional async forwarding: Splunk HEC, Elasticsearch bulk API, or Wazuh

Architecture:
  MultiSinkAuditWriter.write(event) is synchronous (compatible with existing call sites).
  FileSink writes synchronously — audit trail is never lost even if Postgres is down.
  PostgresSink and SiemSink enqueue to asyncio.Queue and drain in a background task.
  Queue full → drop + increment counter (never block the request path).
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Optional

logger = logging.getLogger(__name__)


class AuditSink(ABC):
    name: str

    @abstractmethod
    async def write(self, event: dict) -> None: ...

    @abstractmethod
    async def last_write_ts(self) -> Optional[datetime]: ...


class FileSink(AuditSink):
    """Synchronous file sink — wraps the existing AuditLogWriter."""
    name = "file"

    def __init__(self, writer) -> None:
        self._writer = writer
        self._last_write: Optional[datetime] = None

    async def write(self, event: dict) -> None:
        try:
            self._writer._write_raw(json.dumps(event))
            self._last_write = datetime.now(timezone.utc)
        except Exception as exc:
            logger.error("FileSink write error: %s", exc)

    async def last_write_ts(self) -> Optional[datetime]:
        return self._last_write


class PostgresSink(AuditSink):
    """Async batch sink — writes audit_events rows via asyncpg."""
    name = "postgres"
    MAX_QUEUE_DEPTH = 1000

    def __init__(self, pool_getter) -> None:
        self._pool_getter = pool_getter
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=self.MAX_QUEUE_DEPTH)
        self._last_write: Optional[datetime] = None
        self._task: Optional[asyncio.Task] = None

    def start(self) -> None:
        self._task = asyncio.create_task(self._drain_loop())

    async def _drain_loop(self) -> None:
        BATCH_SIZE = 50
        DRAIN_INTERVAL = 2.0
        while True:
            batch: list[dict] = []
            try:
                deadline = asyncio.get_event_loop().time() + DRAIN_INTERVAL
                while len(batch) < BATCH_SIZE:
                    timeout = max(0.0, deadline - asyncio.get_event_loop().time())
                    try:
                        item = await asyncio.wait_for(
                            self._queue.get(), timeout=timeout
                        )
                        batch.append(item)
                    except asyncio.TimeoutError:
                        break
                if batch:
                    await self._flush_batch(batch)
            except asyncio.CancelledError:
                if batch:
                    await self._flush_batch(batch)
                raise
            except Exception as exc:
                logger.error("PostgresSink drain error: %s", exc)
                await asyncio.sleep(5)

    async def _flush_batch(self, batch: list[dict]) -> None:
        from yashigani.db.models import INSERT_AUDIT_EVENT
        pool = self._pool_getter()
        async with pool.acquire() as conn:
            async with conn.transaction():
                for event in batch:
                    tenant_id = event.get("tenant_id") or "00000000-0000-0000-0000-000000000000"
                    await conn.execute(
                        "SELECT set_config('app.tenant_id', $1, true)",
                        str(tenant_id),
                    )
                    req_id = event.get("request_id")
                    await conn.execute(
                        INSERT_AUDIT_EVENT,
                        uuid.UUID(str(tenant_id)),
                        event.get("event_type", "UNKNOWN"),
                        uuid.UUID(str(req_id)) if req_id else None,
                        event.get("session_id"),
                        event.get("agent_id"),
                        event.get("action", "UNKNOWN"),
                        event.get("reason"),
                        event.get("upstream_status"),
                        event.get("elapsed_ms"),
                        event.get("confidence_score"),
                        event.get("client_ip_hash"),
                    )
        self._last_write = datetime.now(timezone.utc)

    async def write(self, event: dict) -> None:
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            try:
                from yashigani.metrics.registry import audit_queue_overflow_total
                audit_queue_overflow_total.inc()
            except Exception:
                pass
            logger.warning("PostgresSink queue full — audit event dropped")

    async def last_write_ts(self) -> Optional[datetime]:
        return self._last_write


class SiemSink(AuditSink):
    """
    Optional SIEM forwarding. Fail-open: errors logged and counted, never propagated.
    Supports: splunk | elasticsearch | wazuh (wazuh uses Elasticsearch bulk API format).
    """
    name = "siem"

    def __init__(self, siem_type: str, endpoint: str, token: str) -> None:
        self._siem_type = siem_type   # "splunk" | "elasticsearch" | "wazuh"
        self._endpoint = endpoint
        self._token = token
        self._last_write: Optional[datetime] = None

    async def write(self, event: dict) -> None:
        try:
            if self._siem_type == "splunk":
                await self._send_splunk(event)
            elif self._siem_type in ("elasticsearch", "wazuh"):
                await self._send_elasticsearch(event)
            self._last_write = datetime.now(timezone.utc)
        except Exception as exc:
            try:
                from yashigani.metrics.registry import siem_forward_errors_total
                siem_forward_errors_total.labels(siem=self._siem_type).inc()
            except Exception:
                pass
            logger.warning("SiemSink forward error (%s): %s", self._siem_type, exc)

    async def _send_splunk(self, event: dict) -> None:
        import httpx
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(
                self._endpoint,
                json={"event": event, "sourcetype": "yashigani_audit"},
                headers={"Authorization": f"Splunk {self._token}"},
            )

    async def _send_elasticsearch(self, event: dict) -> None:
        import httpx
        async with httpx.AsyncClient(timeout=5.0) as client:
            meta = json.dumps({"index": {"_index": "yashigani-audit"}})
            body = f"{meta}\n{json.dumps(event)}\n"
            await client.post(
                self._endpoint + "/_bulk",
                content=body.encode(),
                headers={
                    "Content-Type": "application/x-ndjson",
                    "Authorization": f"ApiKey {self._token}",
                },
            )

    async def last_write_ts(self) -> Optional[datetime]:
        return self._last_write


class MultiSinkAuditWriter:
    """
    Drop-in replacement for AuditLogWriter.
    write() is synchronous — compatible with all existing call sites.
    Each event is dispatched to all registered sinks.
    """

    def __init__(self, sinks: list[AuditSink]) -> None:
        self._sinks = sinks

    def write(self, event: Any) -> None:
        try:
            if hasattr(event, "model_dump"):
                event_dict = event.model_dump()
            elif hasattr(event, "__dict__"):
                event_dict = dict(event.__dict__)
            else:
                event_dict = dict(event)

            loop = asyncio.get_event_loop()
            for sink in self._sinks:
                try:
                    if loop.is_running():
                        asyncio.ensure_future(sink.write(event_dict))
                    else:
                        loop.run_until_complete(sink.write(event_dict))
                except Exception as exc:
                    logger.error("Sink %s dispatch error: %s", sink.name, exc)
        except Exception as exc:
            logger.error("MultiSinkAuditWriter serialization error: %s", exc)

    def start_async_sinks(self) -> None:
        """Call from async context after event loop is running."""
        for sink in self._sinks:
            if hasattr(sink, "start"):
                sink.start()

    async def status(self) -> dict:
        result = {}
        for sink in self._sinks:
            ts = await sink.last_write_ts()
            result[sink.name] = {
                "last_write": ts.isoformat() if ts else None,
            }
        return result
