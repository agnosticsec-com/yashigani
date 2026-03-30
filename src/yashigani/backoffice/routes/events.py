"""
Yashigani Backoffice — Real-time operator visibility via Server-Sent Events.
GET /admin/events/inspection-feed — SSE stream of live inspection events.

Event payload fields:
  timestamp, agent_id, agent_name, direction (request/response),
  tool, verdict, confidence, reason, latency_ms

Subscribes to the in-process EventBus. No data is buffered between
reconnects — operators see only events that occur while connected.
Security: requires valid admin session; no PII in the event stream.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import AsyncIterator

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from yashigani.backoffice.middleware import AdminSession

logger = logging.getLogger(__name__)

router = APIRouter()

# SSE keep-alive interval in seconds (prevents proxy timeouts)
_KEEPALIVE_INTERVAL = 15


@router.get("/inspection-feed")
async def inspection_feed(
    session: AdminSession,
    request: Request,
) -> StreamingResponse:
    """
    Server-Sent Events stream for real-time inspection event visibility.
    Connect once; events are pushed as they occur at the gateway.
    Heartbeat comments are sent every 15 seconds to maintain the connection.

    Event format (text/event-stream):
        data: {"timestamp": "...", "agent_id": "...", ...}
    """
    return StreamingResponse(
        _sse_generator(request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",       # disable Nginx buffering
            "Connection": "keep-alive",
        },
    )


async def _sse_generator(request: Request) -> AsyncIterator[str]:
    """
    Async generator that yields SSE-formatted strings.
    Terminates when the client disconnects or an error occurs.
    """
    from yashigani.events.bus import get_event_bus

    bus = get_event_bus()

    # Send initial connection acknowledgement
    yield _sse_comment("connected")

    keepalive_task: asyncio.Task | None = None
    sub_gen = bus.subscribe()

    async def keepalive_loop(queue: asyncio.Queue) -> None:
        while True:
            await asyncio.sleep(_KEEPALIVE_INTERVAL)
            await queue.put(None)  # sentinel = heartbeat

    heartbeat_q: asyncio.Queue = asyncio.Queue()
    keepalive_task = asyncio.ensure_future(keepalive_loop(heartbeat_q))

    try:
        # Interleave bus events and heartbeat signals
        event_iter = sub_gen.__aiter__()

        pending_event_task: asyncio.Task | None = None
        pending_hb_task: asyncio.Task | None = None

        while True:
            # Check client disconnect
            if await request.is_disconnected():
                break

            if pending_event_task is None:
                pending_event_task = asyncio.ensure_future(event_iter.__anext__())
            if pending_hb_task is None:
                pending_hb_task = asyncio.ensure_future(heartbeat_q.get())

            done, _ = await asyncio.wait(
                [pending_event_task, pending_hb_task],
                return_when=asyncio.FIRST_COMPLETED,
                timeout=_KEEPALIVE_INTERVAL + 1,
            )

            if not done:
                # Timeout — send keepalive
                yield _sse_comment("heartbeat")
                continue

            if pending_hb_task in done:
                pending_hb_task.result()  # drain sentinel
                pending_hb_task = None
                yield _sse_comment("heartbeat")

            if pending_event_task in done:
                try:
                    event = pending_event_task.result()
                    pending_event_task = None
                    payload = _build_payload(event)
                    if payload is not None:
                        yield _sse_data(payload)
                except StopAsyncIteration:
                    break
                except Exception as exc:
                    logger.debug("SSE event error: %s", exc)
                    pending_event_task = None

    except asyncio.CancelledError:
        pass
    except Exception as exc:
        logger.warning("SSE generator terminated: %s", exc)
    finally:
        if keepalive_task is not None:
            keepalive_task.cancel()
        # Drain the sub_gen to trigger cleanup
        try:
            await sub_gen.aclose()
        except Exception:
            pass


def _build_payload(event: dict) -> dict | None:
    """
    Filter and shape an event dict into the inspection-feed payload.
    Returns None if the event is not relevant to the inspection feed.
    """
    if not isinstance(event, dict):
        return None

    # Accept inspection-class events — gateway publishes these
    event_type = event.get("event_type", "")
    relevant_types = {
        "INSPECTION_RESULT",
        "AGENT_CALL_ALLOWED",
        "AGENT_CALL_DENIED_INSPECTION",
        "AGENT_CALL_DENIED_RBAC",
        "RESPONSE_INJECTION_DETECTED",
        "GATEWAY_REQUEST",
    }
    if event_type not in relevant_types:
        return None

    return {
        "timestamp": event.get("timestamp", ""),
        "agent_id": event.get("agent_id", event.get("caller_agent_id", "")),
        "agent_name": event.get("agent_name", ""),
        "direction": event.get("direction", "request"),
        "tool": event.get("tool", event.get("path", "")),
        "verdict": event.get(
            "verdict",
            event.get("pipeline_action", event.get("action", "UNKNOWN")),
        ),
        "confidence": event.get(
            "confidence",
            event.get("confidence_score", event.get("classification_confidence", 0.0)),
        ),
        "reason": event.get("reason", event.get("classification", "")),
        "latency_ms": event.get("latency_ms", event.get("elapsed_ms", 0)),
    }


def _sse_data(payload: dict) -> str:
    """Format a dict as an SSE data line."""
    return f"data: {json.dumps(payload)}\n\n"


def _sse_comment(text: str) -> str:
    """Format an SSE comment (keepalive / metadata)."""
    return f": {text}\n\n"
