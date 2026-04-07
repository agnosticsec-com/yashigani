"""
ACP (Agent Communication Protocol) client for Goose-style agents.

Translates OpenAI ChatCompletionRequest messages into ACP JSON-RPC calls
and returns the response as an OpenAI-compatible ChatCompletionResponse.

ACP uses JSON-RPC 2.0 over HTTP with SSE streaming. The session lifecycle:
1. POST /acp  {method: "initialize", ...}  → capabilities + session ID
2. POST /acp  {method: "notifications/initialized"}  (fire-and-forget)
3. POST /acp  {method: "prompt", params: {messages: [...]}}  → streamed response

Goose requires Accept: application/json, text/event-stream on ALL requests
and returns text/event-stream with SSE `data:` lines for all responses.
"""

import json
import logging
import uuid

import httpx

logger = logging.getLogger(__name__)

_ACP_JSONRPC = "2.0"

# Goose rejects requests without this Accept header (HTTP 406)
_ACP_HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
}


def _parse_sse(text: str) -> list[dict]:
    """Parse SSE response body into list of JSON objects from data: lines."""
    results = []
    for line in text.splitlines():
        if line.startswith("data: "):
            try:
                results.append(json.loads(line[6:]))
            except json.JSONDecodeError:
                continue
    return results


def _parse_response(resp: httpx.Response) -> dict | None:
    """Parse an ACP response that may be SSE or plain JSON."""
    ct = resp.headers.get("content-type", "")
    if "text/event-stream" in ct:
        chunks = _parse_sse(resp.text)
        return chunks[0] if chunks else None
    try:
        return resp.json()
    except Exception:
        return None


async def acp_chat(
    base_url: str,
    messages: list[dict],
    timeout: float = 120.0,
) -> dict:
    """
    Send messages to a Goose ACP agent and return an OpenAI-compatible response.

    Args:
        base_url: Agent upstream URL (e.g., http://goose:3284)
        messages: List of {"role": ..., "content": ...} dicts
        timeout: Request timeout in seconds

    Returns:
        OpenAI ChatCompletionResponse-shaped dict
    """
    acp_url = f"{base_url}/acp"

    async with httpx.AsyncClient(timeout=timeout, headers=_ACP_HEADERS) as client:
        # Step 1: Initialize
        init_resp = await client.post(acp_url, json={
            "jsonrpc": _ACP_JSONRPC,
            "id": _rid(),
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {
                    "name": "yashigani-gateway",
                    "version": "2.1",
                },
            },
        })

        if init_resp.status_code != 200:
            return _error_response(f"ACP initialize failed: {init_resp.status_code}")

        # Extract session ID from response header
        session_id = init_resp.headers.get("acp-session-id", "")
        if not session_id:
            init_data = _parse_response(init_resp)
            if init_data:
                session_id = init_data.get("result", {}).get("sessionId", "")

        session_headers = {}
        if session_id:
            session_headers["acp-session-id"] = session_id

        # Step 2: Notify initialized (fire-and-forget, no response body expected)
        await client.post(acp_url, json={
            "jsonrpc": _ACP_JSONRPC,
            "method": "notifications/initialized",
        }, headers=session_headers)

        # Step 3: Send prompt
        acp_messages = []
        for m in messages:
            acp_messages.append({
                "role": m.get("role", "user"),
                "content": {"type": "text", "text": m.get("content", "")},
            })

        prompt_resp = await client.post(acp_url, json={
            "jsonrpc": _ACP_JSONRPC,
            "id": _rid(),
            "method": "prompt",
            "params": {"messages": acp_messages},
        }, headers=session_headers)

        if prompt_resp.status_code != 200:
            return _error_response(f"ACP prompt failed: {prompt_resp.status_code}")

        # Parse all SSE chunks from the prompt response
        chunks = _parse_sse(prompt_resp.text)
        text_parts = []

        for chunk in chunks:
            result = chunk.get("result", chunk.get("params", {}))
            if not isinstance(result, dict):
                continue

            # Extract text from various ACP response content shapes
            content = result.get("content", result.get("message", ""))

            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict):
                        t = item.get("text", "")
                        if t:
                            text_parts.append(str(t))
            elif isinstance(content, dict):
                t = content.get("text", "")
                if t:
                    text_parts.append(str(t))
            elif isinstance(content, str) and content:
                text_parts.append(content)

        assistant_text = "\n".join(text_parts) if text_parts else "Agent did not return text content."

    return {
        "id": f"chatcmpl-acp-{uuid.uuid4().hex[:8]}",
        "object": "chat.completion",
        "model": "goose-acp",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": assistant_text},
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


def _rid() -> str:
    return uuid.uuid4().hex[:8]


def _error_response(msg: str) -> dict:
    logger.warning("ACP error: %s", msg)
    return {
        "id": f"chatcmpl-acp-err-{uuid.uuid4().hex[:8]}",
        "object": "chat.completion",
        "model": "goose-acp",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": f"Agent error: {msg}"},
            "finish_reason": "stop",
        }],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }
