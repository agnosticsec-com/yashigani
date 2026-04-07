"""
ACP (Agent Communication Protocol) client for Goose-style agents.

Translates OpenAI ChatCompletionRequest messages into ACP JSON-RPC calls
and returns the response as an OpenAI-compatible ChatCompletionResponse.

ACP uses JSON-RPC 2.0 over HTTP with SSE streaming. The session lifecycle:
1. POST /acp  {method: "initialize", ...}  → capabilities + session ID
2. POST /acp  {method: "notifications/initialized"}
3. POST /acp  {method: "session/new"}  → session created
4. POST /acp  {method: "prompt", params: {messages: [...]}}  → streamed response
"""

import json
import logging
import uuid

import httpx

logger = logging.getLogger(__name__)

_ACP_JSONRPC = "2.0"


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

    async with httpx.AsyncClient(timeout=timeout) as client:
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
            # Try to get from response body
            try:
                init_data = init_resp.json()
                session_id = init_data.get("result", {}).get("sessionId", "")
            except Exception:
                pass

        headers = {}
        if session_id:
            headers["acp-session-id"] = session_id

        # Step 2: Notify initialized
        await client.post(acp_url, json={
            "jsonrpc": _ACP_JSONRPC,
            "method": "notifications/initialized",
        }, headers=headers)

        # Step 3: Create session
        session_resp = await client.post(acp_url, json={
            "jsonrpc": _ACP_JSONRPC,
            "id": _rid(),
            "method": "session/new",
            "params": {},
        }, headers=headers)

        if session_resp.status_code != 200:
            logger.warning("ACP session/new returned %d — continuing anyway", session_resp.status_code)

        # Step 4: Send prompt
        acp_messages = []
        for m in messages:
            acp_messages.append({
                "role": m.get("role", "user"),
                "content": {"type": "text", "text": m.get("content", "")},
            })

        prompt_headers = {**headers, "Accept": "application/json, text/event-stream"}
        prompt_resp = await client.post(acp_url, json={
            "jsonrpc": _ACP_JSONRPC,
            "id": _rid(),
            "method": "prompt",
            "params": {"messages": acp_messages},
        }, headers=prompt_headers)

        if prompt_resp.status_code != 200:
            return _error_response(f"ACP prompt failed: {prompt_resp.status_code}")

        # Parse response — may be JSON or SSE stream
        content_type = prompt_resp.headers.get("content-type", "")

        if "text/event-stream" in content_type:
            # Collect SSE chunks
            text_parts = []
            for line in prompt_resp.text.splitlines():
                if line.startswith("data: "):
                    try:
                        chunk = json.loads(line[6:])
                        # Extract text from various ACP response shapes
                        result = chunk.get("result", chunk.get("params", {}))
                        if isinstance(result, dict):
                            content = result.get("content", result.get("message", ""))
                            if isinstance(content, dict):
                                content = content.get("text", str(content))
                            if isinstance(content, list):
                                content = " ".join(
                                    c.get("text", str(c)) for c in content if isinstance(c, dict)
                                )
                            if content:
                                text_parts.append(str(content))
                    except json.JSONDecodeError:
                        continue
            assistant_text = "\n".join(text_parts) if text_parts else "Agent did not return text content."
        else:
            # Plain JSON response
            try:
                resp_data = prompt_resp.json()
                result = resp_data.get("result", {})
                if isinstance(result, dict):
                    content = result.get("content", result.get("message", ""))
                    if isinstance(content, list):
                        content = " ".join(
                            c.get("text", str(c)) for c in content if isinstance(c, dict)
                        )
                    elif isinstance(content, dict):
                        content = content.get("text", str(content))
                    assistant_text = str(content) if content else "Agent returned empty response."
                else:
                    assistant_text = str(result)
            except Exception as exc:
                assistant_text = f"Failed to parse ACP response: {exc}"

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
