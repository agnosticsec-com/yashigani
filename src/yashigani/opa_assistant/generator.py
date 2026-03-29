"""
OPA Policy Assistant — Natural language to RBAC JSON generator.
Uses internal Ollama (qwen2.5:3b) to generate RBAC data document suggestions.
Zero external API calls — air-gapped compatible.
"""
from __future__ import annotations

import json
import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are an RBAC policy assistant for Yashigani Security Gateway.
Convert natural language access control requirements into a valid RBAC data document.

The output format is EXACTLY this JSON structure (no markdown, no explanation):
{
  "groups": {
    "<group_id>": {
      "id": "<group_id>",
      "display_name": "<human readable name>",
      "allowed_resources": [
        {"method": "GET", "path_glob": "/tools/list"},
        {"method": "*", "path_glob": "/finance/**"}
      ]
    }
  },
  "user_groups": {
    "<user@example.com>": ["<group_id>"]
  }
}

Rules:
- group_id: lowercase, hyphenated (e.g. "engineering-team", "finance-readonly")
- method: specific HTTP method ("GET", "POST", etc.) or "*" for any method
- path_glob: exact path, /prefix/**, or /prefix/*/suffix (single-segment wildcard)
- "**" alone matches any path
- Output ONLY the JSON object. No markdown fences, no explanations."""


class OPAAssistantGenerator:
    """Generates RBAC document suggestions from natural language via Ollama."""

    def __init__(
        self,
        ollama_url: str = "http://ollama:11434",
        model: str = "qwen2.5:3b",
        timeout: float = 30.0,
    ) -> None:
        self._url = ollama_url.rstrip("/")
        self._model = model
        self._timeout = timeout

    async def generate(
        self,
        description: str,
        current_document: Optional[dict] = None,
    ) -> dict:
        """
        Generate an RBAC JSON suggestion from a natural language description.

        Returns:
            {
                "suggestion": dict | None,
                "raw_response": str,
                "valid": bool,
                "error": str | None,
            }
        """
        context = ""
        if current_document:
            context = (
                "\n\nExisting RBAC document (modify this or create fresh based on requirements):\n"
                + json.dumps(current_document, indent=2)
            )

        prompt = (
            f"{_SYSTEM_PROMPT}{context}\n\n"
            f"Requirement: {description}\n\n"
            f"Output ONLY the JSON:"
        )

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    f"{self._url}/api/generate",
                    json={"model": self._model, "prompt": prompt, "stream": False},
                )
                resp.raise_for_status()
                raw = resp.json().get("response", "").strip()
        except httpx.TimeoutException:
            logger.error("OPA assistant: Ollama timeout after %.1fs", self._timeout)
            return {"suggestion": None, "raw_response": "", "valid": False,
                    "error": "ollama_timeout"}
        except httpx.HTTPStatusError as exc:
            logger.error("OPA assistant: Ollama HTTP error: %s", exc)
            return {"suggestion": None, "raw_response": "", "valid": False,
                    "error": f"ollama_http_error:{exc.response.status_code}"}
        except Exception as exc:
            logger.error("OPA assistant: Ollama error: %s", exc)
            return {"suggestion": None, "raw_response": "", "valid": False,
                    "error": f"ollama_error:{exc}"}

        # Strip markdown code fences if the model wrapped the output
        clean = raw
        if clean.startswith("```"):
            lines = clean.split("\n")
            # Remove first line (```json or ```) and last line (```)
            inner = lines[1:] if len(lines) > 1 else lines
            if inner and inner[-1].strip() == "```":
                inner = inner[:-1]
            clean = "\n".join(inner).strip()

        try:
            suggestion = json.loads(clean)
        except json.JSONDecodeError as exc:
            logger.warning(
                "OPA assistant: JSON parse failed: %s | raw=%r", exc, raw[:300]
            )
            return {
                "suggestion": None,
                "raw_response": raw,
                "valid": False,
                "error": f"json_parse_error: {exc}",
            }

        return {"suggestion": suggestion, "raw_response": raw, "valid": True, "error": None}
