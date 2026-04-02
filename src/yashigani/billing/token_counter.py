"""
Yashigani Billing — Token counter.

Extracts token counts from LLM provider responses. Each provider uses a
different response format; this module normalises them into a common
TokenUsage dataclass.

Supported providers:
  - OpenAI:    response.usage.prompt_tokens, completion_tokens, total_tokens
  - Anthropic: response.usage.input_tokens, output_tokens
  - Ollama:    response.prompt_eval_count, eval_count
  - Gemini:    response.usageMetadata.promptTokenCount, candidatesTokenCount
  - Local:     estimated from character count (fallback)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TokenUsage:
    """Normalised token usage from any provider."""
    input_tokens: int
    output_tokens: int
    total_tokens: int
    provider: str
    model: str
    is_local: bool = False
    estimated: bool = False  # True if tokens were estimated, not from provider

    @property
    def cost_input_per_1k(self) -> float:
        """Override in subclass or set via pricing table."""
        return 0.0

    @property
    def cost_output_per_1k(self) -> float:
        return 0.0


# Characters-per-token estimate for fallback counting
_CHARS_PER_TOKEN = 4


class TokenCounter:
    """
    Extract token usage from LLM provider response bodies.

    Usage:
        counter = TokenCounter()
        usage = counter.count("openai", "gpt-4o", response_body)
    """

    def count(self, provider: str, model: str, response_body: dict) -> TokenUsage:
        """
        Extract token counts from a provider response.

        Args:
            provider: Provider name (openai, anthropic, ollama, gemini)
            model: Model name as used in the request
            response_body: Parsed JSON response from the provider

        Returns:
            TokenUsage with normalised counts
        """
        handler = _PROVIDER_HANDLERS.get(provider.lower())
        if handler:
            try:
                return handler(model, response_body)
            except Exception as exc:
                logger.warning(
                    "Token counting failed for %s/%s: %s — using estimate",
                    provider, model, exc,
                )

        # Fallback: estimate from response content
        return self._estimate(provider, model, response_body)

    def count_request(self, provider: str, model: str, request_body: dict) -> int:
        """
        Estimate input token count from a request body (pre-send).

        Used by the Optimization Engine to classify complexity before
        sending the request to a backend.
        """
        messages = request_body.get("messages", [])
        total_chars = sum(len(m.get("content", "")) for m in messages)
        return max(1, total_chars // _CHARS_PER_TOKEN)

    @staticmethod
    def _estimate(provider: str, model: str, response_body: dict) -> TokenUsage:
        """Fallback: estimate tokens from response content length."""
        content = ""
        choices = response_body.get("choices", [])
        if choices:
            msg = choices[0].get("message", {})
            content = msg.get("content", "")
        elif "response" in response_body:
            content = response_body["response"]

        output_tokens = max(1, len(content) // _CHARS_PER_TOKEN)
        return TokenUsage(
            input_tokens=0,
            output_tokens=output_tokens,
            total_tokens=output_tokens,
            provider=provider,
            model=model,
            is_local=provider == "ollama",
            estimated=True,
        )


# ── Provider-specific extractors ─────────────────────────────────────────


def _count_openai(model: str, body: dict) -> TokenUsage:
    """OpenAI / OpenAI-compatible (including Azure OpenAI)."""
    usage = body.get("usage", {})
    inp = usage.get("prompt_tokens", 0)
    out = usage.get("completion_tokens", 0)
    total = usage.get("total_tokens", inp + out)
    return TokenUsage(
        input_tokens=inp,
        output_tokens=out,
        total_tokens=total,
        provider="openai",
        model=model,
    )


def _count_anthropic(model: str, body: dict) -> TokenUsage:
    """Anthropic Claude API."""
    usage = body.get("usage", {})
    inp = usage.get("input_tokens", 0)
    out = usage.get("output_tokens", 0)
    return TokenUsage(
        input_tokens=inp,
        output_tokens=out,
        total_tokens=inp + out,
        provider="anthropic",
        model=model,
    )


def _count_ollama(model: str, body: dict) -> TokenUsage:
    """Ollama local inference."""
    inp = body.get("prompt_eval_count", 0)
    out = body.get("eval_count", 0)
    return TokenUsage(
        input_tokens=inp,
        output_tokens=out,
        total_tokens=inp + out,
        provider="ollama",
        model=model,
        is_local=True,
    )


def _count_gemini(model: str, body: dict) -> TokenUsage:
    """Google Gemini API."""
    meta = body.get("usageMetadata", {})
    inp = meta.get("promptTokenCount", 0)
    out = meta.get("candidatesTokenCount", 0)
    total = meta.get("totalTokenCount", inp + out)
    return TokenUsage(
        input_tokens=inp,
        output_tokens=out,
        total_tokens=total,
        provider="gemini",
        model=model,
    )


_PROVIDER_HANDLERS = {
    "openai": _count_openai,
    "azure": _count_openai,  # Azure OpenAI uses same format
    "anthropic": _count_anthropic,
    "ollama": _count_ollama,
    "gemini": _count_gemini,
    "google": _count_gemini,
}
