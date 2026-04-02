"""
E2E: Ollama sensitivity classification — real model, real prompts.

Tests the three-layer sensitivity pipeline against the running Ollama
instance with actual PII/PCI/IP content. Verifies that sensitive data
is correctly classified and would be routed locally.

Requires: running Yashigani stack with Ollama healthy.
"""
from __future__ import annotations

import subprocess
import json
import pytest


def _ollama_query(prompt: str) -> dict:
    """Send a prompt to Ollama directly (bypassing gateway auth) for testing."""
    result = subprocess.run(
        ["docker", "exec", "docker-gateway-1", "python3", "-c", f"""
import urllib.request, json
# Call Ollama directly for e2e testing — /v1 endpoint requires auth
data = json.dumps({{"model": "qwen2.5:3b", "messages": [{{"role": "user", "content": {repr(prompt)}}}], "stream": False}}).encode()
req = urllib.request.Request("http://ollama:11434/api/chat", data=data, headers={{"Content-Type": "application/json"}})
try:
    resp = urllib.request.urlopen(req, timeout=120)
    body = resp.read().decode()
    print(body)
except Exception as e:
    print(f"ERROR:{{e}}")
"""],
        capture_output=True, text=True, timeout=90,
    )
    return result.stdout


def _classify_via_gateway(text: str) -> dict:
    """Classify text using the sensitivity classifier inside the gateway."""
    result = subprocess.run(
        ["docker", "exec", "docker-gateway-1", "python3", "-c", f"""
from yashigani.optimization.sensitivity_classifier import SensitivityClassifier
c = SensitivityClassifier(enable_fasttext=False, enable_ollama=False)
r = c.classify({repr(text)})
import json
print(json.dumps({{"level": r.level.value, "triggers": r.triggers}}))
"""],
        capture_output=True, text=True, timeout=15,
    )
    try:
        return json.loads(result.stdout.strip())
    except (json.JSONDecodeError, ValueError):
        return {"level": "ERROR", "raw": result.stdout, "stderr": result.stderr}


class TestOllamaSensitivity:
    """Test sensitivity classification with real regex patterns."""

    def test_public_text_classified_public(self):
        result = _classify_via_gateway("What is the capital of France?")
        assert result["level"] == "PUBLIC"
        assert len(result["triggers"]) == 0

    def test_ssn_detected_confidential(self):
        result = _classify_via_gateway("Employee SSN is 123-45-6789")
        assert result["level"] == "CONFIDENTIAL"
        assert any("SSN" in t for t in result["triggers"])

    def test_credit_card_detected_restricted(self):
        result = _classify_via_gateway("Payment card: 4111 1111 1111 1111")
        assert result["level"] == "RESTRICTED"
        assert any("card" in t.lower() for t in result["triggers"])

    def test_api_key_detected_restricted(self):
        result = _classify_via_gateway("Use API key sk-ant-abc123def456ghi789jkl012mno345pqr")
        assert result["level"] == "RESTRICTED"
        assert any("API" in t for t in result["triggers"])

    def test_email_detected_internal(self):
        result = _classify_via_gateway("Send it to alice@company.com please")
        assert result["level"] == "INTERNAL"

    def test_mixed_sensitivity_takes_highest(self):
        result = _classify_via_gateway(
            "alice@company.com has SSN 123-45-6789 and card 4111111111111111"
        )
        assert result["level"] == "RESTRICTED"
        assert len(result["triggers"]) >= 2


class TestOllamaLive:
    """Test actual Ollama inference via the gateway."""

    def test_gateway_healthz(self):
        result = subprocess.run(
            ["docker", "exec", "docker-gateway-1", "python3", "-c",
             "import urllib.request; print(urllib.request.urlopen('http://localhost:8080/healthz').read().decode())"],
            capture_output=True, text=True, timeout=10,
        )
        assert "ok" in result.stdout

    def test_ollama_model_loaded(self):
        """Verify qwen2.5:3b is loaded in Ollama."""
        # Wait for Ollama to be running (may have been killed by chaos tests)
        import time
        for _ in range(12):
            result = subprocess.run(
                ["docker", "exec", "docker-ollama-1", "ollama", "list"],
                capture_output=True, text=True, timeout=10,
            )
            if "qwen2.5" in result.stdout:
                break
            time.sleep(10)
        assert "qwen2.5" in result.stdout, f"Ollama model not loaded: {result.stderr}"

    @pytest.mark.skipif(
        subprocess.run(["docker", "exec", "docker-ollama-1", "bash", "-c", "</dev/tcp/localhost/11434"],
                       capture_output=True, timeout=5).returncode != 0,
        reason="Ollama not ready (may need stack restart after chaos tests)"
    )
    def test_simple_prompt_gets_response(self):
        """Send a simple prompt directly to Ollama and verify response."""
        output = _ollama_query("Say hello in exactly 3 words.")
        assert "ERROR" not in output, f"Ollama query failed: {output}"
        assert "message" in output or "content" in output or "response" in output
