"""Tests for billing module: token counter and budget enforcer."""
from __future__ import annotations

import fakeredis
import pytest

from yashigani.billing.token_counter import TokenCounter, TokenUsage
from yashigani.billing.budget_enforcer import BudgetEnforcer, BudgetSignal


@pytest.fixture
def counter():
    return TokenCounter()


@pytest.fixture
def redis():
    return fakeredis.FakeRedis()


@pytest.fixture
def enforcer(redis):
    return BudgetEnforcer(redis)


# ── Token Counter ────────────────────────────────────────────────────────


class TestTokenCounter:
    def test_openai_response(self, counter):
        body = {"usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150}}
        usage = counter.count("openai", "gpt-4o", body)
        assert usage.input_tokens == 100
        assert usage.output_tokens == 50
        assert usage.total_tokens == 150
        assert usage.provider == "openai"
        assert not usage.is_local

    def test_anthropic_response(self, counter):
        body = {"usage": {"input_tokens": 200, "output_tokens": 80}}
        usage = counter.count("anthropic", "claude-opus-4-6", body)
        assert usage.input_tokens == 200
        assert usage.output_tokens == 80
        assert usage.total_tokens == 280

    def test_ollama_response(self, counter):
        body = {"prompt_eval_count": 50, "eval_count": 120}
        usage = counter.count("ollama", "qwen2.5:3b", body)
        assert usage.input_tokens == 50
        assert usage.output_tokens == 120
        assert usage.is_local

    def test_gemini_response(self, counter):
        body = {"usageMetadata": {"promptTokenCount": 300, "candidatesTokenCount": 100, "totalTokenCount": 400}}
        usage = counter.count("gemini", "gemini-2.0-flash", body)
        assert usage.input_tokens == 300
        assert usage.output_tokens == 100

    def test_unknown_provider_estimates(self, counter):
        body = {"choices": [{"message": {"content": "Hello world this is a test response."}}]}
        usage = counter.count("unknown_provider", "model-x", body)
        assert usage.estimated
        assert usage.output_tokens > 0

    def test_count_request_estimate(self, counter):
        body = {"messages": [{"content": "x" * 400}]}
        tokens = counter.count_request("openai", "gpt-4o", body)
        assert tokens == 100  # 400 chars / 4

    def test_azure_uses_openai_format(self, counter):
        body = {"usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}}
        usage = counter.count("azure", "gpt-4o", body)
        assert usage.total_tokens == 30


# ── Budget Enforcer ──────────────────────────────────────────────────────


class TestBudgetEnforcer:
    def test_no_budget_configured(self, enforcer):
        state = enforcer.check("id1", "anthropic", budget_total=0)
        assert state.signal == BudgetSignal.NORMAL
        assert state.total == 0

    def test_normal_budget(self, enforcer):
        state = enforcer.check("id1", "anthropic", budget_total=10000)
        assert state.signal == BudgetSignal.NORMAL
        assert state.pct == 0
        assert state.remaining == 10000

    def test_warn_budget(self, enforcer, redis):
        # Manually set usage to 85%
        from yashigani.billing.budget_enforcer import _period_key
        pk = _period_key("monthly")
        redis.set(f"budget:identity:id1:anthropic:{pk}", 8500)

        state = enforcer.check("id1", "anthropic", budget_total=10000)
        assert state.signal == BudgetSignal.WARN
        assert state.pct == 85

    def test_exhausted_budget(self, enforcer, redis):
        from yashigani.billing.budget_enforcer import _period_key
        pk = _period_key("monthly")
        redis.set(f"budget:identity:id1:openai:{pk}", 10000)

        state = enforcer.check("id1", "openai", budget_total=10000)
        assert state.signal == BudgetSignal.EXHAUSTED
        assert state.remaining == 0

    def test_record_increments(self, enforcer, redis):
        enforcer.record("id1", "anthropic", tokens=500, group_ids=["g1"], org_id="org1")
        enforcer.record("id1", "anthropic", tokens=300, group_ids=["g1"], org_id="org1")

        from yashigani.billing.budget_enforcer import _period_key
        pk = _period_key("monthly")

        identity_used = int(redis.get(f"budget:identity:id1:anthropic:{pk}") or 0)
        group_used = int(redis.get(f"budget:group:g1:anthropic:{pk}") or 0)
        org_used = int(redis.get(f"budget:org:org1:anthropic:{pk}") or 0)

        assert identity_used == 800
        assert group_used == 800
        assert org_used == 800

    def test_check_group(self, enforcer, redis):
        from yashigani.billing.budget_enforcer import _period_key
        pk = _period_key("monthly")
        redis.set(f"budget:group:g1:anthropic:{pk}", 9500)

        state = enforcer.check_group("g1", "anthropic", budget_total=10000)
        assert state.signal == BudgetSignal.WARN

    def test_check_org(self, enforcer, redis):
        from yashigani.billing.budget_enforcer import _period_key
        pk = _period_key("monthly")
        redis.set(f"budget:org:org1:openai:{pk}", 500000)

        state = enforcer.check_org("org1", "openai", cap=500000)
        assert state.signal == BudgetSignal.EXHAUSTED

    def test_zero_tokens_not_recorded(self, enforcer, redis):
        enforcer.record("id1", "anthropic", tokens=0)
        from yashigani.billing.budget_enforcer import _period_key
        pk = _period_key("monthly")
        assert redis.get(f"budget:identity:id1:anthropic:{pk}") is None
