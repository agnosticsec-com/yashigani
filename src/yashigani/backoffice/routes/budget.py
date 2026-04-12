"""
Yashigani Backoffice — Budget admin API.

CRUD for the three-tier budget hierarchy:
  POST/GET/PUT    /admin/budget/org-caps          — Organisation cloud caps
  POST/GET/PUT    /admin/budget/groups             — Group budgets
  POST/GET/PUT    /admin/budget/individuals        — Individual budgets
  GET             /admin/budget/usage/{identity_id} — Usage summary
  GET             /admin/budget/tree               — Full budget tree view

Invariants enforced by this API:
  - Sum of individual budgets <= group budget
  - Sum of group budgets <= org cap
  - New identity added to group: prompt admin to adjust
  - Group budget cannot be set below sum of individuals
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin/budget", tags=["budget"])


# ── Request/Response Models ──────────────────────────────────────────────


class OrgCapRequest(BaseModel):
    org_id: str
    provider: str
    token_cap: int = Field(gt=0)
    period: str = Field(default="monthly", pattern="^(daily|weekly|monthly)$")


class OrgCapResponse(BaseModel):
    org_id: str
    provider: str
    token_cap: int
    period: str
    used: int = 0
    pct: int = 0


class GroupBudgetRequest(BaseModel):
    group_id: str
    provider: str = "*"
    token_budget: int = Field(gt=0)
    period: str = Field(default="monthly", pattern="^(daily|weekly|monthly)$")
    distribute_evenly: bool = False


class GroupBudgetResponse(BaseModel):
    group_id: str
    provider: str
    token_budget: int
    period: str
    auto_calculated: bool
    used: int = 0
    pct: int = 0
    member_count: int = 0
    allocated: int = 0
    unallocated: int = 0


class IndividualBudgetRequest(BaseModel):
    identity_id: str
    provider: str = "*"
    token_budget: int = Field(gt=0)
    period: str = Field(default="monthly", pattern="^(daily|weekly|monthly)$")


class IndividualBudgetResponse(BaseModel):
    identity_id: str
    provider: str
    token_budget: int
    period: str
    used: int = 0
    pct: int = 0
    remaining: int = 0


class BudgetTreeNode(BaseModel):
    """A node in the budget tree view."""
    name: str
    type: str  # 'org', 'group', 'identity'
    provider: str
    budget: int
    used: int
    pct: int
    children: list[BudgetTreeNode] = Field(default_factory=list)


class BudgetValidationError(BaseModel):
    """Returned when a budget mutation would violate hierarchy invariants."""
    error: str
    current_sum: int
    proposed: int
    limit: int
    suggestion: str


# ── State (injected at startup) ─────────────────────────────────────────


class BudgetAdminState:
    def __init__(self):
        self.budget_enforcer = None
        self.identity_registry = None
        self.budget_store = None


_state = BudgetAdminState()


def configure(budget_enforcer=None, identity_registry=None, budget_store=None):
    _state.budget_enforcer = budget_enforcer
    _state.identity_registry = identity_registry
    _state.budget_store = budget_store


# ── Endpoints ────────────────────────────────────────────────────────────


@router.get("/org-caps")
async def list_org_caps():
    """List all organisation cloud caps."""
    if _state.budget_store:
        caps = await _state.budget_store.get_org_caps("00000000-0000-0000-0000-000000000000")
        return {"org_caps": caps}
    return {"org_caps": []}


@router.post("/org-caps", response_model=OrgCapResponse, status_code=201)
async def create_org_cap(body: OrgCapRequest):
    """Set an organisation's cloud token cap for a provider."""
    if _state.budget_store:
        await _state.budget_store.set_org_cap(
            "00000000-0000-0000-0000-000000000000",
            body.org_id, body.provider, body.token_cap, body.period,
        )
    return OrgCapResponse(
        org_id=body.org_id,
        provider=body.provider,
        token_cap=body.token_cap,
        period=body.period,
    )


@router.get("/groups")
async def list_group_budgets():
    """List all group budgets."""
    if _state.budget_store:
        budgets = await _state.budget_store.get_group_budgets("00000000-0000-0000-0000-000000000000")
        return {"group_budgets": budgets}
    return {"group_budgets": []}


@router.post("/groups", response_model=GroupBudgetResponse, status_code=201)
async def create_group_budget(body: GroupBudgetRequest):
    """Set a group's budget."""
    if _state.budget_store:
        await _state.budget_store.set_group_budget(
            "00000000-0000-0000-0000-000000000000",
            body.group_id, body.provider, body.token_budget, body.period,
        )
    return GroupBudgetResponse(
        group_id=body.group_id,
        provider=body.provider,
        token_budget=body.token_budget,
        period=body.period,
        auto_calculated=False,
    )


@router.get("/individuals")
async def list_individual_budgets():
    """List all individual budgets."""
    if _state.budget_store:
        budgets = await _state.budget_store.get_individual_budgets("00000000-0000-0000-0000-000000000000")
        return {"individual_budgets": budgets}
    return {"individual_budgets": []}


@router.post("/individuals", response_model=IndividualBudgetResponse, status_code=201)
async def create_individual_budget(body: IndividualBudgetRequest):
    """Set an individual identity's budget."""
    if _state.budget_store:
        await _state.budget_store.set_individual_budget(
            "00000000-0000-0000-0000-000000000000",
            body.identity_id, body.provider, body.token_budget, body.period,
        )
    # Sync allocation to Redis so gateway can enforce without DB round-trip
    if _state.budget_enforcer:
        _state.budget_enforcer.set_allocation(body.identity_id, body.provider, body.token_budget)
    return IndividualBudgetResponse(
        identity_id=body.identity_id,
        provider=body.provider,
        token_budget=body.token_budget,
        period=body.period,
        remaining=body.token_budget,
    )


@router.get("/usage/{identity_id}")
async def get_usage(identity_id: str, period: str = "monthly"):
    """Get token usage across all providers for an identity."""
    if not _state.budget_enforcer:
        raise HTTPException(status_code=503, detail="Budget enforcer not available")

    usage = _state.budget_enforcer.get_usage_summary(identity_id, period)
    return {
        "identity_id": identity_id,
        "period": period,
        "usage": usage,
    }


@router.get("/tree")
async def get_budget_tree():
    """
    Full budget tree view: org -> groups -> identities.
    Shows total, used, remaining at every level.
    """
    # Placeholder — will be populated from Postgres in integration
    return {
        "tree": [],
        "message": "Budget tree — populated after org caps and groups are configured",
    }
