"""
Yashigani Backoffice — Optional agent bundle registry (v0.8.0).

These routes expose metadata about the third-party agent containers that users
can opt-in to at install time.  No bundle is installed or removed via this API
— that is handled by the installer / Helm values.  The API exists so the
backoffice UI can display bundle status and show the disclaimer banner.

Routes:
  GET /admin/agent-bundles            — list all bundles with metadata
  GET /admin/agent-bundles/disclaimer — the standard disclaimer text
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter
from pydantic import BaseModel

from yashigani.backoffice.auth import require_admin_session, AdminSession

router = APIRouter()

# ---------------------------------------------------------------------------
# Disclaimer text — single source of truth; displayed at install time,
# in the backoffice banner, and in the docs callout box.
# ---------------------------------------------------------------------------

_DISCLAIMER = (
    "These third-party agent containers are provided AS IS by Agnostic Security "
    "as a courtesy integration. Image digests are pinned to upstream-tagged releases "
    "and updated as part of the Yashigani release cycle. "
    "All support, bug reports, and feature requests must be directed to the "
    "upstream maintainers — Agnostic Security provides no warranty and accepts "
    "no support obligation for these integrations."
)

# ---------------------------------------------------------------------------
# Static bundle catalogue — updated with each Yashigani release when digests
# are pinned.  The `image` field should match docker/docker-compose.yml.
# ---------------------------------------------------------------------------

_BUNDLES: list[dict] = [
    {
        "id": "langgraph",
        "name": "LangGraph",
        "description": "Python MCP-native multi-agent orchestration framework.",
        "upstream_url": "https://github.com/langchain-ai/langgraph",
        "license": "Apache-2.0",
        "stack": "Python",
        "image": "langchain/langgraph-api:latest",
        "integration": "MCP → Yashigani Gateway → tools",
        "compose_profile": "langgraph",
        "helm_key": "agentBundles.langgraph.enabled",
        "size_warning": None,
    },
    {
        "id": "goose",
        "name": "Goose",
        "description": "Python MCP-native developer assistant by Block.",
        "upstream_url": "https://github.com/block/goose",
        "license": "Apache-2.0",
        "stack": "Python",
        "image": "ghcr.io/block/goose:latest",
        "integration": "MCP → Yashigani Gateway → tools",
        "compose_profile": "goose",
        "helm_key": "agentBundles.goose.enabled",
        "size_warning": None,
    },
    {
        "id": "crewai",
        "name": "CrewAI",
        "description": "Python multi-agent orchestration for collaborative AI workflows.",
        "upstream_url": "https://github.com/crewAIInc/crewAI",
        "license": "MIT",
        "stack": "Python",
        "image": "crewai/crewai:latest",
        "integration": "MCP → Yashigani Gateway → tools",
        "compose_profile": "crewai",
        "helm_key": "agentBundles.crewai.enabled",
        "size_warning": None,
    },
    {
        "id": "openclaw",
        "name": "OpenClaw",
        "description": (
            "Personal AI assistant with 30+ messaging channel integrations. "
            "Runs its own Gateway on port 18789. "
            "Integration pattern: OpenClaw Gateway → Yashigani → LLM providers."
        ),
        "upstream_url": "https://openclaw.ai",
        "license": "TBD — verify at openclaw.ai before production use",
        "stack": "Node.js 24",
        "image": "openclaw/openclaw:latest",
        "integration": "OpenClaw Gateway (:18789) → Yashigani Gateway → LLM providers",
        "compose_profile": "openclaw",
        "helm_key": "agentBundles.openclaw.enabled",
        "size_warning": (
            "Node.js 24 image is approximately 800 MB — significantly larger than "
            "the Python agent images (~200 MB). Ensure sufficient disk space."
        ),
    },
]


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class AgentBundleResponse(BaseModel):
    id: str
    name: str
    description: str
    upstream_url: str
    license: str
    stack: str
    image: str
    integration: str
    compose_profile: str
    helm_key: str
    size_warning: Optional[str]


class AgentBundleListResponse(BaseModel):
    bundles: list[AgentBundleResponse]
    disclaimer: str


class DisclaimerResponse(BaseModel):
    disclaimer: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/", response_model=AgentBundleListResponse)
async def list_agent_bundles(session: AdminSession = require_admin_session):
    """Return all available optional agent bundles with their metadata and disclaimer."""
    return AgentBundleListResponse(
        bundles=[AgentBundleResponse(**b) for b in _BUNDLES],
        disclaimer=_DISCLAIMER,
    )


@router.get("/disclaimer", response_model=DisclaimerResponse)
async def get_disclaimer(session: AdminSession = require_admin_session):
    """Return the standard third-party agent bundle disclaimer for use in UI banners."""
    return DisclaimerResponse(disclaimer=_DISCLAIMER)
