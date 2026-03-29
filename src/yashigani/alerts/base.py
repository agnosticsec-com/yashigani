"""
Yashigani Alerts — Base classes.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AlertPayload:
    severity: str                   # critical | warning | info
    title: str
    body: str
    event_id: str
    agent_id: Optional[str] = None
    source_component: str = "yashigani"
    extra: dict = field(default_factory=dict)


class AlertSink(ABC):
    """Abstract base for alert delivery sinks."""

    @abstractmethod
    async def send(self, payload: AlertPayload) -> None:
        """Send an alert. Raises on delivery failure."""
        ...

    @abstractmethod
    async def test(self) -> bool:
        """Send a test message. Returns True on success, False on failure."""
        ...
