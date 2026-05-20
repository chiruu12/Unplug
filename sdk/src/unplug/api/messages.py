"""Agent-facing outcomes after orchestration."""

from __future__ import annotations

from pydantic import BaseModel, Field

from unplug.api.types import ScanResult


class SafeContent(BaseModel):
    """Content safe to pass to an agent."""

    safe: bool = True
    text: str
    redacted: bool = False
    scan: ScanResult | None = None


class BlockedContent(BaseModel):
    """Content blocked from reaching an agent."""

    safe: bool = False
    agent_message: str
    category: str = "unknown"
    risk_score: float = Field(ge=0.0, le=1.0, default=1.0)
    scan: ScanResult | None = None


class ContentOutcome(BaseModel):
    """Unified result from guard facades."""

    safe: bool
    text: str | None = None
    agent_message: str | None = None
    redacted: bool = False
    scan: ScanResult | None = None

    @classmethod
    def from_safe(cls, safe: SafeContent) -> ContentOutcome:
        return cls(
            safe=True,
            text=safe.text,
            redacted=safe.redacted,
            scan=safe.scan,
        )

    @classmethod
    def from_blocked(cls, blocked: BlockedContent) -> ContentOutcome:
        return cls(
            safe=False,
            agent_message=blocked.agent_message,
            scan=blocked.scan,
        )
