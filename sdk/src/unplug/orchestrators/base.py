"""Orchestrator base types."""

from __future__ import annotations

from pydantic import BaseModel

from unplug.api.messages import BlockedContent, ContentOutcome, SafeContent
from unplug.api.types import ScanResult


class OrchestratorResult(BaseModel):
    """Result of an orchestrated flow."""

    outcome: ContentOutcome
    scan: ScanResult

    @property
    def safe(self) -> bool:
        return self.outcome.safe

    def to_safe(self) -> SafeContent | None:
        if not self.outcome.safe or self.outcome.text is None:
            return None
        return SafeContent(
            text=self.outcome.text,
            redacted=self.outcome.redacted,
            scan=self.scan,
        )

    def to_blocked(self) -> BlockedContent | None:
        if self.outcome.safe or self.outcome.agent_message is None:
            return None
        category = "unknown"
        if self.scan.findings:
            category = self.scan.findings[0].category
        return BlockedContent(
            agent_message=self.outcome.agent_message,
            category=category,
            risk_score=self.scan.risk_score,
            scan=self.scan,
        )


def scan_result_to_outcome(
    scan: ScanResult,
    *,
    messages: object,
    original_text: str,
) -> ContentOutcome:
    """Map ScanResult to agent-facing ContentOutcome."""
    from unplug.api.enums import Action
    from unplug.config.messages import MessageConfig

    cfg = messages if isinstance(messages, MessageConfig) else MessageConfig()

    if scan.safe and scan.action == Action.ALLOW:
        return ContentOutcome(safe=True, text=original_text, scan=scan)

    if scan.action in (Action.BLOCK, Action.REVIEW) or not scan.safe:
        category = scan.findings[0].category if scan.findings else "threat"
        if scan.action == Action.REVIEW:
            msg = cfg.format_review(category=category, risk_score=scan.risk_score)
        else:
            msg = cfg.format_blocked(category=category, risk_score=scan.risk_score)
        return ContentOutcome(safe=False, agent_message=msg, scan=scan)

    text = scan.redacted_text if scan.redacted_text is not None else original_text
    return ContentOutcome(
        safe=True,
        text=text,
        redacted=scan.redacted_text is not None,
        scan=scan,
    )
