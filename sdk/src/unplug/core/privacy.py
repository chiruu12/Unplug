"""Privacy Filter stage — PII/secret span detection (heuristic v1, model later)."""

from __future__ import annotations

import re
from typing import Protocol

from unplug.api.types import Finding
from unplug.scanners.leakage import LEAKAGE_PATTERNS

# PF-aligned subcategory labels (openai/privacy-filter taxonomy subset)
_PF_LABEL_MAP: dict[str, str] = {
    "api_key_generic": "secret",
    "aws_key": "secret",
    "github_token": "secret",
    "openai_key": "secret",
    "jwt_token": "secret",
    "email_address": "private_email",
    "phone_number": "private_phone",
    "ssn": "government_id",
    "system_prompt_leak": "private_other",
}


class PrivacyFilterService(Protocol):
    """Server-side optional stage; maps text → PF-style findings."""

    @property
    def is_loaded(self) -> bool: ...

    def scan(self, text: str, *, baseline: list[Finding]) -> list[Finding]: ...


class HeuristicPrivacyFilter:
    """v1 regex stand-in until openai/privacy-filter is bundled."""

    @property
    def is_loaded(self) -> bool:
        return True

    def scan(self, text: str, *, baseline: list[Finding]) -> list[Finding]:
        covered = {(f.span_start, f.span_end) for f in baseline}
        extra: list[Finding] = []
        for subcategory, pattern in LEAKAGE_PATTERNS:
            pf_label = _PF_LABEL_MAP.get(subcategory, "private_other")
            for match in pattern.finditer(text):
                span = (match.start(), match.end())
                if span in covered:
                    continue
                extra.append(
                    Finding(
                        category="leakage",
                        subcategory=pf_label,
                        stage="privacy_filter",
                        span_start=match.start(),
                        span_end=match.end(),
                        score=0.82,
                        evidence=f"Privacy filter matched {pf_label}",
                        replacement="[REDACTED]",
                    )
                )
                covered.add(span)
        return [*baseline, *extra]


class NullPrivacyFilter:
    @property
    def is_loaded(self) -> bool:
        return False

    def scan(self, text: str, *, baseline: list[Finding]) -> list[Finding]:
        return baseline


def build_privacy_filter(*, enabled: bool) -> PrivacyFilterService:
    if not enabled:
        return NullPrivacyFilter()
    return HeuristicPrivacyFilter()
