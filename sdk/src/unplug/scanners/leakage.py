"""Data leakage scanner — detects API keys, PII, and system prompt leakage."""

from __future__ import annotations

import re

from unplug.core.context import ExecutionContext
from unplug.core.taint import TaintedText, TrustLevel
from unplug.models import Finding

_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("api_key_generic", re.compile(r"(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?[\w\-]{20,}")),
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_token", re.compile(r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}")),
    ("openai_key", re.compile(r"sk-[A-Za-z0-9]{32,}")),
    ("jwt_token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+")),
    ("email_address", re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")),
    ("phone_number", re.compile(r"\b(\+?1?\s?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4})\b")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("system_prompt_leak", re.compile(r"(?i)(system\s+prompt|my\s+instructions?\s+(are|say)|I\s+was\s+told\s+to)")),
]


class LeakageScanner:
    name = "leakage"

    def scan(self, text: TaintedText, context: ExecutionContext) -> list[Finding]:
        if text.trust_level in (TrustLevel.USER, TrustLevel.TRUSTED):
            return []

        findings: list[Finding] = []
        raw = text.text
        for subcategory, pattern in _PATTERNS:
            for match in pattern.finditer(raw):
                findings.append(Finding(
                    category="leakage",
                    subcategory=subcategory,
                    stage="regex",
                    span_start=match.start(),
                    span_end=match.end(),
                    score=0.80,
                    evidence=f"Potential data leakage: {subcategory}",
                    replacement="[REDACTED]",
                ))
        return findings
