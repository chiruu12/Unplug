"""Data leakage scanner — detects API keys, PII, and system prompt leakage."""

from __future__ import annotations

import re

from unplug.core.config import ScannerConfig
from unplug.core.stats import MetricsCollector
from unplug.core.taint import TaintedText, TrustLevel
from unplug.scanners.base import RegexScanner

_PATTERNS: list[tuple[str, re.Pattern]] = [
    (
        "api_key_generic",
        re.compile(
            r"(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?[\w\-]{20,}",
        ),
    ),
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_token", re.compile(r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}")),
    ("openai_key", re.compile(r"sk-[A-Za-z0-9]{32,}")),
    ("jwt_token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+")),
    ("email_address", re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")),
    ("phone_number", re.compile(r"\b(\+?1?\s?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4})\b")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    (
        "system_prompt_leak",
        re.compile(
            r"(?i)(system\s+prompt|my\s+instructions?\s+(are|say)|I\s+was\s+told\s+to)",
        ),
    ),
]

_DEFAULT_CONFIG = ScannerConfig(base_score=0.80)


class LeakageScanner(RegexScanner):
    name = "leakage"
    _patterns = _PATTERNS

    def __init__(
        self,
        config: ScannerConfig | None = None,
        metrics: MetricsCollector | None = None,
    ) -> None:
        super().__init__(config=config or _DEFAULT_CONFIG, metrics=metrics)

    def _should_scan(self, text: TaintedText) -> bool:
        return text.trust_level not in (TrustLevel.USER, TrustLevel.TRUSTED)

    def _get_replacement(self, subcategory: str) -> str | None:
        return "[REDACTED]"

    def _make_evidence(self, subcategory: str) -> str:
        return f"Potential data leakage: {subcategory}"
