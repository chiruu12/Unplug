"""Harmful output scanner — detects toxic, dangerous, and policy-violating content."""

from __future__ import annotations

import re

from unplug.core.config import ScannerConfig
from unplug.core.stats import MetricsCollector
from unplug.core.taint import TaintedText, TrustLevel
from unplug.safeguards.base import RegexScanner

_PATTERNS: list[tuple[str, re.Pattern]] = [
    (
        "dangerous_instructions",
        re.compile(
            r"(?i)\b(how\s+to\s+(make|build|create)\s+(a\s+)?(bomb|weapon|explosive|poison))\b",
        ),
    ),
    (
        "self_harm",
        re.compile(
            r"(?i)\b(suicide|self[- ]harm|kill\s+(your|my)self|end\s+(your|my)\s+life)\b",
        ),
    ),
    (
        "illegal_activity",
        re.compile(
            r"(?i)\b(hack\s+into|steal\s+(credentials?|passwords?)|phishing|ransomware)\b",
        ),
    ),
]

_DEFAULT_CONFIG = ScannerConfig(base_score=0.75)


class HarmfulScanner(RegexScanner):
    name = "harmful"
    _patterns = _PATTERNS

    def __init__(
        self,
        config: ScannerConfig | None = None,
        metrics: MetricsCollector | None = None,
    ) -> None:
        super().__init__(config=config or _DEFAULT_CONFIG, metrics=metrics)

    def _should_scan(self, text: TaintedText) -> bool:
        return text.trust_level in (
            TrustLevel.TOOL_OUTPUT,
            TrustLevel.RETRIEVED,
            TrustLevel.EXTERNAL,
        )

    def _make_evidence(self, subcategory: str) -> str:
        return f"Potentially harmful content: {subcategory}"
