"""Prompt injection and jailbreak scanner."""

from __future__ import annotations

import re
from collections.abc import Generator

from unplug.core.config import ScannerConfig
from unplug.core.context import ExecutionContext
from unplug.core.normalize import Normalizer
from unplug.core.stats import MetricsCollector
from unplug.core.taint import TaintedText
from unplug.models import Finding
from unplug.scanners.base import RegexScanner

_PATTERNS: list[tuple[str, re.Pattern]] = [
    (
        "ignore_previous",
        re.compile(
            r"(?i)(ignore|forget|disregard|override|bypass)\s+(all\s+)?"
            r"(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|guidelines?)",
        ),
    ),
    (
        "persona_replacement",
        re.compile(
            r"(?i)(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you\s+are)|from\s+now\s+on\s+you)",
        ),
    ),
    (
        "reveal_prompt",
        re.compile(
            r"(?i)(reveal|show|display|print|output|repeat|tell\s+me)\s+(your\s+)?"
            r"(system\s+)?(prompt|instructions?|rules?|guidelines?|configuration)",
        ),
    ),
    (
        "system_extraction_alt",
        re.compile(
            r"(?i)(what\s+(are|is)\s+your\s+(system\s+)?(prompt|instructions?|rules?)|"
            r"copy\s+your\s+(initial|system)\s+prompt)",
        ),
    ),
    (
        "developer_mode",
        re.compile(
            r"(?i)(developer\s+mode|DAN\s+mode|jailbreak|do\s+anything\s+now|no\s+restrictions?)",
        ),
    ),
    (
        "closing_delimiter",
        re.compile(
            r"(```|<\/?system>|<\/?instruction>|\[\/INST\]|<\|im_end\|>)",
        ),
    ),
    (
        "base64_payload",
        re.compile(
            r"[A-Za-z0-9+/]{20,}={0,2}",
        ),
    ),
    (
        "hex_encoding",
        re.compile(
            r"(?i)(?:\\x[0-9a-f]{2}){4,}",
        ),
    ),
    (
        "unicode_escape",
        re.compile(
            r"(?:\\u[0-9a-fA-F]{4}){3,}",
        ),
    ),
    (
        "indirect_instruction",
        re.compile(
            r"(?i)(when\s+you\s+read\s+this|important\s+instruction|hidden\s+instruction|"
            r"ignore\s+the\s+document\s+and|do\s+not\s+follow\s+the\s+user)",
        ),
    ),
    (
        "embedded_system_tag",
        re.compile(
            r"(?i)(<\s*system\s*>|<<\s*SYS\s*>>|\[INST\].*ignore)",
        ),
    ),
]

_DEFAULT_CONFIG = ScannerConfig(base_score=0.85, normalize=True)


class InjectionScanner(RegexScanner):
    name = "injection"
    _patterns = _PATTERNS

    def __init__(
        self,
        config: ScannerConfig | None = None,
        metrics: MetricsCollector | None = None,
    ) -> None:
        super().__init__(config=config or _DEFAULT_CONFIG, metrics=metrics)
        self._normalizer = Normalizer()

    def _scan(self, text: TaintedText, context: ExecutionContext) -> Generator[Finding, None, None]:
        norm_result = self._normalizer.normalize(text.text)
        normalized = norm_result.text

        for subcategory, pattern in self._patterns:
            for match in pattern.finditer(normalized):
                span_start, span_end = norm_result.to_original_span(match.start(), match.end())
                score = self._compute_score(subcategory, text)
                yield Finding(
                    category=self.name,
                    subcategory=subcategory,
                    stage="regex",
                    span_start=span_start,
                    span_end=span_end,
                    score=score,
                    evidence=f"Matched pattern: {subcategory}",
                    replacement=self._get_replacement(subcategory),
                )
