"""Prompt injection and jailbreak scanner."""

from __future__ import annotations

import re
from typing import Generator

from unplug.core.config import ScannerConfig
from unplug.core.context import ExecutionContext
from unplug.core.normalize import NormalizeResult, Normalizer
from unplug.core.stats import MetricsCollector
from unplug.core.taint import TaintedText
from unplug.models import Finding
from unplug.scanners.base import RegexScanner

_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("ignore_previous", re.compile(
        r"(?i)(ignore|forget|disregard|override|bypass)\s+(all\s+)?"
        r"(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|guidelines?)",
    )),
    ("persona_replacement", re.compile(
        r"(?i)(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you\s+are)|from\s+now\s+on\s+you)",
    )),
    ("reveal_prompt", re.compile(
        r"(?i)(reveal|show|display|print|output|repeat)\s+(your\s+)?"
        r"(system\s+)?(prompt|instructions?|rules?|guidelines?)",
    )),
    ("developer_mode", re.compile(
        r"(?i)(developer\s+mode|DAN\s+mode|jailbreak|do\s+anything\s+now|no\s+restrictions?)",
    )),
    ("closing_delimiter", re.compile(
        r"(```|<\/?system>|<\/?instruction>|\[\/INST\]|<\|im_end\|>)",
    )),
    ("base64_payload", re.compile(
        r"[A-Za-z0-9+/]{20,}={0,2}",
    )),
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

    def _get_scan_text(self, text: TaintedText) -> str:
        self._last_norm_result = self._normalizer.normalize(text.text)
        return self._last_norm_result.text

    def _make_finding(
        self,
        subcategory: str,
        span_start: int,
        span_end: int,
        raw: str,
        text: TaintedText,
    ) -> Finding:
        if hasattr(self, "_last_norm_result") and self._last_norm_result is not None:
            span_start, span_end = self._last_norm_result.to_original_span(
                span_start, span_end
            )
        return super()._make_finding(subcategory, span_start, span_end, raw, text)

    def _make_evidence(self, subcategory: str) -> str:
        return f"Matched pattern: {subcategory}"
