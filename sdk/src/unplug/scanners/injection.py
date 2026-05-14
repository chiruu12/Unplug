"""Prompt injection and jailbreak scanner."""

from __future__ import annotations

import re

from unplug.core.context import ExecutionContext
from unplug.core.normalize import Normalizer
from unplug.core.taint import TaintedText
from unplug.models import Finding

_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("instruction_override", "ignore_previous", re.compile(
        r"(?i)(ignore|forget|disregard|override|bypass)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|guidelines?)",
    )),
    ("role_hijacking", "persona_replacement", re.compile(
        r"(?i)(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you\s+are)|from\s+now\s+on\s+you)",
    )),
    ("system_extraction", "reveal_prompt", re.compile(
        r"(?i)(reveal|show|display|print|output|repeat)\s+(your\s+)?(system\s+)?(prompt|instructions?|rules?|guidelines?)",
    )),
    ("jailbreak", "developer_mode", re.compile(
        r"(?i)(developer\s+mode|DAN\s+mode|jailbreak|do\s+anything\s+now|no\s+restrictions?)",
    )),
    ("delimiter_abuse", "closing_delimiter", re.compile(
        r"(```|<\/?system>|<\/?instruction>|\[\/INST\]|<\|im_end\|>)",
    )),
    ("encoding_evasion", "base64_payload", re.compile(
        r"[A-Za-z0-9+/]{20,}={0,2}",
    )),
]

_normalizer = Normalizer()


class InjectionScanner:
    name = "injection"

    def scan(self, text: TaintedText, context: ExecutionContext) -> list[Finding]:
        findings: list[Finding] = []
        result = _normalizer.normalize(text.text)

        for _category, subcategory, pattern in _PATTERNS:
            for match in pattern.finditer(result.text):
                orig_start, orig_end = result.to_original_span(match.start(), match.end())
                findings.append(Finding(
                    category="injection",
                    subcategory=subcategory,
                    stage="regex",
                    span_start=orig_start,
                    span_end=orig_end,
                    score=0.85,
                    evidence=f"Matched pattern: {subcategory}",
                ))

        return findings
