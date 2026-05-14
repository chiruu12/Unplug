"""Prompt injection and jailbreak scanner."""

from __future__ import annotations

import re

from unplug.models import Finding, Source

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


class InjectionScanner:
    name = "injection"

    def scan(self, text: str, source: Source) -> list[Finding]:
        findings = []
        normalized = _normalize(text)

        for category, subcategory, pattern in _PATTERNS:
            for match in pattern.finditer(normalized):
                findings.append(Finding(
                    category="injection",
                    subcategory=subcategory,
                    stage="regex",
                    span_start=match.start(),
                    span_end=match.end(),
                    score=0.85,
                    evidence=f"Matched pattern: {subcategory}",
                ))

        return findings


def _normalize(text: str) -> str:
    """Basic normalization — expand in later iterations."""
    text = re.sub(r"[​‌‍﻿]", "", text)
    text = re.sub(r"\s+", " ", text)
    return text
