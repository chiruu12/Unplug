"""Harmful output scanner — detects toxic, dangerous, and policy-violating content."""

from __future__ import annotations

import re

from unplug.models import Finding, Source

_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("dangerous_instructions", re.compile(
        r"(?i)\b(how\s+to\s+(make|build|create)\s+(a\s+)?(bomb|weapon|explosive|poison))\b",
    )),
    ("self_harm", re.compile(
        r"(?i)\b(suicide|self[- ]harm|kill\s+(your|my)self|end\s+(your|my)\s+life)\b",
    )),
    ("illegal_activity", re.compile(
        r"(?i)\b(hack\s+into|steal\s+(credentials?|passwords?)|phishing|ransomware)\b",
    )),
]


class HarmfulScanner:
    name = "harmful"

    def scan(self, text: str, source: Source) -> list[Finding]:
        if source != Source.TOOL_OUTPUT and source != Source.RETRIEVED:
            return []

        findings = []
        for subcategory, pattern in _PATTERNS:
            for match in pattern.finditer(text):
                findings.append(Finding(
                    category="harmful",
                    subcategory=subcategory,
                    stage="regex",
                    span_start=match.start(),
                    span_end=match.end(),
                    score=0.75,
                    evidence=f"Potentially harmful content: {subcategory}",
                ))
        return findings
