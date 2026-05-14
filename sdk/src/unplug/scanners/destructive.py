"""Destructive action scanner — prevents agents from dangerous operations."""

from __future__ import annotations

import re

from unplug.models import Finding, Source

_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("sql_drop", re.compile(r"(?i)\b(DROP\s+(TABLE|DATABASE|SCHEMA|INDEX)|TRUNCATE\s+TABLE|DELETE\s+FROM)\b")),
    ("sql_alter", re.compile(r"(?i)\b(ALTER\s+TABLE\s+\w+\s+DROP|DROP\s+COLUMN)\b")),
    ("shell_rm", re.compile(r"(?i)\b(rm\s+-rf|rm\s+-r\s|rmdir|shutil\.rmtree|os\.remove)\b")),
    ("shell_kill", re.compile(r"(?i)\b(kill\s+-9|killall|pkill|shutdown|reboot|halt)\b")),
    ("shell_format", re.compile(r"(?i)\b(mkfs|fdisk|format\s+[A-Z]:)\b")),
    ("file_delete", re.compile(r"(?i)\b(os\.unlink|os\.rmdir|pathlib.*\.unlink|shutil\.rmtree)\b")),
    ("api_delete", re.compile(r"(?i)(DELETE\s+/|\.delete\(|requests\.delete|httpx\.delete)\b")),
    ("git_destructive", re.compile(r"(?i)\b(git\s+(push\s+--force|reset\s+--hard|clean\s+-fd|branch\s+-D))\b")),
]


class DestructiveScanner:
    name = "destructive"

    def scan(self, text: str, source: Source) -> list[Finding]:
        findings = []
        for subcategory, pattern in _PATTERNS:
            for match in pattern.finditer(text):
                findings.append(Finding(
                    category="destructive",
                    subcategory=subcategory,
                    stage="regex",
                    span_start=match.start(),
                    span_end=match.end(),
                    score=0.90,
                    evidence=f"Destructive operation detected: {subcategory}",
                ))
        return findings
