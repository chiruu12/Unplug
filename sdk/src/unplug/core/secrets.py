"""SecretsRegistry and SecretsSanitizer — exact-match secret detection and redaction."""

from __future__ import annotations

import os
import re

from pydantic import BaseModel, Field

_GENERIC_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("generic_api_key", re.compile(
        r"(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?[\w\-]{20,}",
    )),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_token", re.compile(r"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}")),
    ("openai_key", re.compile(r"sk-[A-Za-z0-9]{32,}")),
    ("slack_token", re.compile(r"xox[bpoa]-[A-Za-z0-9\-]{10,}")),
    ("private_key_header", re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----")),
]


class SecretEntry(BaseModel):
    name: str
    value: str = Field(repr=False, exclude=True)
    source: str
    pattern: str | None = Field(default=None, exclude=True)

    def __repr__(self) -> str:
        return f"SecretEntry(name={self.name!r}, source={self.source!r})"

    def __str__(self) -> str:
        return f"SecretEntry({self.name})"


class SecretMatch(BaseModel):
    secret_name: str
    span_start: int
    span_end: int
    source: str


class SanitizeResult(BaseModel):
    clean_text: str
    secrets_found: list[SecretMatch]


class SecretsRegistry:
    """Register and detect known secrets in text."""

    def __init__(self) -> None:
        self._secrets: dict[str, SecretEntry] = {}

    def register(
        self,
        name: str,
        value: str,
        source: str = "user",
        *,
        pattern: str | None = None,
    ) -> None:
        if not value:
            return
        self._secrets[name] = SecretEntry(name=name, value=value, source=source, pattern=pattern)

    def register_from_env(self, prefixes: list[str]) -> int:
        count = 0
        for key, value in os.environ.items():
            if any(key.startswith(p) for p in prefixes) and value:
                self.register(key, value, source="env")
                count += 1
        return count

    def contains(self, text: str) -> list[SecretMatch]:
        matches: list[SecretMatch] = []
        matched_spans: set[tuple[int, int]] = set()

        for entry in self._secrets.values():
            start = 0
            while True:
                idx = text.find(entry.value, start)
                if idx == -1:
                    break
                span = (idx, idx + len(entry.value))
                if span not in matched_spans:
                    matched_spans.add(span)
                    matches.append(SecretMatch(
                        secret_name=entry.name,
                        span_start=span[0],
                        span_end=span[1],
                        source="registry_exact_match",
                    ))
                start = idx + 1

            if entry.pattern:
                compiled = re.compile(entry.pattern)
                for m in compiled.finditer(text):
                    span = (m.start(), m.end())
                    if span not in matched_spans:
                        matched_spans.add(span)
                        matches.append(SecretMatch(
                            secret_name=entry.name,
                            span_start=span[0],
                            span_end=span[1],
                            source="pattern_match",
                        ))

        for subcategory, pat in _GENERIC_SECRET_PATTERNS:
            for m in pat.finditer(text):
                span = (m.start(), m.end())
                if not any(s <= span[0] and span[1] <= e for s, e in matched_spans):
                    matched_spans.add(span)
                    matches.append(SecretMatch(
                        secret_name=subcategory,
                        span_start=span[0],
                        span_end=span[1],
                        source="generic_pattern",
                    ))

        return matches

    def redact(self, text: str) -> str:
        entries = sorted(self._secrets.values(), key=lambda e: len(e.value), reverse=True)
        result = text
        for entry in entries:
            result = result.replace(entry.value, f"[REDACTED:{entry.name}]")
        return result


class SecretsSanitizer:
    """Sanitizes text by replacing all detected secrets."""

    def __init__(self, registry: SecretsRegistry) -> None:
        self._registry = registry

    def sanitize(self, text: str) -> SanitizeResult:
        matches = self._registry.contains(text)
        clean = self._registry.redact(text)

        for subcategory, pat in _GENERIC_SECRET_PATTERNS:
            for m in pat.finditer(clean):
                clean = clean[:m.start()] + "[REDACTED]" + clean[m.end():]
                break

        return SanitizeResult(clean_text=clean, secrets_found=matches)
