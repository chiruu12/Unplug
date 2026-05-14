"""Secrets scanner — exact-match detection using SecretsRegistry."""

from __future__ import annotations

from unplug.core.context import ExecutionContext
from unplug.core.taint import TaintedText
from unplug.models import Finding


class SecretsScanner:
    name = "secrets"

    def scan(self, text: TaintedText, context: ExecutionContext) -> list[Finding]:
        if context.secrets_registry is None:
            return []

        matches = context.secrets_registry.contains(text.text)
        return [
            Finding(
                category="secrets",
                subcategory=f"registered_secret:{m.secret_name}",
                stage="regex",
                span_start=m.span_start,
                span_end=m.span_end,
                score=0.99,
                evidence=f"Registered secret '{m.secret_name}' found in output",
                replacement="[REDACTED]",
            )
            for m in matches
        ]
