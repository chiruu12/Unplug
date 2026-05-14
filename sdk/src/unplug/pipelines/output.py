"""Output pipeline — secrets scan, leakage scan, sanitize."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from unplug.core.context import ExecutionContext
from unplug.core.secrets import SecretsSanitizer
from unplug.core.taint import Tagger, TaintedText, TrustLevel
from unplug.models import Action, Finding, ScanResult

if TYPE_CHECKING:
    from unplug.scanners.leakage import LeakageScanner
    from unplug.scanners.secrets import SecretsScanner


class OutputPipeline:
    def __init__(
        self,
        secrets_sanitizer: SecretsSanitizer | None = None,
        leakage_scanner: LeakageScanner | None = None,
        secrets_scanner: SecretsScanner | None = None,
    ) -> None:
        self._sanitizer = secrets_sanitizer
        self._leakage_scanner = leakage_scanner
        self._secrets_scanner = secrets_scanner
        self._tagger = Tagger()

    def run(
        self,
        text: str | TaintedText,
        *,
        context: ExecutionContext | None = None,
    ) -> ScanResult:
        start = time.perf_counter()

        if isinstance(text, str):
            tainted = self._tagger.tag(text, TrustLevel.TOOL_OUTPUT, "output_pipeline")
        else:
            tainted = text

        ctx = context or ExecutionContext()

        all_findings: list[Finding] = []
        stages_run: list[str] = []

        if self._secrets_scanner:
            findings = self._secrets_scanner.scan(tainted, ctx)
            if findings:
                all_findings.extend(findings)
                stages_run.append("secrets")

        if self._leakage_scanner:
            findings = self._leakage_scanner.scan(tainted, ctx)
            if findings:
                all_findings.extend(findings)
                stages_run.append("leakage")

        clean_text = tainted.text
        if self._sanitizer and all_findings:
            result = self._sanitizer.sanitize(clean_text)
            clean_text = result.clean_text

        latency_ms = (time.perf_counter() - start) * 1000
        risk_score = max((f.score for f in all_findings), default=0.0)

        if risk_score >= 0.8:
            action = Action.BLOCK
        elif all_findings:
            action = Action.REDACT
        else:
            action = Action.ALLOW

        return ScanResult(
            safe=action == Action.ALLOW,
            action=action,
            risk_score=risk_score,
            findings=all_findings,
            redacted_text=clean_text if all_findings else None,
            latency_ms=latency_ms,
            stages_run=stages_run,
        )
