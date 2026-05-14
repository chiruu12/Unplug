"""Input pipeline — taint, normalize, scan, decide."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from unplug.core.context import ExecutionContext
from unplug.core.normalize import Normalizer
from unplug.core.taint import Tagger, TaintedText, TrustLevel, trust_level_from_source
from unplug.models import Action, Finding, ScanResult, Source

if TYPE_CHECKING:
    from unplug.scanners.base import Scanner


class InputPipeline:
    def __init__(
        self,
        scanners: list[Scanner],
        normalizer: Normalizer | None = None,
        tagger: Tagger | None = None,
    ) -> None:
        self._scanners = scanners
        self._normalizer = normalizer or Normalizer()
        self._tagger = tagger or Tagger()

    def run(
        self,
        text: str | TaintedText,
        *,
        source: Source | TrustLevel = TrustLevel.USER,
        context: ExecutionContext | None = None,
    ) -> ScanResult:
        start = time.perf_counter()

        if isinstance(text, str):
            if isinstance(source, Source):
                trust = trust_level_from_source(source)
            else:
                trust = source
            tainted = self._tagger.tag(text, trust, "input_pipeline")
        else:
            tainted = text

        ctx = context or ExecutionContext()

        all_findings: list[Finding] = []
        stages_run: list[str] = []

        for scanner in self._scanners:
            findings = scanner.scan(tainted, ctx)
            if findings:
                all_findings.extend(findings)
                stages_run.append(scanner.name)

        latency_ms = (time.perf_counter() - start) * 1000
        risk_score = max((f.score for f in all_findings), default=0.0)
        action = _decide_action(risk_score, all_findings)
        redacted = _redact(tainted.text, all_findings) if all_findings else None

        return ScanResult(
            safe=action == Action.ALLOW,
            action=action,
            risk_score=risk_score,
            findings=all_findings,
            redacted_text=redacted,
            latency_ms=latency_ms,
            stages_run=stages_run,
        )


def _decide_action(risk_score: float, findings: list[Finding]) -> Action:
    if risk_score >= 0.8:
        return Action.BLOCK
    if risk_score >= 0.5:
        return Action.REDACT
    if risk_score >= 0.3:
        return Action.REVIEW
    return Action.ALLOW


def _redact(text: str, findings: list[Finding]) -> str:
    spans = sorted(
        [(f.span_start, f.span_end, f.replacement) for f in findings if f.score >= 0.5],
        key=lambda s: s[0],
        reverse=True,
    )
    result = text
    for start, end, replacement in spans:
        result = result[:start] + (replacement or "[REDACTED]") + result[end:]
    return result
