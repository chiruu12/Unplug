"""Pipeline base class — shared timing, finding collection, result building."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any

from unplug.core.config import PipelineConfig
from unplug.core.context import ExecutionContext
from unplug.core.logging import get_logger
from unplug.core.stats import MetricsCollector
from unplug.core.taint import Tagger, TaintedText, TrustLevel
from unplug.models import Action, Finding, ScanResult

_log = get_logger("pipelines")


class BasePipeline(ABC):
    """Abstract base for all enforcement pipelines."""

    name: str = ""

    def __init__(
        self,
        config: PipelineConfig | None = None,
        metrics: MetricsCollector | None = None,
    ) -> None:
        self._config = config or PipelineConfig()
        self._metrics = metrics
        self._tagger = Tagger()

    @property
    def config(self) -> PipelineConfig:
        return self._config

    def run(self, input_data: Any, *, context: ExecutionContext | None = None) -> ScanResult:
        ctx = context or ExecutionContext()
        start = time.perf_counter()

        try:
            findings = list(self._execute(input_data, ctx))
        except Exception as exc:
            _log.error("pipeline %s failed: %s", self.name, exc)
            latency_ms = (time.perf_counter() - start) * 1000
            return ScanResult(
                safe=False,
                action=Action.BLOCK,
                risk_score=1.0,
                findings=[
                    Finding(
                        category=self.name,
                        subcategory="pipeline_error",
                        stage="error",
                        span_start=0,
                        span_end=0,
                        score=1.0,
                        evidence=f"Pipeline failed: {type(exc).__name__}",
                    )
                ],
                latency_ms=latency_ms,
            )
        latency_ms = (time.perf_counter() - start) * 1000

        risk_score = max((f.score for f in findings), default=0.0)
        action = self._decide(risk_score, findings)
        stages = list(dict.fromkeys(f.category for f in findings))
        redacted = self._redact(input_data, findings) if findings else None

        result = ScanResult(
            safe=action == Action.ALLOW,
            action=action,
            risk_score=risk_score,
            findings=findings,
            redacted_text=redacted,
            latency_ms=latency_ms,
            stages_run=stages,
        )

        if self._metrics:
            self._metrics.record_pipeline(self.name, action=action.value, latency_ms=latency_ms)

        ctx.update_risk(risk_score)

        log_fn = _log.warning if 0.3 <= risk_score < 0.5 else _log.info
        log_fn(
            "pipeline %s: action=%s risk=%.2f findings=%d latency=%.1fms",
            self.name,
            action.value,
            risk_score,
            len(findings),
            latency_ms,
        )

        return result

    @abstractmethod
    def _execute(self, input_data: Any, context: ExecutionContext) -> list[Finding]:
        """Core pipeline logic. Return findings."""
        ...

    def _decide(self, risk_score: float, findings: list[Finding]) -> Action:
        t = self._config.thresholds
        if risk_score >= t.block:
            return Action.BLOCK
        if risk_score >= t.redact:
            return Action.REDACT
        if risk_score >= t.review:
            return Action.REVIEW
        return Action.ALLOW

    def _redact(self, input_data: Any, findings: list[Finding]) -> str | None:
        text = self._extract_text(input_data)
        if text is None:
            return None
        spans = sorted(
            [(f.span_start, f.span_end, f.replacement) for f in findings if f.score >= 0.5],
            key=lambda s: s[0],
            reverse=True,
        )
        result = text
        for start, end, replacement in spans:
            result = result[:start] + (replacement or "[REDACTED]") + result[end:]
        return result

    def _extract_text(self, input_data: Any) -> str | None:
        if isinstance(input_data, str):
            return input_data
        if isinstance(input_data, TaintedText):
            return input_data.text
        return None

    def _ensure_tainted(
        self,
        text: str | TaintedText,
        default_trust: TrustLevel = TrustLevel.USER,
        origin: str = "",
    ) -> TaintedText:
        if isinstance(text, TaintedText):
            return text
        return self._tagger.tag(text, default_trust, origin or self.name)
