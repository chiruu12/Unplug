"""Input pipeline — taint, normalize, scan, decide."""

from __future__ import annotations

from typing import Any

from unplug.core.config import PipelineConfig
from unplug.core.context import ExecutionContext
from unplug.core.normalize import Normalizer
from unplug.core.stats import MetricsCollector
from unplug.core.taint import TaintedText, TrustLevel, trust_level_from_source
from unplug.models import Finding, Source
from unplug.pipelines.base import BasePipeline
from unplug.scanners.base import BaseScanner


class InputPipeline(BasePipeline):
    name = "input"

    def __init__(
        self,
        scanners: list[BaseScanner],
        normalizer: Normalizer | None = None,
        config: PipelineConfig | None = None,
        metrics: MetricsCollector | None = None,
    ) -> None:
        super().__init__(config=config, metrics=metrics)
        self._scanners = scanners
        self._normalizer = normalizer or Normalizer()

    def run(
        self,
        text: str | TaintedText,
        *,
        source: Source | TrustLevel = TrustLevel.USER,
        context: ExecutionContext | None = None,
    ) -> Any:
        if isinstance(text, str):
            if isinstance(source, Source):
                trust = trust_level_from_source(source)
            else:
                trust = source
            tainted = self._tagger.tag(text, trust, "input_pipeline")
        else:
            tainted = text

        return super().run(tainted, context=context)

    def _execute(self, input_data: TaintedText, context: ExecutionContext) -> list[Finding]:
        findings: list[Finding] = []
        for scanner in self._scanners:
            findings.extend(scanner.scan(input_data, context))
        return findings
