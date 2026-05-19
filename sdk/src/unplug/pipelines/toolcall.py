"""Tool call pipeline — destructive check, taint check, financial check."""

from __future__ import annotations

import json
from typing import Any

from unplug.core.config import PipelineConfig
from unplug.core.context import ExecutionContext, ToolCall
from unplug.core.stats import MetricsCollector
from unplug.core.taint import TrustLevel
from unplug.models import Action, Finding
from unplug.pipelines.base import BasePipeline
from unplug.scanners.base import BaseScanner


class ToolCallPipeline(BasePipeline):
    name = "toolcall"

    def __init__(
        self,
        destructive_scanner: BaseScanner | None = None,
        financial_scanner: BaseScanner | None = None,
        config: PipelineConfig | None = None,
        metrics: MetricsCollector | None = None,
    ) -> None:
        super().__init__(config=config, metrics=metrics)
        self._destructive = destructive_scanner
        self._financial = financial_scanner

    def run(
        self,
        tool_call: ToolCall,
        *,
        context: ExecutionContext | None = None,
    ) -> Any:
        return super().run(tool_call, context=context)

    def _execute(self, input_data: ToolCall, context: ExecutionContext) -> list[Finding]:
        scan_text = f"{input_data.tool_name} {json.dumps(input_data.arguments)}"
        tainted = self._tagger.tag(scan_text, TrustLevel.USER, "tool_call_pipeline")

        findings: list[Finding] = []

        if self._destructive:
            findings.extend(self._destructive.scan(tainted, context))

        findings.extend(self._check_taint(input_data, findings))

        if self._financial:
            findings.extend(self._financial.scan(tainted, context))

        return findings

    def _decide(self, risk_score: float, findings: list[Finding]) -> Action:
        t = self._config.thresholds
        if risk_score >= t.block:
            return Action.BLOCK
        if risk_score >= t.review:
            return Action.REVIEW
        return Action.ALLOW

    def _redact(self, input_data: Any, findings: list[Finding]) -> str | None:
        return None

    def _check_taint(self, tool_call: ToolCall, existing: list[Finding]) -> list[Finding]:
        findings: list[Finding] = []
        has_destructive = any(f.category == "destructive" for f in existing)

        for source in tool_call.taint_sources:
            if source.trust_level in (TrustLevel.EXTERNAL, TrustLevel.UNKNOWN):
                score = 0.90 if has_destructive else 0.60
                findings.append(
                    Finding(
                        category="taint",
                        subcategory="untrusted_source_in_tool_call",
                        stage="taint_check",
                        span_start=0,
                        span_end=0,
                        score=score,
                        evidence=(
                            f"Tool call arguments influenced by untrusted "
                            f"{source.trust_level.value} data from '{source.origin}'"
                        ),
                    )
                )
            elif source.trust_level == TrustLevel.RETRIEVED and has_destructive:
                findings.append(
                    Finding(
                        category="taint",
                        subcategory="retrieved_source_in_destructive_call",
                        stage="taint_check",
                        span_start=0,
                        span_end=0,
                        score=0.85,
                        evidence=(
                            f"Destructive tool call arguments sourced from "
                            f"retrieved data ('{source.origin}')"
                        ),
                    )
                )

        return findings
