"""Tool call pipeline — destructive check, taint check, financial check."""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING

from unplug.core.context import ExecutionContext, ToolCall
from unplug.core.taint import Tagger, TaintedText, TrustLevel
from unplug.models import Action, Finding, ScanResult

if TYPE_CHECKING:
    from unplug.scanners.destructive import DestructiveScanner
    from unplug.scanners.financial import FinancialScanner


class ToolCallPipeline:
    def __init__(
        self,
        destructive_scanner: DestructiveScanner | None = None,
        financial_scanner: FinancialScanner | None = None,
    ) -> None:
        self._destructive = destructive_scanner
        self._financial = financial_scanner
        self._tagger = Tagger()

    def run(
        self,
        tool_call: ToolCall,
        *,
        context: ExecutionContext | None = None,
    ) -> ScanResult:
        start = time.perf_counter()
        ctx = context or ExecutionContext()

        scan_text = f"{tool_call.tool_name} {json.dumps(tool_call.arguments)}"
        tainted = self._tagger.tag(scan_text, TrustLevel.USER, "tool_call_pipeline")

        all_findings: list[Finding] = []
        stages_run: list[str] = []

        if self._destructive:
            findings = self._destructive.scan(tainted, ctx)
            if findings:
                all_findings.extend(findings)
                stages_run.append("destructive")

        taint_findings = self._check_taint(tool_call, all_findings)
        if taint_findings:
            all_findings.extend(taint_findings)
            stages_run.append("taint_check")

        if self._financial:
            findings = self._financial.scan(tainted, ctx)
            if findings:
                all_findings.extend(findings)
                stages_run.append("financial")

        latency_ms = (time.perf_counter() - start) * 1000
        risk_score = max((f.score for f in all_findings), default=0.0)

        if risk_score >= 0.8:
            action = Action.BLOCK
        elif risk_score >= 0.5:
            action = Action.REVIEW
        elif risk_score >= 0.3:
            action = Action.REVIEW
        else:
            action = Action.ALLOW

        return ScanResult(
            safe=action == Action.ALLOW,
            action=action,
            risk_score=risk_score,
            findings=all_findings,
            redacted_text=None,
            latency_ms=latency_ms,
            stages_run=stages_run,
        )

    def _check_taint(
        self, tool_call: ToolCall, existing_findings: list[Finding]
    ) -> list[Finding]:
        findings: list[Finding] = []
        has_destructive = any(f.category == "destructive" for f in existing_findings)

        for source in tool_call.taint_sources:
            if source.trust_level in (TrustLevel.EXTERNAL, TrustLevel.UNKNOWN):
                score = 0.90 if has_destructive else 0.60
                findings.append(Finding(
                    category="taint",
                    subcategory="untrusted_source_in_tool_call",
                    stage="taint_check",
                    span_start=0,
                    span_end=0,
                    score=score,
                    evidence=(
                        f"Tool call arguments influenced by untrusted {source.trust_level.value} "
                        f"data from '{source.origin}'"
                    ),
                ))
            elif source.trust_level == TrustLevel.RETRIEVED and has_destructive:
                findings.append(Finding(
                    category="taint",
                    subcategory="retrieved_source_in_destructive_call",
                    stage="taint_check",
                    span_start=0,
                    span_end=0,
                    score=0.85,
                    evidence=(
                        f"Destructive tool call arguments sourced from retrieved data "
                        f"('{source.origin}')"
                    ),
                ))

        return findings
