"""Guard — main entry point for Unplug."""

from __future__ import annotations

from typing import Any

from unplug.api.enums import Action, Source
from unplug.api.types import Finding, ScanRequest, ScanResult
from unplug.config.guard import GuardConfig
from unplug.core.context import ExecutionContext, ToolCall
from unplug.core.judge import JudgeProvider
from unplug.core.limits import LimitConfig, LimitViolation
from unplug.core.logging import correlation_scope, get_logger
from unplug.core.normalize import Normalizer
from unplug.core.secrets import SecretsRegistry, SecretsSanitizer
from unplug.core.stats import MetricsCollector
from unplug.core.taint import TaintedText
from unplug.pipelines.input import InputPipeline
from unplug.pipelines.output import OutputPipeline
from unplug.pipelines.toolcall import ToolCallPipeline
from unplug.safeguards import ScannerRegistry

_log = get_logger("guard")


def _fail_closed(exc: Exception) -> ScanResult:
    return ScanResult(
        safe=False,
        action=Action.BLOCK,
        risk_score=1.0,
        findings=[
            Finding(
                category="guard",
                subcategory="guard_error",
                stage="error",
                span_start=0,
                span_end=0,
                score=1.0,
                evidence=f"Guard failed: {type(exc).__name__}",
            )
        ],
        latency_ms=0.0,
    )


def _limit_result(violation: LimitViolation, text_len: int = 0) -> ScanResult:
    return ScanResult(
        safe=False,
        action=Action.BLOCK,
        risk_score=1.0,
        findings=[
            Finding(
                category="limits",
                subcategory=violation.kind,
                stage="limits",
                span_start=0,
                span_end=text_len,
                score=1.0,
                evidence=violation.message,
            )
        ],
        latency_ms=0.0,
        stages_run=["limits"],
    )


class Guard:
    """Entry point for Unplug — scans text, output, and tool calls."""

    _instance: Guard | None = None

    def __init__(
        self,
        *,
        scanners: list[str] | None = None,
        mode: str = "local",
        server_url: str | None = None,
        fail_mode: str = "closed",
        secrets_registry: SecretsRegistry | None = None,
        config: GuardConfig | None = None,
        limits: LimitConfig | None = None,
        judge: JudgeProvider | Any | None = None,
    ) -> None:
        cfg = config or GuardConfig()
        overrides: dict[str, Any] = {"mode": mode, "fail_closed": fail_mode == "closed"}
        if scanners is not None:
            overrides["scanners"] = scanners
        if server_url is not None:
            overrides["server_url"] = server_url
        if limits is not None:
            overrides["limits"] = limits
        cfg = cfg.model_copy(update=overrides)

        self._config = cfg
        self._limits = cfg.limits
        self._judge = judge
        self._metrics = MetricsCollector()
        self._secrets_registry = secrets_registry or SecretsRegistry()
        self._context = ExecutionContext(secrets_registry=self._secrets_registry)

        self._registry = ScannerRegistry(metrics=self._metrics)
        v2_scanners = self._registry.get_many(cfg.scanners, configs=cfg.scanner_configs)

        self._input_pipeline = InputPipeline(
            scanners=v2_scanners,
            normalizer=Normalizer(),
            config=cfg.pipeline,
            metrics=self._metrics,
            judge=judge if cfg.judge_enabled or judge is not None else None,
            judge_low=cfg.judge_low,
            judge_high=cfg.judge_high,
        )

        self._output_pipeline = OutputPipeline(
            secrets_sanitizer=SecretsSanitizer(self._secrets_registry),
            leakage_scanner=self._registry.get("leakage"),
            secrets_scanner=self._registry.get("secrets"),
            config=cfg.pipeline,
            metrics=self._metrics,
        )

        self._tool_pipeline = ToolCallPipeline(
            destructive_scanner=self._registry.get("destructive"),
            financial_scanner=self._registry.get("financial"),
            config=cfg.pipeline,
            metrics=self._metrics,
        )

    @property
    def context(self) -> ExecutionContext:
        return self._context

    @property
    def secrets(self) -> SecretsRegistry:
        return self._secrets_registry

    @property
    def limits(self) -> LimitConfig:
        return self._limits

    @property
    def metrics(self) -> MetricsCollector:
        return self._metrics

    @property
    def scanner_registry(self) -> ScannerRegistry:
        return self._registry

    @property
    def config(self) -> GuardConfig:
        return self._config

    def scan(self, text: str, source: Source | str = Source.USER) -> ScanResult:
        """Scan text and return findings with optional redaction."""
        if isinstance(source, str):
            source = Source(source)
        violation = self._limits.check_input_length(text)
        if violation is not None:
            return _limit_result(violation, len(text))
        try:
            with correlation_scope():
                return self._input_pipeline.run(text, source=source, context=self._context)
        except Exception as exc:
            _log.error("guard.scan failed: %s", exc)
            return _fail_closed(exc)

    def scan_output(self, text: str | TaintedText) -> ScanResult:
        """Scan agent output for secrets and data leakage."""
        raw = text.text if isinstance(text, TaintedText) else text
        violation = self._limits.check_input_length(raw)
        if violation is not None:
            return _limit_result(violation, len(raw))
        try:
            with correlation_scope():
                return self._output_pipeline.run(text, context=self._context)
        except Exception as exc:
            _log.error("guard.scan_output failed: %s", exc)
            return _fail_closed(exc)

    def check_tool_call(
        self,
        tool_name: str,
        arguments: dict,
        *,
        taint_sources: list[TaintedText] | None = None,
    ) -> ScanResult:
        """Check a proposed tool call for destructive, taint, and financial risks."""
        if not self._limits.is_tool_allowed(tool_name):
            return _limit_result(
                LimitViolation(
                    kind="tool_blocked",
                    limit=0,
                    actual=0,
                    message=f"Tool not allowed: {tool_name}",
                ),
            )
        count_violation = self._limits.check_tool_call_count(len(self._context.tool_calls) + 1)
        if count_violation is not None:
            return _limit_result(count_violation)
        tc = ToolCall(
            tool_name=tool_name,
            arguments=arguments,
            taint_sources=taint_sources or [],
        )
        try:
            with correlation_scope():
                result = self._tool_pipeline.run(tc, context=self._context)
                if result.safe:
                    self._context.add_tool_call(tc)
                return result
        except Exception as exc:
            _log.error("guard.check_tool_call failed: %s", exc)
            return _fail_closed(exc)

    def scan_request(self, request: ScanRequest) -> ScanResult:
        """Scan from a ScanRequest object."""
        return self.scan(request.text, request.source)

    def stats(self) -> dict:
        """Full metrics snapshot."""
        return self._metrics.snapshot()

    @classmethod
    def init(cls, **kwargs: Any) -> Guard:
        """Initialize a global Guard and auto-instrument detected frameworks."""
        cls._instance = Guard(**kwargs)
        return cls._instance

    @classmethod
    def get(cls) -> Guard:
        """Get the global Guard instance."""
        if cls._instance is None:
            raise RuntimeError("Guard.init() has not been called")
        return cls._instance
