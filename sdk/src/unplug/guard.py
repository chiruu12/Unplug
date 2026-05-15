"""Guard — main entry point for Unplug."""

from __future__ import annotations

from unplug.core.config import GuardConfig, PipelineConfig
from unplug.core.context import ExecutionContext, ToolCall
from unplug.core.normalize import Normalizer
from unplug.core.secrets import SecretsSanitizer, SecretsRegistry
from unplug.core.stats import MetricsCollector
from unplug.core.taint import TaintedText
from unplug.models import ScanRequest, ScanResult, Source
from unplug.pipelines.input import InputPipeline
from unplug.pipelines.output import OutputPipeline
from unplug.pipelines.toolcall import ToolCallPipeline
from unplug.scanners import ScannerRegistry


class Guard:
    """Scan untrusted text for prompt injection, destructive actions, leakage, and harmful output."""

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
    ) -> None:
        cfg = config or GuardConfig()
        if scanners is not None:
            cfg.scanners = scanners
        cfg.mode = mode
        if server_url is not None:
            cfg.server_url = server_url
        cfg.fail_closed = fail_mode == "closed"

        self._config = cfg
        self._metrics = MetricsCollector()
        self._secrets_registry = secrets_registry or SecretsRegistry()
        self._context = ExecutionContext(secrets_registry=self._secrets_registry)

        self._registry = ScannerRegistry(metrics=self._metrics)
        v2_scanners = self._registry.get_many(
            cfg.scanners, configs=cfg.scanner_configs
        )

        self._input_pipeline = InputPipeline(
            scanners=v2_scanners,
            normalizer=Normalizer(),
            config=cfg.pipeline,
            metrics=self._metrics,
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
    def metrics(self) -> MetricsCollector:
        return self._metrics

    @property
    def scanner_registry(self) -> ScannerRegistry:
        return self._registry

    def scan(self, text: str, source: Source | str = Source.USER) -> ScanResult:
        """Scan text and return findings with optional redaction."""
        if isinstance(source, str):
            source = Source(source)
        return self._input_pipeline.run(text, source=source, context=self._context)

    def scan_output(self, text: str | TaintedText) -> ScanResult:
        """Scan agent output for secrets and data leakage."""
        return self._output_pipeline.run(text, context=self._context)

    def check_tool_call(
        self,
        tool_name: str,
        arguments: dict,
        *,
        taint_sources: list[TaintedText] | None = None,
    ) -> ScanResult:
        """Check a proposed tool call for destructive, taint, and financial risks."""
        tc = ToolCall(
            tool_name=tool_name,
            arguments=arguments,
            taint_sources=taint_sources or [],
        )
        return self._tool_pipeline.run(tc, context=self._context)

    def scan_request(self, request: ScanRequest) -> ScanResult:
        """Scan from a ScanRequest object."""
        return self.scan(request.text, request.source)

    def stats(self) -> dict:
        """Full metrics snapshot."""
        return self._metrics.snapshot()

    @classmethod
    def init(cls, **kwargs) -> Guard:
        """Initialize a global Guard and auto-instrument detected frameworks."""
        cls._instance = Guard(**kwargs)
        return cls._instance

    @classmethod
    def get(cls) -> Guard:
        """Get the global Guard instance."""
        if cls._instance is None:
            raise RuntimeError("Guard.init() has not been called")
        return cls._instance
