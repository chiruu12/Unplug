"""Guard — main entry point for Unplug."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from unplug.core.context import ExecutionContext, ToolCall
from unplug.core.normalize import Normalizer
from unplug.core.secrets import SecretsSanitizer, SecretsRegistry
from unplug.core.taint import Tagger, TaintedText, TrustLevel, trust_level_from_source
from unplug.models import Action, ScanRequest, ScanResult, Source
from unplug.pipelines.input import InputPipeline
from unplug.pipelines.output import OutputPipeline
from unplug.pipelines.toolcall import ToolCallPipeline

if TYPE_CHECKING:
    from unplug.scanners.base import Scanner


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
    ) -> None:
        self._mode = mode
        self._server_url = server_url
        self._fail_mode = fail_mode
        self._secrets_registry = secrets_registry or SecretsRegistry()
        self._context = ExecutionContext(secrets_registry=self._secrets_registry)

        scanner_names = scanners or ["injection", "destructive", "leakage", "harmful"]
        v2_scanners = _load_v2_scanners(scanner_names)

        self._input_pipeline = InputPipeline(
            scanners=v2_scanners,
            normalizer=Normalizer(),
            tagger=Tagger(),
        )

        self._output_pipeline = OutputPipeline(
            secrets_sanitizer=SecretsSanitizer(self._secrets_registry),
            leakage_scanner=_get_scanner("leakage"),
            secrets_scanner=_get_scanner("secrets"),
        )

        self._tool_pipeline = ToolCallPipeline(
            destructive_scanner=_get_scanner("destructive"),
            financial_scanner=_get_scanner("financial"),
        )

    @property
    def context(self) -> ExecutionContext:
        return self._context

    @property
    def secrets(self) -> SecretsRegistry:
        return self._secrets_registry

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

    @classmethod
    def init(cls, **kwargs) -> Guard:
        """Initialize a global Guard and auto-instrument detected frameworks."""
        cls._instance = Guard(**kwargs)
        _auto_instrument(cls._instance)
        return cls._instance

    @classmethod
    def get(cls) -> Guard:
        """Get the global Guard instance."""
        if cls._instance is None:
            raise RuntimeError("Guard.init() has not been called")
        return cls._instance


def _get_scanner(name: str):
    """Lazy-load a scanner by name."""
    if name == "injection":
        from unplug.scanners.injection import InjectionScanner
        return InjectionScanner()
    if name == "destructive":
        from unplug.scanners.destructive import DestructiveScanner
        return DestructiveScanner()
    if name == "leakage":
        from unplug.scanners.leakage import LeakageScanner
        return LeakageScanner()
    if name == "harmful":
        from unplug.scanners.harmful import HarmfulScanner
        return HarmfulScanner()
    if name == "financial":
        from unplug.scanners.financial import FinancialScanner
        return FinancialScanner()
    if name == "secrets":
        from unplug.scanners.secrets import SecretsScanner
        return SecretsScanner()
    return None


def _load_v2_scanners(names: list[str]) -> list:
    scanners = []
    for name in names:
        scanner = _get_scanner(name)
        if scanner is not None:
            scanners.append(scanner)
    return scanners


def _auto_instrument(guard: Guard) -> None:
    """Patch detected frameworks to route through the guard."""
    # TODO: auto-detect and patch LangChain, CrewAI, LlamaIndex
    pass
