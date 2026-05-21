"""Guard — main entry point for Unplug."""

from __future__ import annotations

import os
import threading
from typing import Any, ClassVar

from unplug.api.enums import Action, Source
from unplug.api.types import Finding, ScanRequest, ScanResult
from unplug.client import UnplugClient
from unplug.config.guard import GuardConfig
from unplug.config.policy import ScanPolicy
from unplug.core.cache import SafePrefixState, ScanCache, merge_suffix_result
from unplug.core.context import ExecutionContext, ToolCall
from unplug.core.encodings import EncodingClassifier
from unplug.core.judge import JudgeProvider
from unplug.core.limits import LimitConfig, LimitViolation
from unplug.core.logging import correlation_scope, get_logger
from unplug.core.normalize import Normalizer
from unplug.core.policy import policy_from_request
from unplug.core.privacy import NullPrivacyFilter, PrivacyFilterService
from unplug.core.secrets import SecretsRegistry, SecretsSanitizer
from unplug.core.stats import MetricsCollector
from unplug.core.taint import TaintedText
from unplug.core.versions import MODEL_VERSION_LOCAL, NORMALIZER_VERSION
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
    _lock: ClassVar[threading.Lock] = threading.Lock()

    def __init__(
        self,
        *,
        scanners: list[str] | None = None,
        mode: str = "local",
        server_url: str | None = None,
        server_api_key: str | None = None,
        fail_mode: str = "closed",
        secrets_registry: SecretsRegistry | None = None,
        config: GuardConfig | None = None,
        limits: LimitConfig | None = None,
        judge: JudgeProvider | Any | None = None,
        privacy_filter: PrivacyFilterService | None = None,
        shared_scan_cache: ScanCache | None = None,
        encoding_classifier: EncodingClassifier | None = None,
        scan_encodings: bool = True,
    ) -> None:
        cfg = config or GuardConfig()
        overrides: dict[str, Any] = {"mode": mode, "fail_closed": fail_mode == "closed"}
        if scanners is not None:
            overrides["scanners"] = scanners
        if server_url is not None:
            overrides["server_url"] = server_url
        if server_api_key is not None:
            overrides["server_api_key"] = server_api_key
        if limits is not None:
            overrides["limits"] = limits
        cfg = cfg.model_copy(update=overrides)

        self._config = cfg
        self._limits = cfg.limits
        self._judge = judge
        self._metrics = MetricsCollector()
        self._secrets_registry = secrets_registry or SecretsRegistry()
        scan_cache = (
            ScanCache(max_chunk_entries=cfg.cache.max_chunk_entries) if cfg.cache.enabled else None
        )
        self._context = ExecutionContext(
            secrets_registry=self._secrets_registry,
            scan_cache=scan_cache,
        )
        # Privacy Filter loads only with unplug-safeguard model (not in public SDK v1).
        self._privacy_filter = privacy_filter or NullPrivacyFilter()
        self._shared_scan_cache = shared_scan_cache

        self._server_client: UnplugClient | None = None
        if cfg.mode == "server":
            url = cfg.server_url or os.environ.get("UNPLUG_SERVER_URL", "http://localhost:8000")
            key = cfg.server_api_key or os.environ.get("UNPLUG_API_KEY")
            self._server_client = UnplugClient(base_url=url, api_key=key)

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
            encoding_classifier=encoding_classifier,
            scan_encodings=scan_encodings,
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
        return self.scan_request(self._build_scan_request(text, source))

    def _build_scan_request(
        self,
        text: str,
        source: Source = Source.USER,
    ) -> ScanRequest:
        ctx = self._context
        policy = self._config.policy
        return ScanRequest(
            text=text,
            source=source,
            session_id=ctx.session_id,
            agent_id=ctx.agent_id,
            turn_id=ctx.turn_id,
            document_id=ctx.document_id,
            block_coverage_ratio=policy.block_coverage_ratio,
            redact_threshold=policy.redact_threshold,
            review_threshold=policy.review_threshold,
            block_threshold=policy.block_threshold,
        )

    def _apply_request_context(self, request: ScanRequest) -> ScanPolicy:
        ctx = self._context
        if request.session_id:
            ctx.session_id = request.session_id
        if request.agent_id is not None:
            ctx.agent_id = request.agent_id
        if request.turn_id is not None:
            ctx.turn_id = request.turn_id
        if request.document_id is not None:
            ctx.document_id = request.document_id
        policy = policy_from_request(request, self._config.policy)
        ctx.scan_policy = policy
        return policy

    def _request_context(self, request: ScanRequest, *, isolated: bool) -> ExecutionContext:
        policy = policy_from_request(request, self._config.policy)
        if not isolated:
            self._apply_request_context(request)
            return self._context

        cache: ScanCache | None = None
        if self._config.cache.enabled:
            cache = self._shared_scan_cache or ScanCache(
                max_chunk_entries=self._config.cache.max_chunk_entries
            )

        return ExecutionContext(
            session_id=request.session_id or self._context.session_id,
            agent_id=request.agent_id if request.agent_id is not None else self._context.agent_id,
            turn_id=request.turn_id if request.turn_id is not None else self._context.turn_id,
            document_id=(
                request.document_id
                if request.document_id is not None
                else self._context.document_id
            ),
            secrets_registry=self._secrets_registry,
            scan_policy=policy,
            scan_cache=cache,
        )

    def _model_version_for_cache(self) -> str:
        return MODEL_VERSION_LOCAL

    def _run_input_with_cache(self, request: ScanRequest, ctx: ExecutionContext) -> ScanResult:
        cache = ctx.scan_cache
        if cache is None or not self._config.cache.enabled:
            return self._input_pipeline.run(
                request.text,
                source=request.source,
                context=ctx,
            )

        parts = cache.cache_key_parts(
            request.text,
            document_id=request.document_id,
            normalizer_version=NORMALIZER_VERSION,
            model_version=self._model_version_for_cache(),
        )
        hit = cache.get_chunk(parts.full_hash)
        if hit is not None:
            return hit

        prefix_state = cache.get_safe_prefix(parts)
        prefix_len = 0
        if prefix_state is not None and prefix_state.verify(request.text):
            prefix_len = prefix_state.prefix_len

        if 0 < prefix_len < len(request.text):
            suffix_result = self._input_pipeline.run(
                request.text[prefix_len:],
                source=request.source,
                context=ctx,
            )
            result = merge_suffix_result(suffix_result, prefix_len)
        else:
            result = self._input_pipeline.run(
                request.text,
                source=request.source,
                context=ctx,
            )

        if cache.should_advance_prefix(
            result.action,
            advance_on_redact=self._config.cache.advance_prefix_on_redact,
        ):
            cache.set_safe_prefix(
                parts,
                SafePrefixState.from_text(request.text, len(request.text)),
            )
        cache.set_chunk(parts.full_hash, result)
        return result

    def scan_output(self, text: str | TaintedText) -> ScanResult:
        """Scan agent output for secrets and data leakage."""
        raw = text.text if isinstance(text, TaintedText) else text
        return self.scan_output_request(
            self._build_scan_request(raw, source=Source.TOOL_OUTPUT),
        )

    def scan_output_request(
        self,
        request: ScanRequest,
        *,
        isolated: bool = False,
    ) -> ScanResult:
        """Scan output from a ScanRequest (hosted server or local pipeline)."""
        violation = self._limits.check_input_length(request.text)
        if violation is not None:
            return _limit_result(violation, len(request.text))
        try:
            with correlation_scope():
                if self._server_client is not None:
                    return self._server_client.scan_output_request(request)
                ctx = self._request_context(request, isolated=isolated)
                body: str | TaintedText = request.text
                return self._output_pipeline.run(body, context=ctx)
        except Exception as exc:
            _log.error("guard.scan_output_request failed: %s", exc)
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

    def scan_request(
        self,
        request: ScanRequest,
        *,
        isolated: bool = False,
    ) -> ScanResult:
        """Scan from a ScanRequest object."""
        violation = self._limits.check_input_length(request.text)
        if violation is not None:
            return _limit_result(violation, len(request.text))
        try:
            with correlation_scope():
                if self._server_client is not None:
                    return self._server_client.scan_request(request)
                ctx = self._request_context(request, isolated=isolated)
                return self._run_input_with_cache(request, ctx)
        except Exception as exc:
            _log.error("guard.scan_request failed: %s", exc)
            return _fail_closed(exc)

    @property
    def is_server_mode(self) -> bool:
        return self._server_client is not None

    def stats(self) -> dict:
        """Full metrics snapshot."""
        return self._metrics.snapshot()

    @classmethod
    def init(cls, **kwargs: Any) -> Guard:
        """Initialize a global Guard and auto-instrument detected frameworks."""
        with cls._lock:
            cls._instance = Guard(**kwargs)
            return cls._instance

    @classmethod
    def get(cls) -> Guard:
        """Get the global Guard instance."""
        with cls._lock:
            if cls._instance is None:
                raise RuntimeError("Guard.init() has not been called")
            return cls._instance
