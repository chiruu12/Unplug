"""Guard — main entry point for Unplug."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from unplug.models import Action, ScanRequest, ScanResult, Source

if TYPE_CHECKING:
    from unplug.scanner import Scanner


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
    ) -> None:
        self._mode = mode
        self._server_url = server_url
        self._fail_mode = fail_mode
        self._scanners: list[Scanner] = []
        self._load_scanners(scanners or ["injection", "destructive", "leakage", "harmful"])

    def _load_scanners(self, names: list[str]) -> None:
        for name in names:
            scanner = _get_scanner(name)
            if scanner is not None:
                self._scanners.append(scanner)

    def scan(self, text: str, source: Source | str = Source.USER) -> ScanResult:
        """Scan text and return findings with optional redaction."""
        if isinstance(source, str):
            source = Source(source)

        start = time.perf_counter()
        all_findings = []
        stages_run = []

        for scanner in self._scanners:
            findings = scanner.scan(text, source)
            if findings:
                all_findings.extend(findings)
                stages_run.append(scanner.name)

        latency_ms = (time.perf_counter() - start) * 1000
        risk_score = max((f.score for f in all_findings), default=0.0)
        action = _decide_action(risk_score, all_findings)
        redacted = _redact(text, all_findings) if all_findings else None

        return ScanResult(
            safe=action == Action.ALLOW,
            action=action,
            risk_score=risk_score,
            findings=all_findings,
            redacted_text=redacted,
            latency_ms=latency_ms,
            stages_run=stages_run,
        )

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
    return None


def _decide_action(risk_score: float, findings: list) -> Action:
    if risk_score >= 0.8:
        return Action.BLOCK
    if risk_score >= 0.5:
        return Action.REDACT
    if risk_score >= 0.3:
        return Action.REVIEW
    return Action.ALLOW


def _redact(text: str, findings: list) -> str:
    spans = sorted(
        [(f.span_start, f.span_end, f.replacement) for f in findings if f.score >= 0.5],
        key=lambda s: s[0],
        reverse=True,
    )
    result = text
    for start, end, replacement in spans:
        result = result[:start] + (replacement or "[REDACTED]") + result[end:]
    return result


def _auto_instrument(guard: Guard) -> None:
    """Patch detected frameworks to route through the guard."""
    # TODO: auto-detect and patch LangChain, CrewAI, LlamaIndex
    pass
