"""Metrics and statistics tracking for scanners and pipelines."""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from dataclasses import dataclass


@dataclass
class ScannerStats:
    """Per-scanner statistics."""

    scans: int = 0
    findings: int = 0
    total_latency_ms: float = 0.0

    @property
    def avg_latency_ms(self) -> float:
        return self.total_latency_ms / self.scans if self.scans else 0.0

    @property
    def hit_rate(self) -> float:
        return self.findings / self.scans if self.scans else 0.0

    def to_dict(self) -> dict:
        return {
            "scans": self.scans,
            "findings": self.findings,
            "avg_latency_ms": round(self.avg_latency_ms, 3),
            "hit_rate": round(self.hit_rate, 4),
        }


@dataclass
class PipelineStats:
    """Per-pipeline statistics."""

    runs: int = 0
    total_latency_ms: float = 0.0
    blocked: int = 0
    redacted: int = 0
    reviewed: int = 0
    allowed: int = 0

    @property
    def avg_latency_ms(self) -> float:
        return self.total_latency_ms / self.runs if self.runs else 0.0

    def to_dict(self) -> dict:
        return {
            "runs": self.runs,
            "avg_latency_ms": round(self.avg_latency_ms, 3),
            "blocked": self.blocked,
            "redacted": self.redacted,
            "reviewed": self.reviewed,
            "allowed": self.allowed,
        }


class MetricsCollector:
    """Thread-safe metrics collection across scanners and pipelines."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._scanners: dict[str, ScannerStats] = defaultdict(ScannerStats)
        self._pipelines: dict[str, PipelineStats] = defaultdict(PipelineStats)
        self._start_time = time.monotonic()

    def record_scanner(self, name: str, *, findings_count: int, latency_ms: float) -> None:
        with self._lock:
            s = self._scanners[name]
            s.scans += 1
            s.findings += findings_count
            s.total_latency_ms += latency_ms

    def record_pipeline(self, name: str, *, action: str, latency_ms: float) -> None:
        with self._lock:
            p = self._pipelines[name]
            p.runs += 1
            p.total_latency_ms += latency_ms
            if action == "block":
                p.blocked += 1
            elif action == "redact":
                p.redacted += 1
            elif action == "review":
                p.reviewed += 1
            else:
                p.allowed += 1

    def scanner_stats(self, name: str) -> ScannerStats:
        with self._lock:
            return self._scanners[name]

    def pipeline_stats(self, name: str) -> PipelineStats:
        with self._lock:
            return self._pipelines[name]

    def snapshot(self) -> dict:
        """Full metrics snapshot — safe to serialize."""
        with self._lock:
            uptime = time.monotonic() - self._start_time
            return {
                "uptime_seconds": round(uptime, 1),
                "scanners": {k: v.to_dict() for k, v in self._scanners.items()},
                "pipelines": {k: v.to_dict() for k, v in self._pipelines.items()},
            }

    def reset(self) -> None:
        with self._lock:
            self._scanners.clear()
            self._pipelines.clear()
            self._start_time = time.monotonic()


def timed_scan(name: str, collector: MetricsCollector | None = None):
    """Decorator/context-manager that records scanner latency + hit count."""

    class _Timer:
        def __init__(self) -> None:
            self._start = 0.0
            self.findings_count = 0

        def __enter__(self) -> _Timer:
            self._start = time.perf_counter()
            return self

        def __exit__(self, *exc) -> None:
            elapsed = (time.perf_counter() - self._start) * 1000
            if collector is not None:
                collector.record_scanner(
                    name, findings_count=self.findings_count, latency_ms=elapsed
                )

    return _Timer()
