"""Configuration system — replaces hardcoded thresholds with composable config objects."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ThresholdConfig:
    """Action thresholds for deciding ALLOW/REVIEW/REDACT/BLOCK."""

    block: float = 0.8
    redact: float = 0.5
    review: float = 0.3


@dataclass(frozen=True)
class ScannerConfig:
    """Per-scanner configuration — passed to BaseScanner at construction."""

    base_score: float = 0.85
    trust_boost: float = 0.10
    enabled: bool = True
    normalize: bool = False


@dataclass(frozen=True)
class PipelineConfig:
    """Pipeline-level configuration."""

    thresholds: ThresholdConfig = field(default_factory=ThresholdConfig)
    fail_closed: bool = True


@dataclass
class GuardConfig:
    """Top-level configuration for the Guard."""

    scanners: list[str] = field(
        default_factory=lambda: ["injection", "destructive", "leakage", "harmful"]
    )
    mode: str = "local"
    server_url: str | None = None
    fail_closed: bool = True
    pipeline: PipelineConfig = field(default_factory=PipelineConfig)
    scanner_configs: dict[str, ScannerConfig] = field(default_factory=dict)

    def get_scanner_config(self, name: str) -> ScannerConfig:
        return self.scanner_configs.get(name, ScannerConfig())
