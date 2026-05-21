"""Guard and pipeline configuration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from unplug.config.cache import CacheConfig
from unplug.config.limits import LimitConfig
from unplug.config.messages import MessageConfig
from unplug.config.policy import ScanPolicy


class ThresholdConfig(BaseModel):
    """Action thresholds for deciding ALLOW/REVIEW/REDACT/BLOCK."""

    model_config = {"frozen": True}

    block: float = 0.8
    redact: float = 0.5
    review: float = 0.3


class ScannerConfig(BaseModel):
    """Per-safeguard configuration."""

    model_config = {"frozen": True}

    base_score: float = 0.85
    trust_boost: float = 0.10
    enabled: bool = True
    normalize: bool = False


class PipelineConfig(BaseModel):
    """Pipeline-level configuration."""

    model_config = {"frozen": True}

    thresholds: ThresholdConfig = Field(default_factory=ThresholdConfig)
    policy: ScanPolicy = Field(default_factory=ScanPolicy)
    fail_closed: bool = True
    judge_timeout: float = 30.0


class GuardConfig(BaseModel):
    """Top-level configuration for the Guard."""

    scanners: list[str] = Field(
        default_factory=lambda: ["injection", "destructive", "leakage", "harmful"]
    )
    mode: str = "local"
    server_url: str | None = None
    server_api_key: str | None = None
    fail_closed: bool = True
    pipeline: PipelineConfig = Field(default_factory=PipelineConfig)
    policy: ScanPolicy = Field(
        default_factory=ScanPolicy,
        description="Default scan policy; per-request overrides via ScanRequest",
    )
    cache: CacheConfig = Field(default_factory=CacheConfig)
    scanner_configs: dict[str, ScannerConfig] = Field(default_factory=dict)
    limits: LimitConfig = Field(default_factory=LimitConfig)
    messages: MessageConfig = Field(default_factory=MessageConfig)
    judge_enabled: bool = False
    judge_low: float = 0.3
    judge_high: float = 0.8

    def get_scanner_config(self, name: str) -> ScannerConfig:
        return self.scanner_configs.get(name, ScannerConfig())

    @classmethod
    def from_file(cls, path: str | Path) -> GuardConfig:
        from unplug.config.loader import load

        return load(file_path=path)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GuardConfig:
        from unplug.config.loader import build_config

        return build_config(data)
