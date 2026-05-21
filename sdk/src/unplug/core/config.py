"""Re-export config from unplug.config (backward compatibility)."""

from __future__ import annotations

from unplug.config.guard import GuardConfig, PipelineConfig, ScannerConfig, ThresholdConfig
from unplug.config.policy import ScanPolicy
from unplug.config.loader import build_config, load, load_from_env, load_from_file
from unplug.config.messages import MessageConfig

__all__ = [
    "GuardConfig",
    "MessageConfig",
    "PipelineConfig",
    "ScannerConfig",
    "ScanPolicy",
    "ThresholdConfig",
    "build_config",
    "load",
    "load_from_env",
    "load_from_file",
]
