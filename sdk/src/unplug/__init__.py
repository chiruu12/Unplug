"""Unplug — Pull the plug on bad AI."""

from __future__ import annotations

from unplug.core.config import GuardConfig, PipelineConfig, ScannerConfig, ThresholdConfig
from unplug.core.config_loader import load as load_config
from unplug.core.context import ExecutionContext, ToolCall
from unplug.core.logging import correlation_scope, get_correlation_id
from unplug.core.models import ModelProvider, ModelRegistry, ModelSpec
from unplug.core.secrets import SecretsRegistry
from unplug.core.stats import MetricsCollector
from unplug.core.taint import Tagger, TaintedText, TrustLevel
from unplug.guard import Guard
from unplug.models import Action, Finding, ScanResult, Source
from unplug.scanners import ScannerRegistry
from unplug.scanners.base import BaseScanner, ModelScanner, RegexScanner

__all__ = [
    "Action",
    "BaseScanner",
    "ExecutionContext",
    "Finding",
    "Guard",
    "GuardConfig",
    "MetricsCollector",
    "ModelProvider",
    "ModelRegistry",
    "ModelScanner",
    "ModelSpec",
    "PipelineConfig",
    "RegexScanner",
    "ScanResult",
    "ScannerConfig",
    "ScannerRegistry",
    "SecretsRegistry",
    "Source",
    "Tagger",
    "TaintedText",
    "ThresholdConfig",
    "ToolCall",
    "TrustLevel",
    "correlation_scope",
    "get_correlation_id",
    "load_config",
]
__version__ = "0.2.0"
