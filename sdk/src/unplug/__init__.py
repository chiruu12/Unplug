"""Unplug — Pull the plug on bad AI."""

from __future__ import annotations

from unplug.api.messages import BlockedContent, ContentOutcome, SafeContent
from unplug.config import (
    GuardConfig,
    MessageConfig,
    PipelineConfig,
    ScannerConfig,
    ThresholdConfig,
)
from unplug.config import (
    load as load_config,
)
from unplug.config.limits import LimitConfig
from unplug.core.context import ExecutionContext, ToolCall
from unplug.core.logging import correlation_scope, get_correlation_id
from unplug.core.models import ModelProvider, ModelRegistry, ModelSpec
from unplug.core.secrets import SecretsRegistry
from unplug.core.stats import MetricsCollector
from unplug.core.taint import Tagger, TaintedText, TrustLevel
from unplug.guard import Guard
from unplug.models import Action, Finding, ScanResult, Source
from unplug.safeguards import SafeguardRegistry, ScannerRegistry
from unplug.safeguards.base import BaseScanner, ModelScanner, RegexScanner

__all__ = [
    "Action",
    "BaseScanner",
    "BlockedContent",
    "ContentOutcome",
    "ExecutionContext",
    "Finding",
    "Guard",
    "GuardConfig",
    "LimitConfig",
    "MessageConfig",
    "SafeguardRegistry",
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
    "SafeContent",
]
__version__ = "0.2.0"
