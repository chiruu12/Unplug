"""Unplug — Pull the plug on bad AI."""

from unplug.core.context import ExecutionContext, ToolCall
from unplug.core.secrets import SecretsRegistry
from unplug.core.taint import Tagger, TaintedText, TrustLevel
from unplug.guard import Guard
from unplug.models import Action, Finding, ScanResult, Source

__all__ = [
    "Action",
    "ExecutionContext",
    "Finding",
    "Guard",
    "ScanResult",
    "SecretsRegistry",
    "Source",
    "Tagger",
    "TaintedText",
    "ToolCall",
    "TrustLevel",
]
__version__ = "0.2.0"
