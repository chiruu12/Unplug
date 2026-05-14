"""v2 Scanner protocol — context-aware scanning with TaintedText + ExecutionContext."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from unplug.core.context import ExecutionContext
from unplug.core.taint import TaintedText
from unplug.models import Finding


@runtime_checkable
class Scanner(Protocol):
    """v2 scanner interface: receives TaintedText + ExecutionContext."""

    name: str

    def scan(self, text: TaintedText, context: ExecutionContext) -> list[Finding]:
        """Scan tainted text with full execution context. Must be thread-safe."""
        ...
