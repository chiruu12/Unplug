"""Scanner protocol — all scanners implement this interface."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from unplug.models import Finding, Source


@runtime_checkable
class Scanner(Protocol):
    """Interface for all Unplug scanners."""

    name: str

    def scan(self, text: str, source: Source) -> list[Finding]:
        """Scan text and return findings. Must be thread-safe."""
        ...
