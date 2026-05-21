"""Backward compatibility — prefer unplug.safeguards for registry access."""

from __future__ import annotations

from unplug.safeguards.registry import SafeguardRegistry, ScannerRegistry

__all__ = ["SafeguardRegistry", "ScannerRegistry"]
