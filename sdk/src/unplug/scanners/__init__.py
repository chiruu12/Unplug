"""Backward compatibility — use unplug.safeguards."""

from __future__ import annotations

import warnings

from unplug.safeguards.registry import SafeguardRegistry, ScannerRegistry

warnings.warn(
    "unplug.scanners is deprecated, use unplug.safeguards",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = ["SafeguardRegistry", "ScannerRegistry"]
