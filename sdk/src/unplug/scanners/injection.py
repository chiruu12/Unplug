"""Backward compatibility — use unplug.safeguards.injection."""

from __future__ import annotations

import warnings

from unplug.safeguards.injection import InjectionScanner

warnings.warn(
    "unplug.scanners.injection is deprecated, use unplug.safeguards.injection",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = ["InjectionScanner"]
