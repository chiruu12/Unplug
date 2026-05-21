"""Backward compatibility — use unplug.safeguards.base."""

from __future__ import annotations

import warnings

from unplug.safeguards.base import BaseScanner, ModelScanner, RegexScanner, Scanner

warnings.warn(
    "unplug.scanners.base is deprecated, use unplug.safeguards.base",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = ["BaseScanner", "ModelScanner", "RegexScanner", "Scanner"]
