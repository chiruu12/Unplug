"""Re-export limits from unplug.config (backward compatibility)."""

from __future__ import annotations

from unplug.config.limits import LimitConfig, LimitViolation

__all__ = ["LimitConfig", "LimitViolation"]
