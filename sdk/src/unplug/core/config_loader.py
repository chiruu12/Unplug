"""Re-export loader from unplug.config (backward compatibility)."""

from __future__ import annotations

from unplug.config.loader import (
    _coerce,
    _merge,
    build_config,
    load,
    load_from_env,
    load_from_file,
)

__all__ = [
    "build_config",
    "load",
    "load_from_env",
    "load_from_file",
]
