"""Shared schemas — re-exported from unplug.api for backward compatibility."""

from __future__ import annotations

from unplug.api.enums import Action, Source
from unplug.config.policy import ScanPolicy
from unplug.api.types import (
    BatchScanRequest,
    Finding,
    HealthResponse,
    ScanRequest,
    ScanResult,
)

__all__ = [
    "Action",
    "BatchScanRequest",
    "Finding",
    "HealthResponse",
    "ScanPolicy",
    "ScanRequest",
    "ScanResult",
    "Source",
]
