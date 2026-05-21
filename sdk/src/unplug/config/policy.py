"""Scan policy — span thresholds and document-level coverage gate."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ScanPolicy(BaseModel):
    """Controls redact/review/block using per-span scores and flagged coverage."""

    model_config = {"frozen": True}

    block_coverage_ratio: float = Field(
        default=0.2,
        ge=0.0,
        le=1.0,
        description="BLOCK when union of flagged spans / text length >= this ratio",
    )
    redact_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    review_threshold: float = Field(default=0.3, ge=0.0, le=1.0)
    block_threshold: float = Field(
        default=0.8,
        ge=0.0,
        le=1.0,
        description="Per-span high confidence; also contributes to BLOCK",
    )
    merge_overlapping_spans: bool = True
