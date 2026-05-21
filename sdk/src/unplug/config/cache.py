"""Scan cache configuration."""

from __future__ import annotations

from pydantic import BaseModel, Field


class CacheConfig(BaseModel):
    """Safe-prefix and chunk LRU settings."""

    model_config = {"frozen": True}

    enabled: bool = True
    max_chunk_entries: int = Field(default=256, ge=1)
    advance_prefix_on_redact: bool = True
