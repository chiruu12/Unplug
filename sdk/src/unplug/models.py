"""Shared Pydantic schemas for Unplug SDK and server."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class Source(StrEnum):
    USER = "user"
    RETRIEVED = "retrieved"
    TOOL_OUTPUT = "tool_output"
    SYSTEM = "system"


class Action(StrEnum):
    ALLOW = "allow"
    REDACT = "redact"
    BLOCK = "block"
    REVIEW = "review"


class Finding(BaseModel):
    category: str = Field(description="Scanner category")
    subcategory: str = Field(description="Specific threat type")
    stage: str = Field(description="Pipeline stage: regex, classifier, llm_judge")
    span_start: int = Field(description="Start offset in original text")
    span_end: int = Field(description="End offset in original text")
    score: float = Field(ge=0.0, le=1.0, description="Confidence score")
    evidence: str = Field(description="Human-readable explanation")
    replacement: str | None = Field(default=None)


class ScanResult(BaseModel):
    safe: bool = Field(description="Whether the text is safe")
    action: Action = Field(description="Recommended action")
    risk_score: float = Field(ge=0.0, le=1.0, description="Overall risk score")
    findings: list[Finding] = Field(default_factory=list)
    redacted_text: str | None = Field(default=None)
    latency_ms: float = Field(description="Total scan time in milliseconds")
    stages_run: list[str] = Field(default_factory=list)


class ScanRequest(BaseModel):
    text: str = Field(description="Text to scan")
    source: Source = Field(default=Source.USER)
    scanners: list[str] | None = Field(default=None)
    redact: bool = Field(default=True)


class BatchScanRequest(BaseModel):
    items: list[ScanRequest] = Field(description="Texts to scan")


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
    scanners_loaded: list[str]
    model_loaded: bool
