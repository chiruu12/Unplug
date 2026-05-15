"""Shared Pydantic schemas for Unplug SDK and server."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Source(str, Enum):
    USER = "user"
    RETRIEVED = "retrieved"
    TOOL_OUTPUT = "tool_output"
    SYSTEM = "system"


class Action(str, Enum):
    ALLOW = "allow"
    REDACT = "redact"
    BLOCK = "block"
    REVIEW = "review"


class Finding(BaseModel):
    category: str = Field(description="Scanner that produced this: injection, destructive, leakage, harmful")
    subcategory: str = Field(description="Specific threat: role_override, sql_drop, api_key, etc.")
    stage: str = Field(description="Pipeline stage: regex, classifier, llm_judge")
    span_start: int = Field(description="Start character offset in original text")
    span_end: int = Field(description="End character offset in original text")
    score: float = Field(ge=0.0, le=1.0, description="Confidence score")
    evidence: str = Field(description="Human-readable explanation")
    replacement: str | None = Field(default=None, description="Suggested replacement text")


class ScanResult(BaseModel):
    safe: bool = Field(description="Whether the text is safe")
    action: Action = Field(description="Recommended action")
    risk_score: float = Field(ge=0.0, le=1.0, description="Overall risk score")
    findings: list[Finding] = Field(default_factory=list)
    redacted_text: str | None = Field(default=None, description="Text with malicious spans redacted")
    latency_ms: float = Field(description="Total scan time in milliseconds")
    stages_run: list[str] = Field(default_factory=list, description="Pipeline stages that ran")


class ScanRequest(BaseModel):
    text: str = Field(description="Text to scan")
    source: Source = Field(default=Source.USER, description="Where the text came from")
    scanners: list[str] | None = Field(default=None, description="Specific scanners to run (default: all)")
    redact: bool = Field(default=True, description="Whether to return redacted text")


class BatchScanRequest(BaseModel):
    items: list[ScanRequest] = Field(description="Texts to scan")


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
    scanners_loaded: list[str]
    model_loaded: bool
