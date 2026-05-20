"""Public enums."""

from __future__ import annotations

from enum import StrEnum


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
