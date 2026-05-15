"""TaintedText, TrustLevel, and Tagger — data origin tracking for the enforcement layer."""

from __future__ import annotations

import time
import uuid
from enum import Enum

from pydantic import BaseModel, Field

from unplug.models import Source


class TrustLevel(str, Enum):
    TRUSTED = "trusted"
    USER = "user"
    RETRIEVED = "retrieved"
    TOOL_OUTPUT = "tool_output"
    EXTERNAL = "external"
    UNKNOWN = "unknown"


_SOURCE_TO_TRUST: dict[Source, TrustLevel] = {
    Source.SYSTEM: TrustLevel.TRUSTED,
    Source.USER: TrustLevel.USER,
    Source.RETRIEVED: TrustLevel.RETRIEVED,
    Source.TOOL_OUTPUT: TrustLevel.TOOL_OUTPUT,
}


def trust_level_from_source(source: Source) -> TrustLevel:
    return _SOURCE_TO_TRUST.get(source, TrustLevel.UNKNOWN)


class TaintedText(BaseModel):
    text: str
    trust_level: TrustLevel
    origin: str
    timestamp: float = Field(default_factory=time.time)
    parent_id: str | None = None
    metadata: dict = Field(default_factory=dict)
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))


class Tagger:
    """Creates and derives TaintedText instances."""

    def tag(
        self,
        text: str,
        trust_level: TrustLevel,
        origin: str,
        *,
        parent_id: str | None = None,
        **metadata,
    ) -> TaintedText:
        return TaintedText(
            text=text,
            trust_level=trust_level,
            origin=origin,
            parent_id=parent_id,
            metadata=metadata,
        )

    def tag_from_source(self, text: str, source: Source, origin: str) -> TaintedText:
        return self.tag(text, trust_level_from_source(source), origin)

    def derive(self, parent: TaintedText, new_text: str, **override_metadata) -> TaintedText:
        meta = {**parent.metadata, **override_metadata}
        return TaintedText(
            text=new_text,
            trust_level=parent.trust_level,
            origin=parent.origin,
            parent_id=parent.id,
            metadata=meta,
        )
