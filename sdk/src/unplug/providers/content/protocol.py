"""Content scraping protocol and types."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field


class ScrapedContent(BaseModel):
    """Result of scraping and cleaning a URL for LLM consumption."""

    url: str
    markdown: str
    title: str | None = None
    description: str | None = None
    word_count: int = 0
    metadata: dict = Field(default_factory=dict)
    scrape_ms: float = 0.0
    blocked: bool = False
    agent_message: str | None = None


class CleanResult(BaseModel):
    """Result of cleaning raw HTML into LLM-friendly text."""

    text: str
    original_length: int = 0
    cleaned_length: int = 0
    elements_removed: int = 0


@runtime_checkable
class ContentProvider(Protocol):
    """Fetch and clean web content. Implementations: Firecrawl, server API."""

    async def scrape(self, url: str) -> ScrapedContent: ...

    async def clean(self, html: str) -> CleanResult: ...
