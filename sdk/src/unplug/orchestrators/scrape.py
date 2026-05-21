"""Scrape URL via Firecrawl, then filter content for agents."""

from __future__ import annotations

from unplug.api.messages import ScrapeOutcome
from unplug.config.messages import MessageConfig
from unplug.guard import Guard
from unplug.orchestrators.tool_output import ToolOutputOrchestrator
from unplug.providers.content.firecrawl import FirecrawlProvider
from unplug.providers.content.protocol import ContentProvider, ScrapedContent


class ScrapeOrchestrator:
    """Fetch with Firecrawl, scan markdown, return agent-safe content."""

    name = "scrape"

    def __init__(
        self,
        guard: Guard | None = None,
        *,
        provider: ContentProvider | None = None,
        messages: MessageConfig | None = None,
    ) -> None:
        self._guard = guard or Guard()
        self._messages = messages or self._guard.config.messages
        self._provider = provider or FirecrawlProvider.from_env()
        self._filter = ToolOutputOrchestrator(self._guard, messages=self._messages)

    def run(self, url: str) -> ScrapeOutcome:
        scraped = self._fetch(url)
        filter_result = self._filter.run(scraped.markdown)
        outcome = filter_result.outcome

        if not outcome.safe:
            return ScrapeOutcome(
                url=url,
                safe=False,
                agent_message=outcome.agent_message,
                title=scraped.title,
                word_count=scraped.word_count,
                scrape_ms=scraped.scrape_ms,
                scan=filter_result.scan,
            )

        text = outcome.text or scraped.markdown
        return ScrapeOutcome(
            url=url,
            safe=True,
            text=text,
            redacted=outcome.redacted,
            title=scraped.title,
            word_count=len(text.split()) if text else 0,
            scrape_ms=scraped.scrape_ms,
            scan=filter_result.scan,
        )

    def _fetch(self, url: str) -> ScrapedContent:
        if hasattr(self._provider, "scrape_sync"):
            return self._provider.scrape_sync(url)  # type: ignore[union-attr]
        import asyncio

        return asyncio.run(self._provider.scrape(url))
