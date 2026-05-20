"""Firecrawl-backed scraper (optional unplug[scrape] extra)."""

from __future__ import annotations

from unplug.providers.content.protocol import CleanResult, ScrapedContent


class FirecrawlProvider:
    """Local Firecrawl API client. Requires firecrawl-py and API key."""

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key
        self._client: object | None = None

    def _ensure_client(self) -> object:
        if self._client is not None:
            return self._client
        try:
            from firecrawl import FirecrawlApp
        except ImportError as exc:
            msg = "Install scrape extra: uv add 'unplug[scrape]'"
            raise ImportError(msg) from exc
        self._client = FirecrawlApp(api_key=self._api_key)
        return self._client

    async def scrape(self, url: str) -> ScrapedContent:
        client = self._ensure_client()
        result = client.scrape_url(url)  # type: ignore[union-attr]
        markdown = getattr(result, "markdown", "") or str(result)
        return ScrapedContent(url=url, markdown=markdown, word_count=len(markdown.split()))

    async def clean(self, html: str) -> CleanResult:
        return CleanResult(text=html, original_length=len(html), cleaned_length=len(html))
