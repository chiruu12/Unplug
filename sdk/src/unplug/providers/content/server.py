"""Server-backed scrape via unplug-server /v1/optimize (no Firecrawl key on client)."""

from __future__ import annotations

import httpx

from unplug.providers.content.protocol import CleanResult, ScrapedContent


class ServerContentProvider:
    """Delegates scraping to the hosted Unplug API."""

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        api_key: str | None = None,
    ) -> None:
        headers: dict[str, str] = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self._client = httpx.AsyncClient(base_url=base_url, headers=headers, timeout=60.0)

    async def scrape(self, url: str) -> ScrapedContent:
        response = await self._client.post("/v1/optimize", json={"url": url})
        response.raise_for_status()
        data = response.json()
        return ScrapedContent.model_validate(data)

    async def clean(self, html: str) -> CleanResult:
        response = await self._client.post("/v1/clean", json={"html": html})
        response.raise_for_status()
        data = response.json()
        return CleanResult(
            text=data.get("text", ""),
            original_length=data.get("original_length", len(html)),
            cleaned_length=data.get("cleaned_length", 0),
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> ServerContentProvider:
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()
