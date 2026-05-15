"""HTTP client for Unplug server mode."""

from __future__ import annotations

import httpx

from unplug.models import BatchScanRequest, ScanRequest, ScanResult


class UnplugClient:
    """Client for the Unplug server API."""

    def __init__(self, base_url: str = "http://localhost:8000", api_key: str | None = None) -> None:
        headers = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self._client = httpx.Client(base_url=base_url, headers=headers, timeout=30.0)

    def scan(self, text: str, source: str = "user", **kwargs) -> ScanResult:
        request = ScanRequest(text=text, source=source, **kwargs)
        response = self._client.post("/v1/scan", json=request.model_dump())
        response.raise_for_status()
        return ScanResult.model_validate(response.json())

    def batch_scan(self, items: list[ScanRequest]) -> list[ScanResult]:
        request = BatchScanRequest(items=items)
        response = self._client.post("/v1/batch", json=request.model_dump())
        response.raise_for_status()
        return [ScanResult.model_validate(r) for r in response.json()["results"]]

    def health(self) -> dict:
        response = self._client.get("/v1/health")
        response.raise_for_status()
        return response.json()

    def close(self) -> None:
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
