"""HTTP client for Unplug server mode."""

from __future__ import annotations

import os
from typing import Self

import httpx

from unplug.api.enums import Source
from unplug.api.types import BatchScanRequest, ScanRequest, ScanResult


class UnplugClient:
    """Client for the Unplug server API."""

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        *,
        timeout: float = 30.0,
    ) -> None:
        resolved_url = base_url or os.environ.get("UNPLUG_SERVER_URL", "http://localhost:8000")
        resolved_key = api_key or os.environ.get("UNPLUG_API_KEY")
        headers: dict[str, str] = {}
        if resolved_key:
            headers["Authorization"] = f"Bearer {resolved_key}"
        self._client = httpx.Client(
            base_url=resolved_url.rstrip("/"),
            headers=headers,
            timeout=timeout,
        )

    def scan(
        self,
        text: str,
        source: Source | str = Source.USER,
        *,
        scanners: list[str] | None = None,
        redact: bool = True,
    ) -> ScanResult:
        request = ScanRequest(text=text, source=source, scanners=scanners, redact=redact)
        return self.scan_request(request)

    def scan_request(self, request: ScanRequest) -> ScanResult:
        response = self._client.post(
            "/v1/scan",
            json=request.model_dump(mode="json"),
        )
        response.raise_for_status()
        return ScanResult.model_validate(response.json())

    def scan_output(
        self,
        text: str,
        *,
        scanners: list[str] | None = None,
        redact: bool = True,
    ) -> ScanResult:
        request = ScanRequest(
            text=text,
            source=Source.TOOL_OUTPUT,
            scanners=scanners,
            redact=redact,
        )
        return self.scan_output_request(request)

    def scan_output_request(self, request: ScanRequest) -> ScanResult:
        response = self._client.post(
            "/v1/scan/output",
            json=request.model_dump(mode="json"),
        )
        response.raise_for_status()
        return ScanResult.model_validate(response.json())

    def batch_scan(self, items: list[ScanRequest]) -> list[ScanResult]:
        request = BatchScanRequest(items=items)
        response = self._client.post(
            "/v1/batch",
            json=request.model_dump(mode="json"),
        )
        response.raise_for_status()
        return [ScanResult.model_validate(r) for r in response.json()["results"]]

    def health(self) -> dict[str, object]:
        response = self._client.get("/v1/health")
        response.raise_for_status()
        return response.json()

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
