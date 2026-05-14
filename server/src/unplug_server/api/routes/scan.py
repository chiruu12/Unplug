"""Scan endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Request

from unplug.models import BatchScanRequest, ScanRequest, ScanResult

router = APIRouter()


@router.post("/scan", response_model=ScanResult)
async def scan_text(request: ScanRequest, req: Request) -> ScanResult:
    guard = req.app.state.guard
    return guard.scan(request.text, request.source)


@router.post("/batch")
async def batch_scan(request: BatchScanRequest, req: Request) -> dict:
    guard = req.app.state.guard
    results = [guard.scan(item.text, item.source) for item in request.items]
    return {"results": results}
