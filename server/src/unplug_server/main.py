"""FastAPI application with lifespan model loading."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from unplug import Guard

from unplug_server.api.routes import scan
from unplug_server.core.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    guard = Guard(scanners=settings.SCANNERS, mode="local")
    app.state.guard = guard
    yield


app = FastAPI(
    title="Unplug API",
    description="Pull the plug on bad AI.",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(scan.router, prefix="/v1")


@app.get("/v1/health")
async def health():
    return {
        "status": "ok",
        "version": "0.1.0",
        "scanners_loaded": settings.SCANNERS,
    }
