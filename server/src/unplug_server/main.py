"""FastAPI application with lifespan model loading."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from unplug import Guard, __version__

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
    version=__version__,
    lifespan=lifespan,
)

app.include_router(scan.router, prefix="/v1")


@app.get("/v1/health")
async def health():
    guard: Guard = app.state.guard
    return {
        "status": "ok",
        "version": __version__,
        "scanners_loaded": list(guard.scanner_registry.available()),
        "model_loaded": False,
    }


@app.get("/v1/stats")
async def stats():
    guard: Guard = app.state.guard
    return guard.stats()
