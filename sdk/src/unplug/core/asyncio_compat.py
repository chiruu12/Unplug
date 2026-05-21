"""Run coroutines from sync code without breaking an active event loop."""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from concurrent.futures import ThreadPoolExecutor
from typing import TypeVar

T = TypeVar("T")


def run_coroutine_sync(coro: Coroutine[object, object, T]) -> T:
    """Execute ``coro`` when no loop is running, or in a dedicated thread if one is."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(asyncio.run, coro)
        return future.result()
