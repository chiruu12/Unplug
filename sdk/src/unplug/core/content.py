"""Re-export content protocol from providers (backward compatibility)."""

from __future__ import annotations

from unplug.providers.content.protocol import CleanResult, ContentProvider, ScrapedContent

__all__ = ["CleanResult", "ContentProvider", "ScrapedContent"]
