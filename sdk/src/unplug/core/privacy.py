"""Privacy Filter protocol — implementation ships with unplug-safeguard model only."""

from __future__ import annotations

from typing import Protocol

from unplug.api.types import Finding


class PrivacyFilterService(Protocol):
    """Server-side stage after unplug-safeguard model is released."""

    @property
    def is_loaded(self) -> bool: ...

    def scan(self, text: str, *, baseline: list[Finding]) -> list[Finding]: ...


class NullPrivacyFilter:
    """Default for SDK and server until unplug-safeguard is deployed."""

    @property
    def is_loaded(self) -> bool:
        return False

    def scan(self, text: str, *, baseline: list[Finding]) -> list[Finding]:
        return baseline


def build_privacy_filter(*, enabled: bool) -> PrivacyFilterService:
    """SDK never loads PF weights; enabled=True is reserved for future model hook."""
    if enabled:
        import logging

        logging.getLogger("unplug.privacy").warning(
            "privacy_filter_enabled ignored in SDK until unplug-safeguard model ships"
        )
    return NullPrivacyFilter()
