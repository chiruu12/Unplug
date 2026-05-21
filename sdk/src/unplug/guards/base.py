"""Base guard facade."""

from __future__ import annotations

from unplug.config.messages import MessageConfig
from unplug.guard import Guard


class BaseGuardFacade:
    """Shared facade wiring to the core Guard engine."""

    def __init__(
        self,
        guard: Guard | None = None,
        *,
        messages: MessageConfig | None = None,
    ) -> None:
        self._guard = guard or Guard()
        self._messages = messages or self._guard.config.messages

    @property
    def engine(self) -> Guard:
        return self._guard
