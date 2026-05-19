"""Structured logging with correlation ID support using stdlib logging."""

from __future__ import annotations

import logging
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from contextvars import ContextVar

_correlation_id: ContextVar[str | None] = ContextVar("correlation_id", default=None)


def get_correlation_id() -> str | None:
    return _correlation_id.get()


def set_correlation_id(cid: str) -> None:
    _correlation_id.set(cid)


@contextmanager
def correlation_scope(cid: str | None = None) -> Generator[str, None, None]:
    """Set a correlation ID for the duration of the scope."""
    actual = cid or uuid.uuid4().hex[:16]
    token = _correlation_id.set(actual)
    try:
        yield actual
    finally:
        _correlation_id.reset(token)


class CorrelationFilter(logging.Filter):
    """Injects correlation_id into every log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.correlation_id = _correlation_id.get() or "-"  # type: ignore[attr-defined]
        return True


def get_logger(name: str) -> logging.Logger:
    """Return a logger under the unplug namespace with correlation filter."""
    logger = logging.getLogger(f"unplug.{name}")
    if not any(isinstance(f, CorrelationFilter) for f in logger.filters):
        logger.addFilter(CorrelationFilter())
    return logger
