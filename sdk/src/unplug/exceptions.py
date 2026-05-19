"""Unplug exceptions."""

from __future__ import annotations


class UnplugError(Exception):
    """Base exception for Unplug."""


class ScanError(UnplugError):
    """Error during scanning."""


class ServerError(UnplugError):
    """Error communicating with Unplug server."""


class ConfigError(UnplugError):
    """Invalid configuration."""
