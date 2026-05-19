"""Pluggable scanner modules with registry for dynamic loading."""

from __future__ import annotations

from collections.abc import Callable

from unplug.core.config import ScannerConfig
from unplug.core.stats import MetricsCollector
from unplug.scanners.base import BaseScanner
from unplug.scanners.base import Scanner as Scanner

_FACTORIES: dict[str, Callable[..., BaseScanner]] = {}


def _register_builtins() -> None:
    from unplug.scanners.destructive import DestructiveScanner
    from unplug.scanners.financial import FinancialScanner
    from unplug.scanners.harmful import HarmfulScanner
    from unplug.scanners.injection import InjectionScanner
    from unplug.scanners.leakage import LeakageScanner
    from unplug.scanners.secrets import SecretsScanner

    _FACTORIES.update({
        "injection": InjectionScanner,
        "destructive": DestructiveScanner,
        "leakage": LeakageScanner,
        "harmful": HarmfulScanner,
        "financial": FinancialScanner,
        "secrets": SecretsScanner,
    })


class ScannerRegistry:
    """Central registry for creating and caching scanner instances."""

    def __init__(self, metrics: MetricsCollector | None = None) -> None:
        self._metrics = metrics
        self._instances: dict[str, BaseScanner] = {}
        if not _FACTORIES:
            _register_builtins()

    @staticmethod
    def register(name: str, factory: Callable[..., BaseScanner]) -> None:
        _FACTORIES[name] = factory

    @staticmethod
    def available() -> list[str]:
        if not _FACTORIES:
            _register_builtins()
        return list(_FACTORIES.keys())

    def get(
        self,
        name: str,
        config: ScannerConfig | None = None,
        **kwargs,
    ) -> BaseScanner | None:
        if name in self._instances:
            return self._instances[name]

        if not _FACTORIES:
            _register_builtins()

        factory = _FACTORIES.get(name)
        if factory is None:
            return None

        instance = factory(config=config, metrics=self._metrics, **kwargs)
        self._instances[name] = instance
        return instance

    def get_many(
        self,
        names: list[str],
        configs: dict[str, ScannerConfig] | None = None,
    ) -> list[BaseScanner]:
        scanners = []
        for name in names:
            cfg = (configs or {}).get(name)
            scanner = self.get(name, config=cfg)
            if scanner is not None:
                scanners.append(scanner)
        return scanners
