"""Thread safety tests for Guard singleton."""

from __future__ import annotations

import threading

from unplug import Guard


class TestGuardThreadSafety:
    def setup_method(self) -> None:
        Guard._instance = None

    def teardown_method(self) -> None:
        Guard._instance = None

    def test_concurrent_init_single_instance(self) -> None:
        instances: list[Guard] = []
        errors: list[Exception] = []

        def init_guard() -> None:
            try:
                instances.append(Guard.init(scanners=["injection"]))
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=init_guard) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(instances) == 10
        final = Guard.get()
        assert final is Guard._instance
        assert final in instances
