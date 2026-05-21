"""Privacy filter heuristic tests."""

from __future__ import annotations

from unplug.core.privacy import HeuristicPrivacyFilter


class TestHeuristicPrivacyFilter:
    def test_detects_email(self) -> None:
        pf = HeuristicPrivacyFilter()
        findings = pf.scan("reach me at user@example.com", baseline=[])
        assert any(f.stage == "privacy_filter" for f in findings)
        assert any(f.subcategory == "private_email" for f in findings)
