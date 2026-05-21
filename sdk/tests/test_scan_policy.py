"""Tests for ScanPolicy coverage-based BLOCK gate."""

from __future__ import annotations

from unplug.config.policy import ScanPolicy
from unplug.core.policy import decide_action, flagged_coverage, merge_spans
from unplug.models import Action, Finding


def _finding(start: int, end: int, score: float) -> Finding:
    return Finding(
        category="injection",
        subcategory="test",
        stage="regex",
        span_start=start,
        span_end=end,
        score=score,
        evidence="test",
    )


class TestMergeSpans:
    def test_merges_overlapping(self) -> None:
        spans = merge_spans([(0, 5), (3, 10)], merge=True)
        assert spans == [(0, 10)]

    def test_no_merge_when_disabled(self) -> None:
        spans = merge_spans([(0, 5), (3, 10)], merge=False)
        assert spans == [(0, 5), (3, 10)]


class TestCoveragePolicy:
    def test_small_span_redacts_not_blocks(self) -> None:
        policy = ScanPolicy(block_coverage_ratio=0.2)
        findings = [_finding(0, 10, 0.6)]
        action = decide_action(findings, text_len=1000, policy=policy, risk_score=0.6)
        assert action == Action.REDACT

    def test_high_coverage_blocks(self) -> None:
        policy = ScanPolicy(block_coverage_ratio=0.2)
        findings = [_finding(0, 300, 0.6)]
        assert flagged_coverage(1000, findings, policy) >= 0.2
        action = decide_action(findings, text_len=1000, policy=policy, risk_score=0.6)
        assert action == Action.BLOCK

    def test_block_threshold_without_coverage(self) -> None:
        policy = ScanPolicy(block_coverage_ratio=0.5)
        findings = [_finding(0, 5, 0.85)]
        action = decide_action(findings, text_len=10_000, policy=policy, risk_score=0.85)
        assert action == Action.BLOCK


class TestPolicyMatrix:
    """S5: Document expected allow/redact/block outcomes for default thresholds."""

    def test_destructive_score_blocks(self) -> None:
        policy = ScanPolicy()
        findings = [
            Finding(
                category="destructive",
                subcategory="sql_drop",
                stage="regex",
                span_start=0,
                span_end=14,
                score=0.90,
                evidence="test",
            )
        ]
        action = decide_action(findings, text_len=100, policy=policy, risk_score=0.90)
        assert action == Action.BLOCK

    def test_low_score_injection_redacts(self) -> None:
        policy = ScanPolicy(block_coverage_ratio=0.2)
        findings = [_finding(0, 20, 0.55)]
        action = decide_action(findings, text_len=500, policy=policy, risk_score=0.55)
        assert action == Action.REDACT

    def test_no_findings_allows(self) -> None:
        policy = ScanPolicy()
        action = decide_action([], text_len=100, policy=policy, risk_score=0.0)
        assert action == Action.ALLOW
