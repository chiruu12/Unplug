"""Financial scanner — catches crypto addresses, payment APIs, and transfer patterns."""

from __future__ import annotations

import re

from unplug.core.context import ExecutionContext
from unplug.core.taint import TaintedText, TrustLevel
from unplug.models import Finding

_CRYPTO_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("btc_address_legacy", re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")),
    ("btc_address_segwit", re.compile(r"\bbc1[a-zA-HJ-NP-Z0-9]{25,87}\b")),
    ("eth_address", re.compile(r"\b0x[a-fA-F0-9]{40}\b")),
]

_PAYMENT_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("stripe_api", re.compile(
        r"(?i)\b(stripe\.(charges|paymentIntents|transfers|subscriptions)\.create)\b"
    )),
    ("paypal_api", re.compile(
        r"(?i)\b(paypal\.(payment|Payout)\.create)\b"
    )),
    ("wire_transfer", re.compile(
        r"(?i)\b(wire\s+transfer|bank\s+transfer|SWIFT\s+transfer|IBAN\s*[:=]\s*\S+)\b"
    )),
]

_AMOUNT_PATTERN = re.compile(
    r"(?i)\b(send|transfer|pay|withdraw|deposit)\s+\$?\s*([\d,]+\.?\d*)\s*(USD|EUR|GBP|BTC|ETH|SOL)?\b"
)

_LARGE_AMOUNT_PATTERN = re.compile(r"\$\s*([\d,]+\.?\d*)")


def _parse_amount(raw: str) -> float:
    return float(raw.replace(",", ""))


class FinancialScanner:
    name = "financial"

    def __init__(
        self,
        *,
        auto_block_threshold: float = 10_000.0,
        review_threshold: float = 100.0,
    ) -> None:
        self.auto_block_threshold = auto_block_threshold
        self.review_threshold = review_threshold

    def scan(self, text: TaintedText, context: ExecutionContext) -> list[Finding]:
        findings: list[Finding] = []
        raw = text.text
        untrusted = text.trust_level in (TrustLevel.EXTERNAL, TrustLevel.UNKNOWN)

        for subcategory, pattern in _CRYPTO_PATTERNS:
            for match in pattern.finditer(raw):
                score = min(0.80, 0.70 + (0.10 if untrusted else 0.0))
                findings.append(Finding(
                    category="financial",
                    subcategory=subcategory,
                    stage="regex",
                    span_start=match.start(),
                    span_end=match.end(),
                    score=score,
                    evidence=f"Crypto address detected: {subcategory}",
                ))

        for subcategory, pattern in _PAYMENT_PATTERNS:
            for match in pattern.finditer(raw):
                score = min(0.95, 0.85 + (0.10 if untrusted else 0.0))
                findings.append(Finding(
                    category="financial",
                    subcategory=subcategory,
                    stage="regex",
                    span_start=match.start(),
                    span_end=match.end(),
                    score=score,
                    evidence=f"Payment API detected: {subcategory}",
                ))

        for match in _AMOUNT_PATTERN.finditer(raw):
            try:
                amount = _parse_amount(match.group(2))
            except ValueError:
                continue

            if amount >= self.auto_block_threshold:
                score = min(1.0, 0.95 + (0.05 if untrusted else 0.0))
                evidence = f"Large financial transfer: ${amount:,.2f} (above auto-block threshold)"
            elif amount >= self.review_threshold:
                score = min(0.70, 0.60 + (0.10 if untrusted else 0.0))
                evidence = f"Financial transfer: ${amount:,.2f} (above review threshold)"
            else:
                continue

            findings.append(Finding(
                category="financial",
                subcategory="transfer_amount",
                stage="regex",
                span_start=match.start(),
                span_end=match.end(),
                score=score,
                evidence=evidence,
            ))

        return findings
