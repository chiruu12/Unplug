"""Extract encoding blobs from original text (Base64 v1)."""

from __future__ import annotations

import base64
import re
from typing import Protocol

from unplug.api.types import Finding
from unplug.safeguards.injection.patterns import INJECTION_PATTERNS

# Same charset as normalize._decode_base64.
BASE64_BLOB_PATTERN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_SECRET_CONTEXT_BEFORE = re.compile(
    r"(?i)(?:"
    r"(?:sk|pk|ghp|gho|ghu|ghs|ghr|AKIA|eyJ)[-_]?|"
    r"(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?"
    r")$",
)


def _is_probable_base64_blob(text: str, start: int, raw: str) -> bool:
    """Skip blobs that are likely API tokens/secrets, not encoded payloads."""
    _ = raw
    prefix = text[max(0, start - 32) : start]
    return _SECRET_CONTEXT_BEFORE.search(prefix) is None


class EncodingBlob:
    """A contiguous encoding region in the original string."""

    __slots__ = ("start", "end", "raw", "decoded")

    def __init__(
        self,
        *,
        start: int,
        end: int,
        raw: str,
        decoded: str | None,
    ) -> None:
        self.start = start
        self.end = end
        self.raw = raw
        self.decoded = decoded


class EncodingClassifier(Protocol):
    """Classify decoded payload (Prompt Guard on server; heuristic in SDK v1)."""

    def is_malicious(self, decoded: str) -> tuple[bool, float, str]: ...


class HeuristicEncodingClassifier:
    """v1 stand-in: injection regex on decoded UTF-8 (PG wires in later)."""

    def __init__(self, *, base_score: float = 0.85) -> None:
        self._base_score = base_score

    def is_malicious(self, decoded: str) -> tuple[bool, float, str]:
        for subcategory, pattern in INJECTION_PATTERNS:
            if pattern.search(decoded):
                return True, self._base_score, subcategory
        return False, 0.0, ""


def iter_base64_blobs(text: str) -> list[EncodingBlob]:
    blobs: list[EncodingBlob] = []
    for match in BASE64_BLOB_PATTERN.finditer(text):
        raw = match.group(0)
        if not _is_probable_base64_blob(text, match.start(), raw):
            continue
        decoded: str | None = None
        try:
            decoded = base64.b64decode(raw, validate=True).decode("utf-8")
        except Exception:
            continue
        blobs.append(
            EncodingBlob(
                start=match.start(),
                end=match.end(),
                raw=raw,
                decoded=decoded,
            )
        )
    return blobs


def scan_encoding_blobs(
    text: str,
    classifier: EncodingClassifier | None = None,
) -> list[Finding]:
    """Stage 1a: extract → decode → classify → findings on original blob spans."""
    backend = classifier or HeuristicEncodingClassifier()
    findings: list[Finding] = []

    for blob in iter_base64_blobs(text):
        if blob.decoded is None:
            continue

        malicious, score, subcategory = backend.is_malicious(blob.decoded)
        if malicious:
            findings.append(
                Finding(
                    category="injection",
                    subcategory="encoded_payload",
                    stage="encoding",
                    span_start=blob.start,
                    span_end=blob.end,
                    score=score,
                    evidence=f"Encoded payload matched: {subcategory}",
                    replacement="[REDACTED]",
                )
            )

    return findings
