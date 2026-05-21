"""Finding model validation tests."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from unplug.models import Finding


class TestFindingValidation:
    def test_invalid_span_raises(self) -> None:
        with pytest.raises(ValidationError):
            Finding(
                category="injection",
                subcategory="test",
                stage="regex",
                span_start=10,
                span_end=5,
                score=0.9,
                evidence="bad span",
            )

    def test_negative_span_raises(self) -> None:
        with pytest.raises(ValidationError):
            Finding(
                category="injection",
                subcategory="test",
                stage="regex",
                span_start=-1,
                span_end=5,
                score=0.9,
                evidence="negative",
            )
