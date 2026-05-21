"""Server mode delegation for scan_output."""

from __future__ import annotations

from unittest.mock import patch

from unplug import Guard
from unplug.api.enums import Action, Source
from unplug.models import ScanRequest, ScanResult


class TestGuardScanOutputServerMode:
    def test_scan_output_delegates_to_server(self) -> None:
        mock_result = ScanResult(
            safe=False,
            action=Action.REDACT,
            risk_score=0.7,
            findings=[],
            latency_ms=2.0,
        )
        with patch("unplug.guard.UnplugClient") as mock_cls:
            mock_cls.return_value.scan_output_request.return_value = mock_result
            guard = Guard(mode="server", server_url="http://unplug.test")
            out = guard.scan_output("email: user@secret.com")

        assert out.action == Action.REDACT
        call_args = mock_cls.return_value.scan_output_request.call_args[0][0]
        assert isinstance(call_args, ScanRequest)
        assert call_args.source == Source.TOOL_OUTPUT
