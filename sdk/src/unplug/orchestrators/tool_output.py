"""Filter tool output before an agent consumes it."""

from __future__ import annotations

from unplug.config.messages import MessageConfig
from unplug.guard import Guard
from unplug.orchestrators.base import OrchestratorResult, scan_result_to_outcome


class ToolOutputOrchestrator:
    """Scan and sanitize strings returned from tools (scrape, search, etc.)."""

    name = "tool_output"

    def __init__(
        self,
        guard: Guard | None = None,
        *,
        messages: MessageConfig | None = None,
    ) -> None:
        self._guard = guard or Guard()
        self._messages = messages or self._guard.config.messages

    def run(self, text: str) -> OrchestratorResult:
        scan = self._guard.scan(text, source="tool_output")
        outcome = scan_result_to_outcome(
            scan,
            messages=self._messages,
            original_text=text,
        )
        return OrchestratorResult(outcome=outcome, scan=scan)
