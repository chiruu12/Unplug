"""Tests for core/limits.py — input limits and tool permissions."""

from __future__ import annotations

from unplug.core.limits import LimitConfig


class TestLimitConfig:
    def test_defaults(self):
        lc = LimitConfig()
        assert lc.max_input_chars == 50_000
        assert lc.max_input_tokens is None
        assert lc.allowed_tools is None
        assert lc.blocked_tools == []

    def test_input_length_ok(self):
        lc = LimitConfig(max_input_chars=100)
        assert lc.check_input_length("short") is None

    def test_input_length_exceeded(self):
        lc = LimitConfig(max_input_chars=10)
        v = lc.check_input_length("this is too long for the limit")
        assert v is not None
        assert v.kind == "input_too_long"
        assert v.limit == 10
        assert v.actual == 30

    def test_tool_allowed_no_restrictions(self):
        lc = LimitConfig()
        assert lc.is_tool_allowed("any_tool") is True

    def test_tool_blocked(self):
        lc = LimitConfig(blocked_tools=["rm", "DROP"])
        assert lc.is_tool_allowed("rm") is False
        assert lc.is_tool_allowed("ls") is True

    def test_tool_allowlist(self):
        lc = LimitConfig(allowed_tools=["read_file", "search"])
        assert lc.is_tool_allowed("read_file") is True
        assert lc.is_tool_allowed("delete_file") is False

    def test_blocked_overrides_allowed(self):
        lc = LimitConfig(allowed_tools=["rm", "ls"], blocked_tools=["rm"])
        assert lc.is_tool_allowed("rm") is False
        assert lc.is_tool_allowed("ls") is True

    def test_frozen(self):
        lc = LimitConfig()
        try:
            lc.max_input_chars = 100
            assert False, "should be frozen"
        except Exception:
            pass
