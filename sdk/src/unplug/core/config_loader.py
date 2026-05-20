"""Config file loading — TOML (stdlib) with env var overrides."""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any

from unplug.core.config import GuardConfig, PipelineConfig, ScannerConfig, ThresholdConfig
from unplug.core.limits import LimitConfig


def load_from_file(path: str | Path) -> dict[str, Any]:
    """Read a TOML config file and return the raw dict."""
    p = Path(path)
    if not p.exists():
        msg = f"Config file not found: {p}"
        raise FileNotFoundError(msg)

    with p.open("rb") as f:
        return tomllib.load(f)


def load_from_env(prefix: str = "UNPLUG_") -> dict[str, Any]:
    """Read env vars with the given prefix into a nested dict.

    Uses __ as a separator for nesting:
        UNPLUG_PIPELINE__THRESHOLDS__BLOCK=0.9
        → {"pipeline": {"thresholds": {"block": "0.9"}}}
    """
    result: dict[str, Any] = {}
    for key, value in os.environ.items():
        if not key.startswith(prefix):
            continue
        parts = key[len(prefix) :].lower().split("__")
        target = result
        for part in parts[:-1]:
            target = target.setdefault(part, {})
        raw = value
        if "," in raw:
            target[parts[-1]] = [v.strip() for v in raw.split(",")]
        else:
            target[parts[-1]] = _coerce(raw)
    return result


def _coerce(value: str) -> Any:
    """Coerce a string value to the appropriate Python type."""
    if value.lower() in ("true", "yes", "1"):
        return True
    if value.lower() in ("false", "no", "0"):
        return False
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


def _merge(base: dict, override: dict) -> dict:
    """Deep merge override into base. Override wins for leaf values."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = value
    return result


def _build_thresholds(data: dict[str, Any]) -> ThresholdConfig:
    return ThresholdConfig(
        **{k: float(v) for k, v in data.items() if k in ThresholdConfig.model_fields}
    )


def _build_pipeline(data: dict[str, Any]) -> PipelineConfig:
    kwargs: dict[str, Any] = {}
    if "thresholds" in data:
        kwargs["thresholds"] = _build_thresholds(data["thresholds"])
    if "fail_closed" in data:
        kwargs["fail_closed"] = data["fail_closed"]
    return PipelineConfig(**kwargs)


def _build_limits(data: dict[str, Any]) -> LimitConfig:
    return LimitConfig(
        **{k: v for k, v in data.items() if k in LimitConfig.model_fields}
    )


def _build_scanner_configs(data: dict[str, Any]) -> dict[str, ScannerConfig]:
    return {
        name: ScannerConfig(**{k: v for k, v in cfg.items() if k in ScannerConfig.model_fields})
        for name, cfg in data.items()
        if isinstance(cfg, dict)
    }


def build_config(data: dict[str, Any]) -> GuardConfig:
    """Build a GuardConfig from a raw dict (from TOML or env)."""
    guard_data = data.get("guard", data)
    kwargs: dict[str, Any] = {}

    if "scanners" in guard_data and isinstance(guard_data["scanners"], list):
        kwargs["scanners"] = guard_data["scanners"]
    if "mode" in guard_data:
        kwargs["mode"] = guard_data["mode"]
    if "server_url" in guard_data:
        kwargs["server_url"] = guard_data["server_url"]
    if "fail_closed" in guard_data:
        kwargs["fail_closed"] = guard_data["fail_closed"]

    pipeline_data = guard_data.get("pipeline", data.get("pipeline", {}))
    if pipeline_data:
        kwargs["pipeline"] = _build_pipeline(pipeline_data)

    scanner_data = guard_data.get("scanners_config", data.get("scanners_config", {}))
    if not scanner_data:
        scanner_data = data.get("scanners", {})
        if isinstance(scanner_data, dict):
            scanner_data = {k: v for k, v in scanner_data.items() if isinstance(v, dict)}
        else:
            scanner_data = {}
    if scanner_data:
        kwargs["scanner_configs"] = _build_scanner_configs(scanner_data)

    limits_data = guard_data.get("limits", data.get("limits", {}))
    if limits_data:
        kwargs["limits"] = _build_limits(limits_data)

    if "judge_enabled" in guard_data:
        kwargs["judge_enabled"] = guard_data["judge_enabled"]
    if "judge_low" in guard_data:
        kwargs["judge_low"] = float(guard_data["judge_low"])
    if "judge_high" in guard_data:
        kwargs["judge_high"] = float(guard_data["judge_high"])

    return GuardConfig(**kwargs)


def load(
    file_path: str | Path | None = None,
    env_prefix: str = "UNPLUG_",
) -> GuardConfig:
    """Load config from file + env overrides, with sensible defaults."""
    file_data: dict[str, Any] = {}
    if file_path is not None:
        file_data = load_from_file(file_path)
    env_data = load_from_env(env_prefix)
    merged = _merge(file_data, env_data)
    if not merged:
        return GuardConfig()
    return build_config(merged)
