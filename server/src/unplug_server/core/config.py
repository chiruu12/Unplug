"""Server configuration."""

from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    SCANNERS: list[str] = ["injection", "destructive", "leakage", "harmful"]
    MAX_INPUT_LENGTH: int = 10000
    RATE_LIMIT_RPM: int = 1000
    API_KEYS: list[str] = []

    model_config = {"env_prefix": "UNPLUG_"}


settings = Settings()
