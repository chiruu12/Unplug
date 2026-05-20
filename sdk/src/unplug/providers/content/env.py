"""Load API keys from environment and local .env (gitignored)."""

from __future__ import annotations

import os
from pathlib import Path


def _find_dotenv() -> Path | None:
    candidates = [
        Path.cwd() / ".env",
        Path.cwd().parent / ".env",
        Path(__file__).resolve().parents[5] / ".env",
    ]
    for path in candidates:
        if path.is_file():
            return path
    return None


def load_firecrawl_api_key(*, required: bool = True) -> str | None:
    """Resolve FIRECRAWL_API_KEY from env or .env file."""
    key = os.environ.get("FIRECRAWL_API_KEY")
    if key:
        return key

    dotenv_path = _find_dotenv()
    if dotenv_path is not None:
        try:
            from dotenv import load_dotenv

            load_dotenv(dotenv_path, override=False)
        except ImportError:
            for line in dotenv_path.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                name, _, value = line.partition("=")
                if name.strip() == "FIRECRAWL_API_KEY" and value.strip():
                    os.environ.setdefault("FIRECRAWL_API_KEY", value.strip().strip("\"'"))
                    break
        key = os.environ.get("FIRECRAWL_API_KEY")

    if required and not key:
        msg = "Set FIRECRAWL_API_KEY in environment or .env (see .env.example)"
        raise ValueError(msg)
    return key
