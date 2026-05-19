# Unplug

LLM defense layer — SDK package.

## Commands

```bash
make install          # install SDK
make test             # run all tests
make lint             # ruff check
make format           # ruff format

cd sdk && uv sync --all-extras
cd sdk && uv run pytest -v
cd sdk && uv run pytest tests/test_file.py -v
cd sdk && uv run ruff check . && uv run ruff format --check .
```

## Structure

- `sdk/` — Python SDK (`pip install unplug`)

Server, MCP, and site live in separate repos:
- [unplug-server](https://github.com/chiruu12/unplug-server)
- [unplug-mcp](https://github.com/chiruu12/unplug-mcp)
- [unplug-site](https://github.com/chiruu12/unplug-site)

## Conventions

- Python 3.11+, uv, ruff, pytest
- `uv add <package>` — never edit pyproject.toml manually
- `from __future__ import annotations` in every file
- Tests alongside code — every module gets a test file
- Read existing files before creating new ones
- Fail closed — errors default to blocking

## Commits

- One line, under 50 chars
- Describe what shipped, not how
- Never expose internal process
