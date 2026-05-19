.PHONY: install test lint format

install:
	cd sdk && uv sync --all-extras

test:
	cd sdk && uv run pytest -v

lint:
	cd sdk && uv run ruff check .

format:
	cd sdk && uv run ruff format .
