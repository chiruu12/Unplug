.PHONY: install install-sdk install-server test lint format dev

install: install-sdk install-server

install-sdk:
	cd sdk && uv sync --all-extras

install-server:
	cd server && uv sync --all-extras

test:
	cd sdk && uv run pytest -v
	cd server && uv run pytest -v

lint:
	cd sdk && uv run ruff check .
	cd server && uv run ruff check .

format:
	cd sdk && uv run ruff format .
	cd server && uv run ruff format .

dev:
	cd server && uv run uvicorn unplug_server.main:app --reload --port 8000
