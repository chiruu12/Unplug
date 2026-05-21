# Contributing to Unplug

## Branching and PRs

- Do **not** push directly to `main`.
- Branch from `main`: `feature/<short-name>` or `fix/<short-name>`.
- Open a PR; iterate in review until green CI.
- Merge via squash or merge commit after approval.

## CI

GitHub Actions runs on every PR to `main`:

- `sdk/`: ruff + pytest (`/.github/workflows/ci.yml`)

## Local checks (SDK)

```bash
cd sdk
uv sync --all-extras --dev
uv run ruff check . && uv run ruff format .
uv run pytest -q
```

## Related repos

| Repo | Role |
|------|------|
| [Unplug](https://github.com/chiruu12/Unplug) | SDK (this repo) |
| [unplug-server](https://github.com/chiruu12/unplug-server) | Hosted API |
| [unplug-mcp](https://github.com/chiruu12/unplug-mcp) | MCP tools |

Server-heavy work (Postgres cache, Prompt Guard, BIOES, unplug-safeguard model) lives in **unplug-server** after the finetuned model is ready.
