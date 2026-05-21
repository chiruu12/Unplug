# Unplug repo alignment (post–SDK 0.3 refactor)

**Date:** 2026-05-21

The large refactor (Guard → Pipelines → Safeguards, Pydantic config, server mode, ScanPolicy) applies to the **SDK only** (`jakarta/sdk`). Sibling repos stay thin wrappers.

## Repo roles

| Repo | Refactor needed? | What to keep in sync |
|------|------------------|----------------------|
| **jakarta/sdk** | Source of truth | All runtime logic, types, cache, privacy heuristic |
| **unplug-server** | No mirror layout | Editable `unplug>=0.3`, lifespan wiring (classifier, privacy, shared `ScanCache`), `isolated=True` scans |
| **unplug-mcp** | No | Bump dep, `UNPLUG_MODE=server`, optional `document_id` on tools |
| **unplug_exp** | No | Scripts only; eval harness |
| **unplug-site** | No | Marketing/static |

## unplug-server checklist

- [x] Depends on `jakarta/sdk` editable path
- [x] Per-request `scan_request(..., isolated=True)` (no shared `ExecutionContext` races)
- [ ] PF only after unplug-safeguard model (`PRIVACY_FILTER_DEV_HEURISTIC` for internal dev only)
- [x] `UNPLUG_CACHE_ENABLED` + shared `ScanCache` on app state
- [ ] Redis/Postgres cache backend (later)
- [ ] Real `openai/privacy-filter` model extra (later)

## unplug-mcp checklist

- [x] `unplug>=0.3.0`
- [x] Hosted mode via `UNPLUG_MODE` + URL/API key env
- [ ] Document server-mode in README

## Do not duplicate

- Scanner implementations
- Pipeline/policy logic
- `ScanRequest` / `ScanResult` types (import from `unplug`)

Server-only code belongs in `unplug_server/services/` (classifier, privacy re-export, future Redis cache).
