# Cache + ML roadmap (PostgreSQL, BIOES, Prompt Guard)

**Date:** 2026-05-21  
**Status:** Approved direction

## Product gates

| Capability | SDK pip package | Hosted server |
|------------|-----------------|---------------|
| Regex + normalizer + encoding heuristic | Yes | Yes |
| Safe-prefix / chunk cache (in-process) | Yes (v1) | Yes + **PostgreSQL** (next) |
| DeBERTa document classifier | No | Yes (until unplug model) |
| **Privacy Filter** | **No until unplug-safeguard model** | Same — no public PF before model |
| Prompt Guard (22M/86M) on encodings | No | Yes (next) |
| BIOES span classifier (unplug-safeguard) | No | Yes (training + deploy) |

Output path today: `leakage` + `secrets` regex only. PF stage is a protocol stub in SDK.

---

## Cache: PostgreSQL first (Redis optional later)

### Why PostgreSQL as primary

- You already run Postgres for product data; one ops surface.
- Durable **safe_prefix** per `(org_id, document_id)` survives restarts and horizontal scale.
- **Chunk cache** rows with TTL, audit trail, API key metadata later.
- JSONB for `ScanResult` summary; no need for Redis unless latency requires it.

### Why Redis later (optional hot tier)

- Sub-millisecond LRU for hot RAG chunks under high QPS.
- Rate-limit counters per API key.
- Not required for v1 multi-instance if Postgres + connection pool is enough.

### Schema sketch (v1)

```sql
-- safe prefix per document
CREATE TABLE unplug_scan_prefix (
  cache_key TEXT PRIMARY KEY,  -- org:doc:norm_ver:model_ver
  prefix_len INT NOT NULL,
  prefix_hash TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- chunk result cache
CREATE TABLE unplug_scan_chunk (
  content_hash TEXT PRIMARY KEY,
  result_json JSONB NOT NULL,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_unplug_scan_chunk_expires ON unplug_scan_chunk (expires_at);
```

### SDK vs server

| Layer | v1 (now) | Next |
|-------|----------|------|
| SDK `ScanCache` | In-process LRU | Unchanged (local dev) |
| Server | Shared in-process `ScanCache` | `PostgresScanCache` implementing same interface |

Env: `UNPLUG_DATABASE_URL`, `UNPLUG_CACHE_BACKEND=memory|postgres`.

---

## Prompt Guard (encoding stage 1a)

1. Extract Base64 blob on **original** text (done: `core/encodings.py`).
2. Decode → run **Llama-Prompt-Guard-2-22M** on payload; escalate to **86M** on gray margin.
3. Mask whole blob span (`encoded_payload`) — no BIOES inside blob.
4. Lives on **server only** (`unplug_server/services/prompt_guard.py`), called from input pipeline hook post-extract.

Replace `HeuristicEncodingClassifier` when PG is wired.

---

## BIOES span model (unplug-safeguard)

1. Train token classifier (DeBERTa-v3-small → custom) on normalized prose; **exclude** encoding blobs from labels.
2. Server stage 2b: sliding windows 512 / overlap 64; map spans via `NormalizeResult.to_original_span`.
3. Replaces ProtectAI DeBERTa **document** classifier as primary semantic layer when eval beats baseline.
4. **Privacy Filter head** ships on same checkpoint (or companion weights) — only then enable PF in SDK/server for customers.

---

## Implementation order

| Phase | Work | Repo |
|-------|------|------|
| **C1** | `PostgresScanCache` + Alembic `001_scan_cache` | unplug-server — **PR open** |
| **C2** | `UNPLUG_CACHE_BACKEND` + docker-compose Postgres | unplug-server — **PR open** |
| **M1** | Prompt Guard service + encoding hook | unplug-server |
| **M2** | BIOES inference service | unplug-server + unplug_exp train |
| **M3** | unplug-safeguard bundle → enable PF + export spans | server; SDK stays regex-only until BYOM phase |

---

## References

- `unplug-span-pipeline-spec.md` — stage order
- `unplug-repo-alignment.md` — no SDK mirror refactor
- `unplug_exp` — DeBERTa/BIOES eval before production model choice
