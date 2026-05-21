# unplug_exp — Private Experimentation Repo

**Purpose:** Keep dataset downloads, eval runs, training scripts, cost ledgers, and pilot notebooks **out of** the public SDK repo.

**GitHub:** `chiruu12/unplug_exp` (private) — create if not exists.

**Local path (Conductor workspace):** `unplug-v1/repos/unplug_exp/`

---

## What lives here vs `jakarta` (Unplug SDK)

| unplug_exp | jakarta (chiruu12/Unplug) |
|------------|---------------------------|
| HF dataset probe/download scripts | `sdk/benchmarks/` — lightweight eval entrypoints |
| Synthetic data generation jobs | Product spec only |
| Training / Fireworks / MLX notebooks | Production guard code |
| Cost ledger JSONL | `.env.example` |
| Raw `datasets/` (gitignored) | No raw data in git |
| Model checkpoints (gitignored) | ONNX/classifier integration when ready |
| OWASP + neuralchemy eval reports | `context/product/plans/unplug-span-pipeline-spec.md` |

---

## Directory layout

```
unplug_exp/
├── README.md
├── pyproject.toml          # uv project, depends on unplug SDK editable
├── .gitignore
├── .env.example
├── configs/
│   ├── eval.yaml
│   └── taxonomy/map_hf_to_unplug.yaml
├── scripts/
│   ├── probe_hf_datasets.py
│   ├── download_all.py
│   ├── eval_category_report.py
│   └── pilot_pg_base64.py
├── datasets/               # gitignored
│   ├── raw/
│   ├── processed/
│   └── manifests/
├── experiments/
│   └── 2026-05-21_pilot_a/
│       ├── manifest.json
│       └── cost_ledger.jsonl
├── training/               # later
│   └── deberta_bioes/
└── reports/                # gitignored or summary-only in git
```

---

## Setup

```bash
cd unplug_exp
uv sync
# Link local SDK:
uv add --editable ../jakarta/sdk
cp .env.example .env  # API keys local only
```

---

## Experiment manifest (required per run)

```json
{
  "experiment_id": "2026-05-21_pilot_a",
  "spec_version": "unplug-span-pipeline-spec@v0.3",
  "generator_model": "gpt-5.x-nano",
  "judge_model": "claude-sonnet-4",
  "datasets": ["neuralchemy", "owasp-v2"],
  "row_counts": { "train": 0, "eval": 500 },
  "usd_budget": 50
}
```

---

## First scripts (P0)

1. `probe_hf_datasets.py` — metadata only (size, license, columns).
2. `eval_category_report.py` — calls `benchmarks.evaluate` via editable `unplug`.
3. `pilot_pg_base64.py` — encoding extract → PG 22/86 → mask metrics on neuralchemy encoding categories.

---

## Secrets

- Never commit `datasets/`, `.env`, checkpoints, or API keys.
- Synthetic generators use placeholder credentials only.
