# Unplug

LLM defense layer: SDK + self-hosted FastAPI server. Scans untrusted text for prompt injection, destructive actions, data leakage, and harmful output. Returns evidence-based findings with span-level redaction.

## Stack

- **SDK**: Python 3.11+, Pydantic, httpx, ONNX Runtime, transformers (tokenizer only)
- **Server**: FastAPI, uvicorn, ONNX Runtime
- **Models**: ModernBERT/DeBERTa classifiers via ONNX, regex engine
- **Package Manager**: uv
- **Testing**: pytest, pytest-asyncio
- **Linting**: ruff

## Repository Structure

```
unplug/
├── sdk/                    # Python SDK — `pip install unplug`
│   ├── pyproject.toml
│   └── src/unplug/         # Package source
│       ├── guard.py        # Guard class (main entry point)
│       ├── scanners/       # Pluggable scanner modules
│       ├── client.py       # HTTP client for server mode
│       └── models.py       # Shared Pydantic schemas
├── server/                 # FastAPI server — `unplug serve`
│   ├── pyproject.toml
│   └── src/unplug_server/  # Server source
│       ├── main.py         # FastAPI app + lifespan (model loading)
│       ├── api/routes/     # HTTP handlers
│       ├── core/           # Config, security, deps
│       └── services/       # Defense orchestrator, classifiers
├── benchmarks/             # Accuracy + latency benchmarks
├── datasets/               # Test attack datasets
├── examples/               # Integration examples
└── docs/                   # Documentation
```

## Architecture

3-stage pipeline with short-circuit:
1. **Regex + heuristics** (<1ms): 12 normalization stages, 245+ patterns, span offsets
2. **ML classifier** (5-15ms): ONNX-quantized ModernBERT/DeBERTa, CPU-optimized
3. **LLM judge** (500ms-2s): local small model for borderline cases only (~5%)

Key pattern: Routes → Services → Scanners (strict layering, same as crabgrass-backend)

## Commands

```bash
# SDK
cd sdk && uv sync && uv run pytest

# Server
cd server && uv sync && uv run uvicorn unplug_server.main:app --reload

# Lint
uv run ruff check . && uv run ruff format --check .

# Test
uv run pytest

# Benchmark
uv run python -m benchmarks.run
```

## Conventions

- Read existing files of the same type before creating new ones — match patterns
- Routes handle HTTP only — business logic goes in services
- All scanners implement the `Scanner` protocol
- Shared Pydantic schemas live in `sdk/src/unplug/models.py` — server imports from SDK
- ONNX models loaded once in FastAPI lifespan, injected via `app.state`
- CPU-bound inference runs via `run_in_threadpool` — never block the event loop
- Use `uv add <package>` — never edit pyproject.toml directly
- Keep commit messages short and descriptive

## Scanner Protocol

Every scanner (injection, destructive, leakage, harmful) implements:

```python
class Scanner(Protocol):
    name: str
    def scan(self, text: str, source: Source) -> list[Finding]: ...
```

The Guard class orchestrates scanners and aggregates findings.

## Key Design Decisions

- **Span-level redaction over binary blocking** — strip malicious parts, preserve legitimate content
- **Evidence-based findings** — every finding has category, stage, span offsets, score, evidence
- **Offline-first** — no external API calls required for stages 1-2
- **SDK-first, server-second** — SDK works standalone without the server
- **Source-aware scanning** — different policies for user input, retrieved docs, tool results
