# Unplug — Complete Product Roadmap

## Current State (May 9, 2026)

Repo scaffolded with working SDK skeleton + FastAPI server stubs.

**What exists:**
- Guard class with scan(), auto-instrument stub, redaction logic
- 4 scanner modules (injection, destructive, leakage, harmful) — regex-only
- Pydantic schemas shared between SDK and server
- FastAPI server with /v1/scan, /v1/batch, /v1/health
- HTTP client for server mode
- Examples, CLAUDE.md, architecture plan, decisions log

**What doesn't exist yet:**
- Full normalization pipeline (only basic)
- ML classifier (Stage 2)
- LLM judge (Stage 3)
- Tests
- Benchmarks
- Framework integrations (LangChain, CrewAI, etc.)
- MCP server
- SaaS infrastructure (auth, billing, dashboard)

---

## Phase 1: Solidify the SDK (Week 1-2)

**Goal:** Make the regex-only SDK production-quality. Ship v0.1.0 to PyPI.

### 1.1 Normalization Engine
- Port ClawGuard's 12 preprocessing stages with span mapping:
  1. Leetspeak normalization (17 char substitutions)
  2. Character spacing collapse (single-char runs)
  3. Zero-width character stripping (11 Unicode codepoints)
  4. Newline splitting → cross-line joining
  5. Markdown formatting removal
  6. Unicode homoglyph normalization (14 lookalikes → ASCII)
  7. Fullwidth Unicode → NFKC normalization
  8. Base64 auto-detection and decoding
  9. Reversed text variant generation
  10. Enclosed alphanumeric normalization (4 Unicode blocks)
  11. Delimiter separation stripping (pipe-separated words)
  12. Cross-language override verb matching (8 languages)
- Every normalization stage preserves span offsets back to original text
- File: `sdk/src/unplug/normalize.py`

### 1.2 Expand Regex Patterns
- Injection scanner: expand from 6 to 50+ patterns covering all 29 attack categories from neuralchemy dataset
- Destructive scanner: add Kubernetes (kubectl delete), Terraform (destroy), Docker (docker rm -f)
- Leakage scanner: add Anthropic keys (sk-ant-), Google Cloud keys, Slack tokens, database connection strings
- Harmful scanner: expand with configurable policy rules
- Reference: ClawGuard (245 patterns, 15 languages), Agntor SDK (11 built-in patterns)

### 1.3 Tests
- Unit tests for every normalization stage with span mapping verification
- Unit tests for every regex pattern (positive match + benign hard negative)
- Golden test suite: 100+ known attacks from neuralchemy dataset categories:
  - direct_injection, jailbreak, system_extraction, encoding_obfuscation
  - persona_replacement, indirect_injection, token_smuggling, many_shot
  - crescendo, prompt_leaking, context_overflow, benign hard negatives
- Integration test: Guard.scan() end-to-end with multi-scanner aggregation
- Target: 95%+ code coverage on regex engine

### 1.4 CLI
- `unplug scan "text"` — scan from command line
- `unplug scan file.txt --json` — scan file, JSON output
- `unplug scan --stdin` — pipe input
- `unplug serve --port 8000` — start FastAPI server
- Entry point in pyproject.toml: `[project.scripts] unplug = "unplug.cli:main"`
- File: `sdk/src/unplug/cli.py`

### 1.5 Ship v0.1.0
- Publish to PyPI: `pip install unplug`
- Clean README with quickstart, badges, architecture diagram
- GitHub release with changelog
- Announce: nothing public yet, just ship clean

**Deliverables:** Working SDK with 50+ patterns, 12 normalization stages, CLI, tests, on PyPI.

---

## Phase 2: ML Classifier — Stage 2 (Week 3-4)

**Goal:** Add the ONNX classifier for semantic detection. Ship v0.2.0.

### 2.1 Off-the-Shelf Model Integration
- Start with `protectai/deberta-v3-base-prompt-injection-v2` (0.2B, 95.25% accuracy, Apache 2.0)
- Also evaluate:
  - `protectai/deberta-v3-small-prompt-injection-v2` (0.1B, 94.28%, faster)
  - `qualifire/prompt-injection-sentinel` (ModernBERT-large, 98.7%, SOTA)
  - `meta-llama/Llama-Prompt-Guard-2-86M` (multilingual, 7 languages)
  - `meta-llama/Llama-Prompt-Guard-2-22M` (smallest, 22M params)
- ONNX export for all candidates
- File: `sdk/src/unplug/classifiers/onnx_classifier.py`

### 2.2 Classifier Abstraction
```python
class Classifier(Protocol):
    def predict(self, text: str) -> ClassifierResult: ...
    def predict_batch(self, texts: list[str]) -> list[ClassifierResult]: ...

class ClassifierResult:
    label: str          # "safe" | "injection"
    score: float        # 0.0-1.0
    latency_ms: float
```
- Pluggable: swap models without changing scanner code
- Lazy loading: model only loaded when Stage 2 is needed
- File: `sdk/src/unplug/classifiers/__init__.py`

### 2.3 Pipeline Orchestration
- Stage 1 (regex) short-circuits if high confidence (score >= 0.85)
- Stage 2 (classifier) runs only on uncertain regex results
- Confidence thresholds configurable per scanner
- Update injection scanner to use classifier for semantic detection
- Update Guard to orchestrate stages with timing

### 2.4 Benchmark Suite
- Accuracy benchmarks against public datasets:
  - neuralchemy/Prompt-injection-dataset (22K rows, 29 categories)
  - deepset/prompt-injections (662 rows)
  - Open-Prompt-Injection benchmark
- Latency benchmarks: p50, p95, p99 on CPU (Apple Silicon M2+, Intel Xeon)
- Comparison table: Unplug vs LLM Guard vs ProtectAI DeBERTa standalone
- File: `benchmarks/run.py`, `benchmarks/accuracy.py`, `benchmarks/latency.py`

### 2.5 Model Download + Caching
- Auto-download ONNX model on first use (like sentence-transformers)
- Cache in `~/.cache/unplug/models/`
- Configurable model path for air-gapped environments
- Model size check + progress bar during download

**Deliverables:** Two-stage pipeline (regex + ML), benchmark results, v0.2.0 on PyPI.

---

## Phase 3: Server + API Hardening (Week 5-6)

**Goal:** Production-ready FastAPI server. Ship v0.3.0.

### 3.1 DefenseOrchestrator Service
- Move pipeline orchestration from SDK Guard into server service layer
- ONNX model loaded once in lifespan, injected via app.state
- CPU-bound inference via `run_in_threadpool` (never block event loop)
- Batch inference support (stack multiple requests)
- File: `server/src/unplug_server/services/defense/orchestrator.py`

### 3.2 API Endpoints
```
POST /v1/scan          # Scan single text
POST /v1/redact        # Scan + return redacted version
POST /v1/batch         # Batch scan (up to 100 texts)
GET  /v1/health        # Health + model status
GET  /v1/stats         # Scan counts, latency percentiles
POST /v1/feedback      # Report false positive/negative
```

### 3.3 API Key Authentication
- Bearer token auth via `Authorization: Bearer <key>`
- API keys stored in env vars or config file (no database for v1)
- Rate limiting: configurable RPM per key
- File: `server/src/unplug_server/core/security.py`

### 3.4 Request Logging
- Log every scan: timestamp, source, action taken, latency, findings count
- SQLite for local logging (no external DB dependency)
- Optional: export logs as CSV/JSON for compliance evidence
- File: `server/src/unplug_server/services/logging.py`

### 3.5 Docker
- Dockerfile: single-stage, python:3.11-slim, ONNX model baked in
- docker-compose.yml for local development
- Health check endpoint wired to Docker HEALTHCHECK
- `docker run -p 8000:8000 ghcr.io/chiruu12/unplug`

### 3.6 Performance Verification
- Load test: locust or hey against /v1/scan
- Verify targets: p50 <20ms, p99 <50ms (stages 1+2 only)
- Memory profiling: verify <500MB with model loaded
- Concurrent request handling: verify 100+ RPS on single instance

**Deliverables:** Production-ready API server, Docker image, load test results, v0.3.0.

---

## Phase 4: Framework Integrations (Week 7-8)

**Goal:** Zero-friction adoption in every major agent framework. Ship v0.4.0.

### 4.1 Auto-Instrument Engine
- Detect installed frameworks at `Guard.init()` time
- Monkey-patch framework internals to route through Guard
- Pattern: Aegis/Sentry auto-detection
- File: `sdk/src/unplug/integrations/__init__.py`

### 4.2 LangChain Integration
- `UnplugCallbackHandler` — hooks into BaseTool.invoke() and BaseChatModel.invoke()
- `UnplugRunnable` — composable via `|` pipe operator
- Scans: user input (pre-call), tool results (during-call), model output (post-call)
- File: `sdk/src/unplug/integrations/langchain.py`
- Example: `examples/langchain_integration.py`

### 4.3 LlamaIndex Integration
- `UnplugNodePostprocessor` — scan RAG chunks before they reach the LLM
- `UnplugQueryTransform` — scan user queries
- File: `sdk/src/unplug/integrations/llamaindex.py`

### 4.4 OpenAI Agents SDK Integration
- Input guardrail + output guardrail + tool guardrail implementations
- Raises `GuardrailTripwireTriggered` on detection
- File: `sdk/src/unplug/integrations/openai_agents.py`

### 4.5 CrewAI Integration
- Task decorator for scanning agent outputs
- Pre/post tool execution hooks
- File: `sdk/src/unplug/integrations/crewai.py`

### 4.6 MCP Server
- Distribute as MCP server: one JSON entry in config
- Tools exposed: `scan_text`, `scan_tool_result`, `check_destructive`
- Works with Claude Code, Cursor, Windsurf, any MCP client
- File: `mcp/server.py` or separate `unplug-mcp` package
- Install: `uvx unplug-mcp` or `npx unplug-mcp`

### 4.7 GitHub Action
- `chiruu12/unplug-action@v1`
- Scans PR diffs for prompt injection vulnerabilities in agent code
- Comments on PRs with findings
- Free for public repos
- Directory: `github-action/`

**Deliverables:** 5 framework integrations, MCP server, GitHub Action, v0.4.0.

---

## Phase 5: Model Training + Custom Classifier (Week 9-12)

**Goal:** Train our own classifier that beats off-the-shelf models. Ship v0.5.0.

### 5.1 Dataset Preparation
- Combine datasets:
  - neuralchemy/Prompt-injection-dataset (22K, 29 categories)
  - hlyn/prompt-injection-judge-deberta-dataset (400K samples)
  - deepset/prompt-injections (662 rows)
  - MAlmasabi/Indirect-Prompt-Injection-BIPIA-GPT (70K indirect)
- Add hard negatives: benign prompts with injection-like keywords
- Add destructive action examples, leakage examples
- Clean, deduplicate, balance classes
- Export as HuggingFace Dataset for reproducibility

### 5.2 Baseline Evaluation
- Benchmark all off-the-shelf models against our combined dataset:
  - ProtectAI DeBERTa-v3-base-v2 and small-v2
  - Sentinel (ModernBERT-large)
  - Llama Prompt Guard 2 (86M and 22M)
- Measure: accuracy, precision, recall, F1, false positive rate, latency
- Identify gaps: which attack categories are missed?

### 5.3 Fine-Tuning
- Base model: ModernBERT-base (149M, 8192 context, 2x faster than DeBERTa)
- Training: PyTorch + HuggingFace Transformers + LoRA
- Multi-label classification: injection, jailbreak, safe (not just binary)
- Export: ONNX for cross-platform, MLX for Apple Silicon
- Target: beat Sentinel (98.7%) on our combined eval set

### 5.4 Span-Level Detection (Research)
- Investigate CRF sequence labeling (Clean's approach, ~1MB, <10ms)
- Train CRF on annotated spans from regex findings (weak supervision)
- Goal: move from prompt-level to token-level detection
- This is the key differentiator over all competitors

### 5.5 LLM Judge — Stage 3
- Integrate local small model via MLX (Qwen3-0.6B or similar)
- Structured CoT prompt: intent → safety verification → harm assessment → verdict
- FAISS index of known attack embeddings for similarity check
- Only triggered for borderline cases (classifier score 0.3-0.7)
- Hard negative mining: confirmed benign → add to training data

**Deliverables:** Custom-trained classifier, span-level CRF, LLM judge, benchmark report, v0.5.0.

---

## Phase 6: SaaS Launch (Week 13-16)

**Goal:** Hosted API with auth, billing, and dashboard. Launch publicly.

### 6.1 Hosted API Infrastructure
- Deploy FastAPI server on:
  - Edge: Cloudflare Workers for regex (Stage 1)
  - CPU instances: 2-4x c7i.xlarge for classifier (Stage 2)
  - LLM API: Claude Haiku / Gemini Flash Lite for judge (Stage 3)
- Load balancer + auto-scaling
- Estimated cost: $200-500/mo for 1M scans

### 6.2 Authentication + API Keys
- API key management: create, rotate, revoke
- Per-key rate limiting and usage tracking
- OAuth2 for dashboard login

### 6.3 Dashboard
- Real-time scan statistics (requests, blocks, latency)
- Findings breakdown by category and severity
- False positive/negative reporting
- API key management
- Tech: React + Vite (or simple server-rendered pages for v1)

### 6.4 Billing
- Stripe integration
- Pricing tiers:
  | Tier | Price | Scans/mo |
  |------|-------|----------|
  | Free | $0 | 100,000 |
  | Starter | $19/mo | 500,000 |
  | Pro | $49/mo | 2,000,000 |
  | Scale | $149/mo | 10,000,000 |
  | Enterprise | Custom | Unlimited |
- Generous free tier to drive adoption (our Stage 1+2 marginal cost is ~$0)

### 6.5 Compliance + Audit
- Request logging with 6-month retention (EU AI Act requirement)
- Exportable audit trails (CSV, JSON)
- SOC 2 preparation documentation
- GDPR: data residency options (EU / US)

### 6.6 Documentation Site
- docs.unplug.dev (or similar)
- API reference (auto-generated from OpenAPI)
- Quick start guides per framework
- Attack category reference
- Pricing page

### 6.7 Public Launch
- GitHub README polish + badges + demo GIF
- HN Show post
- Reddit: r/MachineLearning, r/Python, r/artificial
- Twitter/X thread with demo video
- Dev.to / Medium launch article
- Target: 500+ GitHub stars in first week

**Deliverables:** Hosted SaaS, dashboard, billing, documentation, public launch.

---

## Phase 7: Growth + Partnerships (Week 17+)

**Goal:** Enterprise adoption, insurance partnerships, market positioning.

### 7.1 Insurance Partnerships
- **Klaimee** (YC W26) — first partner target
  - Integrate Unplug into their certification pipeline
  - Companies using Unplug → better adversarial manipulation score → lower premiums
  - Pitch: "We provide the real-time security posture data you need"
- **Corgi** ($1.3B unicorn, YC S24) — second partner target
  - Their AI insurance explicitly covers "adversarial attacks on models"
  - Pitch: "Companies using Unplug have measurably lower adversarial attack risk"
- **Munich Re aiSure** — enterprise insurance angle

### 7.2 Enterprise Features
- On-premise deployment (Docker + Helm chart)
- Custom policy rules (YAML-based)
- SSO / SAML integration
- Team management + role-based access
- Custom model training on customer data
- SLA with uptime guarantees
- Dedicated inference instances

### 7.3 Viral Growth Mechanics
- **"Can You Hack This Agent?"** — interactive CTF game (Gandalf-style)
  - Public-facing, generates awareness + threat intelligence data
  - Every attack attempt improves our training data
  - Lakera got 1M+ players and 80M+ adversarial prompts from Gandalf
- **Security badges** — "Protected by Unplug" badge for READMEs
- **Open benchmark** — public leaderboard comparing defense tools

### 7.4 Node.js SDK
- `npm install unplug`
- Same API surface as Python SDK
- TypeScript-first with full type safety
- Directory: `packages/js/`

### 7.5 Expand Scanner Verticals
- **Hallucination detection** — factual consistency checking
- **Cost guard** — prevent runaway token usage
- **Compliance scanner** — HIPAA, PCI-DSS, GDPR-specific rules
- **Model drift detection** — alert when outputs diverge from baseline
- **Rate abuse detection** — identify automated attack patterns

### 7.6 Continuous Improvement Loop
- Attack corpus grows from:
  - CTF game submissions
  - Customer-reported false positives/negatives (/v1/feedback)
  - Public dataset updates
  - Adversarial research papers
- Retrain classifier quarterly with expanded data
- Weekly regex pattern updates from emerging attack techniques

---

## Timeline Summary

| Phase | Timeline | Milestone | Version |
|-------|----------|-----------|---------|
| 1. Solidify SDK | Week 1-2 | Regex engine, tests, CLI, PyPI | v0.1.0 |
| 2. ML Classifier | Week 3-4 | ONNX classifier, benchmarks | v0.2.0 |
| 3. Server Hardening | Week 5-6 | Production API, Docker | v0.3.0 |
| 4. Integrations | Week 7-8 | LangChain, MCP, GitHub Action | v0.4.0 |
| 5. Custom Model | Week 9-12 | Trained classifier, span CRF | v0.5.0 |
| 6. SaaS Launch | Week 13-16 | Hosted API, billing, launch | v1.0.0 |
| 7. Growth | Week 17+ | Insurance, enterprise, viral | v1.x |

## Key Metrics to Track

| Metric | Target (6 months) |
|--------|-------------------|
| GitHub stars | 1,000+ |
| PyPI downloads/week | 5,000+ |
| Registered API users | 500+ |
| Paying customers | 50+ |
| MRR | $5,000+ |
| Scan accuracy (F1) | >0.95 |
| p50 latency | <20ms |
| False positive rate | <2% |

## Competitive Moat

1. **Span-level redaction** — only Clean (80% recall) does this, we aim for 95%+
2. **MCP-native distribution** — zero code changes for agent developers
3. **Offline-first + fast** — <20ms, no API dependency, runs on CPU
4. **Multi-vertical** — injection + destructive + leakage + harmful (not single-purpose)
5. **Insurance integration** — Corgi/Klaimee partnership = enterprise sales leverage
6. **Attack data flywheel** — CTF game + customer feedback → better models → better product
7. **Open source core** — developer trust + adoption, enterprise SaaS monetization
