# ARGUS
### Autonomous Reasoning Graph for Unified Security

*A self-evolving, epistemically aware knowledge graph for autonomous red-blue cyber operations.*

---

> **Status**: v0 — six-layer research prototype (all layers built, tested, and evaluated locally)
> **Paper**: pre-print in preparation, targeting arXiv cs.CR
> **License**: MIT

---

## What Is ARGUS?

ARGUS is a research prototype for autonomous adversarial cyber reasoning. It addresses a core
limitation of existing systems: knowledge graphs that are static, coarse-grained, and
*epistemically blind* — they cannot represent what they don't know about themselves.

**Three novel contributions:**

1. **Socratic Node Epistemology** — every node carries a `grain_confidence` score and structured
   `open_questions` about its own granularity, enabling self-directed refinement without a human in
   the loop.

2. **Conditional Edge Semantics** — edges carry `context_conditions`, confidence, directionality,
   and temporal validity, turning binary relations into probabilistic, situation-aware links.

3. **Adversarial Grain Refinement** — a *challenger* agent engages primary agents in structured
   pushback loops, subdividing coarse nodes until retrieval precision converges.

These sit inside a co-evolutionary red/blue simulation where opposing agents share and update a
single knowledge graph, with a reflexion memory that carries lessons across engagements.

> **Everything runs locally on Qwen3 8B via Ollama. No cloud API is required.** Cloud models
> (e.g. Groq) are an *optional* future benchmarking comparison only — not a dependency.

---

## Architecture — The 6 Layers

| Layer | What it does | Key files |
|-------|--------------|-----------|
| **1 — Graph Schema & Ingestion** | Socratic nodes + conditional edges; CVE (NVD) and MITRE ATT&CK → Neo4j | [graph/schema.py](graph/schema.py), [graph/ingestion/](graph/ingestion/) |
| **2 — GraphRAG Retrieval** | Structured traversal, not semantic guessing | [graph/retrieval.py](graph/retrieval.py) |
| **3 — Challenger Agent** | Grain-refinement pushback loop *(the novel part)* | [agents/challenger.py](agents/challenger.py) |
| **4 — Isekai Web Agent** | Crawls threat intel, proposes graph updates (challenger-validated) | [agents/crawler.py](agents/crawler.py) |
| **5 — Red & Blue Agents** | Co-evolutionary attack/mitigation over a shared graph | [agents/red.py](agents/red.py), [agents/blue.py](agents/blue.py) |
| **6 — Reflexion Memory** | Post-engagement self-reflection as episodic context | [memory/reflexion.py](memory/reflexion.py) |

Every layer has a smoke test under [scripts/](scripts/) (`test_ingestion.py` … `test_reflexion.py`).

---

## Hardware Requirements

Designed for consumer hardware — the full prototype runs on a laptop GPU.

| Component | Spec |
|-----------|------|
| GPU | 4GB VRAM (tested on RTX 3050) |
| RAM | 16GB |
| Local model | Qwen3 8B via Ollama |
| Graph DB | Neo4j Desktop (Community) |
| Embeddings | nomic-embed-text via Ollama |

---

## Setup

```bash
# 1. Install Ollama: https://ollama.com/download
ollama pull qwen3:8b
ollama pull nomic-embed-text

# 2. Install Neo4j Desktop: https://neo4j.com/download
#    Create a local database 'argus' (password 'argus1234'), then start it.

# 3. Python environment
conda create -n argus python=3.11 -y
conda activate argus
pip install -r requirements.txt

# 4. Configure environment (no API keys required — everything is local)
copy .env.example .env

# 5. End-to-end smoke test
python scripts/test_ingestion.py
```

> **Note:** `data/enterprise_attack.json` (the MITRE ATT&CK STIX bundle, ~48MB) and generated
> `results/` are intentionally not committed. The ATT&CK bundle is downloaded on first ingest;
> evaluation numbers are summarized in [CONTEXT.md](CONTEXT.md).

---

## Status & Evaluation

All six layers are implemented and their smoke tests pass locally. The four evaluation targets have
been run at least once; results and honest framing (including where statistical significance was
*not* reached) live in [CONTEXT.md](CONTEXT.md) and [PAPER_CLAIMS.md](PAPER_CLAIMS.md).

- [x] Node + Edge schema with Socratic / conditional structure
- [x] NVD CVE ingestion
- [x] MITRE ATT&CK ingestion (full 697 techniques + 15 tactics)
- [x] GraphRAG retrieval
- [x] Challenger, crawler, red/blue, and reflexion agents
- [x] End-to-end smoke tests (Layers 1–6)
- [x] Evaluations: retrieval precision, grain convergence, co-evolution, hardware feasibility
- [ ] Research paper draft (outline only so far)
- [ ] Hosted public read-only demo (see [PRODUCT_HOSTING_HANDOFF.md](PRODUCT_HOSTING_HANDOFF.md))

**This is a research artifact, not production SaaS.** See [BACKLOG.md](BACKLOG.md) for the gap to
production (auth, tenant isolation, safety boundaries, richer serialization, stronger evaluations).

---

## Dashboard

A read-only, force-directed visualization of the live graph (FastAPI + React):

```bash
docker compose up --build   # from the repo root
# open http://localhost:3000
```

The agents write to Neo4j; the dashboard only reads. See [dashboard/](dashboard/).

---

## Documentation Map

| File | Purpose |
|------|---------|
| [AGENTS.md](AGENTS.md) / [CLAUDE.md](CLAUDE.md) | Project rulebook — the layer spec and build rules |
| [CONTEXT.md](CONTEXT.md) | Current state, graph stats, evaluation results, hard-won Ollama quirks |
| [PAPER_CLAIMS.md](PAPER_CLAIMS.md) | Each paper claim mapped to: demonstrated / partial / future work |
| [PLAN.md](PLAN.md) | v0 finalization plan and definition of done |
| [BACKLOG.md](BACKLOG.md) | Out-of-scope work for v0 (production hardening, stronger evals) |
| [PRODUCT_HOSTING_HANDOFF.md](PRODUCT_HOSTING_HANDOFF.md) | How to ship a safe, read-only public demo |

---

## License

MIT — see [LICENSE](LICENSE). Open source.

---

## Responsible Use

ARGUS is a defensive research tool for reasoning about vulnerabilities and attack paths in an
uncertainty-aware way. It is **not** an exploit generator and does not perform live target
scanning. Use it for security research, education, and authorized red/blue evaluation only.
