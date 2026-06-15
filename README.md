# ARGUS
### Autonomous Reasoning Graph for Unified Security

*A self-evolving, epistemically aware knowledge graph architecture for autonomous red-blue cyber operations*

---

> **Status**: Phase 1 — Core Prototype (In Progress)
> **Paper**: Pre-print forthcoming on arXiv cs.CR

---

## What Is ARGUS?

ARGUS is a research prototype for autonomous adversarial cyber reasoning. It addresses the core limitation of existing systems: knowledge graphs that are static, coarse-grained, and epistemically blind.

**Three novel contributions:**

1. **Socratic Node Epistemology** — nodes carry structured open questions about their own granularity, enabling self-directed refinement without human intervention.

2. **Conditional Edge Semantics** — edges carry context conditions, confidence intervals, and open questions, transforming binary relations into probabilistic, situation-aware links.

3. **Adversarial Grain Refinement** — a challenger agent engages primary agents in structured pushback loops, redefining node and edge granularity until retrieval precision converges.

These sit inside a co-evolutionary red-blue simulation where opposing agents share and update a single knowledge graph, driving it toward Nash equilibrium.

---

## Architecture

```
Layer 1 — Graph Schema & Ingestion     (Socratic nodes + conditional edges)
Layer 2 — GraphRAG Retrieval           (structured traversal, not semantic guessing)
Layer 3 — Challenger Agent             (grain refinement loop)
Layer 4 — Isekai Web Agent             (continuous graph updates from threat intel)
Layer 5 — Red & Blue Agents            (co-evolutionary simulation)
Layer 6 — Reflexion Memory             (cross-engagement learning)
```

---

## Hardware Requirements

Designed for consumer hardware:

| Component | Spec |
|-----------|------|
| GPU | 4GB VRAM (tested on RTX 3050) |
| RAM | 16GB |
| Local model | Qwen3 8B via Ollama |
| Cloud model | Groq Llama 3.3 70B (free tier) |

---

## Setup

```bash
# 1. Install Ollama: https://ollama.com/download
ollama pull qwen3:8b
ollama pull nomic-embed-text

# 2. Install Neo4j Desktop: https://neo4j.com/download
#    Create database 'argus', password 'argus1234', then start it.

# 3. Python environment
conda create -n argus python=3.11 -y
conda activate argus
pip install -r requirements.txt

# 4. Configure environment
copy .env.example .env
# Edit .env — add your GROQ_API_KEY (free at https://console.groq.com)

# 5. Smoke test
python scripts/test_ingestion.py
```

---

## Current Phase

**Phase 1 (Weeks 1–2):** Graph schema + CVE ingestion + basic retrieval

- [x] Node and Edge schema with Socratic structure
- [x] NVD CVE ingestion pipeline
- [ ] MITRE ATT&CK ingestion
- [ ] GraphRAG retrieval
- [ ] Smoke test passing end-to-end

---

## Paper

Full research paper outline available in `ARGUS_Research_Paper_Outline.docx`.

Target venues: arXiv cs.CR → IEEE S&P / USENIX Security / ACM CCS

---

## License

MIT — open source forever. Commercial cloud API coming.
