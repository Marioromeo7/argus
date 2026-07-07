# ARGUS — Claude Code Project Bible

**Autonomous Reasoning Graph for Unified Security**
*A self-evolving, epistemically aware knowledge graph for autonomous red-blue cyber operations*

---

## What This Project Is

ARGUS is a research prototype + open-core business. Three deliverables:
1. **GitHub repo** — open source, reproducible
2. **Research paper** — targeting arXiv cs.CR, then IEEE S&P / USENIX Security
3. **SaaS product** — cloud API for enterprise red team simulation (future)

The core novel contribution: knowledge graph nodes and edges that know what they
don't know about themselves, refined through adversarial agent dialogue.

---

## Hardware & Environment

- **OS**: Windows 11
- **GPU**: RTX 3050 — 4GB VRAM
- **RAM**: 16GB
- **Python**: Conda environment (see setup below)
- **Local LLM**: Qwen3 8B via Ollama (hybrid CPU+GPU offload, ~8 tok/sec — acceptable for batch)
- **Graph DB**: Neo4j Desktop (Community, local)
- **Vector store**: ChromaDB (in-memory)
- **Embeddings**: nomic-embed-text via Ollama

> **No cloud API required.** Everything runs locally on Qwen3 8B with thinking mode.
> Groq is an OPTIONAL future upgrade for Phase 3 benchmarking only — do not add it now.

---

## Setup (Run Once)

```bash
# 1. Install Ollama for Windows from https://ollama.com/download
#    Then pull models:
ollama pull qwen3:8b
ollama pull nomic-embed-text

# 2. Install Neo4j Desktop from https://neo4j.com/download
#    Create a local database named 'argus', password 'argus1234'
#    Start the database before running any graph code

# 3. Conda environment
conda create -n argus python=3.11 -y
conda activate argus
pip install -r requirements.txt

# 4. Copy .env.example to .env (no API keys needed yet)
copy .env.example .env

# 5. Verify everything works
python scripts/test_ingestion.py
```

---

## Architecture — The 6 Layers

Build them in order. Do NOT start Layer N+1 before Layer N is tested.

```
Layer 1 — Graph Schema & Ingestion
          Socratic node structure. CVE + MITRE ATT&CK → Neo4j.
          Files: graph/schema.py, graph/ingestion/nvd.py, graph/ingestion/attack.py

Layer 2 — GraphRAG Retrieval
          Traverse edges, not semantic guessing.
          Files: graph/retrieval.py

Layer 3 — Challenger Agent (THE NOVEL PART)
          Evaluates node grain. Proposes subdivisions via pushback loop.
          Files: agents/challenger.py

Layer 4 — Isekai Web Agent
          Crawls NVD/ATT&CK/threat feeds. Proposes graph updates.
          Challenger validates before any write.
          Files: agents/crawler.py

Layer 5 — Red & Blue Agents
          Red: finds attack paths. Blue: patches them.
          Shared graph updated by their conflict.
          Files: agents/red.py, agents/blue.py

Layer 6 — Reflexion Memory
          Post-engagement self-reflection stored as episodic context.
          Files: memory/reflexion.py
```

---

## Node Structure (The Core Innovation)

Every node must follow this schema — do NOT simplify it:

```python
{
  "label": str,                  # e.g. "heap_overflow_glibc_2.35"
  "properties": dict,            # arbitrary key-value facts
  "grain_confidence": float,     # 0.0 = undefined, 1.0 = maximally specific
  "open_questions": list[str],   # "what distinguishes me from similar nodes?"
  "challenger_log": list[dict],  # history: {question, proposal, accepted, timestamp}
  "last_updated": datetime,
  "source": str                  # "nvd" | "attack" | "agent_derived" | "web"
}
```

---

## Edge Structure (Also Novel)

Every edge must follow this schema — flat labels like "exploits" are NOT acceptable:

```python
{
  "source_id": str,
  "target_id": str,
  "relation_type": str,            # "exploits" | "enables" | "mitigates" | "requires"
  "context_conditions": list[str], # ["only if pre-auth", "requires subnet access"]
  "confidence": float,             # 0.0–1.0, updated by agent traversal
  "directionality": str,           # "unidirectional" | "bidirectional" | "conditional"
  "open_questions": list[str],     # "does this edge hold post-patch?"
  "challenger_log": list[dict],
  "temporal_validity": dict,       # {"from": datetime, "until": datetime | None}
  "last_updated": datetime
}
```

---

## Model Usage Rules

**All models are local. Everything runs through Ollama.**

| Task | Model | Mode |
|------|-------|------|
| Entity extraction from CVE text | Qwen3 8B | standard (fast) |
| Graph retrieval query generation | Qwen3 8B | standard (fast) |
| Challenger agent grain evaluation | Qwen3 8B | **/think mode** (deep reasoning) |
| Red agent attack path planning | Qwen3 8B | **/think mode** |
| Blue agent mitigation planning | Qwen3 8B | **/think mode** |
| Reflexion self-critique | Qwen3 8B | **/think mode** |

**How to use thinking mode with Ollama + Qwen3 8B:**
```python
import ollama

# Standard mode (fast, cheap)
response = ollama.chat(
    model="qwen3:8b",
    messages=[{"role": "user", "content": "/no_think\n\nYour prompt here"}]
)

# Thinking mode (slow, deep reasoning — use for challenger + reflexion)
response = ollama.chat(
    model="qwen3:8b",
    messages=[{"role": "user", "content": "/think\n\nYour prompt here"}]
)

# Extract just the response text (strip <think> blocks if present)
text = response["message"]["content"]
```

**When challenger proposals feel too shallow:** that's the signal to test Groq.
Add it in Phase 3 as a comparison point — it becomes a paper finding.
Do NOT add it before then.

---

## Evaluation Targets

These are the claims the paper makes. The code must prove them:

1. **Retrieval precision**: ARGUS GraphRAG retrieves more relevant nodes than baseline
   flat vector RAG on the same queries. Measure: Context Relevance Score, False Positive Rate.

2. **Grain convergence**: grain_confidence distribution shifts right monotonically over
   challenger iterations. Measure: mean + variance over N iterations.

3. **Co-evolutionary improvement**: both red and blue agents improve over successive
   engagements. Measure: attack path discovery rate, mean time to mitigation.

4. **Hardware feasibility**: full prototype runs on 4GB VRAM + 16GB RAM within
   acceptable latency for batch research use.

---

## Current Phase

**v0 — all six layers built, tested, and evaluated locally.** See [CONTEXT.md](CONTEXT.md) for the
live status, graph stats, and evaluation results, and [PAPER_CLAIMS.md](PAPER_CLAIMS.md) for the
evidence ledger.

Phase 1 (schema + ingestion + retrieval, checklist below) is complete:
- [x] Neo4j running locally, connection tested
- [x] graph/schema.py — Node and Edge classes with full structure above
- [x] graph/ingestion/nvd.py — fetch CVEs from NVD API, write to Neo4j
- [x] graph/ingestion/attack.py — load MITRE ATT&CK techniques, write to Neo4j
- [x] graph/retrieval.py — Cypher queries returning nodes by label + traversal
- [x] scripts/test_ingestion.py — end-to-end smoke test passing

Remaining v0 finalization work is tracked in [BACKLOG.md](BACKLOG.md) (paper draft, hosted demo,
stronger evaluations). Do not add features outside the six layers without listing them there first.

---

## What NOT To Do

- Do NOT use `py2neo` — use the official `neo4j` Python driver
- Do NOT use Groq, OpenAI, Anthropic, or any cloud API before Phase 3
- Do NOT flatten node/edge structures for "simplicity" — the structure IS the contribution
- Do NOT start the challenger agent before basic retrieval works
- Do NOT add features not in the 6-layer plan without writing them in a BACKLOG.md first
- Do NOT use Docker for Neo4j — Neo4j Desktop is simpler on Windows
- Do NOT use `langchain` graph integrations that abstract Neo4j — write Cypher directly

---

## File Naming & Style

- Snake case everywhere: `graph_retrieval.py`, not `GraphRetrieval.py`
- Every module has a docstring explaining which layer it belongs to and what it proves
- Every function that touches the graph has a `# ARGUS-LAYER-N` comment
- Keep functions under 40 lines — if longer, split it

---

## Git Commit Convention

```
[L1] add CVE ingestion pipeline          # Layer 1 work
[L2] implement basic GraphRAG traversal  # Layer 2 work
[EVAL] add retrieval precision metrics   # Evaluation work
[PAPER] update section 3 architecture   # Paper work
[FIX] handle Neo4j connection timeout    # Bug fixes
```

---

## Resources

- NVD API: https://services.nvd.nist.gov/rest/json/cves/2.0
- MITRE ATT&CK: https://github.com/mitre/cti (STIX format, downloadable)
- Neo4j Python driver docs: https://neo4j.com/docs/python-manual/current/
- Ollama API: http://localhost:11434/api
- Qwen3 thinking mode: prefix prompt with `/think` or `/no_think`
- ChromaDB docs: https://docs.trychroma.com
- Paper outline: ARGUS_Research_Paper_Outline.docx (in this folder)

---

## The One Rule

**If you're not sure what to build next, read this file again.**
The phases are the plan. The layers are the spec. The evaluation targets are the proof.
Build one thing. Test it. Commit it. Then build the next thing.
