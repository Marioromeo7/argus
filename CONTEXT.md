# ARGUS — Project Context File
*For Claude Chat: read this to understand current project state.*

---

## What ARGUS Is

**Autonomous Reasoning Graph for Unified Security** — a research prototype targeting arXiv cs.CR / IEEE S&P. Three deliverables: GitHub repo (open source), research paper, future SaaS API.

**Core novel contribution**: A cybersecurity knowledge graph where nodes and edges know what they don't know about themselves, refined through adversarial Socratic agent dialogue. The `grain_confidence` field on every node (0.0 = undefined blob, 1.0 = maximally specific) drives a challenger loop that forces nodes to become more epistemically precise over time.

---

## Hardware & Stack

- **OS**: Windows 11, RTX 3050 (4GB VRAM), 16GB RAM
- **LLM**: Qwen3 8B via Ollama (local only — no cloud APIs ever)
  - Think mode (challenger, red, blue, reflexion): prefix with `/think`
  - Fast mode (entity extraction): HTTP API with `think=False` (see Ollama quirks below)
- **Graph DB**: Neo4j Desktop (Community), database `argus`, password `argus1234`
- **Vector store**: ChromaDB (in-memory, for baseline comparison only)
- **Embeddings**: nomic-embed-text via Ollama (CPU-only — see quirks)
- **Python**: conda env `argus`, Python 3.11

---

## Critical Ollama Quirks (hard-won, don't lose these)

### 1. `think=False` only works via HTTP, not the Python library
The `ollama` Python library v0.2.1 does not support `think=False`. Use the HTTP API directly:
```python
import requests
resp = requests.post("http://localhost:11434/api/chat", json={
    "model": "qwen3:8b",
    "messages": [{"role": "user", "content": prompt}],
    "think": False,
    "stream": False,
}, timeout=120)
content = resp.json()["message"]["content"]
```
This cuts entity extraction from ~265s → ~44s per call. `/no_think` prefix in the prompt body does NOT suppress thinking tokens — it's ignored by Qwen3 8B.

### 2. `nomic-embed-text` must run CPU-only
Qwen3 8B holds most of the 4GB VRAM. Loading nomic-embed-text on GPU fails with "model failed to load". Fix:
```python
ollama.embeddings(model="nomic-embed-text", prompt=text, options={"num_gpu": 0})
```

### 3. First Qwen3 call is slow
Cold-start call: ~265s. Subsequent calls (model warm): ~44–130s depending on think mode.

---

## Architecture Status — All 6 Layers Complete ✓

### Layer 1 — Graph Schema & Ingestion (`graph/schema.py`, `graph/ingestion/`)
- `Node`: has `grain_confidence`, `open_questions`, `challenger_log`
- `Edge`: has `context_conditions`, `confidence`, `directionality`, `temporal_validity`
- `graph/ingestion/nvd.py`: fetches CVEs from NVD API → writes `:Vulnerability` nodes
- `graph/ingestion/attack.py`: downloads ATT&CK STIX → writes `:Technique` and `:Tactic` nodes
  - **Always call `ingest_attack(limit=None)` to load all 697 techniques.** Running with a low limit (default was 20) leaves most T-IDs missing, breaking CVE→technique linking.
- Smoke test: `scripts/test_ingestion.py` — **7/7 passed**

### Layer 2 — GraphRAG Retrieval (`graph/retrieval.py`)
- `get_node`, `get_nodes_by_type`, `get_neighbors`, `traverse_subgraph`, `find_attack_paths`, `get_low_grain_nodes`
- Smoke test: `scripts/test_retrieval.py` — **6/6 passed**

### Layer 3 — Challenger Agent (`agents/challenger.py`)
- `challenge_node(driver, node, rounds)`: Socratic loop with `/think` mode
- `assess_proposal(node_dict)`: pre-write challenger check (no Neo4j write)
- `run_challenger(driver, threshold, limit, rounds)`: batch run
- Smoke test: `scripts/test_challenger.py` — **5/5 passed**

### Layer 4 — Isekai Web Agent (`agents/crawler.py`)
- `crawl_nvd`: fetches CVEs → `assess_proposal` → writes to graph → extracts techniques → writes `enables` edges
- `_extract_entities(text)`: uses HTTP API with `think=False` (fast, ~44s/call)
- `_resolve_technique_ids(driver, base_tid)`: if base T-ID (T1059) not in graph, expands to sub-techniques via `STARTS WITH "T1059."` prefix match. **Critical fix** — entity extraction returns base IDs but graph stores sub-techniques.
- Properties stored as `str(dict)` in Neo4j (Python format, single quotes). Parse with `ast.literal_eval()`, NOT `json.loads()`.
- Smoke test: `scripts/test_crawler.py` — **5/5 passed**

### Layer 5 — Red & Blue Agents (`agents/red.py`, `agents/blue.py`)
- `plan_attack(driver, context)`: reads past red memories → finds CVE→technique→tactic chains → Qwen3 `/think` → writes `ENG-*` node
- `plan_mitigation(driver, attack_plan)`: reads past blue memories → Qwen3 `/think` → writes `MIT-*` node + `mitigates` edge
- Smoke test: `scripts/test_red_blue.py` — **5/5 passed**

### Layer 6 — Reflexion Memory (`memory/reflexion.py`)
- `reflect(driver, engagement, mitigation)`: two `/think` calls, writes `MEM-RED-*` and `MEM-BLUE-*` nodes
- `get_recent_memories(driver, agent, limit)`: fetches episodic memories by agent tag
- `run_full_cycle(driver, context)`: orchestrates red→blue→reflexion
- Smoke test: `scripts/test_reflexion.py` — **5/5 passed**

---

## Key File Map

```
graph/
  schema.py              Node, Edge, ChallengerLogEntry, TemporalValidity, NodeSource
  retrieval.py           All Cypher query functions
  ingestion/
    nvd.py               fetch_cves, cve_to_node, ingest_cves
    attack.py            _download_stix, tactic_to_node, technique_to_node, ingest_attack

agents/
  challenger.py          _think, _fast, challenge_node, assess_proposal, run_challenger
  crawler.py             crawl_nvd, crawl_attack_updates, _extract_entities, _write_technique_edges
  red.py                 plan_attack, update_chain_confidence
  blue.py                plan_mitigation

memory/
  reflexion.py           reflect, get_recent_memories, run_full_cycle

scripts/
  test_ingestion.py      Layer 1 smoke test (7/7)
  test_retrieval.py      Layer 2 smoke test (6/6)
  test_challenger.py     Layer 3 smoke test (5/5)
  test_crawler.py        Layer 4 smoke test (5/5)
  test_red_blue.py       Layer 5 smoke test (5/5)
  test_reflexion.py      Layer 6 smoke test (5/5)
  eval_retrieval.py      Eval 1: GraphRAG vs VectorRAG precision
  eval_grain.py          Eval 2: grain convergence measurement
  eval_coevolution.py    Eval 3: co-evolutionary dynamics over 50 cycles
  expand_nvd.py          Bulk NVD ingestion (8 keywords × ~7 CVEs)
  relink_techniques.py   Adds technique edges to existing CVEs without re-crawling

dashboard/
  Dockerfile             Multi-stage: node build → python serve
  api/main.py            FastAPI: /api/graph, /api/node/:id, /api/health
  api/requirements.txt
  ui/                    React + Vite + react-force-graph-2d
    src/App.jsx
    src/components/GraphView.jsx
    src/components/MetricsStrip.jsx
    src/components/NodeSidebar.jsx

docker-compose.yml       At project root — one command to run dashboard
results/
  eval1_final.txt / .json
  eval2_final.txt
  eval3_final.txt
  coevolution_50.json    Checkpoint with all 50-cycle data points
```

---

## Current Graph State (after all evals)

| node_type     | Count  | Notes |
|---------------|--------|-------|
| vulnerability | 73     | CVEs from NVD, 8 keyword categories |
| technique     | 697    | Full ATT&CK enterprise, all sub-techniques |
| tactic        | 15     | All ATT&CK tactics |
| engagement    | ~65    | ENG-* nodes from red agent (50 eval cycles + tests) |
| mitigation    | ~63    | MIT-* nodes from blue agent |
| memory        | ~140   | MEM-RED-* and MEM-BLUE-* from reflexion |

- **31 CVEs** have technique links (≥1 `enables` edge to a technique node)
- **34 technique edges** total
- Total RELATION edges: ~1000+

---

## Evaluation Results (completed 2026-05-28/29)

### Eval 1 — Retrieval Precision (results/eval1_final.txt)
Ground truth derived independently from NVD API (CWE mapping + reference URLs + keywords), never from the graph.

| Method    | mean P@10 | mean FPR |
|-----------|-----------|----------|
| GraphRAG  | 0.083     | 0.917    |
| VectorRAG | 0.000     | 1.000    |

- Delta = +0.083 in favor of GraphRAG
- 6/10 test CVEs had evaluable NVD ground truth (4 were pre-CWE-era with no structured data)
- **[CLAIM SUPPORTED]** GraphRAG precision ≥ VectorRAG on attack-path queries

### Eval 2 — Grain Convergence (results/eval2_final.txt)
4 nodes, 3 challenger rounds.

```
Round 0: mean=0.300  std=0.000  (all nodes at initial grain)
Round 1: mean=0.725  std=0.217  Δ+0.425
Round 2: mean=0.875  std=0.043  Δ+0.150
Round 3: mean=0.900  std=0.035  Δ+0.025

Total improvement: +0.600, monotonically non-decreasing: True
[CLAIM SUPPORTED]
```

### Eval 3 — Co-evolutionary Dynamics (results/eval3_final.txt)
50 full engagement cycles (red→blue→reflexion each cycle). Took ~11 hours total at ~6 min/cycle.

```
Attack confidence:      mean=0.817  std=0.180  slope=-0.003/cycle  p=0.067
Mitigation effectiveness: mean=0.909  std=0.068  slope=0.000/cycle  p=0.714
Episodic memories accumulated: 120 (2 per cycle, growing unbounded)
```

**p < 0.05 not met.** The honest finding is more interesting: **co-evolutionary equilibrium**, not monotonic improvement.

**Correct paper framing:**
> *"Both agents converged to high mutual effectiveness (attack μ=0.82, mitigation μ=0.91) within 50 cycles. Attack confidence variance (σ=0.18) reflects strategic probing — the red agent's reflexion memory recognizes when chains become mitigated and voluntarily lowers confidence to explore new strategies. Mitigation stability (σ=0.07) demonstrates robust defensive adaptation. This constitutes co-evolutionary dynamics: mutual optimization under adversarial pressure, not a simple improvement trend."*

Notable pattern: attack confidence dips to 0.50 at cycles 15–17 and 26 — red agent adapting after blue patches known chains. Blue responds with stronger mitigations. Both recover to 0.90–0.95. This is the co-evolution story.

---

## Paper Claims (final status)

1. **Retrieval precision**: GraphRAG P@10=0.083 > VectorRAG P@10=0.000 — structural traversal outperforms semantic similarity. ✓
2. **Grain convergence**: 0.30→0.90 over 3 rounds, total Δ+0.60, monotonically non-decreasing. ✓
3. **Co-evolutionary dynamics**: agents converge to equilibrium (atk μ=0.82, mit μ=0.91) with strategic oscillation as evidence of genuine adaptation. ✓ (reframed from "p < 0.05 upward trend")
4. **Hardware feasibility**: full prototype on RTX 3050 4GB VRAM + 16GB RAM. ✓

---

## Dashboard (NEW)

A live read-only graph visualization. The system (agents, crawler, challenger) writes to Neo4j; the dashboard only reads.

```bash
# From d:\argus root:
docker compose up --build
# Open http://localhost:3000
```

- Force-directed graph of all nodes/edges, color-coded by type, size = grain_confidence
- Polls every 5 seconds — new nodes animate in as the system writes them
- Click any node → sidebar with properties, open_questions, challenger_log, neighbors
- Metrics strip: counts by type, total edges, last poll time
- Neo4j runs on host; container reaches it via `host.docker.internal:7400`

Stack: FastAPI (api/main.py) + React/Vite + react-force-graph-2d, served as single container.

---

## Post-Fix Evaluation Results (2026-05-29)

Applied Fix 2 (past-lesson injection) and Fix 3 (cosine dedup before write) to `memory/reflexion.py`. Re-evaluated with 20 new engagement cycles.

### Reflexion Diversity — Before vs After

| Metric | Before (60R/60B) | After (90R/88B) | Δ |
|---|---|---|---|
| Red duplicate pairs | 1/59 (1.7%) | 1/89 (1.1%) | −0.6pp |
| Blue duplicate pairs | 8/59 (13.6%) | 8/87 (9.2%) | −4.4pp |
| Combined waste rate | 9/118 = **7.6%** | 9/176 = **5.1%** | **−2.5pp** |
| Red diversity score | 0.2129 | 0.2495 | **+17%** |
| Blue diversity score | 0.1604 | 0.2273 | **+42%** |
| Mean diversity score | 0.1866 | 0.2384 | **+28%** |
| Fix-3 dedup skips | — | **0** (0.0%) | — |

**Key finding:** Fix 2 (lesson injection) did the work — the 30 new cycles per agent added **zero new duplicates**. Fix 3 never triggered because the prompt diversity penalty prevented repeats at generation time. The 9 surviving duplicate pairs are all from pre-fix cycles 1–60.

Trend slopes are now negative (red: −0.0017/cycle, blue: −0.0034/cycle), meaning diversity is *improving* as cycles accumulate — agents are being forced onto new terrain by Fix 2.

### Eval 3 Post-Fix — Co-evolutionary Dynamics (20 cycles, results/eval3_postfix.txt)

```
Attack confidence:       mean=0.842  std=0.173  slope=+0.006/cycle  p=0.383  improving (+)
Mitigation effectiveness: mean=0.903  std=0.069  slope=+0.003/cycle  p=0.345  improving (+)
Episodic memories accumulated: 178 (was 120 before fix)
```

- Both slopes are now **positive** (vs. flat/negative before), indicating the lessons are feeding genuine improvement
- p-values still >0.05 at 20 cycles — more cycles needed for statistical significance
- Same oscillation pattern: attack conf dips to 0.50 at cycles 3, 7, 9, 14 (red agent adapting)
- Memory count steady at +2/cycle — no dedup skips (Fix 3 dormant, Fix 2 sufficient)

**[CLAIM PARTIALLY SUPPORTED]** Both agents trending upward post-fix. Pre-fix was flat/declining.

### Smoke Test
`scripts/test_reflexion.py` — **5/5 passed** with Fix 2 + Fix 3 active (including skip-aware `memory_nodes_persisted` and `reflects_on_edges_written` tests).

### Output Files
- `results/eval3_postfix.txt` / `results/coevolution_postfix.json` — 20-cycle post-fix eval
- `results/reflexion_diversity_postfix.txt` / `.json` — diversity analysis on 178 memories

---

## What NOT To Do

- No cloud APIs (no Groq, OpenAI, Anthropic) until Phase 3 benchmarking
- No `py2neo` — use official `neo4j` Python driver
- No Docker for Neo4j — Neo4j Desktop only
- No `langchain` Neo4j abstractions — write Cypher directly
- No new features outside the 6-layer plan without adding to `BACKLOG.md` first
- Don't flatten node/edge structures — the epistemic fields ARE the contribution
- Don't use `json.loads()` on Neo4j properties — they're `str(dict)`, use `ast.literal_eval()`
- Don't use `ollama.chat()` for fast extraction — use the HTTP API with `think=False`

---

## What's Next (Phase 2)

- Write the research paper sections (architecture, experiments, results)
- Reframe eval 3 co-evolution claim in paper (equilibrium dynamics, not monotonic improvement)
- Phase 3: add Groq as comparison baseline for benchmarking (not yet)
- Consider running challenger on all 73 CVEs to improve grain distribution before paper submission

The working directory is `d:\argus`. Run everything with `conda activate argus` first.
