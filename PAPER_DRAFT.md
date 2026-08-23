# ARGUS: An Epistemically-Aware Knowledge Graph for Autonomous Red–Blue Security Reasoning

**Working draft — target: arXiv cs.CR, then IEEE S&P / USENIX Security.**

> Status (2026-08-17): Architecture and Methods sections are drafted from the
> implemented, tested system and are **not** results-gated. Results are
> transcribed from the current evidence ledger ([PAPER_CLAIMS.md](PAPER_CLAIMS.md));
> the expanded runs that firm up the small-sample claims (narrowing-engine
> revalidation R1, grain-convergence and co-evolution sweeps R2) are pending and
> are marked inline. Do not cite a number here that is not also in the ledger.

---

## Abstract

Retrieval-augmented generation over security knowledge typically treats the
knowledge base as a static, flat store and the retriever as a semantic
similarity function. We present ARGUS, a security knowledge graph whose nodes and
edges carry *epistemic state* — an explicit `grain_confidence`, a set of
`open_questions`, and a `challenger_log` — and that refines that state through
adversarial agent dialogue rather than one-shot ingestion. A challenger agent
interrogates each node's specificity; a red/blue agent pair contests attack and
mitigation paths over a shared graph; and a Docker-based cyber range (GraphRange)
grounds otherwise-model-derived claims in real execution against
version-accurate vulnerable services. We evaluate four claims — retrieval
precision over a flat vector baseline, monotonic grain convergence under
interrogation, co-evolutionary dynamics between red and blue agents, and
feasibility on consumer hardware (4 GB VRAM) — and report honest, small-sample
evidence for each, including a co-evolutionary *equilibrium* result that we argue
is the correct characterization rather than a failed improvement trend. We
further contribute a methodological finding: version-level vulnerability ground
truth cannot be taken from CPE dictionaries or static source reading alone;
execution is required to separate vulnerable from patched releases.

---

## 1. Introduction

Security knowledge bases (CVE, MITRE ATT&CK) are large, heterogeneous, and
uneven in specificity. Systems that reason over them with large language models
generally (a) flatten the structure into embeddings, discarding the typed
relationships that carry the actual security semantics, and (b) treat every node
as equally trustworthy and equally well-specified. Both assumptions degrade
downstream reasoning: flat retrieval surfaces topically-similar but causally
irrelevant nodes, and uniform trust hides the difference between a
precisely-scoped, well-sourced fact and a vague or model-derived one.

ARGUS takes a different position: **a node should know what it does not know
about itself, and that self-knowledge should be refined by adversarial pressure,
not asserted at ingestion.** Concretely, every node carries a `grain_confidence`
(how specifically it is scoped), a list of `open_questions` (what would
distinguish it from similar nodes), and a `challenger_log` (the history of
interrogation). Edges are similarly typed and conditioned, never flat labels.

The contribution is fourfold:

1. **An epistemic graph schema** (Section 3.1) in which uncertainty and
   provenance are first-class node/edge properties.
2. **A challenger / narrowing mechanism** (Section 3.3) that refines node grain
   through an asker/answerer decomposition, explicitly avoiding the
   self-evaluation bias of a single model judging its own output.
3. **Execution-grounded validation** (Section 3.7): a cyber range that
   reproduces documented vulnerable services at the correct historic version so
   that agent claims can be checked against real behavior, not model belief.
4. **An honest evaluation** (Sections 4–5) of retrieval precision, grain
   convergence, co-evolution, and hardware feasibility, with conservative
   language where samples are small or significance is unmet.

## 2. Related Work

*(To expand with citations — grounding areas already identified during
development.)*

- **GraphRAG and structured retrieval.** Graph-structured retrieval vs. flat
  vector RAG; hallucination reduction from grounding in typed relationships.
- **LLM self-judge bias.** Evidence that a single model evaluating its own
  outputs is systematically biased, motivating the asker/answerer split
  (Section 3.3) and correlated-error concerns in ensembles.
- **Groundedness / factuality checking.** Atomic-decomposition + per-claim
  verification (FActScore-style); the Ragas/TruLens/DeepEval line uses a small
  NLI classifier for the verification half — our current term-overlap gate is a
  known-weaker proxy (a planned upgrade, Section 4.5 / limitations).
- **Autonomous red-teaming / agentic pentest.** LLM agents that plan and execute
  attack steps; ARGUS differs in feeding execution outcomes back into a
  persistent, epistemically-typed graph.
- **Iterative question-asking / stopping criteria.** Patience rules for
  interrogation loops.

## 3. Architecture

ARGUS is built in six layers, plus an execution-grounding extension (Layer 7).
Each layer is independently testable; higher layers are not started before lower
ones are validated.

### 3.1 Epistemic node and edge schema

Every node carries, beyond its label and properties: `grain_confidence ∈ [0,1]`
(0 = undefined, 1 = maximally specific), `open_questions` (natural-language
prompts of the form "what distinguishes me from similar nodes?"), a
`challenger_log` (append-only interrogation history), a `last_updated`
timestamp, and a `source` provenance tag (`nvd | attack | agent_derived | web`).

Edges are typed and conditioned rather than flat: a `relation_type`
(`exploits | enables | mitigates | requires | uses | detects | …`),
`context_conditions` (e.g. "only if pre-auth", "requires subnet access"), a
scalar `confidence` updated by agent traversal, a `directionality`
(`unidirectional | bidirectional | conditional`), edge-level `open_questions`,
a `challenger_log`, and a `temporal_validity` window. The MITRE STIX
relationship data is ingested to preserve real procedure-example descriptions on
the edges (as `context_conditions` with citations), not collapsed to a label.

### 3.2 GraphRAG retrieval (Layer 2)

Retrieval traverses typed edges from seed nodes rather than ranking by embedding
similarity alone. For an attack-path query, ARGUS follows
CVE → technique → tactic relations, returning nodes reachable along
security-meaningful edges. Section 4.1 compares this to a flat vector baseline on
identical queries with NVD-derived ground truth.

### 3.3 Challenger agent and the narrowing engine (Layer 3)

The core novelty. The original challenger was self-graded — one model proposed a
subdivision of a node and the same model judged whether it was warranted — which
is exactly the self-evaluation configuration the literature flags as biased. The
**narrowing engine** replaces this with an *asker/answerer* decomposition:

- The **asker** generates `open_questions` that would sharpen a node's grain.
- The **answerer** attempts to answer them from evidence, with each answer
  verified for groundedness (per-clause) against cited source content.
- Grain is a bounded function of answered/total questions (additive weighted
  sum, not multiplicative), with a patience rule (stop after N rounds unchanged)
  and explicit zero-division / round-1 conventions.
- Trust is mapped to provenance and evidence, yielding a three-state model:
  **provisional** (conceptual answers, capped there indefinitely),
  **contested** (conflicting outcomes), and **trusted** (only reachable with
  execution grounding, Section 3.7). Nothing reaches `trusted` on model output
  alone.

Design details (boundedness proof for the weighted sum, the "persist the last
active round" reconciliation, the comma-dilution and empty-answer gate fixes)
are in the implementation notes.

### 3.4 Isekai crawler (Layer 4)

A web agent proposes graph updates from NVD/ATT&CK/threat feeds. The challenger
validates every proposed write before it enters the graph, so ingestion is
gated by the same interrogation the rest of the system uses.

### 3.5 Red and blue agents (Layer 5)

A red agent plans attack paths (CVE→technique→tactic chains) using deep-reasoning
mode; a blue agent plans mitigations. Their conflict updates shared-graph edge
confidences. Reflexion memory (Layer 6) lets each side recognize
previously-seen chains and adapt — the mechanism behind the co-evolution
dynamics in Section 4.3.

### 3.6 Reflexion memory (Layer 6)

Post-engagement self-reflection is stored as episodic context and retrieved to
inform later planning, so lessons persist across engagements rather than being
re-derived.

### 3.7 GraphRange: execution grounding (Layer 7)

Planning-only agents cannot separate "the model believes this technique works"
from "this technique works." GraphRange turns the red/blue agents into real
executors running tools in isolated Docker containers against **version-accurate
vulnerable victims**, feeding outcomes back into the graph (writing
`ScenarioRun`/`Outcome` nodes, updating technique confidence, and flagging
conflicting outcomes into the `contested` state).

The victim layer is the load-bearing part: a scenario is only meaningful if the
victim genuinely runs the vulnerable service at the version the CVE names, not a
modern patched package of the same name. ARGUS builds these victims from a
per-version recipe table, compiling historic sources under a modern toolchain
(a catalogue of era-specific build fixes per version, since the reason old
source fails to build differs each time). Validated victim families to date
include Apache (12 versions across 1.3.x + 2.0.52), plus MySQL, Cyrus IMAP, PHP,
and Squid. Victims are validated end-to-end through the production execution path
— the service must actually build, start, and exhibit its documented behavior —
not merely install.

## 4. Methods

### 4.1 Retrieval precision (Claim 1)

We compare ARGUS GraphRAG against a flat vector RAG baseline on identical
attack-path queries. Ground truth is derived independently from the NVD API
(CWE mapping, reference URLs, keywords), never from the graph itself, to avoid
circularity. Metrics: mean precision@10 and mean false-positive rate.

### 4.2 Grain convergence (Claim 2)

We run the challenger over a set of nodes for N rounds and track the distribution
of `grain_confidence` across rounds — mean and variance — testing whether the
distribution shifts right monotonically and concentrates as nodes specialize.
*Expanded-sample run pending (R2): current sample is small (Section 5).*

### 4.3 Co-evolution (Claim 3)

We run repeated full red/blue engagement cycles and measure attack-path discovery
rate (red) and mitigation effectiveness (blue) over cycles, with reflexion memory
active. We report both the trend and the oscillation, and test for a monotonic
slope. *We pre-registered that reaching statistical significance may require
substantially more cycles; if it does not land, the honest characterization is
equilibrium, not improvement (Section 5.3).*

### 4.4 Hardware feasibility (Claim 4)

We report cold-start and warm-call latency for the full six-layer prototype on an
RTX 3050 (4 GB VRAM) + 16 GB RAM with Qwen3-8B via Ollama, to substantiate
batch-research feasibility on consumer hardware. **Latency numbers reported in
the paper are measured locally**, not on any accelerated/offloaded compute used
during development.

### 4.5 Methodology note: execution-grounded validation

A finding that generalizes beyond ARGUS: **version-level vulnerability ground
truth cannot be taken from CPE dictionaries or static source reading alone.** In
building a victim for a late-1990s authentication-bypass CVE, the affected-version
list in the CPE dictionary was incomplete, and a static reading of the relevant
source function suggested the pinned release was vulnerable. Execution proved the
opposite: the release was the *first patched* one — a length check at the
network entry point, upstream of the function we had read, rejected the malformed
input, and the source's own changelog confirmed the fix landed in exactly that
release. The correct version boundary was recoverable only by running the check,
not by reading the dictionary or the function in isolation. This is the concrete
justification for Layer 7: for a system that assigns `trusted` state, execution
is not a nicety but the only reliable arbiter.

## 5. Results

*Transcribed from the evidence ledger; conservative by design. Expanded runs
(R1/R2) are pending and will replace the "small sample" caveats where they land.*

### 5.1 Retrieval precision — Demonstrated (small sample)

GraphRAG retrieved more relevant nodes than flat vector RAG on the same queries
(mean P@10 0.083 vs 0.000; mean FPR 0.917 vs 1.000; Δ = +0.083), evaluated on
6/10 CVEs with structured NVD ground truth (4 were pre-CWE-era). The claim is
*relative* superiority on this task; absolute precision is low and the sample is
small.

### 5.2 Grain convergence — Demonstrated (small sample)

Over 4 nodes × 3 challenger rounds, mean `grain_confidence` rose 0.30 → 0.90
(Δ +0.60), monotonically non-decreasing, with variance shrinking as nodes
specialized (std 0.000 → 0.217 → 0.043 → 0.035). *Larger-sample run pending
(R2), and pending the narrowing-engine revalidation (R1) that makes the
asker/answerer engine the default.*

### 5.3 Co-evolution — Partial (equilibrium)

Over 50 engagement cycles the agents converged to high mutual effectiveness
(attack μ = 0.82, mitigation μ = 0.91) rather than a monotonic upward trend;
**p < 0.05 was not met.** Attack confidence oscillates (σ = 0.18) as reflexion
memory recognizes mitigated chains and lowers confidence to probe new strategies;
mitigation stays stable (σ = 0.07). We present this as *mutual optimization under
adversarial pressure* (equilibrium), which we argue is the correct
characterization, not a failed improvement trend.

### 5.4 Hardware feasibility — Demonstrated

The full prototype runs on 4 GB VRAM + 16 GB RAM with Qwen3-8B via Ollama; cold
start ≈ 265 s, warm calls ≈ 44–130 s depending on reasoning mode. Suitable for
batch research use, not interactive product use.

## 6. Limitations

- Small evaluation samples across all claims (the R1/R2 runs address this).
- Local model latency limits interactive use.
- Neo4j properties/logs are currently stored as stringified dicts, limiting
  production-grade querying/analytics.
- No production safety, tenant isolation, authorization, or compliance layer.
- The groundedness gate uses term-overlap, a known-weaker proxy than a small NLI
  entailment classifier (planned).
- `challenger_log` is an audit/traceability record, not yet a planning input for
  downstream agents.

## 7. Conclusion and Future Work

ARGUS demonstrates that making uncertainty and provenance first-class in a
security knowledge graph, and refining them through adversarial interrogation and
execution grounding, is feasible on consumer hardware and yields measurable —
if currently small-sample — improvements in retrieval and node specificity, plus
an interpretable co-evolutionary equilibrium between red and blue agents. Future
work: the expanded grain-convergence and co-evolution runs, the NLI-based
groundedness upgrade, and broader execution-grounded technique validation via
the cyber range.
