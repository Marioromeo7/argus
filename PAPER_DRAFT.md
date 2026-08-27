# ARGUS: An Epistemically-Aware Knowledge Graph for Autonomous Red–Blue Security Reasoning

**Working draft — target: arXiv cs.CR, then IEEE S&P / USENIX Security.**

> Status (2026-08-24): Architecture and Methods sections are drafted from the
> implemented, tested system and are **not** results-gated. §5 was updated
> 2026-08-24 with real R2 results, independently re-verified against the
> actual committed data files rather than taken at face value from narrative
> summary docs that in several cases overstated what those files actually
> support — see [ROADMAP.md](ROADMAP.md)'s R2 section for the full
> reconciliation. Net effect: retrieval precision (Claim 1) now has a real
> 44-CVE result (a 2026-08-23 attempt at 12 CVEs was circular and is
> excluded; the mechanism itself was broken — a mixed CVE/technique search
> space — and was fixed before the real run); grain convergence (Claim 2)
> now has a real 73-node population-scale result; co-evolution (Claim 3) now
> has a real 100-cycle result that is still not significant (strengthening,
> not weakening, the equilibrium reading). Narrowing-engine revalidation
> (R1) is tracked separately in ROADMAP.md. `PAPER_CLAIMS.md` (the evidence
> ledger this file is supposed to match) is synced to this section as of
> the same date.

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
circularity. Metrics: mean precision@10 and mean false-positive rate. The
vector baseline's search space is restricted to technique/tactic-type nodes
(the only node types ground truth can ever name), matching what GraphRAG's
own graph traversal is structurally restricted to — the search space is not
the whole graph for either method. We additionally report a two-stage
retrieve-then-rerank variant of the vector baseline (embedding retrieval
over a wider candidate pool, reranked by Qwen3 in fast mode) to test against
a stronger baseline than flat nearest-neighbor search alone.

### 4.2 Grain convergence (Claim 2)

We run the narrowing engine (Section 3.3) over a set of nodes to convergence
(patience-bounded) and track the distribution of `grain_confidence` before vs.
after — mean, variance, and the full histogram — testing whether the
distribution shifts right at the population level. The original small pilot
(4 hand-picked nodes, legacy self-graded challenger) has since been superseded
by a full sweep of the narrowing engine over all 73 CVE/technique nodes with a
technique edge in the graph (Section 5.2).

### 4.3 Co-evolution (Claim 3)

We run repeated full red/blue engagement cycles and measure attack-path discovery
rate (red) and mitigation effectiveness (blue) over cycles, with reflexion memory
active. We report both the trend and the oscillation, and test for a monotonic
slope via linear regression (slope, R², two-tailed p) computed over the
complete cycle sequence, not a subset of it. The original 50-cycle run has
since been extended to 100 cycles (Section 5.3); we re-ran the same test on
the full, current series rather than reusing an earlier partial result.

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

*Conservative by design; §5.1, §5.2, and §5.3 were updated 2026-08-24 with
real R2.1/R2.2/R2.3 results (independently re-verified against raw data —
see the top-of-file status note), and `PAPER_CLAIMS.md` (the evidence ledger
this section is transcribed from) is synced to match. The R1 narrowing-engine
revalidation is still pending expansion.*

### 5.1 Retrieval precision — Demonstrated (44 CVEs)

The original pilot (6/10 CVEs with structured NVD ground truth, 4 pre-CWE-era)
showed GraphRAG beating flat vector RAG (mean P@10 0.083 vs 0.000; mean FPR
0.917 vs 1.000); it remains valid but is a small sample.

A 2026-08-23 attempt to scale this to 12 CVEs (reported elsewhere as
"27.04% vs 0%, a +138% improvement") is excluded from the record: it worked
by writing the evaluation's own ground-truth CVE→technique pairs into the
graph as edges and then measuring GraphRAG precision by retrieving those same
edges back out — ground truth was not independent of the graph, so the
result is circular by construction.

This has since been superseded by a real, methodologically sound run at the
≥50-CVE scale the claim actually needs. Two mechanism bugs were fixed before
scaling, not just the sample size: an unindexed `LIMIT 500` was silently
excluding up to 285 of 785 real graph nodes from the retrieval baseline in
arbitrary order, and — the load-bearing fix, found via a live rank-position
audit — a mixed CVE-and-technique search space let same-genre text dominate
nearest-neighbor retrieval regardless of topical relevance: the correct
ground-truth technique ranked #545 of 783 candidates for one CVE and #184 of
783 for another, far outside any retrievable window. This is a recall
failure, not a ranking failure — confirmed by adding a two-stage
retrieve-then-rerank baseline (Qwen3 reranking a 30-candidate embedding
pool) that made no difference until the search was restricted to
technique/tactic-type nodes only, mirroring what GraphRAG's own graph
traversal already restricts to structurally.

On 44/52 evaluable CVEs (8 dropped for no NVD-derivable ground truth, the
same honest exclusion criterion as the original pilot): GraphRAG mean P@10 =
**0.176** (FPR 0.824); flat VectorRAG mean P@10 = **0.039** (FPR 0.961);
reranked VectorRAG mean P@10 = **0.057** (FPR 0.943). GraphRAG outperforms
both VectorRAG variants (Δ = +0.137 vs. flat, +0.119 vs. reranked); reranking
measurably helps the vector baseline but does not close the gap. This is now
the primary evidence for Claim 1. Still open: P@k for k∈{5,10,20} in one
pass, MRR, nDCG@10, and bootstrapped 95% CIs on the delta — these need
ranked, not set, retrieval results, a real design change beyond this run's
scope (Section 7).

### 5.2 Grain convergence — Demonstrated (population scale)

The original pilot (4 hand-picked nodes, 3 rounds of the legacy self-graded
challenger) showed mean `grain_confidence` rising 0.30 → 0.90 monotonically,
with variance shrinking as nodes specialized (std 0.000 → 0.217 → 0.043 →
0.035). This result stands but is a small, favorable sample from an engine
since superseded (Section 3.3).

It has since been superseded by a population-scale run of the narrowing
engine over **all 73 CVE/technique nodes with a technique edge in the
graph** — the full scope the claim requires, not a subsample. Mean
`grain_confidence` rose **0.300 → 0.354** (seed → converged, +18.0%), std
widening 0.000 → 0.291 as nodes specialized into a spread rather than a
uniform shift: after-convergence, 28/73 nodes sit at 0.0–0.2, 22 at 0.2–0.4,
2 at 0.4–0.6, 13 at 0.6–0.8, and 8 at 0.8–1.0; by stop reason, 23 nodes
reached `resolved`, 40 `stalled`, 9 `partial`, 1 `skipped`. The population
mean shifts right, but convergence is **not uniformly monotonic at the node
level**: 37/73 nodes (50.7%) ended below their 0.3 seed. This is consistent
with the mechanism itself (Section 3.3): the freshness term in the
confidence formula can pull an individual node's score down on a round
where the asker outpaces the answerer, even while that node's cumulative
trust stays healthy. We report the population-level rightward shift as the
evidence for Claim 2 and the node-level non-monotonicity as an honest
qualifier — the claim concerns the distribution, not every individual node.

### 5.3 Co-evolution — Partial (equilibrium, now on 100 cycles)

Over the original 50 engagement cycles the agents converged to high mutual
effectiveness (attack μ = 0.82, mitigation μ = 0.91) rather than a monotonic
upward trend; p < 0.05 was not met. Attack confidence oscillated (σ = 0.18)
as reflexion memory recognized mitigated chains and lowered confidence to
probe new strategies; mitigation stayed stable (σ = 0.07).

The run has since been extended to a full 100 cycles. Re-running the same
regression method directly against the complete, current data: attack
confidence mean 0.832 (σ = 0.147), slope +0.00063/cycle, R² = 0.015,
**p = 0.221**; mitigation effectiveness mean 0.884 (σ = 0.068), slope
+0.00036/cycle, R² = 0.023, **p = 0.134**. Neither reaches significance. (A
narrative summary produced during the run itself reported the attack trend
as significant at p = 0.0395 under a "90/100 cycles, infrastructure
ceiling" framing; that does not reproduce against the actual completed
100-cycle data or the project's own regression code — the closest
reconstruction is an undisclosed one-tailed test on a 90-cycle subset of
what had, by completion, become a 100-cycle series. We report the direct
recomputation against the complete data instead.) Doubling the sample from
50 to 100 cycles did not produce significance — if anything this
strengthens the equilibrium reading rather than weakening it: both slopes
remain small and positive, oscillation persists, and more data did not
resolve it into a trend. We continue to present this as mutual optimization
under adversarial pressure, not a failed improvement trend — now backed by
twice the cycles. The ≥150-cycle target and the stationarity /
change-point / cross-correlation battery originally planned to test the
equilibrium hypothesis directly, rather than only via a linear-trend
p-value, remain open work (Section 7).

### 5.4 Hardware feasibility — Demonstrated

The full prototype runs on 4 GB VRAM + 16 GB RAM with Qwen3-8B via Ollama; cold
start ≈ 265 s, warm calls ≈ 44–130 s depending on reasoning mode. Suitable for
batch research use, not interactive product use.

## 6. Limitations

- All three claims now have real, larger samples (44 CVEs; 73 nodes; 100
  cycles), but retrieval precision (Claim 1) is still P@10 only — not the
  full P@k/MRR/nDCG@10/bootstrapped-CI battery this claim's evaluation plan
  specifies (Section 7); co-evolution (Claim 3) still does not reach
  significance; and grain convergence (Claim 2)'s node-level convergence is
  not uniformly monotonic (Section 5.2). A 2026-08-23 attempt to scale Claim
  1 to 12 CVEs used a circular methodology (ground truth written into the
  graph, then retrieved from it) and is excluded from all of the above.
- Evaluation reporting has a demonstrated failure mode of its own, worth
  naming rather than hiding: a 2026-08-23/24 batch of narrative result
  summaries overstated what the underlying checkpoint/log files actually
  supported — an incomplete 14/50-node checkpoint reported as a headline
  number when a complete 73/73-node checkpoint already existed and showed a
  different figure, and a co-evolution significance claim that does not
  reproduce against the actual completed data using the project's own
  regression code. Section 5 above reflects direct recomputation against the
  raw result files, not the summaries.
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
security knowledge graph, and refining them through adversarial interrogation
and execution grounding, is feasible on consumer hardware and yields
measurable improvements in retrieval precision over a flat vector baseline at
real scale (Section 5.1), in node specificity at population scale (Section
5.2), and an interpretable co-evolutionary equilibrium between red and blue
agents that persists under a doubled sample (Section 5.3). Future work: the
full P@k/MRR/nDCG@10/bootstrapped-CI battery for retrieval precision beyond
the P@10 result already in hand (a 2026-08-23 attempt to reach this via a
circular methodology was invalidated by ground-truth leakage and is not
load-bearing here); a ≥150-cycle co-evolution run with the
stationarity / change-point / cross-correlation battery needed to test the
equilibrium hypothesis directly rather than via a linear-trend p-value alone;
the NLI-based groundedness upgrade; and broader execution-grounded technique
validation via the cyber range.
