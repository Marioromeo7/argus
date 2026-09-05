# ARGUS: An Epistemically-Aware Knowledge Graph for Autonomous Red–Blue Security Reasoning

**Working draft — target: arXiv cs.CR, then IEEE S&P / USENIX Security.**

> Status (2026-09-05): Architecture and Methods sections are drafted from the
> implemented, tested system and are **not** results-gated. §2 (Related Work)
> expanded from a placeholder skeleton to real citations. §5 updated with:
> the full ranked-retrieval battery for Claim 1 (P@k/MRR/nDCG@10/bootstrapped
> CIs — standard-definition P@10 delta is not significant, but MRR/nDCG@10
> deltas are, a more precise claim than the earlier single-number framing);
> the stationarity/change-point/cross-correlation battery for Claim 3,
> validated against the complete 100-cycle series (≥150-cycle extension in
> progress); a new §5.5 reporting the R3.1 groundedness-gate comparison
> (term-overlap vs. a small NLI classifier) and the R3.2 relevance-check
> sanity test; a new §5.6 on reproducibility (pinned model/server versions,
> seed-variance study still open). All independently re-verified against
> committed data files, not narrative summaries — see
> [ROADMAP.md](ROADMAP.md)'s R2/R3 sections for the full reconciliation.
> `PAPER_CLAIMS.md` (the evidence ledger this file is supposed to match)
> still needs this same sync pass as of this writing.

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

*Expanded 2026-09-05 with real citations (previously a placeholder skeleton).
arXiv IDs given where available; full BibTeX pass still needed before
submission (Section 7).*

- **GraphRAG and structured retrieval.** Edge et al. (2024), *From Local to
  Global: A Graph RAG Approach to Query-Focused Summarization*
  (arXiv:2404.16130) — the origin of the GraphRAG name and Microsoft's
  entity-graph + community-summary approach — established that graph
  structure improves retrieval over flat vector similarity for
  relationship-heavy queries. ARGUS's traversal differs in kind, not degree:
  it follows typed, pre-existing security edges (CVE→technique→tactic) laid
  down by ingestion and agent interrogation, rather than LLM-constructed
  entity/community graphs built at index time. Section 5.1's finding that
  GraphRAG wins decisively on MRR/nDCG@10 but not on standard-definition
  P@10 is a more specific, betterlined claim than "graph beats flat" —
  ranking quality, not raw top-k recall, is where the structural signal
  shows up.
- **LLM self-judge bias.** Panickssery et al. (NeurIPS 2024), *LLM Evaluators
  Recognize and Favor Their Own Generations*, and Wataoka et al. (2024),
  *Self-Preference Bias in LLM-as-a-Judge* (arXiv:2410.21819), both show a
  model evaluating its own output is measurably biased toward it — the
  literature-level justification for ARGUS's asker/answerer split (Section
  3.3): the asker (Qwen3) and answerer (Mistral, independent weights) are
  never the same model checking its own claim. By contrast, Madaan et al.
  (2023), *Self-Refine: Iterative Refinement with Self-Feedback*
  (arXiv:2303.17651), is the same-model generate-critique-refine loop ARGUS's
  split is deliberately unlike — cited as the contrasting configuration, not
  a method ARGUS builds on.
- **Groundedness / factuality checking.** Min et al. (2023), *FActScore:
  Fine-grained Atomic Evaluation of Factual Precision in Long Form Text
  Generation* (arXiv:2305.14251), established atomic-decomposition +
  per-claim verification against a source — directly the shape of
  `answer()`'s per-clause groundedness check (Section 3.3). The RAGAS
  framework (Es et al., *Ragas: Automated Evaluation of Retrieval Augmented
  Generation*, arXiv:2309.15217) and TruLens both compute a faithfulness/
  groundedness score this same way; both note the standard stronger
  verification back-end is a small NLI entailment classifier rather than
  lexical overlap. ARGUS's own R3.1 finding is a direct, load-bearing
  instance of exactly this literature point: swapping the term-overlap gate
  for a small NLI classifier (`cross-encoder/nli-deberta-v3-small`, ~140M)
  roughly halved false positives on the hand-labeled hard-case audit
  (Section 5.5) — empirical confirmation, on this project's own data, of
  why the RAGAS/TruLens line moved to NLI in the first place.
- **Reflexion / episodic self-critique.** Shinn et al. (2023), *Reflexion:
  Language Agents with Verbal Reinforcement Learning* (arXiv:2303.11366) —
  ARGUS's Layer 6 memory explicitly implements this pattern (verbal,
  non-parametric reflection stored as episodic context and re-injected into
  later planning), the mechanism behind the co-evolution dynamics in
  Section 5.3.
- **Knowledge graphs for cyber threat intelligence.** CVE-TTP KG
  (arXiv:2606.31557) links CVEs to ATT&CK tactics/techniques via
  classification and relation extraction, and TITAN (arXiv:2510.14670)
  performs graph-executable reasoning over a typed ATT&CK graph — both
  close in spirit to ARGUS's CVE→technique→tactic edges. ARGUS differs in
  making the edges and nodes themselves epistemically self-aware
  (`grain_confidence`, `open_questions`, per-edge `confidence` updated by
  traversal outcome) rather than treating the graph as a static, fully-
  trusted index once built.
- **Autonomous red-teaming / agentic pentest.** *Can LLMs Hack Enterprise
  Networks? Autonomous Assumed Breach Penetration-Testing Active Directory
  Networks* (arXiv:2502.04227) and PentestAgent (Shen et al., AsiaCCS 2025)
  both use LLM agents to plan and execute attack steps end-to-end. ARGUS's
  red/blue agents differ in feeding execution outcomes (Section 3.7,
  GraphRange) back into a persistent, epistemically-typed shared graph that
  both sides read from and write to across engagements, rather than a
  self-contained per-engagement planning loop.

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
reranked VectorRAG mean P@10 = **0.057** (FPR 0.943), all using precision
defined as tp / |retrieved| (not a fixed-k denominator — see below).
GraphRAG outperforms both VectorRAG variants by this measure (Δ = +0.137 vs.
flat, +0.119 vs. reranked); reranking measurably helps the vector baseline
but does not close the gap.

**The full ranked-retrieval battery (P@k/R@k for k∈{5,10,20}, MRR, nDCG@10,
bootstrapped 95% CIs on the delta) has since been completed (2026-09-05) on
the same 44-CVE run**, and tells a more precise story than the number above.
Under the standard IR definition of precision@k (tp-in-top-k / k, a fixed
denominator — the number above instead divides by however many candidates a
method actually returned, which favors GraphRAG when it returns fewer than
k):

| Method | P@5 | P@10 | P@20 | R@5 | R@10 | R@20 | MRR | nDCG@10 |
|---|---|---|---|---|---|---|---|---|
| GraphRAG | 0.109 | 0.055 | 0.027 | 0.420 | 0.420 | 0.420 | 0.477 | 0.433 |
| VectorRAG (flat) | 0.068 | 0.039 | 0.026 | 0.318 | 0.341 | 0.455 | 0.170 | 0.197 |
| VectorRAG (reranked) | 0.059 | 0.034 | 0.025 | 0.273 | 0.295 | 0.432 | 0.188 | 0.199 |

The bootstrapped 95% CI (n=44, 10,000 resamples) on the **standard-definition
P@10 delta includes zero** for both comparisons (GraphRAG−flat:
[-0.007, +0.039]; GraphRAG−reranked: [-0.002, +0.043]) — under a fair,
fixed-denominator measure, top-10 set overlap is not statistically
distinguishable from the vector baseline at this sample size. But the
**MRR and nDCG@10 deltas are real and significant**, all four CIs clear of
zero (MRR: [+0.131, +0.481] vs. flat, [+0.107, +0.470] vs. reranked; nDCG@10:
[+0.071, +0.402] vs. flat, [+0.068, +0.403] vs. reranked). GraphRAG's
R@5/R@10/R@20 being identically 0.420 at every k is itself informative: many
CVEs have a sparse 1–2 hop technique/tactic neighborhood, so widening the
retrieval window finds nothing new — a real structural property of the
graph, not a metric artifact. VectorRAG's recall actually **overtakes**
GraphRAG's by R@20 (0.455/0.432 vs. 0.420), a place the flat baseline wins
that we report rather than omit.

**The claim this evidence actually supports, stated precisely**: GraphRAG
does not clearly retrieve more correct candidates within a fixed top-10
window than flat vector search at this sample size, but when it does surface
the correct technique, it ranks it far higher (MRR ≈ 0.48, i.e. an average
rank near 2, vs. ≈ 0.17–0.19, average rank near 5–6). This is a real,
statistically supported, more specific claim than "GraphRAG has higher
precision" — and, per FActScore/RAGAS-style evaluation practice (Section 2),
exactly the kind of metric a set-only P@k comparison would have hidden.
Still open: this ranked battery has not yet been repeated across ≥3 sampling
seeds to report variance on an inherently stochastic reranking step (Section
5.6 / Section 7).

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
twice the cycles.

**The stationarity / change-point / cross-correlation battery originally
planned to test the equilibrium hypothesis directly (rather than only via a
linear-trend p-value) has since been built and run against the complete
100-cycle series (2026-09-05)**; the ≥150-cycle extension was in progress at
draft time (Section 7 notes the exact status). Three findings, reported
without adjusting the framing to fit a preferred outcome:

1. **Stationarity — supports the equilibrium reading directly.** Both series
   are jointly confirmed stationary: ADF rejects the unit-root null
   (attack: p<0.0001; mitigation: p<0.0001) and KPSS fails to reject the
   stationarity null (both p>0.05) for both series. This is real, positive
   evidence for equilibrium that a slope test alone cannot provide — a
   stationary series is, by construction, not drifting toward either a
   collapse or an unbounded improvement trend.
2. **Change-point detection — a real, honest non-result for the "dips are
   adaptation events" framing.** Using PELT (Killick et al.) with an
   elbow-selected penalty over a pre-registered grid (never a single
   hand-picked constant, which swung the raw finding from 0 to 19
   "changepoints" depending on the value — reported in full for
   auditability), the series resolves to 3 broad regime-level segments
   (cycles 0–25, 25–45, 45–80, 80–100; means 0.806/0.773/0.879/0.840), not
   one changepoint per oscillation dip. At every penalty ≥2.0 in the grid,
   PELT finds **zero** changepoints. The individual single-cycle dips (red
   confidence dropping to ≈0.50, 14 such cycles in the 100-cycle series)
   read as noise within one stable regime, not as distinct structural
   breaks — a different, more conservative conclusion than the original
   plan hoped for, and reported as such rather than adjusted post hoc.
3. **Cross-correlation — no lagged coupling found; a real, different effect
   is.** Testing lags from −10 to +10 cycles between a "red-dip" signal
   (attack confidence below its own series mean) and mitigation
   effectiveness, only lag 0 is significant (r = −0.673, permutation
   p = 0.0005, 2,000 resamples); all ±1…±10 lags are weak and
   non-significant. This does not support the hoped-for "blue strengthens
   in the cycle *after* a red dip" coupling story. What the data does show:
   a strong **same-cycle** negative association — when attack confidence
   dips, mitigation effectiveness tends to be lower in that identical
   cycle, not higher the cycle after. The more defensible reading is that
   both signals respond to shared per-cycle engagement difficulty, not that
   blue is reactively adapting to red's immediately preceding dip.

Net honest synthesis: the equilibrium characterization is now supported by a
direct test (stationarity), not only by the absence of a significant trend;
the "dips as adaptation events" and "lagged red→blue coupling" sub-claims
originally hoped for are not supported by this data and are reported as
such. The ≥150-cycle extension (Section 7) is the remaining open piece of
this claim.

### 5.4 Hardware feasibility — Demonstrated, latency lock-in complete

**Locked in 2026-09-05** (`results/r2_4_local_latency.json`,
`scripts/eval_local_latency.py`), superseding the earlier development-time
observations: with local Ollama genuinely idle (no concurrent GPU load —
verified, not assumed), warm think-mode calls average 189.0 s (σ = 33.0 s,
n=5), warm fast-mode calls average 12.3 s (σ = 0.3 s, n=5), and CPU-only
embedding calls average 0.2 s (σ = 0.3 s, n=5). Suitable for batch research
use, not interactive product use.

Cold-start is reported honestly as unresolved rather than cleanly
re-measured: a first attempt found `load_duration=0` after stopping the
model and a fixed sleep — proof the model was never actually unloaded. A
second attempt polled Ollama's own `ollama ps` until the model genuinely
disappeared before proceeding, yet the resulting call's `load_duration`
*still* reported ≈0, with a wall time (271.5 s) that falls within the
observed warm-call range (max 245.2 s) rather than clearly above it. We do
not know whether this reflects a genuinely smaller cold-start cost on this
hardware/Ollama version than the previously-cited ≈265 s figure once
call-to-call output-length variance is accounted for, or some driver/OS-level
residency Ollama's own instrumentation does not capture. The 271.5 s number
is close to, and does not contradict, the earlier ≈265 s citation — we
report it as the measured value with this caveat stated plainly, rather than
as a cleanly re-isolated cold-start phenomenon.

### 5.5 Groundedness gate: term-overlap vs. a small NLI classifier (R3.1)

Section 3.3's per-clause groundedness check originally used term-overlap
(≥60% of a clause's salient terms must appear in the cited source field, with
a hard veto if a failing term is found verbatim in a sibling field instead —
catching miscitation). A hand-labeled audit of real narrowing-engine output
(`results/narrowing_gate_labeled_audit.jsonl`) benchmarked this against a
small local NLI classifier (`cross-encoder/nli-deberta-v3-small`, ~140M
parameters, CPU-only, argmax decision rule with no threshold tuned against
the audit set). The audit was built in two passes, and the second pass
changes the conclusion the first suggested — reported as a methodological
point in its own right, not just a numbers update:

| Gate | n | TP | FP | TN | FN | Accuracy | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|---|
| Term-overlap (n=27) | 27 | 6 | 12 | 9 | 0 | 0.556 | 0.333 | 1.000 | 0.500 |
| NLI classifier (n=27) | 27 | 4 | 6 | 15 | 2 | 0.704 | 0.400 | 0.667 | 0.500 |
| Term-overlap (n=47) | 47 | 23 | 15 | 9 | 0 | 0.681 | 0.605 | 1.000 | 0.754 |
| NLI classifier (n=47) | 47 | 15 | 8 | 16 | 8 | 0.660 | 0.652 | 0.652 | 0.652 |

At n=27 (built 2026-08-09/10, a curated hard-case set skewed toward known
bugs — 5 good, 21 bad, 1 false-rejection), NLI led clearly on accuracy
(0.704 vs 0.556). Growing the audit to n=47 (2026-09-05, mining 20
previously-generated but never-audited `trusted` claims out of an existing
run log and hand-verifying each against the real cited source text — no new
model calls, just labeling work) produced a more balanced verdict mix (22
good, 24 bad, 1 false-rejection) and **reversed which gate leads on
accuracy and F1**: term-overlap now edges ahead (0.681/0.754 vs
0.660/0.652). NLI still has a meaningfully lower false-positive *rate*
(8/24=0.333 vs 15/24=0.625 — still catches proportionally more fabrications
among what should be rejected), but at a larger recall cost than the small
sample suggested. An AND-ensemble (both gates must agree) is identical to
the NLI classifier alone; an OR-ensemble (either agrees) is identical to
term-overlap alone, at both sample sizes — the NLI classifier's positive
calls are a strict subset of term-overlap's, so there is no combination
benefit beyond picking one.

We read this pattern — a conclusion that looked clear at n=27 and stopped
looking clear at n=47 — as itself a finding worth stating plainly: **a
27-example, non-randomly-curated audit was not sufficient grounds to decide
this gate's default**, and we treat this as direct, empirical support for
that caution rather than a reason to keep chasing a larger n until one
side wins. Both gates remain available in the codebase; promoting either to
the live default is deferred pending a still-larger, ideally less
curation-biased audit set (Section 7).

Separately, groundedness alone cannot catch a true, correctly-cited claim
that answers a *different* question than the one it is attached to — a real
case found in this same audit (a DEP-bypass fact correctly cited but
attached to a privilege-escalation question). We built a candidate relevance
check (cosine similarity between the question and the answer text,
threshold calibrated at the midpoint of the one recovered real on-topic/
off-topic pair: 0.905 vs. 0.652) that separates this one case correctly, but
this is an n=2 sanity check, not a validated benchmark — growing a real
labeled relevance dataset is future work (Section 7), not claimed here as
complete.

### 5.6 Reproducibility

Reported numbers use `qwen3:8b` (Q4_K_M quantization, digest
`500a1f06…8b41`) via Ollama server 0.32.14, default sampling parameters
(temperature 0.6, top_p 0.95, top_k 20, no explicit seed). Local LLM
inference is not fully deterministic under these settings; a systematic
variance-across-seeds study for the headline numbers (Section 5.1's rerank
step, Section 5.2's asker/answerer calls, Section 5.3's red/blue/reflexion
planning) is planned but not yet run at the scale those full sweeps require
(re-running a 73-node or 100+-cycle sweep three times each is a multi-day
compute commitment) — see Section 7 for the smaller, proportionate variance
check actually completed to date.

## 6. Limitations

- All three claims now have real, larger samples (44 CVEs; 73 nodes; 100
  cycles, 150 in progress). Retrieval precision (Claim 1) now has the full
  P@k/MRR/nDCG@10/bootstrapped-CI battery (Section 5.1): the standard-
  definition P@10 delta is **not** statistically significant at this sample
  size (CI includes zero), though MRR/nDCG@10 deltas are — a more precise,
  partially weaker claim than the original single-number framing. Co-
  evolution (Claim 3) still does not reach linear-trend significance, though
  it is now additionally supported by a direct stationarity test (Section
  5.3); the hoped-for change-point and lagged-coupling sub-findings were not
  supported by the data and are reported as genuine non-results, not
  adjusted to fit. Grain convergence (Claim 2)'s node-level convergence is
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
- Local model latency limits interactive use. Numbers are now a locked-in,
  no-concurrent-load local measurement (Section 5.4), though cold-start
  specifically remains not cleanly isolated from warm-call variance.
- Reported numbers are not yet backed by a variance-across-seeds study at
  full evaluation scale (Section 5.6) — a real reproducibility gap for local
  LLM inference, which is not fully deterministic under default sampling.
- Neo4j properties/logs are currently stored as stringified dicts, limiting
  production-grade querying/analytics.
- No production safety, tenant isolation, authorization, or compliance layer.
- The groundedness gate defaults to term-overlap; a small NLI entailment
  classifier is built and benchmarked (Section 5.5) but not promoted to
  default, pending a larger labeled audit set than the current n=27. A
  separate relevance/answering check (distinct from groundedness) is built
  but validated against only n=2 real examples — directional, not conclusive.
- `challenger_log` is an audit/traceability record, not yet a planning input for
  downstream agents.

## 7. Conclusion and Future Work

ARGUS demonstrates that making uncertainty and provenance first-class in a
security knowledge graph, and refining them through adversarial interrogation
and execution grounding, is feasible on consumer hardware and yields
measurable retrieval-ranking improvements over a flat vector baseline at real
scale (Section 5.1), node specificity gains at population scale (Section
5.2), and an interpretable co-evolutionary equilibrium between red and blue
agents — now directly supported by a stationarity test, not only the absence
of a significant trend, and persisting under a doubled sample (Section 5.3).

Future work, in the order it is actually being pursued rather than by
section number:

1. **Co-evolution ≥150-cycle extension** — in progress at draft time. The
   statistical battery (Section 5.3) is already built and validated against
   the complete 100-cycle series; the remaining 50 cycles are compute time,
   not new methodology.
2. **Retrieval-precision seed variance** — the ranked battery (Section 5.1)
   has one run's worth of data; its stochastic component (the Qwen3 rerank
   step) has not yet been re-run across multiple seeds to report variance.
3. **Groundedness gate promotion decision** — the NLI classifier (Section
   5.5) shows a real precision/recall tradeoff against term-overlap on a
   27-example hard-case audit; growing that audit set is the concrete
   prerequisite to deciding whether to promote it to the live default,
   rather than deciding from n=27.
4. **Relevance/answering check validation** — built (Section 5.5) but
   checked against only n=2 real examples; needs a real labeled dataset
   grown alongside the groundedness audit.
5. **Cold-start isolation** — the locked-in warm-call latency numbers
   (Section 5.4) are solid; cold-start specifically resisted clean
   isolation from warm-call variance twice and needs either a better
   methodology (e.g. a full process restart, not just `ollama stop`) or an
   honest note that this hardware/Ollama version's cold-start premium is
   smaller than previously assumed.
6. **Broader execution-grounded technique validation** via the cyber range
   (Section 3.7), and **arXiv cs.CR submission** once the above land.

A 2026-08-23 attempt to reach the retrieval-precision battery via a circular
methodology was invalidated by ground-truth leakage and is not load-bearing
in any of the above.
