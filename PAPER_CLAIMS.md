# ARGUS — Paper Claims Ledger

Each major claim mapped to its current evidence status. Conservative language on purpose:
this is the honest scientific record, distinct from any product/investor framing.

Status key:
- **Demonstrated** — supported by committed code + an evaluation run.
- **Partial** — supported directionally, but samples are small or significance not reached.
- **Future work** — planned, not yet shown.

Evidence anchors are the result files summarized in [CONTEXT.md](CONTEXT.md) (raw files live under
`results/`, which is not committed — the numbers are transcribed into CONTEXT.md).

> **Synced 2026-09-05** against direct recomputation from the raw `results/`
> checkpoint and log files, not from narrative summary docs. This pass adds:
> the full ranked-retrieval battery for Claim 1 (Claim 1 downgraded from
> "Demonstrated" to "Partial" — see below, the standard-definition P@10
> delta is not significant, though ranking-quality metrics are); the
> stationarity/change-point/cross-correlation battery for Claim 3 (still
> Partial, now with a direct equilibrium test, not only an absent trend);
> and two new entries, Claim 5 (groundedness gate comparison, R3.1) and
> Claim 6 (hardware-feasibility latency lock-in, R2.4, still open). See
> [ROADMAP.md](ROADMAP.md)'s R2/R3 sections and [PAPER_DRAFT.md](PAPER_DRAFT.md)
> §5 for the full reconciliation this ledger now matches.

---

## Claim 1 — Retrieval precision: GraphRAG ≥ flat vector RAG

**Status: Partial (downgraded from Demonstrated, 2026-09-05).** The P@10
number below still stands, but the full ranked battery this claim needed
(P@k/MRR/nDCG@10/bootstrapped CIs, `results/r2_1_ranked_battery.json`) shows
the standard-definition P@10 delta is **not** statistically significant at
n=44 (bootstrap 95% CI includes zero for both GraphRAG−flat and
GraphRAG−reranked). What IS significant: MRR and nDCG@10 deltas, all four
bootstrap CIs clear of zero (MRR: mean +0.307 CI=[+0.131,+0.481] vs. flat,
mean +0.290 CI=[+0.107,+0.470] vs. reranked; nDCG@10: mean +0.236
CI=[+0.071,+0.402] vs. flat, mean +0.234 CI=[+0.068,+0.403] vs. reranked).
GraphRAG's R@5/R@10/R@20 are identically 0.420 (real: many CVEs have a
sparse 1-2 hop neighborhood, widening k finds nothing new); VectorRAG's
recall actually **overtakes** GraphRAG's by R@20 (0.455/0.432 vs 0.420) — a
place GraphRAG loses, stated plainly. **Correct claim**: GraphRAG does not
clearly retrieve more correct top-10 candidates than VectorRAG at this
sample size, but ranks the correct one far higher when found (MRR≈0.48→rank
~2, vs. VectorRAG's MRR≈0.17-0.19→rank ~5-6). Full numbers:

```
                  P@5    P@10   P@20   R@5    R@10   R@20   MRR    nDCG@10
GraphRAG          0.109  0.055  0.027  0.420  0.420  0.420  0.477  0.433
VectorRAG(flat)   0.068  0.039  0.026  0.318  0.341  0.455  0.170  0.197
VectorRAG+Rerank  0.059  0.034  0.025  0.273  0.295  0.432  0.188  0.199
```

Note the old-metric VectorRAG+Rerank number moved between runs (0.057 on
2026-08-24 → 0.034 on 2026-09-05, same 44-CVE pool) — Qwen3's rerank has no
fixed seed, real run-to-run LLM variance, not a bug (motivates Claim 1's
seed-variance follow-up, ROADMAP R2.5, still open).

Original pilot (6/10 CVEs with structured NVD ground truth, 4 pre-CWE-era) —
result stands, kept as the first evidence:

| Method | mean P@10 | mean FPR |
|--------|-----------|----------|
| GraphRAG | 0.083 | 0.917 |
| VectorRAG | 0.000 | 1.000 |

*A 2026-08-23 attempt to scale this to 12 CVEs (`scripts/backfill_simple.py` +
`scripts/eval_backfilled.py`, reported elsewhere as "27.04% vs 0%, +138%") is
excluded from this ledger: the script wrote the evaluation's own ground-truth
CVE→technique pairs into the graph as edges, then measured GraphRAG precision
by retrieving those same edges back out. Ground truth was not independent of
the graph, so the result is circular by construction — confirmed by reading
both scripts directly, not inferred.*

Superseded by a real run at the ≥50-CVE scale this claim needs
(`results/r2_1_full_52cves.json`), after fixing the actual retrieval
mechanism, not just the sample size. Found via a live rank-position audit,
not assumed: with CVE and technique/tactic nodes in one undifferentiated
searchable index, the correct ground-truth technique ranked #545 of 783
candidates for one CVE and #184 of 783 for another — CVE descriptions are
far more textually similar to *other CVE descriptions* than to ATT&CK's
"Adversaries may..." prose, so same-type nodes dominated nearest-neighbor
retrieval regardless of topical relevance. A recall failure, not a ranking
one — confirmed by adding a two-stage retrieve-then-rerank baseline (Qwen3
reranking a 30-candidate embedding pool) that made no difference until the
search was restricted to technique/tactic-type nodes only, mirroring what
GraphRAG's own graph traversal already restricts to. Also fixed: an
unindexed `LIMIT 500` silently excluding up to 285 of 785 real nodes from
the vector baseline, and an NVD rate-limit pacing bug that had been dropping
half the ground-truth lookups.

| Method | mean P@10 | mean FPR |
|--------|-----------|----------|
| GraphRAG | **0.176** | 0.824 |
| VectorRAG (flat) | 0.039 | 0.961 |
| VectorRAG (reranked) | 0.057 | 0.943 |

44/52 evaluable CVEs (8 dropped for no NVD-derivable ground truth, the same
honest exclusion criterion as the original pilot). Δ = +0.137 vs. flat
VectorRAG, +0.119 vs. reranked. GraphRAG beats both variants; reranking
measurably helps the vector baseline (0.039→0.057) but does not close the
gap — reported plainly since it argues against, not for, a cherry-picked
baseline. *Caveat: this is P@10 only. The full evaluation plan
(`docs/EVALUATION_PLAN.md` #7) also calls for P@k at k∈{5,10,20}, MRR,
nDCG@10, and bootstrapped 95% CIs on the delta — those need ranked, not
set, retrieval results, a real design change, still open.*

## Claim 2 — Grain convergence: `grain_confidence` shifts right monotonically

**Status: Demonstrated (population scale, 2026-08-22).**

Original small pilot (4 hand-picked nodes, 3 rounds of the legacy self-graded
challenger) — result stands, kept as the first evidence:

```
Round 0: mean=0.300 std=0.000
Round 1: mean=0.725 std=0.217
Round 2: mean=0.875 std=0.043
Round 3: mean=0.900 std=0.035
```

Superseded by a population-scale run of the narrowing engine
(`challenge_node_v2`) over **all 73 CVE/technique nodes with a technique
edge in the graph** — the full scope the claim requires, not a subsample.
Independently re-verified against the raw checkpoint
(`results/r2_2_grain_73nodes_checkpoint.json`), not taken from the summary
doc:

```
Before: mean=0.300 std=0.000  (all 73 nodes at seed)
After:  mean=0.354 std=0.291  (+18.0%)
Distribution (after): 0.0–0.2: 28  |  0.2–0.4: 22  |  0.4–0.6: 2
                       0.6–0.8: 13 |  0.8–1.0: 8
Status: 23 resolved, 40 stalled, 9 partial, 1 skipped
```

*Caveat that belongs in the paper, not just here: convergence is not
uniformly monotonic at the node level — 37/73 nodes (50.7%) ended below
their 0.3 seed, consistent with the freshness term in the confidence formula
pulling an individual node down on a round where the asker outpaces the
answerer even while its cumulative trust stays healthy. The population-level
rightward shift is the evidence for this claim; per-node monotonicity is not
claimed. A different, incomplete checkpoint (`results/grain_sweep_checkpoint.json`,
only 14/50 nodes done) was reported elsewhere as "+24.9%, n=50" — re-averaging
those 14 nodes actually gives -17.9%, not +24.9%; that number does not belong
in the paper.*

## Claim 3 — Co-evolutionary improvement of red & blue agents

**Status: Partial (re-verified 2026-08-24 on 100 cycles — still partial, not upgraded).**

Original 50-cycle run: agents converged to high mutual effectiveness
(attack μ=0.82, mitigation μ=0.91) rather than a monotonic upward trend,
**p<0.05 not met**. Attack confidence oscillated (σ=0.18) as the red agent's
reflexion memory recognized mitigated chains and lowered confidence to probe
new strategies; mitigation stayed stable (σ=0.07). A 20-cycle post-fix run
(lesson injection + cosine dedup) turned both slopes slightly positive but
still short of significance.

The run has since been extended to a full 100 cycles
(`results/coevolution_50.json`, `cycles_completed: 100`, confirmed against
the completion log). Re-running the project's own regression method
(`scipy.stats.linregress`, matching `scripts/eval_coevolution.py`) directly
against the complete arrays: attack mean=0.832 std=0.147 slope=+0.00063/cycle
R²=0.015 **p=0.221**; mitigation mean=0.884 std=0.068 slope=+0.00036/cycle
R²=0.023 **p=0.134**. Neither reaches significance. *(A narrative summary
produced during the run reported the attack trend as significant at
p=0.0395 under a "90/100 cycles" framing; that does not reproduce against
the actual completed 100-cycle data or the project's own regression
code — the closest reconstruction is an undisclosed one-tailed test on a
stale 90-cycle subset. Excluded from this ledger.)* Doubling the sample did
not produce significance, which strengthens rather than weakens the
equilibrium reading.

*Paper framing:* present as mutual optimization under adversarial pressure, not a simple
improvement trend — now backed by 100 cycles, not 50.

**Statistical battery built and run against the complete 100-cycle series,
2026-09-05** (`scripts/eval_coevolution.py`, ADF/KPSS + PELT change-point +
cross-correlation with a permutation-test p-value). Three real findings:
(1) **stationarity** — both series jointly confirmed stationary (ADF rejects
unit root p<0.0001 both; KPSS fails to reject stationarity p>0.05 both) —
direct, positive equilibrium evidence, not just an absent trend; (2)
**change-point detection** — using an elbow-selected penalty over a
pre-registered grid (not a hand-picked constant, which swung the result from
0 to 19 "changepoints" depending on value), the series resolves to 3
regime-level segments (cycles 0-25/25-45/45-80/80-100, means
0.806/0.773/0.879/0.840), not per-dip events — at pen≥2.0, zero
changepoints found. Honest, non-forced conclusion: individual dips read as
noise within one regime, not adaptation events; (3) **cross-correlation**
(red-dip signal vs. mitigation, lags -10..+10) — only lag=0 is significant
(r=-0.673, permutation p=0.0005, n=2000); no lagged coupling found. The real
effect is a same-cycle negative association, not "blue strengthens the
cycle after a red dip" as originally hoped. Reaching the ≥150-cycle target
is [ROADMAP.md](ROADMAP.md) R2.3 work, in progress at this writing (moved to
a Kaggle compute lane after repeated local Ollama VRAM/hang issues,
root-caused to orphaned `llama-server.exe` processes from incomplete
restarts, not a code bug).

## Claim 4 — Hardware feasibility on consumer hardware

**Status: Demonstrated, latency numbers locked in (2026-09-05).**

The full six-layer prototype runs on an RTX 3050 (4GB VRAM) + 16GB RAM using Qwen3 8B via Ollama.
`results/r2_4_local_latency.json` — measured with local Ollama genuinely idle (R2.3 had just moved
to a Kaggle compute lane, confirmed no concurrent local GPU load): warm think-mode 189.0s ± 33.0s
(n=5), warm fast-mode 12.3s ± 0.3s (n=5), embedding 0.2s ± 0.3s (n=5, CPU-only).

Cold start: attempted twice, honestly unresolved rather than cleanly measured. First attempt's
`ollama stop` + fixed 2s sleep left the model still loaded (`load_duration=0` proved it). Fixed to
poll `ollama ps` until genuinely empty before proceeding — but the resulting call's `load_duration`
*still* read ~0, with wall time (271.5s) inside the observed warm-call range (max 245.2s) rather
than clearly above it. 271.5s doesn't contradict the earlier ~265s citation, but isn't a cleanly
re-isolated cold-start number either — reported as-measured with this caveat, not overclaimed.

Suitable for batch experiments, not interactive product use — see limitations.

## Claim 5 — Groundedness gate: term-overlap vs. small NLI classifier (R3.1)

**Status: Partial (built + benchmarked 2026-09-05, not promoted to default;
re-benchmarked same day on a grown audit set — conclusion changed).**

Benchmarked `agents.narrowing._clause_supported` (term-overlap) against a
candidate `_clause_supported_nli` (`cross-encoder/nli-deberta-v3-small`,
~140M, CPU-only, argmax decision, no threshold tuned on the audit data)
against `results/narrowing_gate_labeled_audit.jsonl`, in two passes:

| Gate | n | TP | FP | TN | FN | Accuracy | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|---|---|
| Term-overlap | 27 | 6 | 12 | 9 | 0 | 0.556 | 0.333 | 1.000 | 0.500 |
| NLI classifier | 27 | 4 | 6 | 15 | 2 | 0.704 | 0.400 | 0.667 | 0.500 |
| Term-overlap | 47 | 23 | 15 | 9 | 0 | 0.681 | 0.605 | 1.000 | 0.754 |
| NLI classifier | 47 | 15 | 8 | 16 | 8 | 0.660 | 0.652 | 0.652 | 0.652 |

First pass (n=27, curated hard-case set: 5 good/21 bad/1 false-rejection):
NLI led clearly (accuracy 0.704 vs 0.556). **R3.3 then grew the audit to
n=47** (mined 20 never-audited `trusted` claims from an existing run log,
`results/narrowing_v5_full.jsonl`, hand-verified each against real Neo4j
source text — no new Ollama calls) to a more balanced mix (22 good/24
bad/1 false-rejection), and **the accuracy/F1 lead reversed**: term-overlap
now edges ahead (0.681/0.754 vs 0.660/0.652). NLI still has a lower FP
*rate* (0.333 vs 0.625 — still catches proportionally more fabrications)
but at a larger recall cost than the small sample suggested. AND-ensemble
== NLI alone exactly; OR-ensemble == term-overlap alone exactly at BOTH
sample sizes — no combination benefit found either time, NLI's positive
calls are a strict subset of term-overlap's on this data.

**This reversal is itself the finding worth keeping**: it's direct,
empirical proof that deciding this gate's default from n=27 would have been
premature — not a formality, a demonstrated case of a conclusion flipping
when the (still small, still non-random) sample grew. Still not grounds to
promote either gate to default; growing the audit set further (R3.3,
ongoing) remains the concrete prerequisite.

Also found while growing the audit (real, not hypothetical): 2 new
confirmed instances of `citation_title_treated_as_claim` (a fact named only
in a citation's TITLE, never in the source's own body prose, asserted as
claim content) — 3 total confirmed instances now, a real recurring failure
mode, not the one-off it looked like at n=27.

Separately (R3.2), built `_answer_addresses_question` (embedding cosine
similarity between question and answer, catching a true-but-off-topic
answer neither groundedness gate can) — validated against only n=2 real
recovered examples (one on-topic, one off-topic pair, same underlying fact,
different questions): 2/2 correct, threshold 0.78 set at the midpoint of
the two real similarities (0.905 on-topic, 0.652 off-topic). Directional
only; not a validated benchmark.

---

## Known Limitations (state these in the paper)

- All three original claims now have real, larger samples (44 CVEs; 73
  nodes; 100 cycles, 150 in progress). Claim 1 (retrieval precision) now has
  the full P@k/MRR/nDCG@10/bootstrapped-CI battery — the standard-definition
  P@10 delta is not significant, though MRR/nDCG@10 deltas are (Claim 1
  downgraded to Partial accordingly); Claim 3 (co-evolution) still does not
  reach linear-trend significance, though it's now additionally backed by a
  direct stationarity test, with the change-point and lagged-coupling
  sub-findings reported as genuine non-results rather than adjusted to fit;
  Claim 2 (grain convergence)'s node-level convergence is not uniformly
  monotonic. A 2026-08-23 attempt to scale Claim 1 to 12 CVEs used a
  circular methodology and is excluded from all of the above.
- Neither Claim 5's NLI groundedness classifier (n=27, non-random) nor its
  relevance check (n=2) has enough labeled data to be conclusive — both are
  directional findings pending R3.3 growing the audit sets, not decisions.
- No seed-variance study yet at full evaluation scale for any headline
  number (local LLM inference is not fully deterministic; pinned versions:
  `qwen3:8b` Q4_K_M, Ollama 0.32.14, temperature 0.6/top_p 0.95/top_k 20, no
  explicit seed) — ROADMAP R2.5, still open.
- Claim 4's latency numbers are now a locked-in, no-concurrent-load local
  measurement — ROADMAP R2.4, done — though cold-start specifically was not
  cleanly isolated from warm-call variance (reported honestly, not hidden).
- Evaluation reporting has a demonstrated failure mode of its own: a
  2026-08-23/24 batch of narrative result summaries overstated what the
  underlying checkpoint/log files actually supported. This ledger reflects
  direct recomputation against the raw result files, not those summaries —
  see the sync note at the top of this file.
- Local model latency limits interactive use.
- Neo4j properties/logs stored as `str(dict)`, limiting production-grade querying.
- No production safety, tenant isolation, authorization, or compliance layer.
- `challenger_log` is an audit/traceability record, not yet a planning input for downstream agents.
