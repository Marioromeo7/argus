# ARGUS — Paper Claims Ledger

Each major claim mapped to its current evidence status. Conservative language on purpose:
this is the honest scientific record, distinct from any product/investor framing.

Status key:
- **Demonstrated** — supported by committed code + an evaluation run.
- **Partial** — supported directionally, but samples are small or significance not reached.
- **Future work** — planned, not yet shown.

Evidence anchors are the result files summarized in [CONTEXT.md](CONTEXT.md) (raw files live under
`results/`, which is not committed — the numbers are transcribed into CONTEXT.md).

> **Synced 2026-08-24** (updated same day with the real Claim 1 retrieval
> result) against direct recomputation from the raw `results/` checkpoint
> and log files, not from the narrative summary docs
> (`results/R2_EVALUATION_COMPLETE.md` and siblings) that were written
> 2026-08-23/24 and turned out to overstate what those files support. See
> [ROADMAP.md](ROADMAP.md)'s R2 section and [PAPER_DRAFT.md](PAPER_DRAFT.md) §5
> for the full reconciliation this ledger now matches.

---

## Claim 1 — Retrieval precision: GraphRAG ≥ flat vector RAG

**Status: Demonstrated (44 CVEs, 2026-08-24).**

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
improvement trend — now backed by 100 cycles, not 50. Reaching significance via the
≥150-cycle run + stationarity/change-point/cross-correlation battery is
[ROADMAP.md](ROADMAP.md) R2.3 work.

## Claim 4 — Hardware feasibility on consumer hardware

**Status: Demonstrated.**

The full six-layer prototype runs on an RTX 3050 (4GB VRAM) + 16GB RAM using Qwen3 8B via Ollama.
Latency is acceptable for batch research use (cold start ~265s; warm calls ~44–130s depending on
think mode). Suitable for batch experiments, not interactive product use — see limitations.

---

## Known Limitations (state these in the paper)

- All three claims now have real, larger samples (44 CVEs; 73 nodes; 100
  cycles). Claim 1 (retrieval precision) is still P@10 only, not the full
  P@k/MRR/nDCG@10/bootstrapped-CI battery the evaluation plan specifies;
  Claim 3 (co-evolution) still does not reach significance; Claim 2 (grain
  convergence)'s node-level convergence is not uniformly monotonic. A
  2026-08-23 attempt to scale Claim 1 to 12 CVEs used a circular methodology
  and is excluded from all of the above.
- Evaluation reporting has a demonstrated failure mode of its own: a
  2026-08-23/24 batch of narrative result summaries overstated what the
  underlying checkpoint/log files actually supported. This ledger reflects
  direct recomputation against the raw result files, not those summaries —
  see the sync note at the top of this file.
- Local model latency limits interactive use.
- Neo4j properties/logs stored as `str(dict)`, limiting production-grade querying.
- No production safety, tenant isolation, authorization, or compliance layer.
- `challenger_log` is an audit/traceability record, not yet a planning input for downstream agents.
