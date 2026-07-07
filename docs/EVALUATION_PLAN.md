# ARGUS — Evaluation Plan

*Addresses roadmap items #7, #8, #9.* A concrete plan to turn the current small-sample,
directional results into a defensible evaluation section for the paper. Nothing here changes the
architecture — it scales sample sizes and adds statistical rigor.

Current status of each claim lives in [PAPER_CLAIMS.md](../PAPER_CLAIMS.md). This doc is the
methodology to close the gaps.

---

## #7 — Decent retrieval evaluation (larger, fairer sample)

**Problem today:** retrieval precision (Claim 1) was measured on 6/10 CVEs with structured NVD
ground truth; absolute P@10 is low (0.083 vs 0.000). The direction is right but the sample is thin.

**Plan:**
- Expand the query set to **≥50 CVEs** with structured NVD ground truth (CWE + reference URLs +
  keyword mapping). Filter out pre-CWE-era CVEs *up front* so every query is evaluable.
- Report **P@k and Recall@k for k ∈ {5, 10, 20}**, plus mean FPR, for GraphRAG vs flat vector RAG.
- Add **MRR** and **nDCG@10** so ranking quality (not just set membership) is captured.
- Keep ground truth derivation **independent of the graph** (as now) to avoid leakage.
- Bootstrap 95% confidence intervals over the query set; report the CI on the GraphRAG−VectorRAG
  delta, not just the point estimate.

**Definition of done:** a results table with ≥50 queries, CIs on the delta, and a one-paragraph
honest reading (including where GraphRAG loses).

**Suggested artifacts:** `scripts/eval_retrieval.py` (extend), `results/eval1_large.{txt,json}`.

---

## #8 — Statistical significance for co-evolution

**Problem today:** Claim 3 never reached p<0.05. The honest finding is co-evolutionary
*equilibrium* (attack μ=0.82 σ=0.18, mitigation μ=0.91 σ=0.07), with post-fix slopes barely
positive over 20 cycles.

**Plan (pick the framing you can actually support, don't force a trend):**
- Run **≥150 cycles** (current is 50 + 20 post-fix) so slope tests have power. Log every cycle to
  a checkpoint so a crash doesn't lose the run (as `coevolution_*.json` already does).
- Test the *equilibrium* hypothesis directly rather than only a linear trend:
  - **Stationarity:** ADF / KPSS on the attack- and mitigation-confidence series.
  - **Change-point detection** on the oscillation dips (cycles where red confidence drops to ~0.50)
    to show they are adaptation events, not noise.
  - **Cross-correlation** between red-dip and subsequent blue-mitigation-strength to evidence
    genuine coupling (the co-evolution story).
- If a trend *is* claimed, report slope + p with the cycle count and a power note.

**Definition of done:** either (a) significant coupling/adaptation statistics supporting the
equilibrium framing, or (b) an honest "no significant trend at N cycles" with the equilibrium
evidence. Both are publishable; a forced p-hack is not.

**Suggested artifacts:** `scripts/eval_coevolution.py` (extend), `results/eval3_large.{txt,json}`.

---

## #9 — Challenger sweep across all CVE nodes

**Problem today:** grain convergence (Claim 2) was shown on **4 nodes × 3 rounds** (0.30→0.90).
Compelling but tiny, and the graph-wide grain distribution is still mostly seed values.

**Plan:**
- Run the challenger over **all CVE nodes** (73+), threshold-gated on low `grain_confidence`, for a
  fixed round budget (e.g. 3 rounds each).
- Record the **full before/after grain distribution** (histogram + mean/variance), not just per-node
  deltas — this is the population-level version of Claim 2.
- Report **monotonicity rate** (fraction of nodes that never regress) and mean Δ with a CI.
- Watch cost: this is many `/think` calls at ~44–130s each. Batch overnight; checkpoint after each
  node so it is resumable.

**Definition of done:** a graph-wide grain histogram (before vs after) plus summary stats, showing
the distribution shifts right at population scale.

**Suggested artifacts:** `scripts/eval_grain.py` (extend to full sweep),
`results/grain_sweep.{txt,json}`.

---

## Cross-cutting notes

- **Reproducibility:** pin the model (`qwen3:8b`) and record Ollama version + seed where possible;
  note that local LLM output is not fully deterministic and report variance across ≥3 seeds for the
  headline numbers.
- **Cost budget:** the co-evolution and challenger sweeps are the expensive ones (~6 min/cycle,
  ~1–2 min/challenger call). Plan them as overnight batch jobs; don't block interactive work.
- **Do not** re-derive ground truth from the graph, and **do not** drop unfavorable results — the
  honesty is the credibility.
