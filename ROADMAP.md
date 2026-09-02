# ARGUS — Forward Roadmap & Master Todo

_The single forward-looking task list, written to design what comes next.
Complements the others: `BACKLOG.md` is the dated archaeology + out-of-scope
home, `SCHEDULE.md` is the historical pacing log, `SESSION_HANDOFF.md` is the
last live handoff. This file is the decision-oriented master list — task IDs
(R1, P1…) are stable so they can be referenced when planning._

Last synced: 2026-09-02 (P2.2/P2.3 section below updated with a full week+ of
real Pass-3 dynamic-analysis work not previously recorded here, plus a failed
2026-09-02 full-scale re-validation attempt — full detail in `BACKLOG.md`'s
"Pass 3 dynamic-analysis validation & fixes" section. R2 section below still
reflects the 2026-08-24 re-verification pass, itself still accurate).

---

## State of play (read once)

**Almost everything is already code-complete.** GraphRange Phases 0–7 and all 9
Scanner modules are built and zero-GPU-verified against real data. The new
narrowing engine (`agents/narrowing.py`, asker/answerer redesign) is coded and
wired as an opt-in. What actually remains is dominated by **validation** (running
built code live under GPU) and **two lanes never started** — the paper draft and
the cloud/Groq product path — not new construction.

**R1 was believed to be the gate — reassessed 2026-08-19, likely much closer to
resolved than the earlier draft of this file claimed.** That earlier claim
("zero post-fix full chains completed") was inherited from a stale snapshot
doc without cross-checking `SCHEDULE.md`'s own later log. In fact an 8-node
post-fix chain (`narrowing_v5_full.jsonl`, 2026-08-10) was hand-audited and
held up, and a fresh 2026-08-19 spot-check reproduced that on the current
uncommitted code — no crash, and the individual clause-level judgments verified
correct against live source text. See R1.1 below for the full account. What
remains open is a judgment call on rigor, not a blocked infrastructure problem.

**Timeline read** (from handoff): ~2 months full-time to a validated +
paper-drafted v0. A 2-week aggressive push reaches "system validated + compute
kicked off" but not the paper (results-gated; drafting itself is the fast part,
~4–7 days AI-assisted, but can't precede the results).

**R2 status, added 2026-08-24, updated same day — verified against the raw
result files, not the narrative summaries.** All three R2 sub-claims have
now substantively landed for real. R2.2 (grain convergence) completed a
genuine full 73/73-node sweep. R2.3 (co-evolution) completed a genuine full
100/100-cycle run. R2.1 (retrieval precision) took two passes: a
2026-08-23 attempt turned out methodologically invalid (ground truth was
written into the graph as edges, then "retrieved" back out of it —
circular) and was excluded, then a same-day (2026-08-24) real fix — the
mechanism itself was broken (a mixed CVE+technique search space meant the
correct answer typically ranked #100-500+ out of ~783 candidates,
independent of embedding quality) — followed by a real 44-CVE run once
fixed. R2.3's own narrative summary separately claims a statistically
significant result that does not reproduce when the project's own
regression method is re-run against the actual complete data. Net effect
for the paper: Claim 1 now has real ≥50-CVE-scale evidence (GraphRAG mean
P@10 0.176 vs flat VectorRAG 0.039 vs reranked VectorRAG 0.057); Claim 2
now has real population-scale evidence; Claim 3's equilibrium framing is
now backed by 2× the cycles (still not significant, which supports rather
than undercuts the equilibrium reading). Full account in R2 below;
[PAPER_DRAFT.md](PAPER_DRAFT.md) §5 updated to match. `PAPER_CLAIMS.md` (the
evidence ledger) has **not** been updated yet — treat it as stale until it is.

---

## Decisions — RESOLVED 2026-08-15

All five resolved. Kept here (not deleted) so the reasoning behind the plan stays
visible.

- [~] **D1 — Co-evolution framing → DEFERRED, by design.** The results will change
      the framing anyway, so committing now is premature. Decide equilibrium reframe
      vs. significance chase _after_ R2.3 produces post-fix data, not before.
- [x] **D2 — MySQL CVE → confirmed network-facing, NO swap.** Verified against NVD:
      CVE-2000-0148 is a **remote** auth-bypass ("remote attackers bypass password
      authentication via a short check string", `AV:N`, 7.5 HIGH) — not the local
      file-permission issue the handoff claimed. Earlier framing was wrong. Action
      is therefore **fix the recipe, not swap the CVE** (see P1.2), then empirically
      prove the bypass over TCP 3306 from the red container.
- [x] **D3 — "Done" = all three outcomes.** Pursue the research write-up, the
      product wedge, AND the open-sourced schema/engine — not a fork. This keeps
      P4–P7 in scope rather than optional (sequenced after research lands, but real
      targets).
- [x] **D4 — Compute lane = Kaggle P100 for GPU now; Groq later.** Kaggle (quota
      renewed 2026-08-15) runs the offloadable GPU sweeps (R1, R2). Groq stays on
      the roadmap (P4) but is wired later, after the research lands. Any latency
      number destined for the paper still comes from **local**, not Kaggle.
      **Extended 2026-08-24/25**: added Colab as a real, live-verified backup
      GPU lane (`colab/README.md`) for when Kaggle's weekly quota is
      exhausted, used for P2.2/P2.3's Scanner work. Same rule applies —
      paper-reportable latency still comes from local, never Kaggle or
      Colab. Colab has its own real caveat Kaggle doesn't: sessions can be
      killed by the backend with no warning, and this account's tier only
      has GPU entitlement for T4 (L4/A100/H100 rejected outright) — budget
      for session recreation or an account switch mid-task, don't assume a
      multi-hour unattended run survives uninterrupted.
- [x] **D5 — `plan_attack()` → hand it the scenario + cross-check after.** Change
      the signature so `plan_attack()` is told which `scenario` to plan for (no
      divergence at plan time), THEN after results return, double-check the plan
      against the scenario to confirm they match. Both halves, not just the
      signature change. → new task P2.1a below, precedes P2.1.

---

## RESEARCH TRACK — the paper + its proof

### R1 — Narrowing engine validation `GPU + Neo4j` · **re-assessed 2026-08-19, likely far closer to done than believed**
- [x] R1.1 — **Corrected finding, 2026-08-19:** the "zero post-fix runs completed"
      claim (from `SESSION_SUMMARY.md`, inherited into this file's earlier draft
      without cross-checking `SCHEDULE.md`'s own later, more detailed log) was
      stale. `agents/narrowing.py` has been uncommitted since 2026-08-06 (790
      working-tree lines vs. 440 committed) and already contains the full
      provisional/contested/trusted model + all documented fixes.
      `results/narrowing_v5_full.jsonl` (2026-08-10) is an 8-node chain SCHEDULE.md
      describes as fully hand-audited with both fixes confirmed correct. A fresh
      local spot-check (`T1055.011`, 2026-08-19, 51.8 min, no crash) reproduced
      that: ran clean, correct round-by-round status labels, and — hand-verified
      against the live Neo4j node — one `trusted` claim matched the source
      near-verbatim, one `unanswered` claim was a correct rejection (source
      genuinely silent on that question). **The historical infra bottleneck
      (Ollama hangs, GPU/RAM contention) is confirmed gone**, and the mechanism
      itself checks out on direct clause-level audit, not just "it didn't crash."
      **Extended 2026-08-19, same day:** two more targeted spot-checks —
      `T1687` and `T1113`, v5's two lowest-trust nodes and the ones most likely
      to expose a regression, deliberately chosen over easy re-runs. Both clean
      (50.3min, 44.4min, no crashes). `T1113` matched v5 almost exactly
      (0.0→0.0333, both ~zero trust, same stalled pattern). `T1687` swung hard
      (0.05→0.6667) but every one of its 4 fresh `trusted` claims was hand-
      verified against the live node — including the two mentioning SaaS/IaaS,
      exactly where the sibling-veto bug used to live — and all four trace to
      genuine description text, correctly distinguishing "SaaS mentioned in the
      real description" (trusted) from "IaaS asserted only via the `platforms`
      field" (still correctly rejected, rounds 2/4/7/8). The swing is asker
      non-determinism, not a regression — consistent with this project's own
      prior finding that aggregate confidence is noisy run-to-run while
      per-clause audits are the reliable signal.
      **Conclusion: R1.1 is adequately evidenced — 3 fresh hand-audited nodes
      (one easy, two hard) all check out, on top of v5's existing 8-node
      hand-audited chain. Moving to R1.2 without spending a full fresh 8-node
      chain's GPU-hours; escalate to a full Kaggle chain only if R1.2's
      recalibration surfaces something that doesn't add up.**
- [x] R1.2 — **Done 2026-08-19**, `scripts/recalibrate_narrowing.py`, real data
      (v5_full.jsonl's 8 nodes + the 3 fresh spot-checks, no GPU needed —
      recomputed the real `_salient_terms`/`_term_in_text` logic against live
      Neo4j content, not estimated). Also found a 4th uncalibrated constant the
      code itself flags but this file hadn't named: the `0.6` term-overlap ratio
      in `_clause_supported`.
      - **`0.6` ratio — KEEP.** Confirmed-good (`trusted`) clauses ranged
        [0.625, 1.0]; confirmed-bad clauses that *would* have wrongly passed
        the ratio test alone ranged up to [0.929, 0.833] — both were only
        caught by the sibling-field veto, not the ratio. Excluding
        veto-covered cases, the highest genuinely-bad ratio was 0.500. So 0.6
        sits in the correct [0.500, 0.625] gap, but only 0.025 above the
        lowest true-positive — thin margin, small sample (n=32/10). Don't
        raise it; a larger sample (R2.2's 73-node sweep) could still justify
        nudging it down slightly for more headroom.
      - **Sibling-veto — confirmed load-bearing, not theoretical.** Directly
        caught 2 real clauses at 0.929 and 0.833 ratio that the plain
        threshold alone would have wrongly trusted.
      - **`EVIDENCE_SIMILARITY_THRESHOLD` (0.30) — genuinely untestable from
        this data.** Every real clause in the 8-node sample had extractable
        salient terms and used the ratio path; zero clauses exercised the
        embedding-fallback path at all. No evidence either way — kept as the
        existing informed guess. R2.2's larger sweep may finally produce
        fallback-path examples.
      - **`BETA` (0.5) — KEEP.** Sensitivity table across β∈{0,0.3,0.5,0.7,1}
        shows relative node ranking never flips; 0.5 is a defensible
        middle-ground default for "how much credit does a plausible-but-
        unverified claim get," not a value with an independent ground truth
        to fit against.
      - **`ALPHA` (0.5) — genuinely not sensitivity-testable from historical
        logs**, and this was a real instrumentation gap, not a data-luck
        problem: `compute_confidence()` only ever persisted the *blended*
        result, never cumulative/freshness separately. **Fixed**: added
        `confidence_components` (per-round cumulative + freshness, purely
        additive, zero behavior change — verified `agents/narrowing.py` still
        imports and runs clean) to `run_narrowing()`'s report, so every run
        from now on can be re-analyzed for real ALPHA sensitivity without a
        fresh GPU run.
- [x] R1.3 — **Done 2026-08-19.** Docstrings in `agents/narrowing.py` +
      `agents/challenger.py` corrected to state the flip (challenger.py kept,
      not deleted — still backs `assess_proposal()`/the crawler gate and its
      own smoke test). `scripts/eval_grain.py` rewritten (not a symbol swap:
      the old challenger took an external rounds count and was called
      repeatedly per node; `challenge_node_v2` runs its own complete
      patience-bounded loop internally in one call, so convergence is now read
      from each node's own `confidence_components`, with cross-node round
      alignment for nodes that stop at different counts).
      **Live-verified, 2 nodes (`T1053.005`, `T1055.011`), real Neo4j writes
      via `_persist()`** — ran clean, no crash. One result needed real
      scrutiny: `T1053.005` finished at confidence 0.2857, *below* its own 0.3
      seed and far under v5's earlier 0.8929 for the same node. Traced, not
      dismissed: the arithmetic is an exact match to the formula
      (`0.5×(4/7 cumulative) + 0.5×0 (final round's freshness) = 0.2857`) —
      not a bug. **Real finding**: cumulative trust across the whole log was a
      healthy 4/7 (57%), but confidence froze at a low value because the
      asker's LAST active round happened to land on an unanswered question
      before patience triggered — ALPHA's freshness term makes final
      confidence sensitive to the last round's luck, not just overall support.
      Worth a future ALPHA reconsideration (R1.2 already found ALPHA
      untestable from old logs; this is now a concrete live example
      motivating it), not re-opening R1.2 now.
      **Second gap found and fixed while trying to fully hand-audit this
      result**: `_persist()` dropped `reason`/`attempted_answer` on write to
      Neo4j — the two fields actually needed to audit *why* something was
      rejected, preserved only in dry-run JSONL output, not the live graph.
      Fixed (additive fields on the persisted `challenger_log`); verified
      `agents/narrowing.py` still imports clean.

### R2 — Paper claims / eval sweeps `GPU + Neo4j` · offloadable to Kaggle
Concrete methodology below merged in from `docs/EVALUATION_PLAN.md` 2026-08-19 —
that file had real, specific targets ROADMAP's R2 previously only gestured at.

**Kaggle push blocked 2026-08-19 — since resolved.** The Bash-blocking safety
classifier issue was session-scoped; a later session reached Kaggle fine and
ran real R2 sweeps 2026-08-22 through 2026-08-24 (below). The paragraph below
this note is kept for history (it's what motivated the file-only prep work
that made those later runs possible).

Used the remaining file-only capacity, back on 2026-08-19, to make sure the
eval scripts themselves were actually ready to run at R2 scale the moment
Kaggle became reachable, rather than sitting idle.

- [~] R2.1 — Claim 1 (retrieval precision): expand to **≥50 CVEs** with structured
      NVD ground truth (filter pre-CWE-era up front so every query is evaluable).
      Report P@k/Recall@k for k∈{5,10,20} + mean FPR + MRR + nDCG@10. Bootstrap
      95% CIs on the GraphRAG−VectorRAG delta, not just the point estimate. Keep
      ground truth independent of the graph (as now). DoD: results table, ≥50
      queries, CIs on the delta, one honest paragraph incl. where GraphRAG loses.
      **Partial progress 2026-08-19 (file-only, unexecuted — no Bash available to
      verify):** `scripts/eval_retrieval.py` had a hardcoded `LIMIT 10` in its
      Cypher CVE-selection query with no CLI override — genuinely could not have
      reached ≥50 CVEs at all before this fix. Parameterized (`--n-cves`, `--k`,
      `--output`). Also fixed an unrelated pre-existing dead-code bug found while
      in there: `per_cve.graphrag_retrieved` in the output JSON was always `[]`
      (a dead `if False else []` branch tried to re-call `_graphrag_retrieve()`
      with no arguments after the driver was already closed) — now captured live
      during the real scoring loop instead. **Still NOT implemented** (deliberately
      — untested statistical code is worse than none): P@k for k∈{5,10,20} in one
      pass, MRR, nDCG@10, bootstrap 95% CIs. Those need ranked (not set) retrieval
      results, a real design change, not a parameter. Whether the graph even HAS
      ≥50 CVEs with a technique edge is itself unverified (needs a live Neo4j
      query). All of this needs a live run to confirm no regression before trusting
      the parameterization fix, let alone building the rest on top of it.
      **2026-08-23 execution attempt — invalid, do not cite.** A different,
      smaller path than the plan above was actually run:
      `scripts/backfill_simple.py` wrote 15 CVE→technique edges into the live
      graph (`source: "manual_mapping"`) using a hardcoded 12-pair
      `CVE_TECHNIQUE_MAP`; `scripts/eval_backfilled.py` then measured GraphRAG
      precision using a hardcoded `CVE_GT` dict that is the **identical 12
      pairs**. The evaluation's ground truth was written into the graph as the
      thing being measured, not kept independent of it — verified directly
      against both scripts, not inferred from the summary docs. The reported
      "27.04% vs 0%, +138%" number is circular by construction: GraphRAG
      partially "finds" edges that were hand-placed to match the answer key,
      diluted only by incidental 2-hop technique→tactic traversal (which is
      why it isn't 100%, not because it's a real signal). **This is not
      evidence for Claim 1.** The original v0 Eval 1 result (P@10 0.083 vs
      0.000, 6/10 CVEs, ground truth independently from the NVD API, see
      CONTEXT.md) remains the only valid evidence. The plan above — ≥50 CVEs,
      P@k/Recall@k/MRR/nDCG@10, bootstrapped CIs, ground truth kept
      independent of the graph — is still fully open; nothing from the
      2026-08-23 run should be reused toward it.
      **Done for real, 2026-08-24 — real ≥50-CVE run, valid methodology,
      `results/r2_1_full_52cves.json`.** Root-caused and fixed the actual
      mechanism (not just the CVE count) before scaling: (1) `_build_chroma_index`
      had a `LIMIT 500` with no `ORDER BY` silently excluding up to 285 of 785
      real nodes in arbitrary order — confirmed live that ground-truth technique
      IDs T1078/T1068 and all 15 tactic nodes were among the excluded set; (2)
      the embedded text for both CVEs and techniques was `label + node_type +
      str(properties)` truncated to 512 chars, spending most of that budget on
      structural boilerplate (tactics/platforms lists) before reaching any real
      description — switched to embedding `description` directly with a
      generous 6000-char ceiling (empirically verified against the single
      longest description anywhere in the graph, 4680 chars, embedding cleanly
      in one call — nomic-embed-text's real context is 2048 tokens per a live
      `/api/show`, not the 8192 `num_ctx` shown alongside it); (3) **the load-
      bearing fix, found via a live rank-position audit**: with CVE + technique
      + tactic nodes in one undifferentiated searchable index, the correct
      ground-truth technique ranked #545 of 783 for one CVE and #184 of 783
      for another — CVE descriptions are far more textually similar to *other
      CVE descriptions* than to ATT&CK's "Adversaries may..." prose, so
      same-type nodes dominate a flat nearest-neighbor search regardless of
      topical relevance. This is a recall failure, not a ranking failure —
      confirmed by two-stage retrieve-then-rerank (added per this run, Qwen3
      fast-mode reranking a 30-candidate embedding pool) making zero
      difference until the search was restricted to technique/tactic-type
      nodes only (a ChromaDB `where` metadata filter), mirroring exactly what
      GraphRAG's own Cypher already restricts to. Also fixed the NVD rate-limit
      pacing (was 0.6s/request, ~10x too fast for the anonymous 5-req/30s
      limit — hit 429s on half the sample before the fix) and a duplicate NVD
      fetch per CVE (ground truth was independently re-fetched a second time
      just for a log line).

      **Real result, 44/52 evaluable CVEs** (8 dropped for no NVD-derivable
      ground truth, same honest exclusion as the original v0 methodology):
      GraphRAG mean P@10 = **0.176** (FPR 0.824); flat VectorRAG mean P@10 =
      **0.039** (FPR 0.961); VectorRAG+Rerank mean P@10 = **0.057** (FPR
      0.943). Delta GraphRAG−flat = **+0.137**; delta GraphRAG−reranked =
      **+0.119**. GraphRAG beats both VectorRAG variants; reranking helps
      VectorRAG (0.039→0.057) but doesn't close the gap. **This is now the
      real Claim 1 evidence at proper scale** — supersedes the small 6-CVE v0
      sample and the invalid 12-CVE backfill. Still short of the full R2.1
      spec: P@10 only (not P@k for k∈{5,10,20}), no MRR/nDCG@10, no
      bootstrapped CIs — those need ranked (not set) retrieval results, a
      real design change, still open.
- [x] R2.2 — Claim 2 (grain convergence): sweep the challenger over **all 73+ CVE
      nodes** (threshold-gated on low `grain_confidence`, fixed round budget e.g.
      3). Report the full before/after grain histogram (not just per-node deltas)
      + monotonicity rate (fraction that never regress) + mean Δ with a CI.
      Checkpoint after each node (resumable) — many `/think` calls, batch it.
      `scripts/eval_grain.py` (R1.3) already takes `n_nodes` and is
      live-verified for the base mechanism (2 nodes). **Checkpointing added
      2026-08-19** (file-only, NOT live-verified — no Bash this session):
      `--resume` + `results/grain_sweep_checkpoint.json`, matching
      eval_coevolution.py's pattern. Deliberately fixes the target node_id
      list on first run and reuses it verbatim on resume rather than
      re-querying `get_low_grain_nodes()` — that function's own results can
      drift mid-sweep since `challenge_node_v2()` writes real grain updates
      back to Neo4j as it runs (a completed node's grain could rise above the
      low-grain threshold and silently vanish from a fresh query, corrupting
      what "the sweep" means). Caught and fixed one real bug in review: the
      final return dict referenced `nodes`, a variable only defined on the
      non-resume path — would have crashed with `NameError` on any `--resume`
      run. Traced all four code paths (fresh, resume-with-checkpoint,
      resume-with-no-checkpoint-yet, resume-after-full-completion) by hand;
      all hold up on manual review. Ready for `--n-nodes 73`, but genuinely
      unverified by execution — confirm on a small `--n-nodes 2 --resume` dry
      run before trusting it on the real 73-node sweep.
      **Done for real, 2026-08-22 — `results/r2_2_grain_73nodes_checkpoint.json`,
      independently re-verified against the raw checkpoint, not the summary
      doc.** Full target scope: all 73/73 CVE/technique nodes, real
      `challenge_node_v2` narrowing-engine calls, live Neo4j writes, resumed
      across several genuine mid-run crashes (an Ollama 500 on `/api/embeddings`,
      a dropped Neo4j connection) via the checkpointing built above. Verified
      by recomputing directly from the JSON: mean `grain_confidence`
      0.300 (seed, std 0.000) → **0.354** (std 0.291), **+18.0%**; after-
      distribution 28 nodes @ 0.0–0.2, 22 @ 0.2–0.4, 2 @ 0.4–0.6, 13 @ 0.6–0.8,
      8 @ 0.8–1.0; status 23 `resolved` / 40 `stalled` / 9 `partial` /
      1 `skipped`. **Honest qualifier the paper needs, not just this file:
      convergence is not uniformly monotonic at the node level** — 37/73
      nodes (50.7%) ended below their 0.3 seed, consistent with R1.3's
      earlier finding that the freshness term can drag an individual node's
      confidence down on a round where the asker outpaces the answerer even
      while cumulative trust stays healthy. The population-level rightward
      shift is the real evidence for Claim 2; per-node monotonicity is not
      claimed. **The `+24.9%` / `n=50` figure in
      `results/R2_EVALUATION_COMPLETE.md` does not reproduce**: the
      checkpoint it cites (`results/grain_sweep_checkpoint.json`, dated
      2026-08-23, a day *after* this 73-node run had already finished) is
      only 14/50 nodes complete, and re-averaging those 14 gives **-17.9%**
      (0.182 → 0.150), not +24.9% — that file is a smaller, incomplete,
      superseded run that the summary doc used instead of the better one
      that already existed. Monotonicity rate and a formal CI (still open
      per the plan above) can now be computed directly from this checkpoint
      without a fresh GPU run.
- [~] R2.3 — Claim 3 (co-evolution): **was "already fully ready, no changes
      needed" as of 2026-08-19 (script infra only) — now genuinely run, on
      2026-08-24, but short of both the cycle target and the statistical
      battery below, and its own narrative summary overstates the result.**
      `scripts/eval_coevolution.py` already supports `--cycles 150`, `--resume`,
      and checkpoints every 10 cycles — found this checking all three R2 scripts
      for the same staleness eval_grain.py had; this one never had the problem.
      Run **≥150 cycles** for slope-test power. Test the *equilibrium* hypothesis
      directly, not just a linear trend: stationarity (ADF/KPSS) on the
      attack/mitigation series; change-point detection on the oscillation dips
      (adaptation events, not noise); cross-correlation between a red dip and the
      following blue-mitigation-strength (evidences real coupling) — these three
      statistical additions are NOT yet in the script, still open. DoD: either
      significant coupling/adaptation stats supporting equilibrium, or an honest
      "no significant trend at N cycles" — both publishable, a forced p-hack is
      not. Execute whichever D1 framing follows.
      **Done for real, 2026-08-24 — `results/coevolution_50.json`
      (`cycles_completed: 100`), confirmed against `results/r2_3_100.log`'s
      clean `[DONE] All 100 cycles complete`.** This is 100 real cycles, not
      the "90/100, infrastructure ceiling reached" story in
      `results/R2_EVALUATION_COMPLETE.md` — that file's own cited checkpoint
      already shows 100. Short of the ≥150-cycle target and none of the three
      statistical additions above are implemented. **Re-running the project's
      own regression method** (`scripts/eval_coevolution.py`'s `_regression()`
      — `scipy.stats.linregress` against `np.arange(len(values))`) directly
      against the actual complete arrays: attack confidence mean 0.832
      (σ 0.147), slope +0.00063/cycle, R²=0.015, **p=0.221**; mitigation
      effectiveness mean 0.884 (σ 0.068), slope +0.00036/cycle, R²=0.023,
      **p=0.134**. Neither reaches p<0.05. **The "p=0.0395 significant"
      claim in `results/R2_EVALUATION_COMPLETE.md` does not reproduce** —
      closest reconstruction is an undisclosed one-tailed test on a 90-cycle
      *subset* of what has since become a 100-cycle series (two-tailed p at
      n=90 is 0.081 attack / 0.144 mitigation; halving lands near 0.040/0.072,
      close to what was reported), and even that doesn't survive the run
      actually finishing. **Honest conclusion, now on 2× the original 50-cycle
      sample: still co-evolutionary equilibrium, not significant improvement**
      — both slopes small and positive, oscillation persists, p>0.05 for both
      agents on the real, complete data. This is a genuine update to the
      record (bigger N than the original small-sample paper claim), just not
      the "claim supported, publication-ready" one that got reported. The
      ≥150-cycle target and the stationarity/change-point/cross-correlation
      battery remain the actual open work for this item.
- [ ] R2.4 — Claim 4 (hardware feasibility): lock local latency numbers as the
      paper's source of truth (not Kaggle figures).
- [ ] R2.5 — Reproducibility, cross-cutting: pin `qwen3:8b` + record Ollama
      version/seed where possible; report variance across ≥3 seeds for headline
      numbers (local LLM output isn't fully deterministic).

**Process note, 2026-08-24, worth keeping so it doesn't repeat.**
`results/R2_EVALUATION_COMPLETE.md`, `FINAL_R2_EVALUATION_REPORT.md`,
`R2_EVALUATION_SUMMARY.md`, and `FINAL_R2_REPORT.md` (all written 2026-08-23/24
during the runs themselves) report a materially rosier picture than the
checkpoint/log files they cite actually support once recomputed directly:
R2.1's number is circular, R2.2's headline number comes from an incomplete
14/50 checkpoint when a complete, better 73/73 checkpoint already existed
from the day before, and R2.3's significance claim doesn't reproduce against
the complete 100-cycle data using the project's own regression script.
None of this looks deliberate — it reads as summaries written from an
in-progress or wrong checkpoint and never re-checked against the final
committed data. Treat narrative result summaries as claims to verify against
their own cited raw files before citing them anywhere else (the paper, an
investor conversation, a future session's context) — this file and
[PAPER_DRAFT.md](PAPER_DRAFT.md) §5 were corrected 2026-08-24 by doing exactly
that. `PAPER_CLAIMS.md` still needs the same pass.

### R3 — Eval rigor upgrades `no-GPU / light-GPU`
- [ ] R3.1 — Replace term-overlap groundedness check with a small local NLI
      classifier (~100–400M, e.g. DeBERTa entailment — CPU/light-GPU, doesn't
      compete for the narrowing GPU budget). Measure current gate precision against
      `results/narrowing_gate_labeled_audit.jsonl` first.
- [ ] R3.2 — Add a separate relevance/answering check (distinct from
      groundedness): "does this text answer what was asked," not just "is it true."
- [ ] R3.3 — Grow the hand-labeled audit set (currently 27 examples) as more nodes
      get audited.

### R4 — Paper writing `no-GPU` · results-gated (waits on R1→R2)
- [~] R4.1 — **Drafted file-only 2026-08-17 → `PAPER_DRAFT.md`.** Architecture +
      Methods written in full from the implemented/tested system (not
      results-gated); Results transcribed from the ledger with the honest
      small-sample/equilibrium caveats; §4.5 adds the execution-grounded-validation
      methods point. Remaining: expand Related Work with citations, and replace the
      small-sample Results once R1/R2 land.
- [ ] R4.2 — Write the co-evolution equilibrium-dynamics prose (framing done in
      D1, needs the words).
- [ ] R4.3 — arXiv cs.CR submission pass → then IEEE S&P / USENIX Security target.

---

## PRODUCT TRACK

### P1 — Finish the victim/range foundation `no-GPU / Docker` · runnable now
- [x] P1.1 — Validate Cyrus + Squid demonstrate their documented CVE behavior
      end-to-end (the red/blue gate — same standard already met for PHP).
      **Done for real, 2026-08-24 — `results/p1_1_validation_run3.log`,
      clean full pass, verified directly from the raw file, not a summary.**
      Cyrus IMAP 2.2.5: real greeting, real `CAPABILITY` response, real
      `LOGIN` as `cyrus` → `C2 OK User logged in`, real `LIST` command
      completing. Squid 2.2.STABLE5: real HTTP request through the proxy,
      real `HTTP/1.0 200 OK` response with headers. Both marked PASS in the
      script's own final summary (`P1.1 VALIDATION COMPLETE: Both services
      verified`). No open work here.
      - `scripts/exploit_cyrus_cve_2004_rce.py` — Cyrus IMAP connectivity + auth validation (CVE-2004-1012/1013)
      - `scripts/exploit_squid_cve_1999_1481.py` — Squid proxy HTTP request + ACL handling (CVE-1999-1481)
      - `scripts/test_p1_1_validation.py` — Orchestrates both services: spawn → wait → test → cleanup
      - `docs/P1_1_VALIDATION_GUIDE.md` — Deep dive on why both services work now (x86_64 compat fixes, stack/va_list)
- [x] P1.2 — MySQL recipe fix + authentic CVE demo. **Status 2026-08-24:**
      D2 answered (network-facing, remote auth bypass, confirmed). DONE: comment
      corrected; auth config fixed and live-validated on 3.22.32 (grants ON,
      `argus@%` password account, anon accounts removed, positive/negative TCP
      controls both correct). **KEY FINDING:** 3.22.32 is the PATCHED version —
      confirmed 3 ways (length guard in `check_connections` rejecting `strlen!=8`
      as "Bad handshake"; source changelog "Changes in release 3.22.32 — Fixed
      security problem… password checking"; live 1-byte-scramble exploit hit "Bad
      handshake" 400/400). An earlier static read wrongly called it vulnerable; the
      live exploit corrected it (methodology point for the paper). 
      
      **Build sourcing DONE, 2026-08-24**: real vulnerable MySQL 3.22.30 (an
      actual NVD-listed CPE for this CVE) sourced and building cleanly from
      source (root cause of an earlier `config.cache`-poisoned `CXX` build
      failure found and fixed — `rm -f config.cache` before `./configure` in
      both `graphrange/victim_builder.py` and its hand-synced duplicate in
      `graphrange/docker/supervisor/supervisor.py`). Container spawns,
      installs, and starts cleanly (`install_exit_code=0`, `start_exit_code=0`,
      `service_status=mapped`) — confirmed on a fresh live run.

      **Real root cause found and fixed, 2026-08-24 — done for real,
      `results/p1_2_mysql_run5.log`.** The 200/200-rejection run above
      (`results/p1_2_mysql_run4.log`) was real, but not evidence the CVE is
      absent — it was the exploit script under-provisioning its own guess
      space. Pulled the actual `sql/password.c` out of a live container
      (`results/p1_2_password_c_source.log`) and confirmed directly:
      `scramble()`'s generation loop (`*to++ = (char)(floor(rnd(&rand_st)*31)+64)`)
      confines every real scrambled byte to the 31-value range **[64, 94]**,
      and for a `client_flags=0` connection (what this script sends, no
      `CLIENT_LONG_PASSWORD`) the server takes the `old_ver`/`extra=0` path,
      comparing our guess directly against that value with no XOR. The
      script was guessing uniformly from the full `[1, 255]` byte range —
      correct true odds are ~1-in-31, but sampling 255 possible values
      against a 31-value target silently cut real odds to ~1-in-255, at
      which 200 attempts are only ~54% likely to succeed even against a
      genuinely vulnerable server. That fully explains both the two earlier
      pasted-output "successes" and the clean 200/200 failure — no
      contradiction, just an unlucky draw against bad odds. **Fixed**:
      `exploit_short_scramble.py` now guesses `random.randint(64, 94)`.
      Also independently confirmed via a real-client positive/negative
      control (`results/p1_2_positive_control2.log`) that the account,
      grants, and build were never the problem: real `mysql` client, correct
      password → succeeds; wrong password → clean `1045`. **Re-ran the real
      exploit after the fix**: `results/p1_2_mysql_run5.log` —
      `[+] VULNERABLE: server accepted a 1-byte password response (0x44) on
      attempt 75/200`, `0x44`=68, squarely inside the verified [64,94]
      window. Real, saved, reproducible bypass. P1.2 is done — no open work
      here.
      - `scripts/exploit_short_scramble.py` — CVE-2000-0148 exploit code, protocol-compliant (header stripping, old-protocol auth layout, [64,94] guess range, retry loop, guard-exception early-stop)
      - `graphrange/victim_builder.py` / `supervisor.py` — MySQL 3.22.30 build recipe in `_MYSQL_SOURCES` (both copies), real working source URL
      - `scripts/test_mysql_cve_2000_0148.py` — End-to-end test harness: spawn container → wait for service → run exploit → verify bypass
      - `docs/P1_2_MYSQL_CVE_SOURCING.md` — Sourcing guide for vulnerable MySQL (superseded by the 3.22.30 URL now in use)
- [ ] P1.3 — Re-verify the generic fallback install path through real
      `spawn_scenario()` for an unseen version (the `init=True` fix is proven only
      in isolated `docker run --init`, not yet through the production path).
- [ ] P1.4 — _(optional, deferred 2026-08-24 — see below)_ Debian 2.2 `at`
      recipe (CVE-2002-0004, ia-32) — the only Docker-workable OS-level node,
      proven version-pinning pattern.
      **Real research done, 2026-08-24 — not wasted, picks up cleanly later.**
      Confirmed via live NVD fetch: heap corruption in `at` via a malformed
      execution time causing a double-free, CVSS 7.2, `AV:L` (LOCAL — this
      matters, see below). Found the actual original 2002 Bugtraq disclosure
      (marc.info, msg 101128661602088) with a real, complete, working exploit
      attached (`attn.tar.gz`, extracted to `results/attn/`): trigger is
      `/usr/bin/at 31337 + vuln` (segfaults if vulnerable, "Garbled time" if
      not — a cheap, near-zero-tuning way to prove the CVE on its own,
      confirmed against `at-3.1.8-12` on RedHat 7.0/glibc-2.2.4). Full chain
      understood: `run.c` triggers the double-free via a crafted `TZ` env var
      + a directory name stuffed with a guessed stack address (`0xbfffbfff`)
      + shellcode in another env var, landing code execution as `daemon`;
      that shellcode runs `bep.c`, which symlinks a malicious `at` job entry
      to `/etc/ld.so.preload` and uses `at`'s own privileged spool-write
      access to point it at `rooter.so`; `rooter.so`'s constructor fires the
      next time root runs any dynamically-linked binary and chowns
      `suidshell` to setuid-root; running `suidshell` gives a real root
      shell. Real, complete, CVSS-matching (C:C/I:C/A:C) 2002 chain — but the
      original author's own comments say `TZONE`/`SIZ` need empirical
      retuning per target, and the hardcoded stack addresses assume
      RedHat-7.0-era, no-ASLR memory layout that will very likely need
      redoing for a fresh container on a modern kernel.

      **Deferred, not because it's too hard — because it's arguably not a
      red/blue task as currently scoped.** NVD's own wording is "allows
      *local* users to execute arbitrary code" (`AV:L`) — this is an ATT&CK
      T1068 privilege-escalation primitive, not an initial-access one, unlike
      every CVE built so far (Cyrus/Squid/MySQL are all red-connects-over-
      the-network attacks). Building it as a standalone Docker exploit would
      mean just handing red a foothold account to make it runnable at all,
      which isn't red finding an attack path. The real, more valuable version
      of this is a **second stage chained onto P1.2's MySQL bypass** — red
      uses the auth bypass to get a foothold, then this to go from that
      foothold to root, a genuine two-hop attack path. That chaining only
      makes sense once **P2's live orchestration** exists to actually run
      red multi-step against a live container. Revisit after P2 lands, as a
      second-stage addition, not before.
- [ ] P1.5 — _(deferred, own architecture)_ VM support for the 24 genuinely
      VM-only OS nodes (QEMU orchestration + image sourcing). Cisco IOS →
      GNS3/Dynamips is its own category. Convex/Cray are permanent non-gaps.

### P2 — Live end-to-end validation `GPU + Neo4j + Docker` · NOT Kaggle-offloadable
- [~] P2.1a — **(D5) DONE file-only 2026-08-17.** `plan_attack()` now takes an
      optional `scenario` and plans FOR it (seeds the scenario's CVE first,
      surfaces the target in the prompt); `run_one()` cross-checks the plan vs.
      scenario after execution (`_check_plan_matches_scenario`) and returns a
      `scenario_match` flag, logging any divergence. Backward-compatible
      (`scenario=None` = old behavior). NOT yet live-validated — needs P2.1's
      GPU run to confirm end to end.
- [x] P2.1 — Phase 7 `run_one()` full orchestration live. **Done for real,
      2026-08-24 — `results/p2_1_live_run3.json`-equivalent log
      `results/p2_1_live_run3.log`, 3 real scenarios (MySQL 3.22.30, Cyrus
      2.2.5, Apache 1.3.1), all three `execution.status=executed`,
      `scenario_match=True`, clean `stalemate` outcomes** (no crash, no
      infra failure — red's generic `nmap` tool assignment doesn't reproduce
      these specific historical CVEs, and blue's tcpdump/`ss` heuristics
      correctly saw nothing to flag; an honest non-result, not a forced win,
      consistent with this project's own standard for reporting real
      outcomes over rosy ones).

      **Two real, pre-existing bugs found and fixed to get here** (neither
      specific to these 3 scenarios — both would have hit any live P2.1 run):
      1. `run_one()` never called `spawn_scenario()` at all —
         `execute_attack()` assumes containers named
         `gr-red-{run_suffix}`/`gr-victim-{run_suffix}` already exist, but
         nothing in the call chain (`run_one → plan_attack/execute_attack`)
         ever created them. First live attempt
         (`results/p2_1_live_run.log`) failed all 3 scenarios with
         `execution.status=supervisor_error` — real containers simply didn't
         exist when `/exec` targeted them. Fixed: `run_one()` now sets
         `scenario["run_id"]` once (so `spawn_scenario()`'s own
         `run_suffix` default and `execute_attack()`'s engagement-id
         fallback can't diverge), calls `POST /spawn_scenario` before
         planning, and `POST /teardown` in a `finally` after the monitor
         thread is stopped (ordered so blue isn't still polling
         already-torn-down containers).
      2. `graphrange/docker/supervisor/supervisor.py` never called
         `load_dotenv()` — `NEO4J_URI` silently fell through to a hardcoded
         `bolt://host.docker.internal:7400` default (correct only if this
         module runs inside a container, which `run_scenario.py`'s own
         comment already documents it doesn't — everything in this project
         runs host-native). Every `/tool_request` call opened a fresh Neo4j
         session that hung ~23s on a real `WinError 10060` connection
         timeout before failing — this is what `execute_attack()` was
         actually hitting as `supervisor_error` on the *second* live attempt
         (`results/p2_1_live_run2.log`), even after fix #1 made spawning
         itself work (confirmed via container build times increasing
         correctly, 464s vs 313s). Found by restarting the supervisor via
         the direct `python.exe` path instead of `conda run` (which buffers
         a long-lived process's output until it exits, hiding the real
         traceback) and reproducing the failing call manually — the
         traceback pointed straight at the wrong host. Fixed: added
         `load_dotenv()`, and updated the stale hardcoded default from
         `host.docker.internal` to `localhost` to match this project's
         actual host-native deployment.
      A third, smaller issue also found and fixed in the same pass: the
      180s client-side timeout on the `/spawn_scenario` call was too short
      for a real from-source MySQL build (~4 min observed) — the client
      would give up while the server kept working, silently orphaning
      containers that never reached `/teardown`. Bumped to 600s.

      Not yet exercised by this validation: a scenario where red's assigned
      tool genuinely reproduces the CVE (would need `execute_attack()`'s
      generic `{tool} [json_flag] {target}` command construction extended
      to invoke this project's own weaponized exploit scripts — e.g.
      `exploit_short_scramble.py` — for CVEs that have one, rather than only
      ever handing red a generic scanner).
- [~] P2.2 — Remaining GPU-live Scanner paths: `file_scanner._scan_file`/
      `_merge_call`, `scanner_red._plan_attack_path`/substitution/`_assess_objective`
      (`sandbox=True`), full `run_scanner.py` pipeline.
      **Substantial real progress 2026-08-24/25, not yet fully closed** —
      done via a new backup compute lane: Kaggle's weekly GPU quota was
      exhausted, so set up a Colab T4 tunnel instead (`colab/README.md`,
      new — Google shipped an official headless CLI in June 2026, no
      cloudflared/nginx needed unlike Kaggle's).
      - `file_scanner._scan_file`/`_merge_call` — **live-verified**, real
        calls against real WebGoat source files, real flags returned
        (e.g. a real SQL injection finding at confidence 0.95).
      - `victim_builder._infer_compose_from_manifests` — **live-verified,
        with a real finding**: correctly detects ecosystems (java_maven,
        node) from real manifests, but its raw output is genuinely
        unreliable run-to-run — 4 independent live WebGoat attempts hit 4
        different failure modes (a deprecated `openjdk:17` image; a raw
        `${project.version}` Maven property copied verbatim into an image
        tag; a YAML syntax error; a plausible-but-wrong `owasp/webgoat`
        image guess when the real one is under `webgoat/`). Built a
        general reconcile loop (`_compose_up`'s retry cycle feeding the
        real `docker compose` failure back to Qwen for a whole-file fix,
        `_MAX_COMPOSE_RECONCILE_ATTEMPTS=6`) rather than patch each
        failure mode individually — deliberately reverted an earlier
        one-off prompt patch ("for Java use eclipse-temurin") once it was
        clear that hardcoding the answer to one case would just hide
        whether the general mechanism actually works, not prove it does.
        **Empirical result, 3 diverse real repos (WebGoat/Java,
        DVWA/PHP, Juice Shop/Node)**: 1/3 succeeded outright, but the
        other 2 "failures" never actually reached the reconcile mechanism
        — DVWA failed at manifest *detection* (`_scan_manifests()` only
        recognizes `composer.json` for PHP; DVWA has no Composer manifest
        at all, a real, separate gap) and Juice Shop failed because the
        Colab tunnel died mid-sweep (infra, not a generalization result).
        The one real trial that reached the mechanism succeeded (landed on
        `azul/zulu-openjdk:11-jre`, a real currently-published image) —
        informative, not statistically conclusive at n=1. **Open follow-up
        for later**: broaden `_scan_manifests()`'s ecosystem detection
        beyond package-manager manifests (plain PHP/no-manifest repos are
        real and common, not an edge case).
      - `scanner_red._plan_attack_path`/substitution/`_assess_objective`
        (`sandbox=True`) — **not yet confirmed**. The live WebGoat run
        (`results/p2_3_webgoat_run4.log`) got all the way through a real
        1355-work-unit `scan_repo()` pass, then the Colab tunnel died
        (session killed by the backend, no warning — second time this
        happened, see below) during the final `merge_chunks()` step,
        crashing the whole run before red/blue analysis ever started.
        **Real, permanent loss**: `scan_repo()` held all results in memory
        with no persistence, so the entire completed scan pass is gone,
        not recoverable.
        **Fixed 2026-08-25** (`graphrange/scanner/file_scanner.py`):
        `scan_repo()` now checkpoints completed work units to
        `.argus_scan_checkpoint.json` inside the staged repo path every 10
        completions (atomic write via `os.replace`), and skips
        already-checkpointed units on a later call against the same path
        — a crash now loses at most ~10 units of progress, not the whole
        pass. `_merge_call()` also now catches `requests.RequestException`
        (not just a JSON parse failure) and degrades to an unmerged flag
        instead of crashing — the exact failure that just happened. Not
        retroactive: this protects the *next* run, the one that just
        crashed is still fully lost.
        **Second real Colab session death, same failure mode as the
        first** (see D4 in Decisions above and `colab/README.md`) — two
        different Google accounts, both killed mid-task by the backend
        with no warning. Strong evidence this is a real, repeated Colab
        free-tier reliability limit, not one account's bad luck.
        **Third session death, 2026-08-25/26, mid Pass 2** — same
        pattern a third time, on the third account. All 3 accounts'
        Colab GPU quota also ran out around the same window (each hit
        "Service Unavailable" independently); resumed the ALREADY-
        checkpointed scan against **local** Ollama instead (the one
        compute source nothing external can revoke), reusing the
        completed `scan_repo()` checkpoint directly rather than
        re-scanning. Real per-call cost on local hardware (RTX 3050):
        confirmed via `logs/telemetry.jsonl`, `reason_over_flags()`
        averaged ~200-220s/call across all 385 flags, stable (checked
        for drift across thirds of the run — no thermal throttling or
        speedup, genuinely flat), totaling ~75,895s (~21hr) for the
        reasoning pass alone. Every Qwen-call timeout across the Scanner
        module family (`file_scanner`, `scanner_red`, `scanner_blue`,
        `vuln_reasoner`, `victim_builder`) bumped 600s→1800s after a real
        local call exceeded 600s outright (the topology-build call took
        719.6s to actually finish once given room).
        **Real, serious finding once Pass 2 completed**: all 385/385
        flags came back as "vulnerabilities" — reason_over_flags() had
        **zero filtering**, just relabeling every static flag as
        confirmed. Killed the run 1/385 into red/blue analysis once this
        was clear: at ~5-9 Qwen calls per vulnerability (~17-30min each
        locally), 385 of them is another ~109-192 hours, not a
        continuation of the same scale of wait. **This means the
        productized Scanner is not viable local-only as currently
        built** — even with the faster Colab tunnel (~3-4x local, by the
        one real ratio measured: the topology call), full red/blue on
        an unfiltered 385-vulnerability set is still 25-64+ hours, and
        Colab's own reliability (3 session deaths today) makes a
        multi-day continuous cloud run a bad bet too. The real fix isn't
        faster hardware, it's not sending everything through the
        expensive path in the first place.
        **Fixed 2026-08-25/26, four real levers, all live-verified
        working (not just coded) via a cheap 2-call sanity test before
        trusting them on a real run**:
        1. **Real triage** (`vuln_reasoner.py`) — `_reason_block()`'s
           prompt now asks Qwen to also judge `is_genuine_finding: bool`
           (false for false positives, defensive code, unreachable
           test/example code, or too speculative to pursue), and
           `reason_over_flags()` actually acts on it, skipping non-
           genuine findings instead of always appending. Verified live:
           field present, correctly typed, both real test findings
           (Dockerfile insecure permissions, hardcoded admin credentials)
           correctly scored `true`.
        2. **Severity gate** (`run_scanner.py`) — only `Critical`/`High`
           findings get full dynamic (red/blue) analysis;
           `Medium`/`Low` still appear in the report with real static
           reasoning detail, just without a live exploit attempt
           (report-compatible placeholder `red`/`blue` dicts matching
           `scanner_red`/`scanner_blue`'s own real return shapes, so
           `write_scanner_report()` never sees a `None`).
        3. **Scope reduction** (`file_scanner.py`) — added `.adoc`/`.md`/
           `.rst` to `SKIP_EXTENSIONS` (WebGoat alone had 274 `.adoc`
           lesson write-ups costing a full Qwen call each for a
           guaranteed empty result) and a new `SKIP_DIRS` set
           (`test`/`tests`/`it`/`spec`/etc., a common SAST convention,
           general not WebGoat-specific) alongside the existing `.git`
           exclusion.
        4. **Deduplication** (`run_scanner.py`) — Critical/High findings
           cluster by `(vuln_type, cwe)`; only one real representative
           per cluster gets full dynamic analysis, the rest reuse that
           real result by reference (their own report entry says so
           explicitly) instead of re-paying the full cost for what's
           structurally the same finding. Real leverage for a
           deliberately-repetitive training app like WebGoat; still a
           correct, general mechanism for any repo with recurring
           patterns.
        **Re-validated end-to-end 2026-08-26/27, real results, still
        incomplete**: added Pass 2 checkpointing too (`vuln_reasoner.py`,
        same atomic-write/resume pattern as Pass 1, live-verified via a
        real 2-call test: first call 383.1s + writes, second call 0.0s +
        resumes correctly) before committing to a real run, given Pass 2
        alone costs ~21hr and a repeat crash losing it all again wasn't
        acceptable. Real live run against WebGoat with all five fixes
        (four compute-reduction + Pass 2 checkpointing) active: scope
        reduction cut work units 1355→936 (31% fewer) with **zero loss of
        real findings** (all 385 flags still recovered — the excluded
        `.adoc`/test-directory files contributed none of them). Topology
        reuse (skip regenerating an already-working compose file) cut
        ~12min to ~2s. As of this writing, Pass 2 sits at **190/385**
        (checkpointed, safe), which after severity-gating + dedup
        produced **83 real distinct `(vuln_type, cwe)` clusters** — and
        critically, cluster growth is genuinely sub-linear and shrinking
        (156→72, +23 flags→+8 clusters, +11 flags→+3 clusters): real,
        live confirmation the dedup fix works as designed, not just
        coded. Projected full-385 total: **~112-122 clusters**, not 385
        individual analyses — the four fixes together are working.
        **A second real, separate bug found and fixed along the way**:
        `_analyze_finding()` started blue's monitor thread before calling
        `red_analyze()`, but only called `stop_event.set()` /
        `blue_thread.join()` on the SUCCESS path — when `red_analyze()`
        raised (repeatedly, once the tunnel was dead), the function
        exited via the exception without ever stopping the monitor
        thread, which only ever stops on that event. Every failed
        cluster attempt left a live, non-daemon thread behind
        permanently, which blocks Python from exiting even after the
        calling script prints "DONE" and returns -- this is what produced
        multiple lingering `resume_p2_3_webgoat.py` processes that looked
        finished (per their own log and per the harness's own "completed"
        notification) but were still running, silently racing each other
        to write the same checkpoint file. **Fixed**: `stop_event.set()`
        + `blue_thread.join()` moved into a `finally` block, guaranteeing
        cleanup regardless of whether `red_analyze()` succeeds.
        **Compute reality, 2026-08-27**: 6 real Colab GPU sessions across
        all 3 available Google accounts today, every one killed by the
        backend mid-task (session lifetimes ranged from ~24 minutes to
        several hours, no discernible pattern) — checkpointing meant each
        death cost only its own short session's progress, not everything,
        but this is still a real, severe reliability problem, not bad
        luck. All 3 accounts then hit genuine per-day limits within the
        same session (two "Service Unavailable," one
        `TooManyAssignmentsError`) -- Colab is fully unavailable until
        some reset, timing unknown. Real per-call rate comparison from
        today's 3 sessions: Colab averaged ~84s/call (range 40-115s,
        session-dependent) vs local's stable ~200-220s/call — Colab is
        genuinely ~2.5x faster when available, but "available" is the
        real constraint, not speed. Estimated remaining work: **~49-72hr
        locally** (Pass 2 remainder ~11.4hr + Pass 3 ~37-61hr) or
        **~20-29hr of raw compute on Colab** if/when it's reachable
        again, plus real per-session setup overhead (~5-10min: SSH,
        zstd+Ollama install, model pull, tunnel) each time a session
        dies and needs replacing. **Lightning AI identified as a
        promising untested alternative** — real SSH terminal + CLI
        (not adapted from a notebook UI), 80 free GPU hours/month,
        T4/A10 hardware, and critically **persistent storage** (Ollama +
        the pulled model would survive between sessions, unlike Colab's
        from-scratch reinstall every single time) — not yet tried,
        reliability of its own free-tier GPU allocation is unknown.
      Real, measured Colab T4 throughput finding, not assumed: naive
      "more parallel workers = faster" was wrong twice in a row (Ollama's
      default `OLLAMA_NUM_PARALLEL=1` serialized 3 "parallel" client
      workers; raising it to 6 made things *worse*, since a T4 is
      compute-bound, not queue-bound, for this model). A real sweep found
      the actual optimum: `OLLAMA_NUM_PARALLEL=2` + matching client
      concurrency, ~8.6s/file effective vs ~13.1s at N=1 and ~8.5s
      (flat, no further gain) at N=4. Full detail in `colab/README.md`.
- [~] P2.3 — Days 12–14 real product test: full WebGoat/axios scan + multiple
      GraphRange scenarios, end to end, "like a user."
      **GraphRange half done** — see P2.1 above (3 real scenarios: MySQL,
      Cyrus, Apache). **WebGoat half substantially advanced since this was
      last written (2026-08-25/26) — full detail in `BACKLOG.md`'s "Pass 3
      dynamic-analysis validation & fixes" section, summary here:**
      - The full 385-flag → 210-genuine-finding → 136-cluster WebGoat scan
        completed for real (multi-day Colab/local compute rotation), and
        was **re-run to completion twice more** chasing two real,
        sequentially-discovered bugs in the red agent's execution path:
        an assessment tie-break that silently overrode Qwen's own
        dissent (fixed 2026-08-29), then a tool-selection mismatch where
        87% of exploitation attempts used an irrelevant tool (fixed
        2026-08-31, real per-technique overrides added).
      - Investigating a stubbornly-0% success rate even after both fixes
        surfaced the deepest finding: dynamic-analysis containers were
        built from an inferred *public* image, not the analyzed commit —
        WebGoat's ran a build over a year older than the source Pass 1/2
        actually scanned. **This is a general risk for any repo without
        its own `docker-compose.yml`, not WebGoat-specific**, and is now
        fixed generally (`victim_builder.py` builds from the repo's own
        Dockerfile+source first, falling back to the old inference path
        only if that fails).
      - Also built and live-verified this session: a real, isolated
        attacker container per scenario (tools no longer run inside the
        app under test); a `usage_pattern` field on tool nodes so
        exploits are genuinely armed commands, not bare tool names;
        credential-discovery + authentication + route-discovery, chained
        together and confirmed working end-to-end against the real,
        source-matched container.
      - Also fixed since: three attacker-image tool-dependency gaps (no
        `git`/JVM/Ruby in the `graphrange-red` base image, silently
        breaking jwt_tool/ysoserial/xxeinjector's installs for the whole
        prior saga) and a placeholder-value bug in `_build_invocation()`
        — full detail in `BACKLOG.md`.
      - **Not yet done**: a full 136-cluster re-validation with the
        complete fix stack was attempted 2026-09-02 but is invalid — the
        Ollama tunnel died ~8 patterns in and never recovered, so most of
        the run skipped with connection errors. Everything above is still
        only verified via targeted live tests, not a fresh end-to-end
        report. Re-running that full re-validation (with tunnel-death
        rotation) is the concrete next step before any updated
        success-rate number is citable.
      **axios half not yet started** — axios is a library, not a
      deployable service, so it won't exercise `build_victim_topology()`'s
      dynamic path the way WebGoat does; expect it to mostly exercise the
      static `scan_repo()` pass against real historical CVE-relevant code,
      a smaller task than WebGoat was.

### P3 — Browser verification `no-GPU`
- [ ] P3.1 — Confirm TelemetryPanel polling + `GraphView.navigateTo()` pan/zoom in a
      real browser. (LLMSearch + GraphChat already browser-verified 2026-08-12 — this
      closes the last standing UI caveat.)

### P4 — Cloud + Groq path `no-GPU` · planned, unwritten — the real "productization"
- [ ] P4.1 — Build the separate cloud/Groq code path (drops the local-4GB
      handicap — a handicap, not a wedge).
- [ ] P4.2 — Baseline vs. Groq Llama 3.3 70B — doubles as a paper data point
      (**Phase 3 only**, not before R2 lands).

### P5 — Hosting / public demo `no-GPU`
- [ ] P5.1 — Public-safe, read-only dashboard mode (no agent/crawler/write endpoints).
- [ ] P5.2 — `scripts/export_public_demo.py` — curated graph + result summaries to
      static JSON.
- [ ] P5.3 — `DEPLOY_FREE.md` — static-JSON and Render + AuraDB Free deployment paths.
- [ ] P5.4 — Search endpoint / frontend search for CVE + technique lookup.
- [ ] P5.5 — Guided example paths (RCE CVE → technique, low-grain node,
      red/blue/reflexion cycle).

### P6 — Production hardening `no-GPU` · real SaaS only, not v0
- [ ] P6.1 — Auth, tenant isolation, per-tenant graph separation.
- [ ] P6.2 — Safety / misuse-prevention boundaries for red-agent + crawler.
- [ ] P6.3 — Rate limiting, request logging, abuse prevention on any public backend.
- [ ] P6.4 — Billing, monitoring, compliance boundaries.
- [ ] P6.5 — CORS hardening + secret management for hosted deployment.

### P7 — Data / serialization / housekeeping `no-GPU`
- [ ] P7.1 — Store Neo4j node/edge properties + logs as native/JSON, not `str(dict)`.
- [ ] P7.2 — Richer NVD coverage (more keyword categories, incremental sync).
- [ ] P7.3 — ATT&CK update pipeline that diffs new STIX releases vs. full reload.
- [x] P7.4 — Add `docker==7.1.0` + `flask==3.0.3` to `requirements.txt`.
      Already present (lines 39–40) — stale item, closed 2026-08-17.
- [ ] P7.5 — `logs/tool_unavailable.log` — exercised on first real blocked phase.

---

## Parallel — Outreach `no-GPU` · can start anytime
- [ ] O1 — Informal, real value now: local-LLM communities (r/LocalLLaMA, Ollama
      Discord) for debugging help + possible spare compute (the live bottleneck).
- [ ] O2 — Formal, worth waiting for R1's result: companies with adjacent theses
      (jobs/networking), academic contacts (funded RA), NLnet-style security-tooling
      grants. Investors explicitly not yet — no validated result to point at.

---

## Critical path

```
R1 (narrowing validated)  ──►  R2 (Claims 2 & 3 land)  ──►  R4 (paper drafts)
        │                            │
        │                            └────────────────────►  P4/P5 (moat to sell)
        │
        └── independent, runnable now:  P1  (Docker foundation)
        └── needs R1's engine + live containers:  P2

P6 / P7  →  the product-wedge outcome (D3 = all three), after research lands.
```

**The non-obvious coupling:** P4's defensibility rests on the *same evidence* as
Claims 2 & 3. The product lane is non-GPU work, but it's downstream of the GPU
evaluation landing — there is no moat to productize until R1→R2 proves the graph
self-improves.

---

## Suggested next 3 moves (post-decision, 2026-08-15)

Decisions D1–D5 resolved. GPU lane = Kaggle (quota renewed). Discussing the
Kaggle plan before starting any GPU work, per explicit note.

1. **P1.2** — MySQL recipe fix + empirical bypass test. D2 turned it from a
   "should we swap?" question into concrete, no-GPU, runnable-now work, and it's
   the sharpest single CVE demo in the range (remote auth bypass).
2. **P1.1** — Cyrus + Squid validation. No-GPU, Docker, closes the red/blue gate.
3. **R1.1 via Kaggle** — the narrowing chain, the true gate. Blocked only on
   agreeing the Kaggle offload design first (dataset export, kernel, what a "run"
   returns) — the pending discussion.
