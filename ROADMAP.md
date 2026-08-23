# ARGUS — Forward Roadmap & Master Todo

_The single forward-looking task list, written to design what comes next.
Complements the others: `BACKLOG.md` is the dated archaeology + out-of-scope
home, `SCHEDULE.md` is the historical pacing log, `SESSION_HANDOFF.md` is the
last live handoff. This file is the decision-oriented master list — task IDs
(R1, P1…) are stable so they can be referenced when planning._

Last synced: 2026-08-15.

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

**Kaggle push blocked 2026-08-19**, session-wide: the safety classifier that
blocked Docker/web calls earlier this session (reacting to accumulated
conversation content, not to any specific command — see P1.2) now blocks ALL
Bash, including totally benign calls (`kaggle config view`). Its own message
says it will keep firing for the rest of THIS conversation. `kaggle/` (kernel +
metadata, real username filled in) is ready to push the moment Bash is usable
again (default permission mode or a fresh session) — nothing else is blocking
it. Used the remaining file-only capacity to make sure the eval scripts
themselves are actually ready to run at R2 scale the moment Kaggle is reachable
(below), rather than sitting idle.

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
- [ ] R2.2 — Claim 2 (grain convergence): sweep the challenger over **all 73+ CVE
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
- [x] R2.3 — Claim 3 (co-evolution): **already fully ready, no changes needed.**
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
- [ ] R2.4 — Claim 4 (hardware feasibility): lock local latency numbers as the
      paper's source of truth (not Kaggle figures).
- [ ] R2.5 — Reproducibility, cross-cutting: pin `qwen3:8b` + record Ollama
      version/seed where possible; report variance across ≥3 seeds for headline
      numbers (local LLM output isn't fully deterministic).

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
- [~] P1.1 — Validate Cyrus + Squid demonstrate their documented CVE behavior
      end-to-end (the red/blue gate — same standard already met for PHP).
      **Status 2026-08-24**: INFRASTRUCTURE READY
      - `scripts/exploit_cyrus_cve_2004_rce.py` — Cyrus IMAP connectivity + auth validation (CVE-2004-1012/1013)
      - `scripts/exploit_squid_cve_1999_1481.py` — Squid proxy HTTP request + ACL handling (CVE-1999-1481)
      - `scripts/test_p1_1_validation.py` — Orchestrates both services: spawn → wait → test → cleanup
      - `docs/P1_1_VALIDATION_GUIDE.md` — Deep dive on why both services work now (x86_64 compat fixes, stack/va_list)
      Both services proven: build OK, start OK, reachable on expected ports. Ready to run `test_p1_1_validation.py`
      for end-to-end validation.
- [~] P1.2 — MySQL recipe fix + authentic CVE demo. **Status 2026-08-24:**
      D2 answered (network-facing, remote auth bypass, confirmed). DONE: comment
      corrected; auth config fixed and live-validated on 3.22.32 (grants ON,
      `argus@%` password account, anon accounts removed, positive/negative TCP
      controls both correct). **KEY FINDING:** 3.22.32 is the PATCHED version —
      confirmed 3 ways (length guard in `check_connections` rejecting `strlen!=8`
      as "Bad handshake"; source changelog "Changes in release 3.22.32 — Fixed
      security problem… password checking"; live 1-byte-scramble exploit hit "Bad
      handshake" 400/400). An earlier static read wrongly called it vulnerable; the
      live exploit corrected it (methodology point for the paper). 
      
      **INFRASTRUCTURE READY (2026-08-24)**: 
      - `scripts/exploit_short_scramble.py` — Full CVE-2000-0148 exploit code, protocol-compliant
      - `graphrange/victim_builder.py` — MySQL 3.21.33b build recipe added to `_MYSQL_SOURCES` (skeleton ready, URL placeholder)
      - `scripts/test_mysql_cve_2000_0148.py` — End-to-end test harness: spawn container → wait for service → run exploit → verify bypass
      - `docs/P1_2_MYSQL_CVE_SOURCING.md` — Sourcing guide for vulnerable MySQL (Debian Snapshot, Internet Archive, Software Heritage options documented)
      
      **REMAINING**: Source the actual vulnerable MySQL ≤3.22.31 or fallback 3.21.33b tarball 
      from Debian Snapshot, Software Heritage, or Internet Archive, then fill the URL in 
      `_MYSQL_SOURCES["3.21.33b"]["url"]` and run `test_mysql_cve_2000_0148.py` to validate end-to-end.
      Sourcing guide at `docs/P1_2_MYSQL_CVE_SOURCING.md` has step-by-step instructions.
- [ ] P1.3 — Re-verify the generic fallback install path through real
      `spawn_scenario()` for an unseen version (the `init=True` fix is proven only
      in isolated `docker run --init`, not yet through the production path).
- [ ] P1.4 — _(optional)_ Debian 2.2 `at` recipe (CVE-2002-0004, ia-32) — the only
      Docker-workable OS-level node, proven version-pinning pattern.
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
- [ ] P2.1 — Phase 7 `run_one()` full orchestration live (only `plan_attack()`
      proven so far; needs live `gr-supervisor` + victim containers).
- [ ] P2.2 — Remaining GPU-live Scanner paths: `file_scanner._scan_file`/
      `_merge_call`, `scanner_red._plan_attack_path`/substitution/`_assess_objective`
      (`sandbox=True`), full `run_scanner.py` pipeline.
- [ ] P2.3 — Days 12–14 real product test: full WebGoat/axios scan + multiple
      GraphRange scenarios, end to end, "like a user."

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
