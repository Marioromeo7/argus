# ARGUS — Session Summary (Narrowing Thesis Expansion)

Covers the session that took ARGUS from a completed v0 (six layers) through the
Narrowing Thesis redesign, its pilot, debugging, and the resulting plan. Two parts:
the plan going forward, and an honest accounting of who did what.

---

## Part 1 — The Plan

### Where things actually stand
- v0 (Layers 1-6) complete and evaluated, unchanged this session.
- THESIS.md designed and coded (`agents/narrowing.py`), wired in as an **opt-in**
  alternative to the old self-graded Challenger — not yet the default.
- **Zero post-fix validation runs have completed.** Every attempt has died to
  infrastructure (a genuine Ollama hang, then GPU/RAM contention with another
  local project) — not to the mechanism itself. This is the actual bottleneck,
  not the design.
- Three commits landed: `[L7] expansion initiation`, `[L7] narrowing thesis`,
  `[L7] wire narrowing engine as opt-in alternative`.

### Phase 1 — Validate the fix (next, blocking everything else)
Resume the 8-node chain (`scripts/run_narrowing_single.py`, one node at a time,
user-gated) once local GPU/RAM are free. Judge the output the same way as
before — empty-answer rate, similarity distribution — before trusting any
confidence number it produces.

### Phase 2 — Calibrate, then flip the default
Recalibrate `α`, `β`, `EVIDENCE_SIMILARITY_THRESHOLD` against real post-fix
data. Only then does `challenge_node_v2` become the actual default, replacing
`agents/challenger.py`'s self-graded loop system-wide.

### Phase 3 — GraphRange Phase 1: Docker topology
Supervisor + red/blue/victim containers (GRAPHRANGE.md Phase 1). This is what
unlocks real `trusted`-by-execution instead of the weaker provisional/provenance
paths. Docker Desktop availability on this machine is still unverified — check
that before any container work.

### Phase 4 — GraphRange Phases 2-7
Tool graph + crawler, scenario generator, execution additions to
`agents/red.py`/`agents/blue.py`, observation normalizer, graph updater
(extends `check_and_flag_conflict()` for the `contested` state), `run_scenario.py`.
Full checklist in BACKLOG.md.

### Phase 5 — GraphRange Scanner (Layer 8)
Points the validated, execution-grounded engine at arbitrary input repos.
Repo intake/safety layer, multi-container victim topology, scanner red/blue,
report generation. Depends on Phase 3-4 being real first.

### Parallel track — outreach (not sequential, can start anytime)
Two different audiences for two different reasons, neither requiring the
phases above to be finished first:
- **Informal (real value now):** local-LLM communities (r/LocalLLaMA, Ollama
  Discord) for debugging help and possible spare-compute access — the actual
  live bottleneck this session hit repeatedly.
- **Formal (worth waiting for Phase 1's result):** direct outreach to
  companies with adjacent product theses (e.g. Beacon Security) as a jobs/
  networking move, academic contacts for possible funded RA positions,
  open-source security-tooling grants (NLnet-style). Investors explicitly
  not yet — no validated result to point at.

### What "done" looks like
Not "finish every BACKLOG.md line." One of three outcomes, decided by what
Phase 1-2 actually show: a narrow research write-up (the real claim being
convergence under execution-grounded interrogation, not the broader pitch),
an open-sourced schema/engine, or a product wedge distinct from existing
autonomous-pentesting players. Which one depends on evidence not yet in hand.

---

## Part 2 — Contribution Sheet

Honest split of who did what, this session. Where an idea originated matters
more than who typed it, so that's the basis for attribution below.

### What the user did
- Set every strategic direction and made every call at each real decision
  point: pursuing the venture framing, keeping everything local (budget
  constraint, not preference), rejecting Llama for Mistral once the
  hallucination-benchmark evidence was in, choosing pilot scope, deciding
  when to stop vs. keep debugging, declining the Kaggle offload, leaving
  `ballnet` untouched.
- **Originated the core mechanics of the narrowing design**, each proposed in
  compressed/intuitive form and then formalized: the answered/total-questions
  confidence idea; the "stop after 3 rounds unchanged" patience rule; the
  additive (not multiplicative) formula correction; using GraphRange execution
  itself as the answerer; mapping trust to node provenance (NVD/ATT&CK vs.
  web/model-derived); the three-state provisional/contested/trusted model.
- Pushed back hard at exactly the right moments and each pushback surfaced a
  real gap: "isn't execution just model output too?" (correct — led to the
  plan/execute/interpret decomposition), "doesn't detail mean correct?"
  (correct — led to the calibration-vs-correctness distinction), "run
  separately so we can stop early" (correct — avoided burning the full
  overnight budget on one bug).
- Set the operational ground rules that kept the session from wasting more
  time than it already did: "no more extra runs," single-node gating,
  auto-chain only when explicitly told to.
- Provided the actual hardware, ran Neo4j Desktop, tolerated a multi-hour
  overnight run, a VS Code crash, and a resource fight with their own other
  project — all real-world conditions no amount of design work controls for.

### What Claude Code did
- Diagnosed the self-graded Challenger's core flaw (same model judging its
  own output) and proposed the asker/answerer split as the fix direction,
  before the detailed design existed.
- Formalized every user-proposed mechanism into a rigorous spec: worked
  through zero-division conventions, the round-1 squaring artifact, the
  "persist the last active round" reconciliation, boundedness proofs for the
  weighted-sum formula, and the honest limits (conceptual questions capped at
  `provisional` forever; nothing reaches `trusted` without GraphRange).
- Did the grounding research throughout — real citations on LLM self-judge
  bias, correlated-error ensembles, GraphRAG hallucination evidence, Llama
  vs. Mistral hallucination benchmarks, iterative-question stopping criteria
  — rather than asserting from priors.
- Wrote and debugged all the code: `agents/narrowing.py`, both pilot runner
  scripts, the schema additions, `scripts/populate_observables.py` and
  `create_execution_schema.py`, the `challenger.py` wiring.
- **Found the actual root cause of the pilot's bad results** — the
  similarity check comparing the citation label instead of the claim, and a
  silent parser gap letting empty answers through — via direct inspection of
  rejected question/answer/source-content triples, using zero additional
  model calls once told not to run anything else.
- Handled every infrastructure failure as it happened: the split Ollama
  model-directory bug (fixed by running a second server instance), the
  VS Code crash recovery (diagnosing an orphaned hung connection via TCP
  state, not just process existence), and the GPU/RAM contention diagnosis
  (via `nvidia-smi`, tracing it to a specific competing process).
- Organized the git history into three logically separate, accurately
  described commits rather than one undifferentiated dump.
- Ran the researcher/investor critique passes, with real literature search
  each time claims needed checking rather than confirming what was already
  believed.
