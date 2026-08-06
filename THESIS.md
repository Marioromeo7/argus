# ARGUS — The Narrowing Thesis

**This supersedes the vague parts of the moat claim in [INVESTOR_BRIEF.md](INVESTOR_BRIEF.md)
and the self-graded `grain_confidence` mechanism as currently described in [CLAUDE.md](CLAUDE.md).
Read this before touching the Challenger agent, GraphRange, or the Scanner.**

We are pursuing the venture. The gap a technical investor would find first — the Challenger
judging its own output — gets closed by design, not by argument. This file is that design.

---

## The core research question

**How narrow can a piece of security knowledge get when a model is the one asking the questions?**

Not "can an LLM assign itself a confidence score" (that's the self-graded version, and the
literature is clear it's unreliable — a model rating its own output is circular). The question
we're actually asking is about **convergence under iterative, model-driven interrogation**:
if a model keeps generating the sharpest open question it can about a node, and each question
gets an independently-sourced answer, does the node's unresolved-question set shrink toward
zero, plateau, or diverge? That's measurable. That's falsifiable. That's the paper and the product.

---

## The mechanism (replaces the current Challenger loop)

The old loop: one model (Qwen3 8B) proposes a refinement, the *same* model in a different prompt
accepts or rejects it, and emits a float. Nothing external ever checks the float. That's the flaw.

The new loop separates **asking** from **answering**, and answering must come from a source
independent of the asker:

```
Node (label, properties, open_questions=[])
  │
  ▼
ASKER — explores the node, produces open_questions
  "what would make this ambiguous or wrong?"
  Same role the Challenger plays today. Its only job is to generate
  the sharpest question it can — it never gets to answer its own question.
  │
  ▼
open_questions: [q1, q2, q3, ...]
  │
  ▼
ANSWERER — attempts each question from a source the asker doesn't control:
  (a) GraphRange execution — run the scenario, get real stdout/observations.
      Resolves questions like "does this technique succeed against config X"
      and "is this detected by blue" with actual evidence, not an opinion.
  (b) An independent model — different weights than the asker (see Decisions
      below). Resolves conceptual questions execution can't reach, e.g.
      "what distinguishes this CVE from a similar one."
  Every answer records its source: {"resolved_by": "execution:OUT-1234"}
  or {"resolved_by": "model:<name>"}. No answer without a citation.
  │
  ▼
grain_confidence = α·(answered_total / total_open_questions) + (1-α)·(answered_new / all_new)
                   default α = 0.5
```

**Addition, not multiplication** — a weighted average of two ratios, not a product:

- **`answered_total / total_open_questions`** — overall progress, all rounds combined.
- **`answered_new / all_new`** — this round's freshness: of the questions the asker generated
  *this round specifically*, what fraction got answered *this round*.
- `α` is a tunable knob (like patience or the ceiling), not a fixed constant — 0.5 is the starting
  point, unweighted. Because it's a convex combination of two values in `[0,1]`, the result is
  always in `[0,1]` for *any* choice of `α` — no renormalization needed, and it stays compatible
  with the existing `Node.grain_confidence: float 0.0–1.0` contract the rest of the schema and the
  dashboard's node-sizing already depend on.

This is a meaningfully different epistemic stance than multiplication was. Multiplying is an AND —
one bad factor collapses the whole score to near-zero. Adding is a softer OR — a node with a strong
history and one rough fresh round gets pulled down proportionally, not erased. That's more robust
to a single noisy round, and probably the more defensible choice: a mature node shouldn't lose all
its earned confidence because the asker found two new unanswered questions this round.

**Zero-division convention still applies to each ratio independently: `0/0 := 0`.** An unprobed
node (`total_open_questions = 0`) scores its cumulative term as 0. A round where the asker finds
nothing new to ask (`all_new = 0`) scores its freshness term as 0 for that round only. Under
addition, a zeroed freshness term no longer zeroes the whole score — it *halves* it (at α=0.5),
which is the same reconciliation problem as before, just quieter: a "resolved" node's confidence
now drops to a plausible-looking half-value instead of an obviously-wrong zero, which is easier to
miss if nobody's watching for it. **The rule from before still holds, and matters more now, not
less: the persisted `grain_confidence` for a `"resolved"` or `"stalled"` node is the value from the
last round where `all_new > 0`, never a trailing round where the freshness term was forced to 0 by
convention.**

One artifact from the multiplicative version disappears under addition, for any `α`: at round 1,
every question is new by definition, so `total_open_questions == all_new` and
`answered_total == answered_new` — the two ratios are identical, and the weighted average of a
number with itself is just that number. No round-1 squaring penalty. Round 1 now reads at face
value, whatever `α` is.

**The formula still only scores confidence while the loop is active — it still isn't a substitute
for the `"resolved"` vs `"stalled"` label.** Two nodes can hit the same halved score for opposite
reasons (converged vs. plateaued); only the stop reason distinguishes them. The metric is a
fraction, not a vibe — it still needs the status label next to it to mean anything.

This is a straightforward extension of the existing `Node` schema
(`open_questions`, `challenger_log` already exist in `graph/schema.py`) — it changes how
`grain_confidence` is *computed*, not the shape of the node. `challenger_log` entries now need a
`resolved_by` field; that's the only structural addition.

---

## Why this is the actual research contribution

Compare against the earlier critique of the self-graded version:

| Problem raised | How the narrowing mechanism answers it |
|---|---|
| Same model judges its own output (self-enhancement bias, circular) | Asker and answerer are structurally separate; answerer is never the asker |
| No external validation signal | Execution answers are ground truth (real stdout); independent-model answers are at minimum a second, differently-weighted opinion |
| Confidence is an unfalsifiable float | Confidence is a counted fraction — auditable, reproducible, disprovable |
| Eval 2's "0.30→0.90 convergence" could just be the model learning to say bigger numbers | Convergence is now "did the open-question count actually shrink," which can't be gamed by tone |
| Elenchus already does prover-skeptic dialogue with a stronger epistemic design (human + formal reasoner) | We don't have a human or a formal reasoner, but execution-grounded answers are a comparable-strength external check for the parts of the graph that are executable — which is most of a security graph |
| Horizon3/XBOW already build attack-surface knowledge graphs at production scale | Neither publishes or tracks *what the graph still doesn't know*. A confidence-scored, audit-trailed "here's what we couldn't resolve and why" is not what either of them sells today — that's the wedge |

---

## Where GraphRange and the Scanner fit

They stop being separate expansions bolted onto a finished v0 graph — they become **the answerer**.

- **GraphRange (Layer 7)** — every `ScenarioRun` / `Outcome` produced by red/blue execution against
  the Docker victim topology is a candidate answer to a specific open question on the technique or
  CVE node that scenario targeted. `graph_updater.py`'s job is no longer just "log the outcome" —
  it's "find the open question this outcome resolves, check it against any prior `provisional`
  claim on that question, mark the question `trusted` (after 3 consistent agreeing runs) or
  `contested` (on disagreement), cite the `Outcome` node as the source, recompute
  `grain_confidence`." `check_and_flag_conflict()` already does almost this for execution-vs-prior-
  execution disagreement (Phase 6) — it just needs to also fire when execution disagrees with a
  `provisional` model claim, not only with a prior `Outcome`. The red/blue range *is* the execution
  half of the answerer, and this makes GraphRange Phase 1 (the Docker layer, not yet built) load-
  bearing: nothing can reach `trusted` by execution until it exists, so the narrowing experiment
  can't run with real teeth until it does.
- **GraphRange Scanner (Layer 8)** — takes the whole engine (asker → answerer → confidence) and
  points it at an arbitrary input repo instead of the ARGUS graph's existing CVE/technique nodes.
  Pass 1/2 flag suspicious code and generate open questions about it; scanner red/blue attempt to
  answer them by executing against the repo's own victim topology; scanner blue's mitigation advice
  and the report's confidence scores are only as strong as the fraction of questions that got a
  *cited* answer. A finding with 3/3 open questions execution-verified should visibly outrank one
  with 3 open questions and 0 answers — the current scanner report spec doesn't yet surface that
  distinction and needs to.

---

## Decisions

1. **Who is the independent answerer for non-executable questions? → local only, no cloud option.**
   Not a brand choice — there is no budget for cloud inference, full stop. The answerer is a second
   *local* model (different weights/architecture than Qwen3 8B — a different Ollama model), plus
   GraphRange execution for anything testable, plus direct citation of authoritative-source graph
   fields (see #2). A second local model is weaker independence than a frontier model would be —
   different open-weight models trained on overlapping corpora still share blind spots — which is
   exactly why it never gets full weight on its own; see the state model below.

2. **What counts as "answered"? → three states, not a binary, plus a rubric for each.**
   A detailed, confidently-cited model answer is not the same thing as a correct one — verbalized
   confidence in LLMs is documented to track *"answer plausibility and provenance rather than
   correctness"*, and surface-plausible wrong answers get rated about as confidently as right ones.
   So "answered" can't mean "the answerer replied with specifics." It has to mean one of three
   distinct, differently-weighted states:

   ```
   provisional — a model claim exists, no execution has corroborated it yet
                 (or none ever can — see the conceptual-question caveat below).
                 weight = β, default 0.5.
   contested   — execution ran and disagrees with the prior claim (model-sourced
                 or provenance-sourced). NOT counted as answered — this is worse
                 than unanswered, not neutral. weight = 0, and it spawns a new,
                 sharper open_question: "why do these disagree?"
   trusted      — either (a) execution has agreed with the claim consistently
                 across 3 independent attempts (reuse patience=3 — a single
                 agreeing run isn't enough; see the 400-run pentest-consistency
                 finding on why single-run agreement is not reliable), or
                 (b) the claim is a direct, unmodified citation of a field that
                 was copied from an authoritative external source (see below).
                 weight = 1.0.
   ```

   **Getting to `provisional` in the first place requires a rubric**, so a bare assertion never
   silently counts as a claim worth tracking. The answerer must reply in a structured form:
   ```
   ANSWER:   <a specific claim — no hedging>
   EVIDENCE: <cite a real node_id/property, or "insufficient evidence">
   COMMITS:  <yes | no>
   ```
   Gated mechanically, not by trusting the model's self-assessment: `COMMITS` must be `yes`
   (a hedge is an honest non-answer, not a weak answer); `EVIDENCE` must be non-empty and must
   name something that actually exists in the graph (a plain lookup catches fabricated citations
   for free). A further, still-cheap check: embed `EVIDENCE` and the actual content of the cited
   node with `nomic-embed-text` (already in the stack, CPU-only) and require reasonable cosine
   similarity — this catches "cites a real node, but the evidence text doesn't match what's
   actually in it," a step up from merely checking the node_id exists. None of this verifies the
   *claim* is true, only that it isn't lazily fabricated — the thing that actually corrects a
   wrong-but-well-cited claim is `contested`, not the rubric.

   **Provenance path to `trusted`, without execution:** `graph/ingestion/nvd.py` and
   `graph/ingestion/attack.py` copy fields directly from NVD/MITRE's own structured data into node
   properties — the one other place in this system (besides execution) where the chain bottoms out
   in something that isn't itself model-generated text. So a citation to an *original ingested
   field* (`properties.description`, `properties.cvss_score`, the CPE list) on a node whose
   `source` is `nvd` or `attack` earns `trusted` directly. This does **not** extend to:
   - `web`-sourced nodes — `agents/crawler.py` runs crawled text through an LLM
     (`_extract_entities`) before writing anything, so a model has already touched it; `web` does
     not have the property that makes `nvd`/`attack` trustworthy.
   - `agent_derived` or `challenger_refined` nodes, ever.
   - any edge, `grain_confidence`, `open_questions`, or `challenger_log` — `Edge` carries its own
     `source` field independent of the nodes it connects (e.g. a `nvd`-sourced CVE node can have an
     `agent_derived` edge to a technique, from the crawler's entity extraction). Provenance trust
     applies to the *specific field cited*, never inherited from the node as a whole.
   - **Nothing here is unconditional.** A later, actually-contradicting execution result can still
     flip a provenance-`trusted` claim to `contested` — NVD entries get disputed and corrected;
     authoritative source is strong prior evidence, not an unfalsifiable trump card.

   **Honest limit, not fixed by any of this:** a purely conceptual open_question (no execution could
   ever test it, no authoritative field settles it) can never leave `provisional`. That's the
   correct behavior, not a gap to close — this system only claims real trust for what it can
   actually check.

   `answered_total` and `answered_new` in the confidence formula are weighted sums over these
   states (`trusted`=1.0, `provisional`=β, `contested`=0), not plain counts — the denominators
   (`total_open_questions`, `all_new`) stay plain counts. `β = 0.5` is a starting guess, like `α`
   and `patience` — calibrate it once real data exists, using exactly the contradiction rate
   between model claims and later execution results as the empirical signal.

3. **When does a node stop being probed? → patience-based early stopping, patience = 3.**
   Same pattern as early stopping on a validation loss curve: stop probing a node once 3 consecutive
   rounds produce no change. The comparison must be on the raw integer pair
   `(answered_count, total_count)`, **not** the `grain_confidence` ratio — the ratio can hold steady
   while the underlying counts are still moving (e.g. 5/10 → 6/12 are both 0.50 but real work
   happened between them). "Unchanged" means the exact `(answered_count, total_count)` tuple repeats
   for 3 straight rounds.
   - Correctly stops immediately on an already-precise node (nothing to ask → flat from round 1).
   - Correctly does *not* trigger on genuine divergence — if the asker outpaces the answerer, `total`
     keeps growing and the ratio actually declines round over round, so it never reads as "unchanged."
   - Pair patience=3 with a hard ceiling (`max_rounds = 10`) so an oscillating node
     (5/10 → 6/12 → 5/10 → ...) can't dodge the patience check and run forever.
   - A node that plateaus at low confidence (answerer keeps failing, not just the asker succeeding)
     stops for the same reason and should be logged with a different status than a node that
     converges high — `"stalled"` vs `"resolved"` — since both trip patience=3 but mean opposite things.
4. **Does the open-question set converge or diverge?** Unknown, and that's fine — it's the actual
   experiment. If asking more questions reliably produces more questions faster than they get
   answered, that's a real, reportable, negative-but-honest result, not a bug to hide.

---

## Pilot results (8 technique nodes, 2026-08-06)

First real run of `agents/narrowing.py` via `scripts/run_narrowing_pilot.py`, dry-run only (no
graph writes). Full reports in `results/narrowing_pilot.jsonl`.

- **One clean end-to-end success: `T1021.005`.** Converged genuinely via patience at round 8 (not
  the ceiling), `grain_confidence = 0.625` — highest in the batch — and produced one real `trusted`
  answer: a question about which OS platforms the technique applies to got resolved by citing
  `T1021.005.platforms` (an untouched ATT&CK-ingested field), correctly answered "Linux, Windows,
  macOS." The provenance path works end to end, as designed. The same node also shows the
  anti-fabrication gate catching a real attempt to slip a speculative claim through under an
  "insufficient evidence, but..." EVIDENCE field — correctly rejected as a fabricated citation, not
  counted as answered.
- **The real bug wasn't the threshold — it was comparing the wrong string, and a silent parse
  failure let empty answers through.** Manually inspecting the rejected question/answer/real-content
  triples (no model calls, just reading `results/narrowing_pilot.jsonl` against a fresh Neo4j read)
  showed every single similarity-rejected case had `answer_text: ""` — genuinely empty, not just
  weak. Root causes, both in `answer()`/`_parse_answer()`:
  1. The similarity check compared `parsed["evidence"]` (a short citation label like
     `"T1055.011:description"`, per the prompt's own instructions) against the real paragraph,
     instead of `parsed["answer"]` (the actual claim). A citation label will never resemble a
     paragraph regardless of answer quality — this alone explains the near-identical scores per
     node (0.38 / 0.40 / 0.41) independent of which question produced them: the compared string
     barely varied, so the score barely varied.
  2. `_parse_answer()` used a strict `line.startswith("ANSWER:")` check with no guard for an empty
     result — a reply Mistral formatted slightly differently (markdown bolding like `**ANSWER:**`
     is the likely culprit, since other replies in the same run parsed fine) silently produced an
     empty claim that then sailed through to the similarity check instead of being caught as a
     parse failure.

  My first-pass diagnosis (recalibrate `0.55` down) was real — 0.55 was still too strict for this
  embedding space — but not the root cause: no threshold would have fixed comparing the wrong
  string. Fixed both: `_parse_answer()` now strips markdown/leading punctuation before matching,
  `answer()` now rejects an empty parsed answer explicitly (`"ANSWER line missing or
  unparseable"` — a distinct, honest reason, not folded into the fabrication or hedge cases), and
  the similarity check now compares `parsed["answer"]` against the source. `EVIDENCE_SIMILARITY_
  THRESHOLD` stays at the recalibrated `0.30`, but it hasn't been re-validated against a correct
  comparison yet — that's still an open question for the next run, not a fixed constant. Final
  tally across all 8 nodes: 4 landed at `grain_confidence = 0.0` (`T1055.011`, `T1205.002`,
  `T1687`, `T1113`), 5 of 8 hit `max_rounds=10` without patience ever triggering (`stalled`), 3
  reached `resolved`. None of that should be read as evidence about the asker/answerer mechanism's
  real quality — it mostly measured a parsing bug, not the design.
- **High hedge rate (`COMMITS=no`) throughout — this is correct behavior, not a bug.** The answerer
  regularly declined to commit rather than fabricate a confident claim. Exactly the property the
  rubric was designed to produce.
- **Patience rarely triggered — 5 of 8 nodes hit `max_rounds=10` instead of converging.** The asker
  kept generating genuinely distinct new questions round after round (verified by reading the
  actual questions — they're substantively different sub-topics, not paraphrase-inflated), not
  hitting the embedding dedup check. Good sign for the core research question — the asker isn't
  just repeating itself — but it also means 10 rounds isn't enough to distinguish "would have
  converged at round 15" from "genuinely diverges." Unresolved by this pilot; the recalibrated
  threshold should be tried before increasing round budget, since starved provisional/trusted rates
  may be why patience wasn't triggering (an all-`unanswered` node's `(trusted, total)` tuple never
  stops moving because `total` keeps growing every round with nothing to counterbalance it).

---

## What changes in the existing specs

This does not get implemented yet — this file is the design, not the build order. But it means,
when Phase 0+ work resumes:

- `graph/schema.py`'s `ChallengerLogEntry` needs a `resolved_by` field, and a `status` field
  (`provisional`/`contested`/`trusted`) per open question — not just a resolved/unresolved bool.
- `agents/challenger.py`'s `_primary_prompt`/accept-reject step is replaced by the answerer step —
  it stops being "the same model decides if it agrees with itself," and its output must follow the
  `ANSWER`/`EVIDENCE`/`COMMITS` structured format so "answered" can be gated mechanically.
- A new, small module (or a function in `agents/challenger.py`) does the provenance check: given a
  citation, look up the cited node's `source` and confirm the cited field is an original ingested
  property (not an edge, not `grain_confidence`/`open_questions`/`challenger_log`) before granting
  `trusted`-by-provenance.
- The `EVIDENCE`-vs-cited-node-content similarity check needs `nomic-embed-text` wired into the
  answerer path (CPU-only, per the existing Ollama quirks in CONTEXT.md).
- `graphrange/graph_updater.py`'s `check_and_flag_conflict()` (GRAPHRANGE.md Phase 6) extends to
  compare execution results against `provisional` model/provenance claims, not only against prior
  `Outcome` nodes — that's the `contested` state.
- `graphrange/scanner/scanner_report.py` needs a status column (`trusted`/`contested`/`provisional`)
  per open question per finding, not just a confidence float.
- `BACKLOG.md`'s GraphRange/Scanner sections stay valid as a build order — this changes *what
  grain_confidence means* and raises the priority of GraphRange Phase 1 (execution is now required
  to reach `trusted` for anything testable), not the phase sequencing itself.
