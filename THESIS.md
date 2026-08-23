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

## Truncation fix and the comma-dilution gap (2026-08-09/10)

Two sessions after the pilot above, real validation runs finally landed (the per-clause
verification gate — clause splitting, entity/term-overlap checking, `spawned_questions` for
unsupported clauses — was designed and built in between, replacing the whole-answer similarity
check discussed in the pilot section; not documented here yet, see `agents/narrowing.py` directly).
Two more real findings:

- **97% of ATT&CK technique descriptions were silently truncated at ingestion.**
  `graph/ingestion/attack.py` hard-capped `description` at `[:500]` characters with no comment
  explaining why (traced via `git log` to the very first commit that added the file — no prior
  untruncated version existed). Real corpus check via the `mitreattack` API: full descriptions run
  207-4680 chars, median 1298, and 674 of 697 techniques (97%) exceed 500. A live audit of every
  hedge (`COMMITS=no`) question against real source text showed most hedges were the answerer
  correctly declining to fabricate content that had literally been cut off mid-sentence
  (`"(Citati"`, `"<cod"`, `"...suc"`) — not the mechanism failing, the mechanism correctly refusing
  to guess past a truncation boundary. Fixed: removed `[:500]` on both tactic and technique
  descriptions, re-ingested all 697 techniques, and pinned `num_ctx=4096` on both the asker and
  answerer calls (neither had ever set it explicitly — harmless while every prompt was ~130 tokens,
  worth pinning now that some prompts jump to ~1200 tokens of description alone, on a 4GB card
  where the KV cache competes with everything else). Smoke test on `T1055.011` confirmed real
  improvement: `grain_confidence` 0.675 → 0.8125, trusted answers 3→7 of 12, no GPU
  oversubscription (peaked ~2377 MiB of 4096).

- **A perfect `grain_confidence = 1.0` on `T1053.005` (6/6 trusted) turned out to be inflated —
  found by refusing to trust a suspiciously clean number, same as an earlier suspiciously clean
  zero.** Manual audit of all 6 "trusted" answers against the real source text: 3 were genuinely
  faithful restatements, but 3 contained real problems the gate should have caught:
  1. *"...conduct remote execution as part of lateral movement **by** running a process under a
     specified account, such as SYSTEM."* — source states these as two separate, unconnected abuse
     patterns (`"...and/or..."`); the model invented the causal link.
  2. *"...for **privilege escalation**."* — that phrase never appears in the cited `description`
     field at all; the model appears to have pulled it from the node's separate `tactics` list
     (which does include `privilege-escalation`) and asserted it as if the cited field said so.
  3. *"...**without requiring user interaction**."* — flatly fabricated; the source never
     addresses user interaction.

  Root cause: `_split_clauses()` only splits on `, and/but/while/whereas` or `;` — it does not
  split on bare commas or trailing purpose/manner phrases (`"for X"`, `"without Y"`). Each
  fabrication above rides as a short tail on an otherwise-faithful, longer sentence, so it gets
  checked as part of one large clause instead of in isolation — enough of the sentence's other
  salient terms genuinely match the source that the 60% term-overlap threshold still clears despite
  the tail being unsupported or invented. This is the same *bundled-claim confabulation* failure
  mode the per-clause gate was built to close, resurfacing in a syntactic shape (comma-appended
  trailing phrases, not conjunctions) the splitter regex doesn't cover. **Not yet fixed** — found
  mid-run on the full 8-node v3 chain; per standing practice this session, the fix is deferred to
  after the chain completes rather than interrupting an in-flight run.
  - Fix direction (not yet implemented): broaden `_split_clauses()` to also split on trailing
    prepositional/purpose phrases (`", for "`, `", without "`, `" without "`, `" for the purpose
    of "` etc.), or move to a stricter unit than regex-split sentences — e.g. requiring every
    independently-checkable noun phrase within a clause to individually clear the containment
    check, not just the clause's aggregate ratio.

**Update, same session — fixed and verified, plus two more bugs found the same way.** Continued
auditing every node as it landed rather than trusting the number, per the user's own standard
("are you sure that's a consistent mistake without reading?" — applied to a suspiciously *good*
0.32 exactly as rigorously as the suspicious 1.0). Found two more real, distinct bugs this way,
neither a repeat of the dilution pattern:

- **`T1560.001` (`0.0`) was unauditable, not provably wrong.** `_unanswered()` always set
  `answer_text=""`, discarding whatever the model actually claimed even when it was rejected —
  no way to tell a correct rejection from a false negative without a live re-query. Fixed: added
  an `attempted` parameter, threaded through every call site in `answer()`.
- **`T1021.005`: a compound `EVIDENCE` citation broke field lookup.** The model cited two fields
  at once (`"T1021.005:platforms, T1021.005:description"`); `partition(":")` on the whole string
  left `cite_field = "platforms, T1021.005:description"` — a garbage key that read back empty,
  producing the misleading reason *"cited field ... is empty"* when the real field had 1449 real
  characters. Fixed: take only the first citation (matching what the prompt actually asks for —
  one citation per answer); checking against the union of multiple cited fields is a possible
  future improvement, not built now.

**The dilution fix landed as regex+spaCy union, not regex alone**, per the same skepticism —
"is regex really the answer?" was the right question, and the honest answer was no: regex
clause-splitting is a syntactic proxy for a semantic boundary question, and the first fix already
had a second failure mode by the time it was audited. Before wiring anything in: fetched the real
Kali... no — fetched the real MITRE description text and ran spaCy's dependency parse against the
exact 5 fabricated sentences found via audit. Result: 4 of 5 fabricated tails isolate cleanly as
distinct `prep`/`advcl`/`mark` subtrees (the ones riding on a purpose/reason/exception phrase —
"for X", "without Y", "since Z", "in order to W"). One (`"...by running a process under...
SYSTEM"` — an invented causal link between two independently-true facts) isolates syntactically
but wouldn't be caught by splitting alone, since both resulting fragments are individually true;
that's a structurally different bug (relationship fabrication, not tail fabrication) that neither
regex nor spaCy nor word-overlap fully closes — logged honestly, not fixed by pretending clause
splitting solves everything.

Implementation: `_split_clauses()` now unions the existing regex split (sentence boundaries,
`and`/`but`/`while`/`whereas`, semicolons) with spaCy-identified boundaries — `mark` tokens always
split (that dependency relation *is* "this starts a subordinate clause"), `prep` tokens split
only when the preposition is in a curated purpose/manner/exception set (`for`, `without`, `by`,
`despite`, `except`, `unless`) attached directly to a verb — deliberately narrow so structural
prepositions ("under X", "of Y") don't over-fragment the core claim. Both are pure CPU/text
operations (`spacy` + `en_core_web_sm`, no GPU, no Ollama call) — verified before trusting it:
unit-tested against all 4 real fabricated sentences (all now correctly isolated and rejected in
isolation) and regression-tested against every genuinely clean answer found tonight (no
regressions once the full real source-field text was used instead of a hand-picked excerpt — the
first "regression" was a test-setup artifact, not a real one).

Not yet done: a live end-to-end smoke test with all three fixes active (unit tests only so far,
deliberately — no concurrent Ollama calls while the v3 chain has the GPU). That's the next step
once the chain finishes, before trusting any new confidence number these fixes produce.

## Recalibration methodology (design only — not run, a decision queued for later)

`ALPHA`, `BETA`, `EVIDENCE_SIMILARITY_THRESHOLD`, and the 0.6 term-overlap ratio in
`_clause_supported()` have all been unvalidated guesses since the pilot. Drafting the actual
approach now, ahead of having trustworthy data to run it against, so the method itself gets
scrutinized before any numbers do.

The four constants don't have the same calibration problem, and shouldn't be treated as one:

- **Term-overlap ratio (0.6) and `EVIDENCE_SIMILARITY_THRESHOLD`** are genuinely calibratable
  against `results/narrowing_gate_labeled_audit.jsonl` — for every labeled (clause, source,
  verdict) triple, compute the actual overlap ratio / embedding similarity, then sweep candidate
  thresholds and pick the one maximizing precision on the "bad" class (false "trusted" is worse
  than a missed "good" one here, given the whole point of the redesign is not overclaiming — so
  precision matters more than recall, and the sweep should say so explicitly rather than defaulting
  to F1). This only works once the labeled set is big enough to trust a sweep on — 15 examples
  isn't there yet; needs growing alongside every future audit, not just this session's.

- **`ALPHA`/`BETA` (the node-level confidence formula) don't have an equivalent ground truth.**
  There's no labeled "T1053.005's true confidence is X" to fit against — that number doesn't
  exist independent of the formula itself. Point-calibrating them the same way as the thresholds
  above would be false precision. The honest alternative: a sensitivity analysis, not a fit — run
  the formula across a small grid of ALPHA/BETA values against real node data, and check whether
  the *relative ranking* of nodes (which ones are more/less confident than which others) stays
  stable across that grid. Calibrate for ranking stability, not for hitting an absolute target
  that was never real. Write this distinction into the paper explicitly — presenting ALPHA/BETA
  as equally "calibrated" as the thresholds above would overclaim rigor that doesn't exist.

Not started — logged here so the method is on record before any numbers are, and so running it
is a decision made on purpose, not a default reflex once trustworthy data exists.

## Sixth real bug — found auditing the v4 (all-fixes-active) run itself, 2026-08-10

Continuing to audit every node after the three fixes landed, rather than treating them as "done"
once verified in isolation, surfaced a fourth, unrelated bug. `T1055.011` (v4) landed at
`grain_confidence=0.3`, down from v3's `0.8125` — a big enough drop to warrant checking rather
than assuming the fixes explain it. One of the six `trusted` answers claimed EWM injection
*"differs from other memory injection techniques like APC injection and thread hijacking"* —
neither "APC injection" nor "thread hijacking" appears anywhere in the source; the model asserted
a comparison it had no basis for. It should have been caught and wasn't.

Root cause, confirmed with a clean side-by-side test: `_salient_terms()` never deduplicates.
The clause repeats "injection" three times (it's the technique's own name, appears in nearly
every sentence of the source). Raw ratio: 8/13 = 61.5%, passes the 0.6 threshold. Deduplicated
ratio: 6/11 = 54.5%, correctly fails. The repeated word pads both the numerator and denominator
enough to flip a genuinely-failing clause into a passing one — a distinct mechanism from the
dilution bug (that was about clause *boundaries*; this is about term *counting* within an
already-correctly-isolated clause).

**Fixed and verified, 2026-08-10, while the v4 chain kept running.** Editing the file while a
chain is actively running was already established as safe — an already-started process doesn't
hot-reload the module (confirmed earlier when a v3 node ran on pre-fix code despite the fix
already being on disk), so the fix could be written and unit-tested in parallel without touching
the live chain's outcome, same pattern as building GraphRange Phase 1 during the v3 chain. Only a
*live* smoke test (a real Ollama call) would have contended for GPU — the fix and its tests don't
need one.

Fix: deduplicate terms before computing the overlap ratio in `_clause_supported()`. Verified
against the exact real fabrication (`"EWM injection...APC injection...thread hijacking"` now
correctly returns `supported=False`) and regression-tested against clean answers from tonight —
one apparent regression turned out to be the same mistake as before (an abbreviated source
excerpt in the test, not the real full field text); confirmed clean once tested against the
actual full source.

## The clearest proof yet of the term-overlap ceiling — T1687 (v4), 2026-08-10

Auditing `T1687`'s v4 run (post all four fixes, including the dedup fix above) found something
more important than another bug instance: proof the ceiling on term-overlap verification isn't a
threshold-calibration problem at all.

A `trusted` answer claimed *"vulnerabilities in cloud-based (**IaaS**/SaaS) infrastructure..."* —
"IaaS" does not appear anywhere in the `description` field. It's real, but it's from the node's
separate `platforms` property (`['IaaS', 'Linux', 'macOS', 'SaaS', 'Windows']`) — smuggled into a
claim cited against a different field. Checked precisely: **14 of 15 salient terms matched
(93.3%)** — only "IaaS" itself failed. The clause is a single atomic sentence (nothing for the
dilution fix to split) with no duplicate terms (not the dedup bug). One fabricated, specific,
checkable fact, buried inside a sentence that's otherwise 93% correct, is completely invisible to
a ratio-based check — and no threshold adjustment fixes this. A threshold strict enough to catch
one wrong word in an otherwise-accurate sentence would reject enormous numbers of genuinely
correct answers that simply paraphrase loosely. This is the difference between "how much of this
matches" (what term-overlap measures) and "is every specific entity actually present" (what it
cannot). That's exactly the gap the NLI-classifier / entity-level-check `BACKLOG.md` item exists
to close — this case makes it a mechanism-ceiling problem, not a calibration problem, concretely
rather than theoretically.

Same audit also found two more instances of already-logged categories: a third
`coincidental_term_overlap` case (a `trusted` claim about "zero-day" vulnerabilities sourced from
a citation *title*, not the actual claim text) and a recurrence of `unsupported_recategorization`
specific to this node (source lists antivirus/EDR/firewalls as one "security tools" category; the
model invented a tools-vs-infrastructure comparison and miscategorized firewalls into the wrong
side of it). All four logged in `results/narrowing_gate_labeled_audit.jsonl` (now 21 examples).

## Three more fixes — T1113's false negative and the IaaS sibling-field veto, 2026-08-10

Found at the very end of the v4 chain (`T1113`) and during the T1687 audit above. All three are
zero-GPU, pure Python, fixed and verified in parallel with the (separate, already-finished) v4
chain — same "safe to edit, unsafe to live-test mid-run" distinction as the dedup fix.

- **Trailing punctuation stripped from tokens in `_salient_terms()`.** The regex's character
  class allows internal periods (needed for real tokens like `T1055.011`), which let end-of-
  sentence periods ride along as part of the last word — `"screenshots."` never matched source's
  `"screenshot"` for exactly that reason.
- **`_term_in_text()` — minimal plural/singular tolerance.** Not a full stemmer, just a trailing-
  `s` check both directions. `"screenshots"` (clause) now matches source's `"screenshot"`.
- **The cited node's own ID excluded from required terms**, via a new `cited_node_id` parameter
  threaded through `_clause_supported()`. A description never self-references its own technique
  ID; requiring `"T1113"` to appear inside `T1113`'s own description was a guaranteed failure
  regardless of the claim's truth.
- **Sibling-field hard veto**, via a new `sibling_text` parameter (the cited node's other property
  values, concatenated). If a term fails against the cited field but *is* found in a sibling field
  on the same node, that's confirmed evidence of wrong-field citation — hard veto regardless of
  overall ratio. This is what actually closes the T1687 "IaaS" case: previously 14/15 terms
  matched (93.3%, passed easily) because the fabrication was diluted by an otherwise-correct
  sentence; the veto catches it directly instead of relying on the ratio noticing a single
  diluted miss. Does not claim to close the general term-overlap-vs-entailment ceiling — the
  NLI-classifier item in `BACKLOG.md` still stands for cases with no sibling field to check
  against (the citation-title cases, the invented-causal-link cases).

All three unit-tested against the exact real cases that motivated them, then a full regression
pass against every previously-confirmed fabrication (T1053.005 x2, T1205.002) and clean answer
(T1055.011, T1053.005) using real full source text — 5/5 pass, nothing broken.

**Update — the compound-citation fix was too narrow, found by continuing to audit every node as
it landed rather than stopping once "enough" bugs were found.** `T1047` landed on the *pre-fix*
code (confirmed: its log entries have no `attempted_answer` key at all, meaning the already-running
chain process loaded the old module before the fixes were edited on disk — expected, a running
process doesn't hot-reload). Its rejection reasons revealed a second, different way `EVIDENCE`
citations break the naive parse:

> *"cited field T1047:description mentions that WMIC will be replaced by PowerShell as the
> primary WMI interface in subsequent Windows releases. is empty — nothing to verify against"*

Not a compound `field1, field2` citation this time — the model appended a whole justification
sentence after the field name instead of stopping. No comma before the runaway text, so the
comma-split fix wouldn't have caught this shape at all. Generalized the fix: instead of splitting
on comma, extract only the leading identifier-like token (`[A-Za-z_][A-Za-z0-9_]*`) from the
field portion — this naturally subsumes the comma case too (a comma isn't part of an identifier
either) and stops at the first space, comma, or punctuation regardless of what follows. Verified
against both real cases plus a plain clean citation (no regression): all correctly extract
`description`/`platforms` instead of a garbage multi-word key.

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
