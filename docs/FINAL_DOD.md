# ARGUS — Final Definition of Done (v0)

*Addresses roadmap item #4.* Master checklist for the v0 research artifact. This is the single
place to see what is built, what is proven, and what is explicitly deferred. Distinct from
[PLAN.md](../PLAN.md) (the finalization *plan*) — this is the *acceptance* checklist.

> **Scope note (2026-08-19):** this file's "v0" is the ORIGINAL six-layer prototype
> (dated by `CONTEXT.md`'s eval timestamps, 2026-05-28/29) and predates GraphRange
> (Layer 7), the Scanner (Layer 8), and the narrowing-engine (asker/answerer)
> redesign — all real, mostly-built, and NOT yet validated. Do not read "v0 is
> done" as "the project is done." Current scope + status lives in
> [ROADMAP.md](../ROADMAP.md); this file is a historical snapshot, not the live
> acceptance bar.

Status key: ✅ done · 🟡 partial · ⬜ not started · ⏭️ deferred (tracked in [BACKLOG.md](../BACKLOG.md))

## 1. Code — the six layers

| Layer | Built | Smoke test | Notes |
|-------|-------|-----------|-------|
| 1 Schema & Ingestion | ✅ | ✅ 7/7 | NVD + full ATT&CK (697 techniques) |
| 2 GraphRAG Retrieval | ✅ | ✅ 6/6 | Cypher traversal, not semantic guessing |
| 3 Challenger | ✅ | ✅ 5/5 | grain refinement loop |
| 4 Crawler | ✅ | ✅ 5/5 | challenger-validated writes |
| 5 Red & Blue | ✅ | ✅ 5/5 | co-evolution over shared graph |
| 6 Reflexion | ✅ | ✅ 5/5 | episodic memory |

> Test counts are carried forward from prior local runs (documented in [CONTEXT.md](../CONTEXT.md)),
> not re-run during finalization. Re-run before any formal release if the code has changed since.

## 2. Repository hygiene

- ✅ Public repo published (MIT [LICENSE](../LICENSE))
- ✅ README reflects true v0 status (no stale "Phase 1", no Groq-as-requirement)
- ✅ Secrets excluded (`.env`, `.vscode/` gitignored); no keys in tree
- ✅ Large data (`data/`, 48MB STIX) and generated `results/` gitignored
- ✅ Aider artifacts removed
- ✅ Consistent doc story across README / CLAUDE / CONTEXT / PLAN

## 3. Evidence & claims

- ✅ [PAPER_CLAIMS.md](../PAPER_CLAIMS.md) maps each claim → demonstrated / partial / future
- 🟡 Claims 1 & 2 demonstrated on **small** samples → strengthen per [EVALUATION_PLAN.md](EVALUATION_PLAN.md)
- 🟡 Claim 3 (co-evolution) is *equilibrium*, not significant → see [EVALUATION_PLAN.md](EVALUATION_PLAN.md)
- ✅ Claim 4 (hardware feasibility) demonstrated

## 4. Deferred to post-v0 (not blocking)

- ✅ Research paper prose draft — `PAPER_DRAFT.md` (2026-08-17), architecture +
      methods complete, results transcribed from the ledger. No longer outline-only.
- ⏭️ Stronger evaluations → [EVALUATION_PLAN.md](EVALUATION_PLAN.md)
- ⏭️ Public read-only demo → [DEMO_AND_DEPLOY.md](DEMO_AND_DEPLOY.md)
- ⏭️ Production hardening → [PRODUCTION_HARDENING.md](PRODUCTION_HARDENING.md)

## v0 acceptance statement

**v0 is "done" when sections 1–3 are ✅/🟡 and section 4 is captured in planning docs.**
That condition is met: ARGUS is a credible, reproducible, honestly-framed research artifact.
Everything remaining is enhancement, not a v0 blocker.
