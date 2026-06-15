# ARGUS Finalization Plan

## Summary

ARGUS is a local-first research prototype for an epistemically aware cyber
knowledge graph. The six-layer system already exists in code: graph schema and
ingestion, GraphRAG retrieval, challenger refinement, crawler updates, red/blue
agents, and reflexion memory.

The near-term goal is a one-day v0 finalization package: make the repository,
paper framing, and investor/demo story coherent enough that a future engineer,
reviewer, or advisor can understand what is built, what is proven, and what
remains future work without reading prior chat history.

ARGUS is not production-ready SaaS as-is. The credible v0 target is a
research-backed demo package and open-source artifact, with an investor-facing
product thesis kept separate from demonstrated technical claims.

## Definition of Done

- Public docs tell one consistent story about ARGUS as a local-first v0
  six-layer research prototype.
- Setup, smoke tests, evaluation scripts, and dashboard launch steps are
  documented clearly.
- Existing results are summarized in plain English:
  - retrieval precision
  - grain convergence
  - co-evolution/reflexion findings
  - hardware feasibility
- Known limitations are named explicitly:
  - not production-ready SaaS
  - small evaluation samples
  - local model latency
  - stringified Neo4j properties/logs
  - no production safety, tenant isolation, compliance, or authorization layer
- Paper and investor language separates:
  - demonstrated claims
  - partially supported claims
  - future hypotheses
- Dashboard instructions are verified or clearly marked as not rerun during the
  finalization pass.

## Documentation Cleanup

- Fix the README Groq/cloud contradiction:
  - remove Groq setup as a current requirement
  - state that Groq or other cloud models are future Phase 3 benchmarking only
  - keep all current model usage local through Ollama
- Update phase/status language:
  - replace "Phase 1" public status with "v0 six-layer research prototype"
  - note that production SaaS is a future direction, not current state
- Align schema wording with implementation:
  - `grain_confidence` is seeded during ingestion and refined by challenger
    cycles
  - `challenger_log` is an audit/traceability mechanism, not a current planning
    input for future agents
  - `context_conditions` and edge confidence support context-aware traversal,
    but production-grade validation remains future work
- Keep `AGENTS.md` as the project rulebook. `PLAN.md` is only a handoff plan,
  not a replacement.

## Evidence and Claims Package

Create or update these root-level documents:

- `FINAL_DOD.md`
  - final checklist for repo, paper, demo, evaluation, and product-readiness
    criteria
  - include what was rerun today and what was only carried forward from prior
    results
- `PAPER_CLAIMS.md`
  - map each major paper claim to one of:
    - demonstrated by code/results
    - partially supported
    - citation needed
    - future work
  - include current result files as evidence anchors
- `INVESTOR_BRIEF.md`
  - problem, product thesis, moat, likely buyers, risks, estimated costs,
    revenue assumptions, and next milestones
  - state clearly that the immediate product is an epistemically aware cyber
    knowledge graph for planning/research, not autonomous enterprise cyber
    operations
- `BACKLOG.md`
  - capture product and engineering work that is out of scope for v0
  - include production hardening, richer Neo4j property serialization, stronger
    evaluations, auth/tenant isolation, safer red-team boundaries, and API
    packaging

Claim framing rules:

- Use investor-friendly ambition in `INVESTOR_BRIEF.md`.
- Use conservative evidence language in README, paper notes, and
  `PAPER_CLAIMS.md`.
- Do not claim production readiness, statistical significance, or broad
  superiority unless current results support it.
- Do not claim that challenger logs are used by agents unless code is changed to
  make that true.

## Product and Investor Package

Near-term product framing:

> ARGUS is an epistemically aware cyber knowledge graph for red/blue planning,
> security research, and autonomous-agent evaluation.

Initial audience:

- security researchers
- red-team labs
- cyber education teams
- early-stage security teams willing to evaluate research tooling

Do not position v0 as:

- a production autonomous red-team platform
- a replacement for certified cybersecurity expertise
- an enterprise-ready SaaS
- a compliance-ready security product

Investor story:

- The thesis is that cyber knowledge graphs become more useful when they expose
  uncertainty directly instead of forcing agents to infer missing context.
- The moat is the schema plus refinement loop: `grain_confidence`,
  `open_questions`, `context_conditions`, challenger refinement, and reflexion
  memory.
- The first fundable milestone is a polished research/demo artifact with
  stronger evaluations and a credible advisor review.

## Testing and Verification

For finalization, document or rerun these smoke tests:

- `python scripts/test_ingestion.py`
- `python scripts/test_retrieval.py`
- `python scripts/test_challenger.py`
- `python scripts/test_crawler.py`
- `python scripts/test_red_blue.py`
- `python scripts/test_reflexion.py`

If Neo4j or Ollama are unavailable during the finalization pass, do not pretend
tests passed. Mark them as not rerun and cite the existing status in
`CONTEXT.md`.

Do not rerun long evaluations unless explicitly needed:

- avoid 50-cycle co-evolution reruns by default
- preserve existing result files as evidence anchors
- rerun only targeted checks needed to validate doc claims

Verify dashboard instructions:

```powershell
docker compose up --build
```

Expected local URL:

```text
http://localhost:3000
```

## Known Risks

- Commercial readiness is weak today; ARGUS is a research artifact first.
- Founder-market fit is a major risk because the product crosses agentic AI,
  cybersecurity, and graph analytics.
- Existing evaluations are promising but small.
- Local Qwen3/Ollama latency limits interactive product use.
- Neo4j properties and logs are often stored as stringified Python or JSON
  values, which limits production querying and analytics.
- There is no production-grade safety, misuse-prevention, authorization,
  tenancy, billing, monitoring, or compliance boundary.
- The dashboard is a read-only visualization, not yet an operator workflow.

## Assumptions

- "Finalize" means produce a credible v0 package, not a production SaaS.
- No cloud APIs are added during this pass.
- No major schema migration happens during the one-day finalization pass.
- Existing result files remain valid evidence unless a later rerun contradicts
  them.
- Future commercialization should wait until the repo, paper claims, demo, and
  advisor feedback are stronger.
