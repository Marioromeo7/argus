# ARGUS Backlog

Work that is intentionally **out of scope for v0** (the six-layer local research prototype).
This file is the required home for any feature not in the original layer plan — per the project
rulebook, nothing outside the six layers gets built without being written here first.

## Evaluation & Research Rigor

- [ ] Larger evaluation samples (retrieval eval currently uses 6/10 evaluable CVEs).
- [ ] More challenger nodes for grain convergence (currently 4 nodes × 3 rounds).
- [ ] Run co-evolution long enough to reach statistical significance (p<0.05 not met at 50 cycles;
      current honest finding is co-evolutionary *equilibrium*, not a monotonic trend).
- [ ] Baseline comparison against a cloud model (e.g. Groq Llama 3.3 70B) as a paper data point —
      **Phase 3 only**, not before.
- [ ] Run the challenger across all CVE nodes to improve the graph-wide grain distribution.

## Data & Serialization

- [ ] Store Neo4j node/edge properties and logs as native/JSON values instead of `str(dict)`.
      Current stringified storage limits production querying and analytics.
- [ ] Richer NVD coverage (more keyword categories, incremental sync).
- [ ] ATT&CK update pipeline that diffs new STIX releases instead of full reload.

## Product & Hosting

- [ ] Public-safe, read-only dashboard mode (no agent/crawler/write endpoints).
- [ ] `scripts/export_public_demo.py` — export curated graph + result summaries to static JSON.
- [ ] `DEPLOY_FREE.md` — static-JSON and Render + AuraDB Free deployment paths.
- [ ] Search endpoint / frontend search for CVE and technique lookup.
- [ ] Guided example paths (RCE CVE → technique, low-grain node, red/blue/reflexion cycle).

## Production Hardening (not v0)

- [ ] Authentication, tenant isolation, and per-tenant graph separation.
- [ ] Safety / misuse-prevention boundaries for red-agent and crawler functionality.
- [ ] Rate limiting, request logging, and abuse prevention on any public backend.
- [ ] Billing, monitoring, and compliance boundaries.
- [ ] CORS hardening and secret management for a hosted deployment.

## Paper

- [ ] Draft the paper sections (architecture, experiments, results) — outline exists only.
- [ ] Reframe the co-evolution claim as equilibrium dynamics (done in framing, needs prose).

---

*See [PLAN.md](PLAN.md) for the v0 definition of done and
[PRODUCT_HOSTING_HANDOFF.md](PRODUCT_HOSTING_HANDOFF.md) for the hosting strategy.*
