# ARGUS — Production Hardening Plan

*Addresses roadmap items #13 (data serialization cleanup) and #14 (auth / tenancy / safety / ops).*
Everything here is **explicitly out of scope for v0** — this is the gap between a research artifact
and a product. Do not build any of it into v0 without promoting it here first (per the project
rulebook).

---

## #13 — Neo4j serialization cleanup

**Problem:** node/edge properties and logs are stored as `str(dict)` (Python repr, single quotes),
so they must be parsed with `ast.literal_eval()` and can't be queried natively. This blocks
analytics, indexing, and safe multi-tool access.

**Plan (incremental, backward-compatible):**
- Store structured fields as **native Neo4j types** where possible (lists, numbers, ISO datetime
  strings) and complex blobs as **valid JSON** (double-quoted), not Python repr.
- Serialize on write with `json.dumps`; deserialize with `json.loads`. Keep an `ast.literal_eval`
  fallback during migration so old rows still read.
- Write a **one-time migration script** (`scripts/migrate_props_to_json.py`) that rewrites existing
  `str(dict)` properties to JSON, idempotent and checkpointed.
- Add **indexes/constraints** on the fields that queries actually filter on (`node_type`, `label`,
  ID uniqueness) once they're native.
- Update `graph/schema.py` serialization helpers as the single choke point so no module hand-rolls
  `str(dict)` again.

**Definition of done:** new writes are JSON/native, a migration converts old rows, retrieval and the
dashboard read both formats during transition, and `ast.literal_eval` can eventually be removed.

---

## #14 — Auth, tenancy, safety, and operations

The full agent system must stay local until these exist. Grouped by concern:

### Authentication & authorization
- User accounts + API keys/OAuth; per-route authorization.
- Role separation: read-only viewer vs. operator who can run agents.

### Multi-tenancy & isolation
- Per-tenant graph separation (separate DBs or strict label/namespace partitioning).
- No cross-tenant traversal; enforce tenant scoping at the query layer, not the app layer only.

### Safety & misuse prevention (critical for dual-use cyber content)
- Hard boundaries on red-agent and crawler functionality: no arbitrary target input, no live
  external scanning, no shell execution, no exploit-generation prompts.
- Content policy + refusal layer on agent outputs; defensive-framing enforcement.
- Audit log of every agent action, immutable and per-tenant.

### Operations & reliability
- Rate limiting and abuse detection on all public endpoints.
- Monitoring, metrics, alerting; structured logging.
- Backups and disaster recovery for the graph DB (AuraDB Free has none).
- Secret management (vault/env), no secrets in repo or frontend.

### Compliance & billing (SaaS stage)
- Billing/metering, plan limits.
- Data handling / retention policy; compliance boundary appropriate to security data.

**Definition of done (per item):** each concern has an owner, a design doc, and tests before any
public write surface or hosted agent execution is enabled. Until then: **local only.**

---

## Sequencing recommendation

1. **#13 serialization** first — it's a prerequisite for real querying, analytics, and safe
   multi-tenant access, and it's low-risk/backward-compatible.
2. Then **safety boundaries** (#14 safety) before anything agent-related is ever hosted.
3. Then auth → tenancy → ops → billing, in that order, as the product actually needs them.
