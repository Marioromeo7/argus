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

## GraphRange — Cyber Range Expansion (Layer 7)

Turns ARGUS's planning-only red/blue agents into real executors running tools in
isolated Docker containers, with outcomes fed back into the graph. See
[GRAPHRANGE.md](GRAPHRANGE.md) for the full spec. Touches nothing in the existing
six layers — append-only extensions plus new files under `graphrange/`.

- [x] Phase 0: `scripts/populate_observables.py` + `scripts/create_execution_schema.py`
      (append `ScenarioRun`/`Outcome` dataclasses to `graph/schema.py`) — done: all 697/697
      technique nodes have `expected_observables`; constraints/indexes created.
- [ ] Phase 1: Docker topology — supervisor, red, blue, victim containers;
      extend `docker-compose.yml` with a `graphrange` profile
- [ ] Phase 2: Tool graph (`graphrange/tool_graph.py`) + crawler
      (`graphrange/crawler/tool_crawler.py`)
- [ ] Phase 3: Scenario generator — valid CVE/technique/CPE combos emerge from
      graph constraints (`graphrange/scenario_generator.py`)
- [ ] Phase 4: `execute_attack()` appended to `agents/red.py`,
      `monitor()` + `assess_detection()` appended to `agents/blue.py`
- [ ] Phase 5: Observation normalizer (`graphrange/observer.py`)
- [ ] Phase 6: Graph updater — write outcomes, update technique confidence,
      flag conflicting outcomes (`graphrange/graph_updater.py`)
- [ ] Phase 7: `graphrange/run_scenario.py` end-to-end orchestration
- [ ] `requirements.txt` — add `docker==7.1.0`, `flask==3.0.3`

## GraphRange Scanner — Vulnerability Scanner Product (Layer 8)

Standalone repo scanner (any GitHub repo → vulnerabilities + mitigation advice)
built on top of GraphRange, plus a separate WebGoat evaluation harness. Requires
GraphRange Phase 0-7 complete first. See [GRAPHRANGE_SCANNER.md](GRAPHRANGE_SCANNER.md)
for the full spec — note the file contains several in-place revision passes
(multi-container victim topology supersedes an earlier single-container version,
capability-cached tool requests supersede an earlier 2-cycle cap, execution-primary
dual assessment supersedes plain Qwen assessment); the checklist below reflects the
final spec state, not every intermediate version.

### Repo intake & safety (`graphrange/scanner/`)
- [ ] `repo_intake.py` — GitHub URL / local path validation, staging directory,
      symlink + path traversal checks, exec-bit stripping, XML-wrapped file
      content via `read_file_safe()` (prompt injection defense — the only way
      file contents may enter the scanner pipeline)

### Product pipeline (`graphrange/scanner/`)
- [ ] `telemetry.py` — token counting, cost estimation, system load tracking,
      `logs/telemetry.jsonl`
- [ ] `victim_builder.py` — generalized multi-container topology builder:
      `docker-compose.yml` first, manifest fallback (Qwen infers compose from
      `pom.xml`/`package.json`/etc), compose validation (dry-run + unsafe flag
      check + image registry allowlist) before every `docker compose up`
- [ ] `file_scanner.py` — Pass 1, bounded-parallel Qwen scan (3 workers),
      chunk/merge for long files, uses `read_file_safe()` exclusively
- [ ] `vuln_reasoner.py` — Pass 2, deep reasoning per flag → VulnContext
- [ ] `scanner_red.py` — topology-aware attack path planning across containers;
      `acquired_capabilities` cache (capability → tool, reused across
      containers without re-requesting); tool substitution reasoning with
      `max_cycles=3` broadening before falling back to installed tools; phase
      blocked vs. scenario stopped; `_assess_objective()` with
      execution-primary / Qwen-secondary dual assessment (execution stdout is
      ground truth, conflicts logged)
- [ ] `scanner_blue.py` — ARGUS mitigation lookup + static advice;
      multi-container monitoring (one thread per service, shared event list +
      lock); per-service/per-phase detection assessment; `missed_lateral` flag
- [ ] `scanner_report.py` — MD + PDF + HTML report: per-finding vuln +
      mitigation, multi-container kill chain table (status/result/evidence/
      qwen/conflict columns, blocked phases, substituted tools), per-service
      detection table
- [ ] `run_scanner.py` — pipeline entry point: `intake()` → topology build →
      Pass 1 → Pass 2 → parallel red/blue per finding (`stop_event`
      coordination) → report → `teardown_victim_topology()`
- [ ] `logs/tool_unavailable.log` — auto-created on first blocked phase

### Dashboard extensions
- [ ] Extend `dashboard/api/main.py` — `/api/telemetry`, `/api/llm/navigate`
- [ ] `LLMSearch.jsx` — query → pan/zoom graph navigation
- [ ] `TelemetryPanel.jsx` — polls `/api/telemetry` every 10s
- [ ] Extend `GraphView.jsx` — `forwardRef` + `navigateTo()`
- [ ] Extend `App.jsx` — wire `LLMSearch` + `TelemetryPanel`

### Evaluation harness (`eval/`) — research tool, not part of the product
- [ ] `ground_truth.py` — WebGoat GitHub advisories + `SECURITY.md` loader
- [ ] `comparator.py` — Table A (CVE-joined) + Table B (code-level) + Qwen summary
- [ ] `false_positive_analyzer.py` — classifies unvalidated Table A findings
- [ ] `defense_plan.py` — Claude Code prompt generator for `eval/defense_plan.md`
- [ ] `run_eval.py` — orchestrator: `run_scanner()` on WebGoat → compare → report
- [ ] `requirements.txt` — add `reportlab==4.1.0`, `psutil==5.9.8`, `tiktoken==0.7.0`

---

*See [PLAN.md](PLAN.md) for the v0 definition of done and
[PRODUCT_HOSTING_HANDOFF.md](PRODUCT_HOSTING_HANDOFF.md) for the hosting strategy.*
