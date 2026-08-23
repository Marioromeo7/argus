# ARGUS — Session Handoff

_Written 2026-08 to continue work in a fresh session. The previous session's
command execution became unavailable partway through, so this captures state
for a clean continuation. Kept deliberately at task/status altitude — granular
recipe internals already live in the code and `BACKLOG.md`; pull them only as
needed._

## Project
ARGUS — Autonomous Reasoning Graph for Unified Security. Research prototype +
open-core product: an epistemically-aware security knowledge graph (nodes/edges
carry `grain_confidence` + `open_questions`, refined by a challenger agent),
plus a Docker-based cyber range (GraphRange, Layer 7) and a scanner (Layer 8).
See `CLAUDE.md` for the project bible, `BACKLOG.md` for the live backlog.

## Done this session (all reflected in code + BACKLOG.md)
- **`spawn_scenario()` hardening** (`graphrange/docker/supervisor/supervisor.py`):
  added `init=True` (tini as PID 1) to all three `containers.run()` calls —
  fixes a zombie-reaping failure where a daemonizing installer left an unreaped
  process that broke package configuration. Also fixed the exception-cleanup
  path to locate containers by deterministic name when the local variable is
  `None` (orphan-on-partial-create). Both verified in code.
- **Squid 2.2.STABLE5 victim recipe**: root-caused two independent startup
  crashes — (1) a fixed-size stack array in the main loop sized from Docker's
  default fd ulimit (1,048,576) = an 8 MB stack array against the 8 MB stack
  limit; fixed by constraining `ulimit -n 1024` around configure/build/start;
  (2) a `va_list` reused across `printf`-family calls — harmless on the code's
  original 32-bit target, undefined on x86_64; fixed with `va_copy`. Recipe now
  builds, starts, and serves real proxied traffic. Registered in
  `victim_builder.py` `_VERSION_MAP` and synced to `supervisor.py`
  `_VICTIM_VERSION_MAP`.
- **PHP 4.2.2 victim recipe**: fixed so the mail function is actually compiled
  in (`./configure` only enables it if a sendmail binary exists at configure
  time; added a minimal stand-in created *before* `./configure`). Documented
  CVE-2002-0985 behavior validated end-to-end through the real HTTP + apache2 +
  php-cgi path. Synced to both files.
- **VM/OS research (Task 3)**: surveyed the 24 OS-level CVE nodes / 75 CPE
  tuples. Only Debian 2.2's `at` package (CVE-2002-0004, ia-32) is Dockerizable
  via the existing version-pinning pattern — it is the only Linux-family node
  and the affected component is a userspace package, not the kernel. Everything
  else needs a real VM (foreign kernel: BSD / Windows / SunOS / IRIX / AIX /
  HP-UX / SCO), router emulation (Cisco IOS → GNS3/Dynamips), or is a dead end
  (Convex / Cray, extinct ISAs). Two unresolved "maybes": freebsd-update
  (CVE-2009-4358), Sun portmapper (CVE-1999-0168).

## Open tasks (highest leverage first)
1. **Validate the Cyrus + Squid victims demonstrate their documented CVE
   behavior end-to-end** — the same validation standard already met for PHP.
   Both are currently only proven to build/run/reach (Cyrus: real authenticated
   IMAP session; Squid: serves traffic). This is the **red/blue gate** — a range
   whose victims are "authentic" but not confirmed to *behave as documented*
   isn't yet meaningful for red/blue testing. Docker-only, no GPU.
   **Recommended first action in the fresh session.**
2. **Reconsider the MySQL victim's CVE choice** — CVE-2000-0148 is a local
   file-permission class issue, likely the wrong shape for a network red/blue
   scenario (nothing network-reachable for red to exercise). Confirm its exact
   mechanism; evaluate swapping to a network-facing MySQL CVE. Decision needed.
3. **Re-verify the generic fallback install path through the real
   `spawn_scenario()`** for an unseen (unvalidated) version — the `init=True`
   fix is proven only in an isolated `docker run --init`, not yet through the
   production path end-to-end.
4. **Phase 7 `run_one()` live end-to-end** — full orchestration is coded; only
   `plan_attack()` has run live so far. Needs live supervisor + victim
   containers (GPU for the reasoning agents).

## Strategic context (from this session's discussion)
- **Product direction**: moving to cloud + Groq (separate code path, planned but
  not written). Dropping the local-4GB angle — it's a handicap (slow, weaker
  results), not a competitive wedge.
- **The moat is the epistemic graph** (a graph that knows what it doesn't know).
  Its defensibility depends on self-improvement *compounding* over use — which is
  the **same evidence** as paper Claims 2 (grain convergence) and 3
  (co-evolution). So those evaluations are moat-validation, not just paper
  homework; prioritize them accordingly.
- **Co-evolution is p ≥ 0.05 at 50 cycles.** Decision pending: commit the
  equilibrium-dynamics reframe (bounded — measurement + prose) vs. chase
  significance (open-ended compute, may not land). Recommendation: the reframe.
- **Timeline read**: ~2 months full-time to a validated + paper-drafted v0. A
  2-week aggressive push can reach "system validated + compute kicked off" but
  not the paper (results-gated, and writing is the incompressible tail — the
  drafting itself is fast, ~4–7 days AI-assisted, but can't precede the results).

## Needs the user / environment (blocks a fresh session can't clear alone)
- **Start Neo4j** — was down (connection refused) at end of session;
  graph-dependent work and evals need it.
- **Compute lane**: confirm local Ollama status; check the Kaggle weekly GPU
  quota at kaggle.com/settings (the CLI/API does **not** expose quota — web UI
  only); provide a Groq API key if wiring that path.
- **Two decisions**: (a) equilibrium reframe vs. significance chase for
  co-evolution; (b) MySQL CVE swap, yes/no.

## Key files
- `graphrange/victim_builder.py` — victim recipes (`_VERSION_MAP`),
  `resolve_victim_service()`. Recipes are validated via the production
  `container.exec_run(["sh","-c", cmd])` path, not isolated `docker run`.
- `graphrange/docker/supervisor/supervisor.py` — `spawn_scenario()`,
  `_VICTIM_VERSION_MAP` (a hand-synced duplicate of the recipes — keep the two
  in sync when either changes).
- `BACKLOG.md` — dated archaeology + open items (search `2026-08-13` for this
  session's entries).
- `CLAUDE.md` — project bible (6-layer plan, node/edge schema, model rules).

## Recommended first move in the fresh session
Start task 1 (Cyrus + Squid validation) — Docker-only, no GPU, and it unblocks
both the paper's co-evolution claim and the product's core promise. In parallel,
start Neo4j and check the Kaggle quota so the compute lane is ready for the
evaluation runs.
