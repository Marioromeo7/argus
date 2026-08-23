# ARGUS — Two-Week Closing Schedule

Started 2026-08-09. Goal: narrowing engine validated, GraphRange (topology through Scanner),
end-to-end product test — in 14 days. This is a tracking tool, not a vibes document — it gets
updated as things actually land, and it says so plainly when something's behind instead of
quietly sliding the dates.

Two standing rules that apply to every day below, learned the hard way on 2026-08-09/10:

1. **Any day with model-exposure/GPU work launches its long run at the end of working hours,
   not the start.** A run that lands overnight costs zero waking hours. A run that eats the
   afternoon costs the whole day.
2. **No full 8-node validation chain for every fix.** Narrow, well-understood fixes get a
   capped-round single-node smoke test (~15-30 min). Full chains are for real milestones only —
   not a default reflex.

---

## Pacing reality check (added 2026-08-10, called out by the user directly)

The day-labels below stopped tracking real elapsed time partway through. In one
continuous sitting on 2026-08-10, scope that was allocated across Days 4 through 11
(MITRE relationship ingestion, all of GraphRange Phase 1-7, and the entire 9-module
Scanner product plus its eval harness) got built back to back, with the day-index
still sitting at "Day 6-7" when that happened.

**Why it compressed**: both standing rules above are specifically about *GPU-hour*
budget — launch GPU work at day's end, don't reflexively re-run full chains. Nearly
everything built in that stretch was zero-GPU (Python logic, parsing, report
formatting) or small-GPU (the Apache version-pinning builds were CPU compiles, not
model calls). The pacing was designed to protect a resource that stretch mostly
wasn't spending, so it didn't slow anything down.

**Why that's not the same as "safely ahead of schedule"**: the original Day 8-11
allocation (4 days) for Scanner presumably assumed slower, more iterative building —
real time between sessions for problems to surface, for a second look with fresh
context. Moving this fast doesn't just risk missing GPU-live-testing issues (already
flagged everywhere below); it risks the kind of cross-cutting bug that per-file
testing doesn't catch on its own. The `SUPERVISOR_URL` hostname bug (Docker-internal
`gr-supervisor` vs the `localhost` that's actually reachable from this host — see the
live status log) is a real example: every individual file's own tests passed, and it
still took tracing a real cross-file interaction to find it. Compressed time means
fewer chances for that kind of thing to surface before it's load-bearing.

**What this means going forward**: treat everything below marked DONE as
"code-complete and verified wherever verification didn't need a GPU or a browser,"
not as "production-hardened by elapsed time." The day-labels are kept for historical
reference (what was originally scoped where) but are no longer a real pacing signal —
the honest current state is: two real checkpoints remain (a full live GPU run, and
genuine browser verification of the dashboard), and until those happen, nothing past
this point should be assumed more solid than "passed what could be tested without
them."

---

## Week 1 — Research close-out → GraphRange core

- **Day 1-3** (2 working days + 1 break) — Close the Narrowing Thesis validation. **DONE.**
  - [x] Found and fixed the 500-char truncation bug (97% of ATT&CK descriptions affected)
  - [x] Pinned `num_ctx=4096`, re-ingested all 697 techniques
  - [x] Smoke-tested the fix (T1055.011: 0.675 → 0.8125)
  - [x] Full 8-node v3 chain — landed, every node hand-audited, found 5 real bugs
  - [x] Fixed comma-dilution (spaCy+regex split), `_unanswered()` text-discarding, two
        citation-malformation shapes, term-dedup inflation
  - [x] Full 8-node v4 chain with those fixes — landed, hand-audited, found 3 more real
        bugs (T1113 false-negative, T1687 sibling-field/IaaS smuggling, one confirmed
        false rejection)
  - [x] Fixed T1113 (punctuation strip + plural tolerance + node-self-reference
        exclusion) and T1687 (sibling-field hard veto)
  - [x] Recalibrated against the 22-example labeled set — 54.5% measured accuracy, every
        remaining miss maps to the already-logged NLI-classifier/relevance-check gap,
        not a new bug
  - [x] Full 8-node v5 chain, first run with both newest fixes live — hand-audited every
        node again; retroactively confirmed the sibling-veto fix closes the exact false
        positive v4 had produced on `T1687`. No new bugs found. Labeled set now at 27
        examples.
  - **STATUS: fully closed out 2026-08-10, ahead of the original 2-day+1-break estimate
    once the parallel-track GraphRange work is factored in.**
- **Day 4** — MITRE relationship ingestion (groups/software/mitigations/detection-components
  from STIX data, already confirmed to exist and be unused). Not GPU-bound — scope it to
  "ingest and expose," not "also run a fresh full narrowing validation same day."
  **DONE 2026-08-10** — full run, 136s, zero GPU. Found and fixed a real bug along the
  way: the detection-coverage convenience method in the `mitreattack` library silently
  returns 0 for every technique because this STIX bundle uses a newer schema
  (`x-mitre-detection-strategy` objects) than the method was written for — worked around
  via the library's lower-level `get_related()`. Verified against BACKLOG.md's own
  pre-written prediction (T1021.005: 4 groups/7 software/4 mitigations, T1687: zero of
  all three) via direct Neo4j query — exact match both nodes.
- **Day 5** — GraphRange Phase 1: Docker topology (supervisor/red/blue/victim). Not GPU-bound.
  **DONE** — Docker Desktop verified working, full topology built and smoke-tested live.
- **Day 6-7** — GraphRange Phases 2-4ish: tool graph, scenario generator, red/blue execution
  wiring. This is model-exposed (agents calling Qwen/Mistral mid-scenario) — the highest-risk
  part of week 1 for repeating tonight's GPU-hour pattern. Apply rule 1 hard here.
  **DONE 2026-08-10** — Phase 2, Phase 3, Phase 4 (`execute_attack()`/`monitor()`/
  `assess_detection()`), and Phase 5 (`observer.py`) all built and live-tested. Real GPU
  cost for the whole Phase 4+5 build: two live test cycles, 119.5s + 157.3s — about 4.6
  minutes total, far under the 3-6 hour estimate given beforehand (that estimate assumed
  each cycle would include a `/think` planning call; it didn't need to, since
  `plan_attack()`/`plan_mitigation()` already existed from the original build and Phase
  4's own new pieces are mostly Docker exec + heuristics + one `/no_think` fast-mode
  call in `observer.py`). First live cycle found a real bug (tool install commands
  crawled verbatim from Kali's site include `sudo`, which doesn't exist in these
  containers, and lack `-y` for non-interactive apt) — fixed in `supervisor.py`, image
  rebuilt, second cycle succeeded mechanically end to end with zero orphaned containers
  after teardown. Found a real, deeper, NOT-yet-fixed gap: victim containers don't
  actually run the CVE's vulnerable service (`victim_builder.py` from the Phase 1 spec
  was never built), so every scenario's `success` will read False regardless of whether
  the attack logic was right — logged in `BACKLOG.md`, needed before Phase 4's results
  mean anything beyond "the wiring works."
  **Later same day**: `victim_builder.py` gap closed (real Apache version-pinning, 12
  versions), GraphRange Phase 6 (`graph_updater.py`) and Phase 7 (`run_scenario.py`)
  both built and zero-GPU-verified. **All of GraphRange Phase 0-7 is now code-complete.**
  `plan_attack()`'s live Phase 7 GPU run still hasn't happened — see the pacing note
  above and the live status log below for the full detail.

## Week 2 — Scanner + product test (more optimistic pass, same logic as week 1)

- **Day 8-11** (4 days) — Scanner build + repo intake/injection. `file_scanner.py` and
  `vuln_reasoner.py` are model-bound passes — same overnight-launch discipline as days 6-7.
  **DONE 2026-08-10, same continuous sitting as Day 6-7 above — see the pacing note.**
  All 9 Scanner modules (`repo_intake.py`, `telemetry.py`, `victim_builder.py`,
  `file_scanner.py`, `vuln_reasoner.py`, `scanner_red.py`, `scanner_blue.py`,
  `scanner_report.py`, `run_scanner.py`) plus the 5-module eval harness built and
  zero-GPU-verified against real data. Dashboard extensions (`/api/telemetry`,
  `/api/llm/navigate`, `LLMSearch.jsx`, `TelemetryPanel.jsx`, `GraphView.jsx`,
  `App.jsx`) built and build-verified (`npm run build`: 1065 modules, zero errors) but
  **not** browser-verified — no browser session available in this environment, stated
  plainly rather than implied tested. Every Qwen-calling function across all 9 modules
  plus the eval harness is written and syntax-verified but has never run live — full
  detail, including every real bug found and fixed along the way, in the live status
  log below.
- **Day 12-14** (3 days) — Test it like a user, end to end. **NOT STARTED.** Blocked on
  the two real checkpoints above (live GPU run, browser verification) — an end-to-end
  product test before either of those would just be testing the same untested paths
  again, not adding real signal.

---

## Explicitly not scheduled (stays in `BACKLOG.md` until its day arrives, if ever)

Anything not listed above doesn't get worked on as a side effect of being a good idea mid-task —
including ideas that come up *during* scheduled work. Add to `BACKLOG.md`, don't just start.

---

## Live status log

- **2026-08-09/10** — Day 1-3 in progress. v3 narrowing chain running (4/8 nodes landed as
  of this entry). Two real bugs found via manual audit, not assumed: comma-dilution
  (fabricated clause tails riding past the gate on true sentences — confirmed in both
  T1053.005 and T1205.002) and `_unanswered()` discarding attempted answer text on
  rejection (made T1560.001's `0.0` unauditable). Both logged, both fixes deferred until
  the chain finishes — cheap, non-GPU changes, not another long run.
- **2026-08-10** — Day 5 (GraphRange Phase 1: Docker topology) started and finished
  **in parallel** with the still-running narrowing chain, since Phase 1 needs zero GPU.
  Docker Desktop verified working (was never actually checked before — daemon wasn't
  running, confirmed via `docker run hello-world` after starting it). Full topology
  built and smoke-tested live: `gr-supervisor` spawns red/blue/victim containers on an
  isolated network, controls them via HTTP exec, confirmed real DNS resolution between
  containers, teardown genuinely removes all three. One real infra fix along the way
  (Kali's default apt mirror was unreachable, pinned to `kali.download`). Day 5 is
  done — ahead of where Day 1-3 finishing would have implied, because the two tracks
  don't actually block each other.

- **2026-08-10, continued** — v3 8-node narrowing chain finished completely (all 8
  landed, verified against actual file content, not just exit code). Every single node
  hand-audited against real source text, not sampled — found 5 distinct real bugs this
  way, not repeats: comma-dilution (fabricated clause tails riding on true sentences),
  `_unanswered()` discarding attempted answer text on rejection, two different shapes
  of malformed `EVIDENCE` citations breaking field lookup, and a relevance gap
  (a fully truthful, grounded answer that doesn't address the question it's attached
  to still counts as `trusted`). All four fixable ones fixed, unit- and
  regression-tested against the exact real broken sentences before being trusted — the
  fifth (relevance) logged in `BACKLOG.md`, not fixed, needs its own design decision.
  GraphRange Phase 2 (`tool_graph.py` + `tool_crawler.py`) written and verified against
  real live Kali pages (categories, install commands, listing structure all confirmed
  against the actual site, one real bug caught: nav links masquerading as tools).
  `crawl_kali()` itself not run at scale — queued as a decision, not executed
  unilaterally. Also queued: the full 8-node re-chain with all fixes active (~6hrs),
  and whether to start GraphRange Phase 3. A single-node capped-round smoke test
  (already-agreed, low-cost next step) is running now to validate the fixes live
  before any of those bigger decisions get made.

- **2026-08-10, continued** — GraphRange Phase 3 (scenario generator) built and
  tested against the live graph: found and fixed a real bug (`expected_observables`
  is a top-level Neo4j property, not nested under `properties` — the Cypher was
  reading the wrong shape). Recalibration done against the 22-example labeled set:
  measured accuracy 54.5%, and — checked, not assumed — every one of the 10 misses
  maps cleanly onto an already-logged NLI-classifier or relevance-check gap; no
  unexplained residue, no threshold-sweep opportunity (failures are categorical, not
  borderline). `crawl_kali()` at full scale then hit a deterministic hang, twice, at
  the identical point (117/418 tools written both times, confirmed via exact log-line
  match). Root-caused properly, not guessed around: isolated the exact next tool
  (`gnuradio`) and fetched its page standalone first — page itself was fine (0.8s,
  200 OK, 89KB), ruling out a network/page-size cause. Inspecting the page's actual
  structure found the real cause — zero Kali category tags on this page, and 25
  installable packages, so the existing per-package fallback logic fired the LLM
  fallback independently 25 times in a row for one tool page, each call able to take
  up to several minutes on this hardware — not a hang, unbounded sequential fanout.
  This was also a real modeling bug independent of performance: those 25 "packages"
  (`gnuradio-dev`, `gnuradio-doc`, `libgnuradio-analog3.10.12`, ...) are build
  artifacts of one tool, not 25 distinct tools, so they should never have been
  classified independently. Fixed by resolving the fallback capability once per page
  and sharing it across all packages on that page. Verified live before relaunching:
  1 LLM call (not 25), 246.5s, all 25 packages assigned the same capability
  (`traffic_capture` — a reasonable fit for GNU Radio/SDR). `write_tool_node()`
  confirmed idempotent (`MERGE` on `node_id`), so the full crawl was relaunched from
  scratch rather than needing a resume mechanism — safe to re-touch the 117 already-
  written nodes. Full crawl relaunched, failed once immediately (`ModuleNotFoundError:
  neo4j` — used the base conda env instead of `argus`), relaunched correctly and ran
  to completion: 418 tools found, 679 packages written, 28 LLM fallback calls, 0
  failed requests, ~25 min wall time. Verified against real Neo4j, not the exit code:
  679 tool nodes present, count matches exactly. One small residual gap found and
  logged (not fixed): 2/679 packages (`chirp`, `shell-gpt`) got `capability="none"`
  — genuinely off-taxonomy tools the fallback prompt has no valid category for, not a
  parsing bug. GraphRange Phase 2 is now fully done, not partial. Zero-GPU tier is
  now completely clear — next up per the zero→small→full ordering is the small-GPU
  smoke test of the T1113 false-negative + T1687 sibling-veto fixes on a real node.

- **2026-08-10, continued** — SMALL-GPU tier: ran a genuinely live single-round
  smoke test on `T1113` (real asker `/think` call, 63.8s, then real answerer call,
  26.8s) to confirm the full pipeline runs clean end to end with every fix active —
  it did, no crashes, and `attempted_answer` came back correctly populated (the
  earlier `_unanswered()` fix holding up live, not just in regression tests). The
  live asker asked a different question than the original bug case, though, so it
  didn't exercise the specific code paths the T1113/T1687 fixes changed — a model
  re-asking its own historical mistake on demand isn't a thing that can be forced,
  so that's not the right way to test a deterministic logic fix anyway. Instead ran
  the exact original failing clauses through `_clause_supported()` against the real,
  current Neo4j node data (not hand-typed excerpts — flagged earlier this session as
  a real methodology mistake, avoided here on purpose). Both confirmed correct live:
  T1113's `"Screen Capture in T1113 includes taking single screenshots."` now
  returns `supported=True` (was a false rejection before), and T1687's IaaS clause
  now returns `supported=False` (sibling-field hard veto fires correctly against the
  live `platforms=['IaaS','Linux','macOS','SaaS','Windows']` field). Small-GPU tier
  done. Per the user's explicit zero→small→full ordering, moving to the full-run
  tier next: a fifth complete 8-node chain with every fix active, launched to run in
  the background per the standing GPU-bound-work rule.

- **2026-08-10, continued** — FULL-RUN tier: v5 8-node chain finished (all 8, real
  elapsed times 18.6-66.1min/node, none crashed). This is the first real run with
  both the T1113 false-negative fix and T1687 sibling-veto fix simultaneously live —
  v4 predates both (they were found auditing v4's own output, then fixed after).
  Three nodes came back with near-zero trust (`T1560.001` 0/7, `T1687` 1/15,
  `T1113` 0/11), which on a first glance looks like a regression from the new fixes.
  Did not report those numbers without checking, per this session's own standing
  rule — hand-audited 8 real rejected clauses across all three nodes against the
  actual live source text before drawing any conclusion. Every one held up as a
  genuinely correct rejection, not a false negative: T1560.001's claim that certutil
  use "falls under the encryption aspect" is flatly wrong (source says certutil
  Base64-*encodes* data, not encrypts it — the model conflated encoding with
  encryption and the verifier caught it correctly); T1113's "platform-specific APIs"
  framing adds structure (per-tool platform attribution) the actual 3-sentence
  description never states, even though the underlying real-world fact is true;
  T1687's rejected claims (SIEM, hybrid environments, containers, "non-security
  tool" framing) each reference something genuinely absent from the real
  description text, and its one IaaS-sourced claim correctly hit the sibling veto.
  The low trust counts reflect the asker generating a cluster of speculative
  "can this apply to X environment" questions that these particular (fairly terse)
  MITRE descriptions just don't support — not the verifier misbehaving. No bug
  found; both fixes hold up under a real full-chain run, not just the earlier
  isolated live-data check.

  Aggregate trust rate: v4 29/80 (36.2%) vs v5 20/77 (26.0%) — a drop that looks
  like a regression at a glance. Did not report it without checking. Per-node
  diff showed `T1687` alone accounted for most of it (v4 6/11 trusted -> v5
  1/15). Pulled v4's actual 6 "trusted" T1687 claims and checked each against
  this session's own labeled audit log (`narrowing_gate_labeled_audit.jsonl`):
  at least 3 of the 6 are EXACT matches to bugs that same audit already found —
  claim #2 is verbatim the IaaS-smuggled-from-`platforms` clause the sibling-veto
  fix targets (confirmed: this exact clause now returns `supported=False` with
  the fix live, matching the earlier isolated check), claim #3 matches the logged
  `unsupported_recategorization` bug (invented tools-vs-infrastructure framing),
  claim #5 matches the logged `coincidental_term_overlap` bug (`zero-day` only
  appears in a citation title, not as a substantive claim). So v4's 36.2% was
  never the correct number — it was already inflated by false positives this
  session's own audit had independently found. v5's 26.0% is the more honest
  figure: one of those three holes is now mechanically closed by the sibling
  veto; the other two are the already-known, already-deferred NLI-classifier
  gap (unfixed by design this cycle). The rest of the node-to-node swing (e.g.
  `T1053.005` v4 6/12->v5 5/7, `T1047` v4 4/14->v5 4/8) is asker-question
  non-determinism, not a fix side-effect — v4 and v5 never asked the same
  question set per node, so raw aggregate comparison across runs was always
  going to be noisy; the per-clause hand-audit is the reliable signal, not the
  topline percentage. Zero→small→full ordering is now complete, both fixes
  independently verified correct via three separate methods (isolated live-data
  check, full live-chain hand-audit of new rejections, and retroactive check of
  the exact v4 false positive the fix was built to close).

- **2026-08-10, continued** — `victim_builder.py` gap investigated properly
  before fixing, not assumed. User asked specifically about a SunOS substitute;
  checked real graph data first: only 4/73 vulnerability nodes reference Sun at
  all, 3 true OS-level SunOS. Real finding was bigger than the question asked:
  21/73 nodes are OS-only CPEs across a whole family of kernel-incompatible
  historic OSes (FreeBSD, Windows, Cisco IOS, IRIX, SunOS, AIX, HP-UX, BSD
  variants, SCO, Convex, Cray) — none of these can run under Docker on a Linux
  host, full stop, not an image-availability problem. Corrected an overstatement
  made along the way: "Docker can't run a different kernel" does NOT mean "these
  vulnerabilities are gone" — the software is exactly as vulnerable as it ever
  was, it just needs a VM, not a container. Broke the 21 down by real
  feasibility (FreeBSD/Windows/NetBSD high, SunOS/Cisco-IOS medium via real
  emulation ecosystems, AIX/HP-UX/BSD-OS/SCO low, Convex/Cray/SPP-UX very low —
  no realistic path, hardware doesn't exist anymore). User chose Docker-only now,
  VM support as its own deferred item — logged in `BACKLOG.md`, not built.

  Of the remaining 52 application-level nodes, checked real fit for the
  network-attack execution model before building anything: 3 Windows-only (same
  kernel wall), 7 client-side software (browsers, PowerPoint — no listening
  service for a network tool to reach at all, a different execution model,
  logged separately, not addressed). 39 real Linux server-daemon candidates.
  Built `graphrange/victim_builder.py` mapping the ones with a real apt package
  — each verified against a live `debian:12-slim` image before being added, not
  guessed: Apache, MySQL/MariaDB, Squid, Cyrus IMAP, PHP+Apache. Live-verified
  end to end: spawned a real Apache scenario, nmap-scanned the victim from red
  over the actual network, got back `80/tcp open http` — the structural bug is
  closed, victims now run something real.

  Found and fixed three more real bugs while wiring this in, each via an actual
  live failure, not review: (1) the image-pull fallback caught the wrong
  exception class (`ImageNotFound` instead of the broader `NotFound` that
  `.pull()` actually raises for a nonexistent remote tag), so it silently never
  fired and crashed the whole request with a 500 — hit this immediately on the
  first real Apache CVE tested (`httpd:1.3.1` doesn't exist as an image); (2)
  `spawn_scenario()` was unconditionally overriding every victim's command with
  `sleep infinity`, which would have silently defeated even a correctly-resolved
  purpose-built image's own default service — now scoped to only generic base
  images; (3) `spawn_scenario()` wasn't atomic — the exception-class bug above
  crashed a request after red+blue containers already existed, orphaning them
  with no way for the caller to clean up (found a real orphaned pair, cleaned up
  by hand) — fixed with an all-or-nothing try/except around the whole spawn.

  One known, explicitly-not-fixed fidelity gap remains, logged separately:
  installing "apache2" via today's apt repo installs today's Apache, already
  patched against a 20+-year-old CVE — proper fidelity needs version-pinned
  installs (e.g. via `snapshot.debian.org`), not built this cycle.

- **2026-08-10, continued** — Fixed the version-pinning gap for one real case,
  per explicit direction to build it as an exception table rather than a
  general mechanism. Checked real archive availability first, not assumed:
  archive.apache.org has every historic Apache release as a source tarball,
  confirmed for the exact 11 versions our CVE nodes need. Tried actually
  compiling `apache_1.3.1` (1998) on a live `debian:12-slim` container and hit
  three completely unrelated real failures in about 15 minutes: the ancient
  `Configure` script assumes bash but Debian's default `/bin/sh` is dash now;
  `_sys_siglist` was removed from glibc entirely; Apache's own internal
  `getline()` helper collides with glibc's own `getline()` across several
  files. Patched all three (rename, `strsignal()` swap, function rename +
  call-site updates), then hit three more purely-config gaps getting it to
  actually start (missing `ServerRoot`-relative directories/files the default
  config expects, a legacy `Group #-1` default modern `initgroups()` rejects) —
  fixed those too. End state: `curl -sI` returns `Server: Apache/1.3.1 (Unix)`,
  the real historic version, genuinely serving.

  Encoded the validated recipe as `_VICTIM_VERSION_MAP`/`_VERSION_MAP`, an
  exact `(vendor, product, version)` lookup checked before the existing
  generic latest-apt table — the architecture the user explicitly asked for
  ("let the workflow determine whether this version uses this or that, like
  an exception") rather than a general source-compiler. This is the right
  shape because the three build failures and three config failures found for
  this ONE version don't generalize — a different old CVE's source would hit
  a different, unpredictable set of era-specific breakages, so a per-version
  validated-recipe table is realistic where a general auto-patcher isn't.

  Verified twice: isolated `docker run` testing to find and validate the
  recipe itself, then a full run through the real live supervisor HTTP API
  (145.3s spawn) to confirm it works through the actual system, not just in
  isolation — and on the real fallback base image (`ubuntu:22.04`, since
  `httpd:1.3.1` isn't a pullable tag), which differs from the `debian:12-slim`
  image the recipe was validated against. The base-image difference didn't
  matter; same recipe worked cleanly there too. Clean teardown confirmed, no
  orphaned containers.

  Found one more real bug while wiring this in, not specific to this recipe:
  `deliver_tool()`, `collect_output()`, and the victim install/start calls in
  `spawn_scenario()` all built exec commands as `f"sh -c '{command}'"` — any
  single quote inside the command (every `sed -i 's/.../.../'` in the new
  recipe has several) would silently terminate that string early and corrupt
  the command. Fixed at all four call sites by switching to list-form
  `exec_run(["sh", "-c", command])`, which passes the command as one argv
  element with no extra shell-quoting layer to break. A real latent fragility
  in code that predates today, just never triggered until a command with
  embedded quotes existed.

  Scope, stated honestly rather than implied complete: only ONE version
  (`apache:http_server:1.3.1`) has a cataloged recipe. The other ~10 Apache
  versions our graph needs and the other four mapped software families
  (MySQL, Squid, Cyrus IMAP, PHP) still fall back to latest-apt until someone
  does this same real, non-trivial, per-version validation work for them —
  logged in `BACKLOG.md` as ongoing, not a quick follow-up.

- **2026-08-10, continued** — extended from one Apache version to the whole
  1.3.x branch, working autonomously while the user stepped away. Checked
  archive availability for all remaining versions first: `1.3.5`/`1.3.7`/
  `1.3.8`/`1.3.18` have no tarball at all on Apache's own archive — never
  actually released despite NVD listing them, a permanent gap, not a bigger
  patching job. The other 10 have real tarballs; batch-testing the 1.3.1
  recipe against them found it did NOT fully generalize — `1.3.6` onward hit
  a different real failure, a linker "multiple definition" error. First
  guess (`-fcommon`) was tested directly and only partially worked, so it
  was wrong, not applied blindly — traced the real cause to GCC ≥5's inline
  semantics default breaking Apache's own `INLINE` macro, fixed with
  `-fgnu89-inline`. Also found that passing compiler flags via `CC=` doesn't
  propagate through this build system's nested sub-makes reliably (real,
  confirmed quirk) — worked around with a `gcc` wrapper on `PATH` instead.
  Found one more real per-version config difference testing `1.3.17`
  (different `mime.types` path, a `@@ServerRoot@@` placeholder `1.3.1`
  doesn't have) and handled both defensively rather than branching per
  version. Consolidated all 11 versions into one parameterized template.
  Verified live through the real supervisor API on `1.3.9` (previously only
  compile-tested) — real `Server: Apache/1.3.9 (Unix)`, clean teardown, no
  orphans. Full detail and reasoning trail in `BACKLOG.md`.

  Remaining, unchanged in kind: `apache:http_server:2.0.52` (different major
  version, new internals, probably a fresh discovery) and MySQL/Squid/Cyrus
  IMAP/PHP (no recipe at all yet). Making a bounded attempt at 2.0.52 next;
  if it turns into its own multi-issue investigation rather than resolving
  quickly, deferring it and moving to Phase 6 (graph updater, zero-GPU,
  well-specified) instead of open-ended grinding.

- **2026-08-10, continued** — 2.0.52's bounded attempt paid off fast: built
  cleanly with zero source patches and a standard `make install`, unlike the
  whole 1.3.x branch. 2.0.x bundles its own APR library specifically for
  cross-toolchain portability, which is exactly what 1.3.x's old build
  system lacked. Verified live through the real supervisor API:
  `Server: Apache/2.0.52 (Unix)`, clean teardown, no orphans. **Apache is
  now fully done** — 12 validated versions total, every real tarball our
  graph references now covered. Stopping the version-pinning thread here on
  purpose: Apache being completely closed out is a clean unit of work,
  MySQL/Squid/Cyrus IMAP/PHP are each their own open-ended discovery with no
  guaranteed quick win, and Phase 6 is better-specified, zero-GPU, and moves
  the actual roadmap forward rather than continuing to fill in fidelity gaps
  indefinitely. Moving to Phase 6 (graph updater) now.

- **2026-08-10, continued** — GraphRange Phase 6 (`graphrange/graph_updater.py`)
  built to spec and verified against real live graph data (technique T1113),
  not synthetic. All 5 functions confirmed real, not just written:
  `write_scenario_run`/`write_outcome` write real `ScenarioRun`/`Outcome`
  nodes and all three spec edge types; `update_technique_confidence`
  produced real observed +0.05/-0.02 deltas, correctly capped/floored;
  `check_and_flag_conflict` genuinely detected a real conflicting outcome,
  wrote the `conflicts_with` edge, added the exact spec-worded
  open_question, and reduced confidence by 0.1; `decay_stale_nodes`
  applied the exact `*0.95` multiplier after a real backdated node. Test
  data and the technique's baseline state cleaned up afterward. Moving to
  Phase 7 (`run_scenario.py` orchestration) next — writing the code now,
  but live end-to-end testing calls `plan_attack()`/`plan_mitigation()`
  (real `/think` GPU calls), so that's the checkpoint to report back at
  before running it live, same as Phase 4 was.

- **2026-08-10, continued** — Phase 7 code written and wired to spec:
  `run_one()` (write ScenarioRun, start blue monitor thread, red
  plan_attack->execute_attack, stop monitor, assess detection, write
  outcome, update confidence, check conflicts, update ScenarioRun status,
  mark scenario complete) and `run_batch()`. Imports/syntax verified clean,
  no live execution yet — holding at the GPU checkpoint as planned, since
  `plan_attack()` makes a real `/think` call. All of GraphRange Phase 0-7 is
  now code-complete; only Phase 7's live end-to-end run remains, and that's
  the natural check-in point for when the user returns. Moving to
  zero-GPU Scanner work in the meantime rather than sitting idle.

- **2026-08-10, continued** — user stepped away ("get to work, imma hit the
  gym and come check"), continued autonomously through Scanner's Day 8-11
  scope. Four modules built and verified this stretch, each hand-audited
  against real data, not assumed correct from writing to spec:

  **`repo_intake.py`** (repo intake & safety layer) — 9 real test cases, all
  passing: real local-repo staging, a genuinely oversized file correctly
  flagged (not deleted) with the skip list written correctly, a genuinely
  executable script correctly stripped of its execute bit, `read_file_safe()`
  correctly XML-wrapping content and correctly returning `None` for skipped
  files, a nonexistent path and two non-github.com URLs (including the
  github.io lookalike specifically) all correctly rejected, and a real live
  `git clone` of a real public repo (`octocat/Hello-World`) succeeding end
  to end. `STAGING_ROOT` deliberately uses `tempfile.gettempdir()` instead
  of the spec's hardcoded `/tmp/...` — this step runs natively on Windows
  here, not in a container.

  **`telemetry.py`** — `tiktoken` wasn't installed, added to
  `requirements.txt`. Verified live: real token counts, real elapsed-time/
  CPU/RAM sampling around a real timed block, `patch_last_tokens_out()`
  correctly updating both memory and the on-disk `.jsonl` line. Test entry
  cleared from the log afterward, since it wasn't real telemetry.

  **`victim_builder.py`** (Scanner's own — distinct from GraphRange's
  CPE-based one) — every zero-GPU path verified against real data: manifest
  scanning found real `package.json`/`requirements.txt` content correctly,
  compose validation correctly passed a safe file and correctly rejected
  both a real `privileged: true` file and a disallowed-registry image, and
  a full real `docker compose up` → topology parse → real teardown cycle on
  a real 2-service compose file, confirmed zero orphaned containers after.
  Found and fixed a real bug in `_infer_role()`: port 8080 is listed under
  both `web_frontend` and `api_backend` in spec (a genuine overlap), and
  checking ports before names meant a clearly-named `api-server` service
  misclassified as `web_frontend` — fixed by checking name keywords first.

  **`file_scanner.py`** + **`vuln_reasoner.py`** — almost entirely
  Qwen-dependent per spec, so factored out the one genuinely zero-GPU piece
  (`_chunk_content()`, boundary-aware + raw-fallback chunking) and verified
  it against real generated content: a 10,000-token file correctly split
  into 2 chunks with all content preserved, a 100,000-token blob with zero
  blank lines correctly forced the raw-slicing fallback into 7 overlapping
  chunks, `merge_chunks()` correctly passed through and correctly
  short-circuited single-chunk groups without invoking the Qwen-dependent
  merge call.

  **Growing GPU-checkpoint list, stated plainly rather than left implicit**:
  `plan_attack()`/`plan_mitigation()` (Phase 7), `_infer_compose_from_manifests()`
  (victim_builder.py), `_scan_file()`/`_merge_call()` (file_scanner.py), and
  `_reason_block()` (vuln_reasoner.py) are all real, written, syntax-verified
  code that has NOT been run live yet — every one is a real `/think` or
  `/no_think` Ollama call, and per the standing rule from earlier in this
  session, those get run only after checking in, not automatically. Nothing
  in this list has been silently skipped; it's accumulating on purpose,
  waiting for one deliberate GPU-committed session rather than many small
  ad-hoc ones.

- **2026-08-10, continued** — finished the rest of Day 8-11's Scanner scope:
  `scanner_red.py`/`scanner_blue.py` (synthesized 3-4 layered spec revisions
  each into one final implementation — topology-aware attack planning,
  capability-cache tool requests, execution-primary/Qwen-secondary dual
  assessment for red; multi-container per-service monitoring and
  `missed_lateral` detection for blue), `scanner_report.py` (MD/PDF/HTML,
  fully verified with realistic synthetic finding data since report
  generation itself is 100% zero-GPU formatting), and `run_scanner.py` (the
  final pipeline orchestrator).

  **Real, meaningful bug found while building `run_scanner.py`**:
  `SUPERVISOR_URL = "http://gr-supervisor:8000"` — the spec's literal value,
  copied into `run_scenario.py` (Phase 7) and `scanner_red.py`'s default too
  without questioning it — is the Docker-internal hostname, which only
  resolves from inside a container on the `graphrange-public` network.
  Confirmed live it fails DNS resolution entirely from the host, which is
  where every actual Python execution in this project runs (every real
  Phase 4 test this session connected via `localhost` successfully). This
  would have silently broken every live orchestration run across BOTH
  GraphRange and Scanner: the health check would report the sandbox
  unavailable even though the supervisor genuinely was running and
  reachable, degrading every scenario to static-analysis-only for a
  completely wrong reason — not a loud crash, a silent wrong-mode
  degradation, the worst kind to catch after the fact. Fixed in all three
  locations, confirmed live (`_check_range_health()` correctly flips from
  `False` to `True` against the actually-running `gr-supervisor` container
  once the fix is in).

  All of GraphRange Phase 0-7 and 6 of 9 Scanner modules are now
  code-complete and zero-GPU-verified where verification is possible.
  Remaining Scanner scope: dashboard extensions, the eval harness, and the
  full live GPU run of everything — all still waiting at the same
  checkpoint, unchanged.

- **2026-08-10, continued** — dashboard extensions built: `/api/telemetry` +
  `/api/llm/navigate` in `main.py`, `LLMSearch.jsx` + `TelemetryPanel.jsx`
  (new), `GraphView.jsx` (`forwardRef`/`navigateTo`) and `App.jsx` (wiring
  everything together) both matched precisely against the real existing
  component structure, not written blind from spec. `/api/telemetry`
  verified live — started the real FastAPI app, wrote real telemetry data,
  confirmed the summary math, cleaned up after. Ran a real `npm install` +
  `npm run build`: 1065 modules transformed, zero errors, confirming every
  import resolves and all four files are syntactically valid. Stated plainly
  rather than glossed over: there's no browser session in this environment,
  so none of this was verified at runtime — a clean build proves the code
  compiles, not that the feature works. That's a real gap against this
  project's own UI-testing standard, left open on purpose rather than
  claimed done. Also added `node_modules/` to `.gitignore` (a real one now
  exists from the verification install, wasn't excluded before).

  Only the eval harness (`eval/`, WebGoat-based) and the full live GPU run
  remain of the original Scanner scope.

- **2026-08-10, continued** — eval harness built: `ground_truth.py`,
  `comparator.py`, `false_positive_analyzer.py`, `defense_plan.py`,
  `run_eval.py`. Checked the real WebGoat repo live before writing
  `ground_truth.py`, not assumed: both spec-defined ground-truth sources
  (GitHub Security Advisories API, `SECURITY.md`) are genuinely empty for
  WebGoat specifically. Makes sense once you consider what WebGoat actually
  is — an intentionally vulnerable teaching app whose vulnerabilities are
  deliberate lesson content, not CVE-tracked disclosures against the
  project itself. Handled honestly: an empty ground truth writes a real
  file explaining why, so a 0% coverage result later doesn't read as a
  scanner failure. Found and fixed two more real bugs verified live: a
  markdown-table rendering bug in `comparator.py` (auto-derived column-to-
  key mapping silently rendered an empty CVE column), and a misleading
  message in `false_positive_analyzer.py` (a real graph node with
  grain_confidence 0.4 was reported as "not yet cross-checked" when it
  genuinely had been checked, just scored below the 0.5 bar) — both
  confirmed against real data before and after the fix, not assumed fixed.

  **This closes out all 9 Scanner modules plus the eval harness.** Every
  zero-GPU path across the entire Scanner + eval + GraphRange Phase 0-7
  stack has been built and verified against real data where verification
  was possible. What's left, unchanged: the full live GPU run (every
  flagged Qwen call across `run_scenario.py`, `victim_builder.py`,
  `file_scanner.py`, `vuln_reasoner.py`, `scanner_red.py`, `scanner_blue.py`,
  `comparator.py`, and `/api/llm/navigate`), genuine browser verification of
  the dashboard UI changes, and Days 12-14's end-to-end product test. All
  waiting at the same GPU/browser checkpoints, stated plainly rather than
  implied complete.

- **2026-08-12 — the GPU checkpoint closed.** Built dashboard search
  (`LLMSearch.jsx`/`/api/llm/navigate`) and a new conversational feature
  (`GraphChat.jsx`/`POST /api/chat`, user-requested) fully browser-verified
  through real back-and-forth with the user — found and fixed real bugs
  along the way none of the zero-GPU verification could have caught: a
  frontend field-name mismatch (`node.node_id` vs the API's real `id`) that
  silently no-op'd every successful search, a too-tight Ollama timeout, an
  unreliable text-marker grounding convention replaced with Ollama's
  `format: "json"` (a user-suggested fix), un-ranked candidate matching, and
  a graceful fallback for nodes outside the dashboard's 800-node render cap.

  **Then: Kaggle P100 GPU acceleration**, at the user's request, to make the
  long-deferred full GPU run actually tractable this week. Not a permanent
  dependency -- explicitly for faster dev/test iteration, with local runs
  still the source of truth for any latency number that goes in the paper.
  Built via `kaggle` CLI (kernel push/pull/status/output all worked,
  including live-output polling on a running kernel -- a real, useful
  capability the docs don't make obvious). Real problems hit and fixed, in
  order: Ollama's installer needs `zstd`, not in Kaggle's base image;
  piping `cloudflared`'s stdout into a live Python readline loop hung
  silently (Go binaries block-buffer non-TTY stdout -- fixed via `stdbuf
  -oL` to a polled file instead); `OLLAMA_ORIGINS=*` does NOT bypass
  Ollama's own Host-header rejection of non-localhost requests (that's a
  CORS-only setting, a different mechanism) -- fixed with a local nginx
  reverse proxy rewriting the Host header before forwarding to Ollama, with
  the tunnel pointed at the proxy instead of Ollama directly. Verified
  externally (not just self-reported): real model list, real inference
  call (37 tok/sec vs this hardware's ~8, confirming genuine GPU
  acceleration), then wired end-to-end through the real dashboard
  (`config.py`, a new shared module, replaced hardcoded
  `http://localhost:11434` across 13 files).

  **One more real bug found wiring the agent files back in**: `agents/red.py`,
  `blue.py`, `challenger.py`, `memory/reflexion.py` call the `ollama` Python
  package directly, which reads its own `OLLAMA_HOST` env var -- already
  set as a persistent Windows system env var (`0.0.0.0:11434`, likely by
  the native Ollama installer), which `load_dotenv()` never overrides by
  default. Forcing it in `config.py` wasn't enough on its own either: the
  `ollama` package reads `OLLAMA_HOST` once at `import ollama` time to
  build its default client, so `config` has to be imported *before*
  `ollama` in every one of those four files, not just imported somewhere.
  Confirmed via the exact failure (`WinError 10049`, since `0.0.0.0` isn't
  even a valid address to connect *to*, only to bind) before and the fix
  after.

  **With that fixed, ran the entire standing GPU-checkpoint list for real,
  live, for the first time this whole project**: `eval/chat_grounding_eval.py`
  (Precision 0.80, Recall 1.00, one real false positive documented), Scanner's
  `vuln_reasoner.py` (correctly diagnosed a real SQL injection snippet),
  `scanner_red.py`/`scanner_blue.py` (`analyze()` in `sandbox=False` mode --
  real Neo4j lookups, real Qwen reasoning, no Docker needed for this scope),
  `victim_builder.py`'s `_infer_compose_from_manifests()` (produced a
  genuinely correct Flask+Postgres+Redis compose file from bare manifest
  content), `eval/comparator.py`'s summary call, and finally `agents/red.py`'s
  `plan_attack()` -- the original, longest-standing gap in this entire
  project, now confirmed live: real attack-surface query, real `/think`-mode
  reasoning that correctly used past-lesson memory from
  `memory/reflexion.py`, a real engagement node written to Neo4j.

  **Still open, correctly out of this scope**: the heavier execution-path
  functions that need live Docker containers via `gr-supervisor`
  (`_execute_attack_plan`, `_request_tool_for_phase`, `execute_attack`), and
  the full-scale run (complete WebGoat scan, multiple GraphRange scenarios)
  -- both are Day 12-14's actual end-to-end product test, not this
  checkpoint's job.
