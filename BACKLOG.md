# ARGUS Backlog

Work that is intentionally **out of scope for v0** (the six-layer local research prototype).
This file is the required home for any feature not in the original layer plan — per the project
rulebook, nothing outside the six layers gets built without being written here first.

## Evaluation & Research Rigor

- [ ] Replace term-overlap clause verification with a small local NLI (natural
      language inference) classifier (~100-400M params, e.g. a DeBERTa
      entailment model — not another Ollama LLM call, this runs on CPU/light
      GPU and doesn't compete with the narrowing engine's GPU budget). This is
      the actual field standard for groundedness checking (what Ragas/TruLens/
      DeepEval do under the hood, and the verification half of the FActScore
      atomic-decomposition pattern our per-clause design already follows) —
      term-overlap is a known-weaker proxy, kept for now because it's free and
      the dilution-specific failure mode is fixed (see THESIS.md). Before
      building: measure the current gate's precision against
      `results/narrowing_gate_labeled_audit.jsonl` (15 hand-labeled examples
      from manual audits 2026-08-09/10, grown from the original 11 as more
      nodes were audited). Grow that labeled set as more nodes get audited;
      it's the actual standard to hold any verifier to, not just this one.

- [ ] Add a relevance/answering check, separate from the groundedness check.
      Found via manual audit of T1055.011 (2026-08-09/10): a fully truthful,
      source-grounded answer can still be counted as `trusted` even when it
      doesn't address the question it's attached to — e.g. a question asked
      about privilege escalation got an answer that only restated an
      unrelated DEP-bypass fact, verbatim-correct but non-responsive, while
      the source explicitly discussed privilege escalation elsewhere and was
      never cited. The pipeline verifies "is this text true," never "does
      this text answer what was asked" — those are different checks, and only
      one exists today. Likely the same NLI-classifier or a lightweight
      question-answer relevance scorer could cover both; worth deciding
      together, not as two separate builds.

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
- [x] Ingest currently-unused MITRE STIX relationship data as new node types + edges:
      groups/software using each technique (real-world procedure examples with citations),
      mitigations, and detection coverage. Done 2026-08-10, `graph/ingestion/attack.py`
      extended (append-only — existing technique/tactic ingestion untouched). New node
      types: `group` (174), `software` (821), `mitigation` (44), `detection_component`
      (106, reference content), `detection_strategy` (697). New edge relation_types:
      `uses` (group/software -> technique, 4826+11211 edges), `mitigates` (mitigation ->
      technique, 1448 edges), `detects` (detection_strategy -> technique, 697 edges) —
      each edge carries the real STIX relationship's own procedure-example description
      (with citations) as `context_conditions`, not a flat label. Full run: 136s, zero GPU.
      Verified against this note's own pre-written prediction: T1021.005 shows exactly
      4 groups / 7 software / 4 mitigations, T1687 shows exactly zero of all three —
      both confirmed via direct Neo4j query after ingestion, not assumed.

      Real bug found and fixed along the way: `mitreattack`'s own
      `get_datacomponents_detecting_technique()` convenience method silently returned 0
      for every technique, including well-documented ones like T1055. Traced to a schema
      version mismatch, not missing data — this STIX bundle uses MITRE's newer
      `x-mitre-detection-strategy` object type (699 objects) for detection coverage,
      superseding the older data-component-detects-technique model the library method
      still assumes. Confirmed via raw JSON inspection: 697 real `detects` relationships
      exist, 100% with `x-mitre-detection-strategy` as source, 0% with
      `x-mitre-data-component` — so the library wasn't wrong that data-components don't
      detect anything anymore in this schema, it just never got updated to look at the
      new object type. Worked around using the library's lower-level `get_related()`
      instead of the stale convenience method. `detection_component` nodes are still
      ingested as reference content (they're real, current ATT&CK taxonomy) but
      deliberately not wired to techniques with a synthetic edge that doesn't reflect
      the real STIX relationships. See THESIS.md narrowing-engine notes (2026-08-09/10
      truncation-fix + Type 1/2/3 question taxonomy discussion) for the original
      reasoning trail this item came from.

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
- [x] Phase 1: Docker topology — supervisor, red, blue, victim containers;
      extended `docker-compose.yml` with a `graphrange` profile. Built and
      smoke-tested end to end 2026-08-10: `gr-supervisor` (Flask + Docker SDK)
      spawns red/blue/victim on an isolated `graphrange-public` network,
      controls them via `/exec`, confirmed real DNS resolution between
      containers, and `/teardown` genuinely removes all three (verified via
      `docker ps -a`, not just a returned status). One real fix needed along
      the way: the Kali base image's default apt mirror (`mirror1.sox.rs`)
      was unreachable from this network — pinned `graphrange/docker/red/
      Dockerfile` to `kali.download` explicitly rather than the round-robin
      default. Docker Desktop itself was also unverified before today —
      confirmed working (`docker run hello-world`) after starting it, daemon
      was simply never running.
- [x] Phase 2: Tool graph (`graphrange/tool_graph.py`) + crawler
      (`graphrange/crawler/tool_crawler.py`) — verified against real live Kali
      pages before writing selectors, category map expanded after sampling
      showed 82% would hit the LLM fallback with the original narrow map
      (0% on the same sample after expanding to real ATT&CK tactic names).
      Full 418-tool crawl completed and verified 2026-08-10: 679 real tool
      nodes in Neo4j (count matches `packages_written` exactly, confirmed via
      direct query, not exit code), 28 LLM fallback calls, 0 failed requests.
      Hit and fixed a real bug along the way: `gnuradio`'s page carries zero
      Kali category tags and lists 25 packages (build artifacts of one tool,
      e.g. `gnuradio-dev`/`libgnuradio-analog3.10.12`), and the original
      per-package fallback logic called the LLM independently for all 25 —
      not a hang, but unbounded sequential fanout (confirmed via CPU-delta
      check: 0% sustained, consistent with blocking on the Ollama request,
      not a loop). Fixed by resolving the fallback capability once per page
      and sharing it across all packages on that page — also the correct
      data model, since packages on one page aren't independent tools.
      Known small gap, not fixed: 2/679 packages (`chirp`, `shell-gpt`)
      landed `capability="none"` — the LLM's answer was syntactically valid
      JSON but named a category outside the 8-item taxonomy, which the
      fallback's parse-failure-only default doesn't catch. Both are
      genuinely off-taxonomy tools (ham radio software, an AI CLI), not a
      systemic mapping failure — low priority, noted for whenever the
      fallback prompt gets revisited.
- [x] Phase 3: Scenario generator — valid CVE/technique/CPE combos emerge from
      graph constraints (`graphrange/scenario_generator.py`). Tested against
      the live graph, real combinations, not invented. Found and fixed a
      real bug while testing: `expected_observables` is a top-level Neo4j
      property, not nested in `properties` like other fields — the first
      version of the query missed it, returned empty for every scenario,
      caught by checking actual output instead of trusting the query looked
      right. `mark_scenario_complete()` and `get_conflict_scenarios()` are
      real, tested queries that correctly return empty until Phase 4+
      execution produces ScenarioRun/Outcome data — not stubs, just nothing
      to find yet.
- [x] Phase 4: `execute_attack()` appended to `agents/red.py`,
      `monitor()` + `assess_detection()` appended to `agents/blue.py`. Built and
      live-tested end to end 2026-08-10 (spawn -> execute -> monitor -> assess ->
      teardown, real Docker containers, real Ollama calls, no mocks). First live
      cycle found a real bug: `deliver_tool()` execs `install_command` values
      verbatim from Kali's own human-facing "How to install" text (crawled by
      `tool_crawler.py`) — `sudo apt install nmap` fails outright inside these
      containers (`sh: 1: sudo: not found`; exec already runs as root, the minimal
      Kali image doesn't ship a sudo binary at all) and lacks `-y`, which would
      hang/abort against apt's confirmation prompt with no TTY. Fixed at the
      right layer — `_normalize_install_command()` in `supervisor.py`'s
      `deliver_tool()`, the one chokepoint every agent's installs go through —
      rather than patching each caller. Also fixed `execute_attack()` itself: it
      was firing the install request and ignoring whether it actually succeeded
      before trying to run the tool; now returns a distinct `install_failed`
      status. Second live cycle after the fix: real `nmap` install + real scan
      against the real victim container over the actual `graphrange-public`
      network, real DNS resolution (`gr-victim-{run}.graphrange-public`), clean
      teardown, 157.3s total (includes the live `observer.py` Phase 5 model call
      — see below). Zero orphaned containers after, confirmed via `docker ps -a`.

      Real, deeper limitation surfaced (not a Phase 4 bug, logged separately, not
      fixed here): `success` came back `False` because the victim container never
      actually runs the CVE's vulnerable service — `graphrange/victim_builder.py`,
      which `GRAPHRANGE.md`'s own Phase 1 spec calls for (CPE -> install_commands
      + start_command, per the `Dockerfile.template` spec), was never actually
      built. `supervisor.py`'s `_resolve_cpe_to_image()` only maps a CPE to a
      base OS image and starts it with `sleep infinity` — nothing from the CPE's
      vulnerable software ever gets installed or started. Every scenario will
      report `success: False` for this reason specifically until `victim_builder.py`
      exists — worth building before trusting any Phase 4+ result as a real
      finding about a technique, not just a wiring smoke test.
- [x] Phase 5: Observation normalizer (`graphrange/observer.py`). Live-tested as
      part of the same Phase 4 run above (nmap's plain-text output correctly
      routed to the `/no_think` slot-fill path, not the JSON fast-path — real
      Ollama call, not a mock). Correctly returned `null` for every expected
      observable field, since nothing in a bare port-scan of an unconfigured
      victim relates to the scenario's actual (VNC-specific) expected fields —
      correct behavior given the victim-container gap above, not an observer bug.
- [x] Build `graphrange/victim_builder.py` — CPE -> install_commands + start_command
      on the victim container, per `GRAPHRANGE.md`'s own Phase 1 spec. Done and
      live-verified 2026-08-10: spawned a real Apache scenario (CVE-2002-1658,
      `cpe:2.3:a:apache:http_server:1.3.1`), nmap-scanned the victim from the red
      container over the real `graphrange-public` network, got back
      `80/tcp open http` — a real listening service, not an empty container.

      Scope, checked against real graph data before building, not assumed: 73
      vulnerability nodes total, 21 OS-only (need a VM, not a container —
      deliberately deferred, see the VM-support entry below), 3 Windows-only
      application software (same kernel wall), 7 client-side software (browsers,
      PowerPoint — no listening service for a network tool to reach, a different
      execution model entirely, not this file's job). That leaves 39 real
      Linux server-daemon candidates; mapped the ones with a real apt package
      (verified with `apt-cache show` against a live `debian:12-slim` image
      before adding each one — not guessed): Apache, MySQL/MariaDB, Squid,
      Cyrus IMAP, PHP+Apache. Everything else returns an honest
      `no_install_mapping`/`windows_only`/`client_side_not_executable` status
      rather than silently spawning an empty container.

      Known remaining fidelity gap, not fixed here: installing "apache2" via
      today's apt repo gets today's Apache, already patched against a
      20+-year-old CVE — same caveat as substituting a modern OS for an old
      one. A real fix needs version-pinned installs (e.g. Debian's
      snapshot.debian.org archive) to run the actual historic vulnerable
      version, not just "a real service of the right name." Not built —
      logged as its own item below, separate from the structural fix (nothing
      running -> something running) done here.

      Found and fixed three more real bugs along the way, all confirmed via
      actual live failures, not code review: (1) `spawn_scenario()`'s image-pull
      fallback caught `docker.errors.ImageNotFound`, but `.pull()` on a
      nonexistent remote tag (e.g. `httpd:1.3.1` — no official image for that
      old a version exists) raises the broader parent class
      `docker.errors.NotFound` instead, so the fallback never fired and the
      whole request crashed with a 500 — fixed by catching the broader class
      (`ImageNotFound` is itself a `NotFound`, so this covers both). (2) Even
      when a purpose-built image WAS correctly resolved (e.g. the official
      `httpd` image via the existing `_CPE_IMAGE_MAP`), `spawn_scenario()`
      unconditionally overrode every victim's command with `sleep infinity`,
      silently defeating that image's own default service-starting CMD — now
      only forced on genuinely generic base images (`ubuntu`/`debian`), not
      purpose-built ones. (3) `spawn_scenario()` wasn't atomic: a crash midway
      (the NotFound bug above, hit live) left red+blue containers running with
      no way for the caller to know what to tear down, since it never got IDs
      back — confirmed via a real orphaned pair found after the crash, cleaned
      up manually, then fixed by wrapping the whole function in a
      try/except that tears down whatever was already created before the
      error propagates, same all-or-nothing guarantee `teardown_scenario()`
      already gives on the normal path.
- [x] Version-pin `victim_builder.py`'s installs to the actual historic
      vulnerable version instead of "latest" apt packages. Done and
      live-verified 2026-08-10 for `apache:http_server:1.3.1`
      (CVE-2002-1658): real `curl -sI` from the red container against the
      victim returns `Server: Apache/1.3.1 (Unix)` — the exact historic
      version, not today's patched Apache. Verified twice: once via direct
      `docker run` build isolation (debian:12-slim) to find and validate the
      recipe, once through the actual live supervisor API end-to-end
      (145.3s spawn, real `ubuntu:22.04` fallback base since `httpd:1.3.1`
      isn't a real pullable image — the base-image difference from the
      isolated test didn't matter, same recipe worked cleanly there too).

      Architecture, per explicit direction: an exact-version exception table
      (`_VICTIM_VERSION_MAP` / `_VERSION_MAP`), checked before the generic
      "latest apt package" table, not a general "compile any CPE from
      source" mechanism. `resolve_victim_service()`/`_resolve_victim_service()`
      look up `(vendor, product, version)` first; only versions with an
      actual validated recipe get one, everything else falls back to the
      existing latest-apt path automatically. This is the right shape
      because the *reason* old source doesn't build is different every
      time, confirmed by hitting three completely unrelated failures for
      apache_1.3.1 alone: a build script written for bash breaking under
      Debian's default `/bin/sh` (dash), a removed glibc symbol
      (`_sys_siglist`), and a name collision with glibc's own `getline()`
      across multiple files — followed by three more purely-config gaps
      (missing `ServerRoot`-relative directories/files the default config
      expects, and a legacy `Group #-1` default modern `initgroups()`
      rejects). None of these generalize to a different old CVE's build; a
      genuinely general auto-patcher isn't a realistic target, a per-version
      recipe table is.

      Found and fixed one more real bug while wiring this in: `deliver_tool()`,
      `collect_output()`, and `spawn_scenario()`'s victim install/start calls
      all wrapped commands as `f"sh -c '{command}'"` — a single quote
      anywhere in the command (which every `sed -i 's/.../.../'` patch in
      the new recipe has) would silently terminate that string early and
      corrupt the command. Switched all four call sites to list-form
      `exec_run(["sh", "-c", command])`, which passes the command as one
      argv element with no extra shell-quoting layer to break — a real
      latent fragility in the existing code, just never triggered until a
      command with embedded quotes existed.

      **Update 2026-08-10, same day**: extended from one version to the
      whole Apache 1.3.x branch our graph references. Checked real archive
      availability for all remaining needed versions first, not assumed:
      `1.3.5`, `1.3.7`, `1.3.8`, `1.3.18` have no tarball on
      archive.apache.org at all — apparently never actually released
      despite NVD's CPE dictionary listing them, a permanent gap latest-apt
      is the correct (only) answer for, not something more patching fixes.
      The other 10 (`1.3.0`, `1.3.2`-`1.3.4`, `1.3.6`, `1.3.9`, `1.3.11`,
      `1.3.12`, `1.3.14`, `1.3.17`) all have real tarballs; batch-tested the
      1.3.1 recipe against all of them and found it didn't fully
      generalize — `1.3.6` onward hit a *different* real failure
      (`multiple definition of 'ap_os_is_path_absolute'`, a linker error,
      not a compile error). Diagnosed properly rather than guessed: first
      hypothesized `-fcommon` (GCC ≥10's `-fno-common` default breaking old
      tentative data definitions) since the failure pattern superficially
      resembled it; tested it directly, only partially reduced the error
      count, so that hypothesis was wrong, not just applied automatically.
      Traced the real cause — Apache's own `INLINE` macro (used by
      `ap_os_is_path_absolute`) depends on GNU89 inline semantics that
      changed under GCC ≥5's default; needs `-fgnu89-inline` specifically,
      confirmed by testing it in isolation and getting a clean build. Also
      found that passing compiler flags via a `CC=` environment variable or
      configure argument doesn't propagate reliably through this build
      system's nested per-directory sub-makes (a real, separately-confirmed
      quirk, not assumed) — worked around with a `gcc` wrapper script
      placed on `PATH`, which every recursive `make` invocation picks up
      transparently regardless of how (or whether) `CC` gets threaded
      through. Also found one more real per-version config difference
      testing `1.3.17` specifically: its default config expects
      `mime.types` under `conf/`, not `etc/` like `1.3.1`, and uses a
      literal `@@ServerRoot@@` placeholder token elsewhere in the file that
      `1.3.1`'s config doesn't have — handled by writing `mime.types` to
      both locations and substituting the placeholder globally, which is
      harmless when it doesn't apply rather than needing to branch per
      version. Consolidated into one parameterized template
      (`_apache_13x_build_command()`) instead of 11 hand-duplicated
      entries. Verified live end-to-end through the real supervisor API on
      `1.3.9` (previously only compile-tested, not start-tested) — real
      `Server: Apache/1.3.9 (Unix)` response, clean teardown, no orphans.
      `1.3.1` and `1.3.17` were also confirmed to fully start and serve;
      the other 8 were confirmed to compile cleanly (real `src/httpd`
      binary produced, no build errors) but not individually start-tested,
      on the reasoning that the two known per-version config variants are
      both already handled defensively.

      **Update 2026-08-10, same day**: `apache:http_server:2.0.52` also done
      — turned out much simpler than the whole 1.3.x investigation predicted.
      Built cleanly with **zero source patches** and a standard, unmodified
      `make install` — 2.0.x bundles its own APR/APR-util libraries
      specifically for cross-platform/cross-toolchain portability, which is
      exactly the problem that broke 1.3.x's old custom APACI build system
      on a modern compiler. Only needed the same config-layer fix 1.3.x also
      needed (User/Group/ServerName), plus 2.0.x uses `httpd -k start`
      instead of a direct invocation. Verified live through the real
      supervisor API: `Server: Apache/2.0.52 (Unix)`, clean teardown, no
      orphans. **Apache is now fully closed out** — 12 total validated
      versions (11 from 1.3.x + 2.0.52), covering every real tarball
      available for what the graph references; the 4 that don't exist at all
      are a confirmed, permanent non-gap, not unfinished work.

      Scope note, still accurate: the other four mapped software families
      (MySQL, Squid, Cyrus IMAP, PHP) still have no recipe and fall back to
      latest-apt. Each is expected to be its own real, non-trivial discovery
      process, not a quick follow-up — this is exactly the kind of
      per-version/per-family work the exception-table architecture exists to
      absorb incrementally, not something meant to block on. Paused here
      (Apache being fully done is a clean, complete unit of work) in favor
      of GraphRange Phase 6, which is better-specified and doesn't carry the
      same open-ended discovery risk.
    - [x] **2026-08-12 — three of the four closed out.** MySQL 3.22.32
      (CVE-2000-0148), Cyrus IMAP 2.2.5 (CVE-2004-1012/1013), and PHP 4.2.2
      (CVE-2002-0985) all validated end-to-end via the exact production
      code path (`exec_run(["sh","-c", command])` against a genuinely
      fresh `debian:12-slim` container, not just isolated `docker run`
      testing), registered in `victim_builder.py`'s `_VERSION_MAP`, and
      hand-synced into `supervisor.py`'s duplicate copy (byte-for-byte
      verified identical between the two).
      - **MySQL 3.22.32**: real source from `snapshot.debian.org` (MySQL's
        own archive has nothing this old any more, sha256-verified against
        the fetched file). 12 real fixes: config.guess/config.sub predate
        x86_64; `ps` genuinely absent from `debian:12-slim`; LinuxThreads
        detection greps a marker string only present in pre-NPTL glibc,
        forced to the "Found" branch; missing curses/termcap
        (`libncurses-dev`); `strnlen`'s own prototype conflicts with
        glibc's real one; `errno` compiled as a plain `extern int` under a
        dead `HAVE_ERRNO_AS_DEFINE` branch, conflicting with glibc's real
        TLS-based errno; a removed GNU C++ `>?`/`<?` min/max extension;
        a `sigset()` compat macro for old LinuxThreads clobbering glibc's
        real declaration; glibc's own `strcasestr()` conflicting with
        MySQL's declaration; four separate cases of code relying on a
        pre-standard C++ compiler behavior (friend-only declarations
        satisfying ordinary lookup) that modern GCC rejects; two
        `'\0'`-to-pointer conversions modern G++ rejects. Real mysqld,
        real `SELECT VERSION()` over TCP 3306.
      - **Cyrus IMAP 2.2.5**: real source from GitHub's tag archive
        (missing `configure`/`config.h.in`/`aclocal.m4` since it's a raw
        git snapshot, not an official release tarball — regenerated via
        `aclocal -I ../cmulocal && autoconf && autoheader`). Real fixes
        beyond the MySQL-shared ones (config.guess/sub): the checked-out
        `sieve/` sits as a sibling of the `cyrus/` build dir but
        configure.in wants it as a subdirectory — a symlink broke
        `sieve/Makefile`'s own `../et`-relative paths (symlinked dirs
        resolve `..` against their physical location), fixed with a real
        directory copy instead; `--without-bdb` (the bundled Berkeley DB
        support targets the pre-4.1 API, five majors older than Debian
        12's libdb-dev, so disabled rather than migrated — the three
        disabled cyrusdb roles fall back to the already-working skiplist
        backend); configure's own `__attribute__` support probe is
        broken on modern GCC, so config.h silently strips
        `__attribute__` everywhere including glibc's `transparent_union`
        on the socket types, degrading `connect()`/etc. into a plain
        incompatible union (root-caused by direct preprocessor-output
        inspection, not guessed); the `tools/config2header` generator
        emits an `extern` array declaration before the struct it's an
        array of is defined; OpenSSL 1.1+ made `X509_STORE_CTX` and
        `SSL_SESSION` opaque (three files' worth of direct field access
        replaced with the 1.1+ accessor functions); the same
        `-fgnu89-inline` old-code-vs-modern-GCC-inline-semantics issue as
        Apache 1.3.x; `sieve/Makefile`'s own rule for generating its two
        flex lexers was commented out with nothing put in its place for
        `addr-lex.c`'s required `-Paddr` prefix, so both generated via
        direct `yacc`/`flex` invocations instead of relying on make.
        Real authenticated IMAP session: `LOGIN` succeeded, `SELECT`
        correctly parsed and rejected a nonexistent mailbox.
      - **PHP 4.2.2**: real source from PHP's own official historic
        archive (`museum.php.net`, `Last-Modified` header matches the
        real July 2002 release date). Only two fixes needed, both
        already-solved bugs from the same investigation: PHP bundles a
        copy of MySQL's own client library (built-in MySQL support is
        configure's default), hitting the identical `errno`/
        `HAVE_ERRNO_AS_DEFINE` conflict as the standalone MySQL recipe;
        Zend's two flex-generated lexers each tentatively-define a
        global `yytext`, the same GCC≥10 `-fno-common` default issue as
        Apache (fixed with `-fcommon` this time, a different flag than
        Apache needed for the same underlying "old code assumed a
        pre-GCC10 default" reason). Real PHP source executed and served
        over real HTTP through modern apache2 + mod_cgi (PHP's SAPI is
        loosely coupled to whatever fronts it via CGI, unlike Apache's
        own version pinning which needed the actual old httpd binary).
        **Real, honestly-flagged limitation** (checked the graph before
        writing this, not assumed): CVE-2002-0985's own `affected` CPE
        list is a single version *wildcard* entry
        (`cpe:2.3:a:php:php:*:...`), not a concrete version like MySQL's
        or Cyrus's. `scenario_generator.py` builds `victim_cpe` by
        iterating a CVE's `affected` list verbatim, so this CVE's own
        auto-generated scenarios will carry that literal wildcard
        through to `resolve_victim_service()`, which will never match an
        exact `_VERSION_MAP` key of `"4.2.2"`. The recipe is fully real
        and directly usable by anything that queries
        `resolve_victim_service()` with a concrete CPE, but won't
        auto-fire for this specific CVE's generated scenarios today —
        stated plainly rather than left implicit.
      - Squid 2.2.STABLE5 remains the one open gap (see its own dated
        entry above) — genuinely unresolved after real investigation
        with two diagnostic tools, not a quick-follow-up miss.
    - [x] **2026-08-13 — Squid 2.2.STABLE5 closed too, all four families
      now done.** Revisited with fresh eyes at the user's request. The
      SIGSEGV had two independent real causes, both found by hitting the
      actual crash through gdb, not guessed:
      - `struct pollfd pfds[SQUID_MAXFD]` in `comm_poll()` (the main event
        loop) is a fixed-size **stack** array. `SQUID_MAXFD` is baked in
        at `./configure` time from `getrlimit(RLIMIT_NOFILE)`'s soft
        limit. Docker's default fd ulimit is 1,048,576 (vs. the few
        hundred a 1998 system would have had), producing an 8MB stack
        array that exactly matches the container's 8MB default stack
        limit — a guaranteed stack-overflow SIGSEGV the moment
        `comm_poll()` runs. This is what the 2026-08-12 investigation
        actually hit and misdiagnosed as an SSE/ABI miscompilation (the
        `divps` disassembly at "a benign double add+store" was just
        normal codegen for the next local's initializer, i.e. the first
        write to touch the guard page) — explaining why the `-m32`
        rebuild "fixed" it once and didn't reproduce (coincidental
        smaller stack layout, not a real fix). Actual fix: `./configure`
        (and `squid -z`/start) under a constrained `ulimit -n 1024`,
        matching what `SQUID_MAXFD` was always meant to be sized for.
      - `_db_print()` (`src/debug.c`) reused one `va_list args` across
        three consumers (syslog's `vsnprintf`, a `vfprintf` to the log
        file, a second `vfprintf` to stderr) with no `va_copy()` between
        them. On i386 (the 1998 target) `va_list` is just a stack
        pointer, so re-reading it was harmless; on x86_64 SysV ABI it's a
        stateful struct passed by reference, consumed by each call, so
        every call after the first read garbage pointers as its `%s`
        args — crashing on literally the first `debug()` call at
        startup. Fixed by giving each consumer its own `va_copy()`'d
        list, all copied from the pristine original before any of them
        run.
      The already-real sys_nerr fix from 2026-08-12 (a removed glibc
      global, used only as a redundant bounds check before `strerror()`)
      is kept; that investigation's `setresuid`/`_GNU_SOURCE` note and
      the `-m32` toolchain were specific to the abandoned attempt and
      aren't part of this recipe. Verified end-to-end from a fresh
      `ubuntu:22.04` container via the real `exec_run(["sh","-c",...])`
      path: real build, real `squid -z` cache init, real daemon start, a
      real proxied HTTP request through it (`TCP_MISS/200` in Squid's own
      `access.log` for a genuine external fetch), clean `squid -k
      shutdown`. Registered in `victim_builder.py`'s `_VERSION_MAP` under
      `("national_science_foundation", "squid_web_proxy", "2.2.STABLE5")`
      — this is the real NVD CPE vendor:product for Squid (Squid began as
      an NSF-funded Harvest project descendant), not `("squid","squid")`
      — and hand-synced into `supervisor.py`'s duplicate copy. One real
      recipe-authoring bug found and fixed along the way, worth noting
      for future recipes: an earlier draft chained a heredoc redirect
      straight into `&&` with nothing else queued before its own body
      started, which feeds the heredoc's Python source text to the shell
      parser as if it were shell commands ("Syntax error: '(' unexpected"
      on `replace_once`'s own opening paren) — fixed by switching to
      plain newline-separated statements under `set -e`, which reproduces
      the same "abort on first failure" behavior as `&&`-chaining without
      that fragility.
    - [x] **2026-08-13 — does the fallback (generic, unvalidated-version)
      install path actually survive an unseen version?** Tested for real,
      not just unit-tested: unit tests of `resolve_victim_service()`
      against unseen versions (Apache 1.3.5, MySQL 5.7.44, Cyrus 2.1.16,
      PHP wildcard, unknown vendor, malformed CPE) all passed cleanly —
      but that only proves the *lookup* logic degrades gracefully, not
      that the fallback's actual install/start commands work when really
      executed. Ran a real unseen MySQL version
      (`cpe:2.3:a:oracle:mysql:5.7.44:...`) through the real
      `spawn_scenario()` pipeline end-to-end and found it did **not**
      survive cleanly — two real, distinct bugs, both fixed:
      - `spawn_scenario()` never checked `exec_run()`'s exit code at all,
        so a genuinely broken victim install was reported as
        `"victim_service_status": "mapped"` — confirmed via a real failed
        `SELECT VERSION()` against a victim the code had just reported as
        successfully mapped. Fixed by capturing and checking the
        install/start exit codes, setting `service_status` to
        `"install_failed"`/`"start_failed"` accordingly (still not a full
        health check — a `start_command` that backgrounds itself with `&`
        returns exit 0 immediately regardless of whether the backgrounded
        process later dies — but it now catches the command-itself-fails
        class of failure found here).
      - The MySQL fallback's `_INSTALL_MAP` entry had `"service mariadb
        start"`, but `default-mysql-server` on Ubuntu 22.04 resolves to
        real MySQL (`mysql-server-8.0`), never installing MariaDB at all
        — silently guaranteed to no-op. Fixing the service name surfaced
        a second, deeper issue: `mysql-server-8.0`'s postinst script
        starts `mysqld --daemonize` to bootstrap the initial data
        directory, then tries to shut it down again within an 18-second
        budget; this container's PID 1 (`sleep infinity`, not a real init
        system) never reaps the orphaned, re-parented process once it
        dies, so it becomes a permanent zombie (confirmed via `ps`
        showing `[mysqld] <defunct>`) — and the postinst's own `ps $pid`
        liveness check still sees it as "running" (`ps` lists zombies
        too), so it reports `"Error: Unable to shut down server"` and
        fails the whole package configure, even though mysqld itself
        already exited cleanly. This is Docker's well-known PID-1-doesn't-
        reap-zombies problem. Fixed with Docker's `--init` flag
        (`init=True` in the SDK call, tini as PID 1) on all three
        `spawn_scenario()` containers, not just victim — any of them
        could run a daemonizing installer during their own setup.
        Reproduced and verified on a fresh container: identical install
        fails every time without `--init`, succeeds cleanly every time
        with it, and a real `mysqladmin status` afterward showed a live
        mysqld actually serving queries.
      A third, unrelated real bug was found (not fixed by the above) and
      fixed separately while investigating: `spawn_scenario()`'s own
      `except Exception:` cleanup block only checked `if c is not None`
      for `red`/`blue`/`victim`, but `containers.run()` does
      create-then-start internally — if `.start()` fails after
      `.create()` succeeds, the exception propagates without ever
      returning a container object, leaving the local variable `None`
      even though a real container now exists, orphaned and invisible to
      the cleanup loop (hit live: a missing `graphrange-public` Docker
      network made `.start()` fail after `.create()` had already run,
      leaving a genuinely orphaned `gr-red-*` container that had to be
      cleaned up manually with `docker rm -f`). Fixed by falling back to
      a deterministic-name lookup (`gr-{role}-{run_suffix}`) whenever the
      local variable is `None`, instead of trusting only the variable.
    - [x] **2026-08-13 — PHP CVE-2002-0985 actually exploited, not just
      "the interpreter runs."** Every prior PHP validation (2026-08-12)
      proved the CVE-2002-0985-era build works — real interpreter, real
      HTTP serving — but never exercised the vulnerability itself. Did
      that here, end-to-end, against the real HTTP + apache2 + php-cgi
      path (not `exec_run` calling php directly):
      - Read `ext/standard/mail.c` directly rather than assuming: `mail()`
        has **no `safe_mode` check at all** on the 5th argument
        (`additional_parameters`/`extra_cmd`). It only passes through
        `php_escape_shell_arg()`, which prevents *shell metacharacter*
        injection (breaking out via quotes/backticks) but does nothing to
        stop inserting an entire extra, legitimate-looking command-line
        **flag** — sendmail has no way to distinguish "attacker data"
        from "a real flag," so escaping the string doesn't help.
      - Exploited the classic technique: a query-controlled 5th argument
        injects `-X/var/www/html/pwned.php` (sendmail's real transcript-
        logging flag), with the attacker-controlled message body
        containing a `<?php system($_GET["c"]); ?>` payload. Verified via
        a stand-in `/usr/sbin/sendmail` that logs its real argv (proving
        the injected flag reaches the MTA command line completely
        unfiltered) and honors `-X<file>` exactly like real sendmail does
        (dumps the raw transcript to that file). Confirmed live: the
        injected flag arrived intact, `pwned.php` was written into the
        web root **by the real `www-data` apache worker process** (not
        root — ownership checked, not assumed), and a subsequent real
        HTTP GET showed Apache genuinely interpreting it as PHP (the
        `<?php ?>` tags were consumed from the output, not returned as
        literal text) — a full unauthenticated arbitrary-file-write into
        the web root via one HTTP request.
      - Honest nuance, found rather than glossed over: the naive
        `system($_GET["c"])` payload's actual command didn't run.
        Apache's error log showed why: `sh: 1: /id: not found` — a
        **separate** safe_mode mechanism (`safe_mode_exec_dir`, empty by
        default) rewrites exec-family calls to look inside a restricted
        directory. This doesn't touch the mail() vulnerability at all
        (confirmed no such check exists in mail.c) and doesn't change
        that the core CVE — unauthenticated arbitrary file write via
        argument injection — is fully proven; it just means a real
        attacker's payload would avoid `system()`/`exec()` in favor of
        functions safe_mode's exec restriction doesn't cover (e.g. file
        read/write).
      - Real gap found in the *already-registered* recipe, not this
        test's fault: PHP's own `./configure` (`PHP_PROG_SENDMAIL` in
        `acinclude.m4`) probes for a `sendmail` binary on disk and only
        defines `HAVE_SENDMAIL` if one exists at configure time. The
        validated `_VERSION_MAP` recipe in `victim_builder.py`/
        `supervisor.py` never installs one, so `mail()` compiles as a
        dead `warn_not_available` stub in every victim built from that
        recipe today — this CVE cannot be demonstrated against the
        currently-registered PHP 4.2.2 victim at all. (Also cost real
        debugging time here: after adding a stand-in sendmail and
        re-running `./configure`, `mail()` still silently failed at
        first — incremental `make` doesn't know `main/php_config.h`
        changing should invalidate `ext/standard/mail.o` *and*
        `ext/standard/basic_functions.o`, which has its own independent
        `#ifdef HAVE_SENDMAIL` deciding whether `mail` registers as the
        real function or the `warn_not_available` stub — both had to be
        force-deleted and recompiled by hand.) **Fixed in the registered
        recipe, same session**: `victim_builder.py`'s `build_command` now
        creates a minimal sendmail stand-in (`_PHP_MAIL_STANDIN_SCRIPT`)
        *before* `./configure` runs, so `HAVE_SENDMAIL` gets detected
        properly, plus sets `safe_mode = On` in php.ini (the CVE's own
        documented precondition) and fixes web-root/PHPRC wiring so
        Apache's real `www-data` worker actually picks it all up.
        Deliberately not a real MTA — explicitly commented as a stand-in
        that only reproduces the one piece of real sendmail behavior the
        exploit needs (argv passthrough + honoring `-X<file>` exactly
        like real sendmail's transcript-logging flag), a decision worth
        revisiting if this ever needs to send real mail rather than just
        demonstrate the injection. Re-verified end-to-end through the
        real, unmodified `build_command`/`start_command` against a
        completely fresh container — exploit succeeded on the first try,
        no manual intervention needed (the incremental-rebuild issue
        above only applied to patching a container that was already
        built; a fresh build compiles everything in the right order from
        scratch). Synced into `supervisor.py`'s duplicate copy.
    - [~] **2026-08-16/17 — MySQL victim's actual CVE re-examined; the
      pinned version turned out to be the PATCHED one.** The recipe's
      comment described CVE-2000-0148 as a "mysqladmin password-file
      world-readable" LOCAL issue — wrong. NVD (verified live): it is a
      REMOTE authentication bypass via a short check string (`AV:N`, CVSS
      7.5) — the server compares the client's scramble byte-for-byte over
      the CLIENT's length, so a 1-byte scramble gets 1 byte compared
      (~1/31 odds), letting a remote attacker who knows only a username
      authenticate with no password in <=32 tries. Good red/blue shape.
      - **Methodology lesson (paper-worthy): static source read said
        "vulnerable," the live exploit proved "patched" — neither alone
        sufficed.** First inspected `sql/password.c`'s `check_scramble()`,
        saw the unbounded `while (*scrambled)` compare loop, and wrongly
        concluded 3.22.32 was vulnerable. A hand-rolled 1-byte-scramble
        exploit client (pre-4.1 protocol, run from a separate container)
        then hit "Bad handshake" 400/400. Root cause found by reading the
        REAL rejection path: `sql/sql_parse.cc` `check_connections()`
        rejects any non-empty scramble whose `strlen != SCRAMBLE_LENGTH`
        (8) BEFORE `check_scramble` is ever reached — that length guard is
        the fix. Confirmed independently by the source's own
        `Docs/manual.txt`: "Changes in release 3.22.32 — Fixed security
        problem in the protocol regarding password checking" (and 3.23.11
        for that branch). So 3.22.32 is the first FIXED release; the CVE
        needs <=3.22.31, matching NVD's <=3.22.30 CPE list.
      - **Sourcing wall:** snapshot.debian.org's earliest 3.22.x is
        3.22.32-6 and upstream MySQL archives that old are dead, so a
        genuinely vulnerable build must come from a mirror of the old
        `Downloads/MySQL-3.22/` tree, Software Heritage, or the Internet
        Archive; fallback is the 3.21.33b branch (on Debian snapshot, same
        bug class, outside the CVE's CPE list). NOT yet sourced — user
        chose "pursue authentic build" (ROADMAP P1.2).
      - **Done file-only, staged pending live re-validation on the
        vulnerable build:** (1) recipe refactored to a per-version
        `_MYSQL_SOURCES` table (url + extracted-dir), fixing a latent bug
        where the single hardcoded 3.22.32 URL meant any other version in
        the list would download the wrong tarball and fail to `cd`;
        (2) auth config corrected — dropped `--skip-grant-tables` (an
        auth-bypass CVE needs auth ENABLED), provisioned a
        password-protected network account `argus`@`%`, set a root
        password, removed the default anonymous no-password accounts
        (which shadowed `argus` on local connections and confused the
        controls); (3) both changes synced into `supervisor.py`'s
        duplicate. Auth config + positive/negative TCP controls were
        validated live on the (patched) 3.22.32 build before the vulnerable
        source was even needed — it is a faithful *authenticated* MySQL
        victim, just not a vulnerable one.
- [ ] VM support for the victim layer, alongside Docker. **2026-08-13
      update: re-counted against the real graph** (`cpe:2.3:o:` scan),
      superseding the earlier "21 nodes" categorical estimate — the real
      number is **24 distinct CVE nodes, 75 distinct (vendor, product,
      version) OS-level CPE tuples** (SunOS, FreeBSD, Windows, Cisco IOS,
      IRIX, AIX, HP-UX, various BSDs, SCO, Convex, Cray). Checked real
      feasibility per OS family, not assumed uniform, using kernel-sharing
      as the actual boundary (Docker shares the HOST kernel via
      namespaces/cgroups — it never virtualizes hardware or runs a
      different kernel — so Dockerizing needs both the same kernel family
      *and* the same CPU ISA as the host):
      - **One real Docker-workaround candidate found**: CVE-2002-0004
        (Debian 2.2) is the only OS-level node sharing Linux kernel
        lineage. Its own CPE list spans six CPU architectures (68k,
        alpha, arm, ia-32, powerpc, sparc) — only the `ia-32` variant is
        genuinely dockerizable on a modern x86_64 host without CPU
        emulation. The vulnerable component is a specific package (`at`,
        a double-free heap-corruption bug), not the kernel itself, so
        this doesn't need "the whole OS as a VM" at all — just the old
        `at` package on a modern-kernel-compatible Debian base, the exact
        same version-pinning pattern already proven this session for
        MySQL/Cyrus/PHP/Squid. Not yet built — a real candidate for a
        future session, not done here.
      - **Everything else genuinely needs a VM**, split further by what
        actually breaks: kernel-level bugs (FreeBSD AIO/execve race,
        fd/procfs handling, kqueue UAF, ZFS ZIL, swapgs; NetBSD kernel
        heap overflow; SunOS SPARC integer-multiplication kernel
        emulation code; Windows kernel-mode services/RPC) need a real
        foreign kernel, full stop. Userspace-level bugs on incompatible
        OSes (BSD/SCO `passwd`, FreeBSD `libmytinfo`/`k5su`, SGI
        `rdist`/`rwhod`, HP-UX `dtlogin`/`dtsession`) are conceptually
        smaller but still need the real foreign OS/libc/ABI, so they're
        no more Docker-workaroundable than the kernel bugs.
      - Cisco IOS (CVE-2004-0714) is a separate tooling category
        entirely — router firmware needs GNS3/Dynamips-style
        network-device emulation, not a general-purpose VM or Docker.
      - Convex (ConvexOS/SPP-UX) and Cray (UNICOS), both in
        CVE-1999-0099 alongside bsdi, are vector-supercomputer
        architectures with no viable modern emulation path — essentially
        permanent non-gaps, not worth pursuing.
      - Two unconfirmed "maybe" cases, real investigation not assumption
        needed if ever revisited: CVE-2009-4358 (`freebsd-update`
        insecure permissions — a userspace *script* bug, but
        FreeBSD-specific tooling, low priority given narrow impact) and
        CVE-1999-0168 (Sun portmapper proxy/redirect — might have a Linux
        `rpcbind` analog, genuinely unconfirmed).
      Deliberately deferred 2026-08-10, re-scoped 2026-08-13 — needs QEMU
      orchestration and VM image sourcing for the genuine VM-only cases, a
      real architecture extension, not a quick addition. The Debian 2.2
      finding means the very next step, if picked up, should be adding
      that one Docker-workaround recipe first (cheap, proven pattern)
      before starting the larger VM architecture work.
- [x] Phase 6: Graph updater — write outcomes, update technique confidence,
      flag conflicting outcomes (`graphrange/graph_updater.py`). Built and
      verified 2026-08-10 against real live graph data (technique T1113),
      not a synthetic in-memory test — all 5 spec functions confirmed:
      `write_scenario_run`/`write_outcome` (writes real `ScenarioRun`/
      `Outcome` nodes plus all three edge types: `used_technique`,
      `targeted_cve`, `validates`), `update_technique_confidence` (real
      +0.05/-0.02 deltas observed, correctly capped/floored),
      `check_and_flag_conflict` (a real conflicting outcome for the same
      technique+config was detected, a `conflicts_with` edge written, the
      exact spec-worded open_question added, confidence reduced by 0.1),
      `decay_stale_nodes` (backdated a real node's `created_at`, confirmed
      the exact `* 0.95` multiplier applied). Test nodes and the technique's
      baseline state cleaned up afterward, not left in the graph.
- [~] Phase 7: `graphrange/run_scenario.py` end-to-end orchestration. Code
      written and wired to spec 2026-08-10 — `run_one()` (write ScenarioRun
      -> start blue monitor thread -> `plan_attack()`/`execute_attack()` ->
      stop monitor -> `assess_detection()` -> `write_outcome()` ->
      `update_technique_confidence()`/`check_and_flag_conflict()` ->
      `update_scenario_run_status()` -> `mark_scenario_complete()`) and
      `run_batch()`. Imports and syntax verified clean.
      **`plan_attack()` itself live-tested 2026-08-12** (Kaggle P100,
      genuine `/think` mode — the longest-standing gap in this whole
      project): real attack-surface query found 6 real chains, real
      reasoning correctly cited past-lesson memory from
      `memory/reflexion.py`, selected a coherent 3-hop chain
      (CVE-1999-0181 -> T1557 -> TA0006) with 0.95 confidence, wrote a real
      engagement node to Neo4j, 48.0s. **Still not live-tested**: the full
      `run_one()` orchestration through `execute_attack()`/monitor/assess —
      needs live `gr-supervisor` + victim containers, Day 12-14 scope, not
      this checkpoint's.
      One real architectural gap flagged in the code's own docstring, not
      hidden: `plan_attack()` independently selects a CVE/technique chain
      from the graph's real attack surface rather than being told which
      `scenario` (from `get_valid_scenarios()`) to plan for — both are
      separate inputs to `execute_attack()` per spec, so it won't crash,
      but "what red planned" and "what actually got tested/measured" can
      genuinely diverge. Fixing that would mean changing `plan_attack()`'s
      signature, out of scope for just wiring Phase 7 together.
      **Update, same day**: found and fixed a real bug while building the
      Scanner's `run_scanner.py` — `SUPERVISOR_URL` here was
      `http://gr-supervisor:8000`, copied straight from spec, but that
      Docker-internal hostname doesn't resolve from the host (confirmed
      live), which is where this code actually runs. Would have silently
      broken every live run of this file too. Fixed to `localhost:8000`.
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
- [x] `repo_intake.py` — GitHub URL / local path validation, staging directory,
      symlink + path traversal checks, exec-bit stripping, XML-wrapped file
      content via `read_file_safe()` (prompt injection defense — the only way
      file contents may enter the scanner pipeline). Built and verified
      2026-08-10 against 9 real cases, not synthetic: a real staged directory
      with a genuinely oversized file (correctly flagged in `.argus_skip`,
      not deleted), a genuinely executable script (execute bit correctly
      stripped), `read_file_safe()` correctly XML-wrapping real content and
      correctly returning `None` for a skipped file, a nonexistent local path
      correctly rejected, `gitlab.com` and `github.io` URLs both correctly
      rejected by the exact-domain regex, and a real live `git clone` of a
      real public GitHub repo (`octocat/Hello-World`) succeeding end to end.
      One deliberate adaptation from the spec, not a deviation from its
      intent: `STAGING_ROOT` uses `tempfile.gettempdir()` instead of the
      spec's hardcoded `/tmp/argus_scanner_staging` — this step runs
      natively on Windows in this codebase, not inside a container, and a
      hardcoded Unix path would silently fail there.

### Product pipeline (`graphrange/scanner/`)
- [x] `telemetry.py` — token counting, cost estimation, system load tracking,
      `logs/telemetry.jsonl`. Built 2026-08-10, `tiktoken` installed (wasn't
      present — added to `requirements.txt`, pinned to the already-installed
      `psutil==7.2.2` rather than the spec's `5.9.8` guess). Verified live:
      `count_tokens()` on real text, `track()` sampling real elapsed time/
      CPU/RAM around a real timed block, `patch_last_tokens_out()` correctly
      updating both the in-memory entry and the on-disk `.jsonl` line, real
      cost math confirmed against the entry's own token counts. Test entry
      cleared from the log afterward — it was synthetic verification data,
      not real telemetry, and shouldn't sit in the log real usage will
      accumulate into.
- [~] `victim_builder.py` (Scanner's own, distinct from GraphRange's CPE-based
      one) — generalized multi-container topology builder: `docker-compose.yml`
      first, manifest fallback (Qwen infers compose from `pom.xml`/
      `package.json`/etc), compose validation (dry-run + unsafe flag check +
      image registry allowlist) before every `docker compose up`. Built
      2026-08-10 and verified against real data for every zero-GPU path: real
      constructed multi-ecosystem repo → `_scan_manifests()` correctly found
      and read both `package.json` and `requirements.txt`; `_validate_compose()`
      correctly passed a real safe compose file, correctly rejected a real
      `privileged: true` file, correctly rejected a real disallowed-registry
      image; full `build_victim_topology()` → real `docker compose up` on a
      real 2-service compose file (nginx + alpine), real container IDs
      captured via `docker compose ps`, roles/entry_point/network_map all
      inferred correctly, real teardown, confirmed zero orphaned containers
      after. Found and fixed a real bug in `_infer_role()`: port 8080 is
      listed under both `web_frontend` and `api_backend` in spec (the ranges
      genuinely overlap), and checking ports before names meant a clearly
      named `api-server` service on `:8080` was misclassified as
      `web_frontend` — fixed by checking name keywords before falling back to
      ambiguous ports. **Live-tested 2026-08-12** (via Kaggle P100
      acceleration): `_infer_compose_from_manifests()` given a realistic
      Python manifest (flask/SQLAlchemy/psycopg2/redis) produced a genuinely
      correct docker-compose.yml — right services, right images, correct
      dependency wiring, sensible env vars, 31.9s.
- [~] `file_scanner.py` — Pass 1, bounded-parallel Qwen scan (3 workers),
      chunk/merge for long files, uses `read_file_safe()` exclusively. Built
      2026-08-10; the chunking logic (`_chunk_content()`) was factored out
      of `scan_repo()` specifically so it's independently testable without
      a live Qwen call, and verified against real generated content: a
      10,000-token real Python file correctly split into 2 boundary-aware
      chunks with all 400 functions preserved across them; a 100,000-token
      single blob with zero blank lines (forcing the raw-slicing fallback)
      correctly split into 7 overlapping chunks; `merge_chunks()` correctly
      passed through non-merge-needed flags and correctly short-circuited a
      single-chunk group without invoking the Qwen-dependent `_merge_call()`.
      **Not yet live-tested**: `_scan_file()`/`_merge_call()` (the actual
      Qwen calls) — holding at the same checkpoint as Phase 7.
- [x] `vuln_reasoner.py` — Pass 2, deep reasoning per flag → VulnContext.
      Built 2026-08-10, imports verified clean (reuses `file_scanner.py`'s
      chunker rather than duplicating it). **Live-tested 2026-08-12** (Kaggle
      P100): given a real SQL injection snippet (string-concatenated query),
      `reason_over_flags()` correctly identified it as SQL Injection/CWE-89,
      Critical severity, 0.95 confidence, valid JSON, 12.8s.
- [~] `scanner_red.py` — topology-aware attack path planning across containers;
      `acquired_capabilities` cache (capability → tool, reused across
      containers without re-requesting); tool substitution reasoning with
      `max_cycles=3` broadening before falling back to installed tools; phase
      blocked vs. scenario stopped; `_assess_objective()` with
      execution-primary / Qwen-secondary dual assessment (execution stdout is
      ground truth, conflicts logged). Built 2026-08-10 — this file had 3-4
      layered revision passes in the spec (base → topology-aware →
      phase-aware tool request → capability-cache gap closure →
      execution-primary assessment); read and synthesized all of them into
      one final implementation rather than the first draft, per this repo's
      own note that later passes supersede earlier ones. Zero-GPU pieces
      verified against real data: `_broaden_to_category()` (6 real capability
      strings, all correctly bucketed) and the real `_argus_lookup()` Cypher
      query against the live graph (5 real technique matches for "vnc").
      **`analyze()`'s main reasoning call live-tested 2026-08-12** (Kaggle
      P100, `sandbox=False` so no Docker/topology needed for this scope): a
      synthetic SQL-injection `vuln_context` produced a real `_argus_lookup()`
      Neo4j match plus a coherent Qwen exploitation-path/attack-steps
      reasoning, valid JSON, 28.2s. **Still not live-tested**:
      `_plan_attack_path()`, the substitution reasoning call, and
      `_assess_objective()`'s Qwen signal — all three need a real live
      topology/Docker execution (`sandbox=True`), out of this checkpoint's
      scope; that's Day 12-14's job.
- [~] `scanner_blue.py` — ARGUS mitigation lookup + static advice;
      multi-container monitoring (one thread per service, shared event list +
      lock); per-service/per-phase detection assessment; `missed_lateral` flag.
      Built 2026-08-10, synthesizing the base spec + its multi-container
      monitoring revision. Verified against real data: `assess_detection()`
      tested with 3 real scenarios (entry caught/pivot missed, everything
      caught, nothing caught) — correctly identified `missed_lateral` only
      in the genuine catch-then-miss case, not the other two; the real
      `_argus_mitigation_lookup()` Cypher query against the live graph found
      exactly the 4 mitigations for T1021.005 this session's own earlier
      audit had already confirmed exist (M1037, M1033, M1047, +1).
      **`analyze()`'s static-advice Qwen call live-tested 2026-08-12** (Kaggle
      P100, `sandbox=False`, chained with real `scanner_red.analyze()`
      output): produced genuinely correct advice (parameterized queries as
      the code fix for the SQL injection case), real
      `_argus_mitigation_lookup()` Neo4j results, valid JSON, 54.5s.
- [x] `scanner_report.py` — MD + PDF + HTML report: per-finding vuln +
      mitigation, multi-container kill chain table (status/result/evidence/
      qwen/conflict columns, blocked phases, substituted tools), per-service
      detection table. Built and fully verified 2026-08-10 with realistic
      synthetic finding data shaped exactly like `scanner_red.py`/
      `scanner_blue.py`'s real output (report generation is 100% zero-GPU
      formatting, so this could be tested completely, unlike the modules
      that produce the data) — all three formats generated real files;
      every branch exercised and confirmed present in the output: a
      substituted tool, a blocked phase with the `tool_unavailable.log`
      reference, a Qwen/execution conflict flag, a `missed_lateral` case, a
      fully-skipped-sandbox finding, and "none found in graph" for an
      unmatched CVE. Real ARGUS dashboard palette used (`#080814` bg, the
      actual `TYPE_COLOR` values from `dashboard/ui/src/components/GraphView.jsx`),
      not guessed colors. `reportlab` wasn't installed — added to
      `requirements.txt`.
- [x] `run_scanner.py` — pipeline entry point: `intake()` → topology build →
      Pass 1 → Pass 2 → parallel red/blue per finding (`stop_event`
      coordination) → report → `teardown_victim_topology()`. Built
      2026-08-10, synthesizing the base pipeline + the repo_intake and
      multi-container-topology revisions. Real bug found and fixed here,
      with real cross-file impact: `SUPERVISOR_URL` was `http://gr-supervisor:8000`
      (the spec's literal value) in `run_scanner.py`, `scanner_red.py`'s
      `analyze()` default, **and** `graphrange/run_scenario.py` (Phase 7,
      copied from spec without questioning it) — that hostname only
      resolves from inside a container on the `graphrange-public` network,
      confirmed live to fail DNS resolution entirely from the host, which
      is where every actual Python execution in this project runs (all of
      this session's real Phase 4 tests connected via `localhost`
      successfully). This would have silently broken every live
      orchestration run — the health check would report the sandbox
      unavailable even though the supervisor genuinely was running and
      reachable, degrading every scenario to static-analysis-only for a
      completely wrong reason. Fixed in all three locations, confirmed live
      (`_check_range_health()` correctly flips from `False` to `True`
      after the fix, against the actually-running `gr-supervisor`
      container).
- [ ] `logs/tool_unavailable.log` — auto-created on first blocked phase
      (code path exists in `scanner_red.py`'s `_request_tool_for_phase()`,
      not yet exercised by a real blocked phase since that needs a live run)

### Dashboard extensions
- [~] Extend `dashboard/api/main.py` — `/api/telemetry`, `/api/llm/navigate`.
      Built 2026-08-10. `/api/telemetry` verified live: started the real
      FastAPI app (`uvicorn`), wrote real telemetry lines, confirmed the
      endpoint's summary math against them (2 calls, 300 in/130 out tokens,
      3.3s, correct cost sums) — cleaned up afterward. Corrected one real
      spec inconsistency while wiring `/api/llm/navigate`: the spec's Ollama
      call used `"think": false` as a JSON field, but this codebase's actual,
      already-proven Ollama calling convention everywhere else (narrowing.py,
      observer.py, tool_crawler.py) is a `/no_think` prefix in the message
      content, not a `think` field — used the real convention instead.
      **Not yet live-tested**: `/api/llm/navigate` itself (the one Qwen call)
      — same GPU checkpoint as the rest of this session's GPU-touching code.
- [~] `LLMSearch.jsx` — query → pan/zoom graph navigation
- [~] `TelemetryPanel.jsx` — polls `/api/telemetry` every 10s
- [~] Extend `GraphView.jsx` — `forwardRef` + `navigateTo()`
- [~] Extend `App.jsx` — wire `LLMSearch` + `TelemetryPanel`

      All four JSX items built 2026-08-10, matched precisely against the
      real existing component structure (not written blind from spec) —
      `TYPE_COLOR`/`#080814` palette already existed in the real
      `GraphView.jsx`, confirmed and reused rather than reinvented. Real
      `npm install` + `npm run build` (`vite build`) succeeded cleanly:
      1065 modules transformed, zero errors — confirms every import
      resolves and all four files are syntactically valid React. **Genuine
      limitation, stated plainly rather than implied as "done"**: no
      browser session is available in this environment, so none of this
      was verified at runtime — does the search box actually navigate,
      does the telemetry panel render and update correctly, does the pan/
      zoom animation work. A clean build is necessary but not sufficient
      for that; per CLAUDE.md's own standard for UI changes, this needs a
      real browser check before being called fully done. Also added
      `node_modules/` to `.gitignore` — running `npm install` for this
      verification created a real untracked one that wasn't excluded
      before.

      **Confirmed exactly right, real bug found**: the user ran the dev
      server and reported no search bar visible at all. Real cause: the
      `LLMSearch.jsx`/`TelemetryPanel.jsx` JSX was correct, but no CSS was
      ever added for either component — the spec being implemented from
      only provided JSX snippets, never a stylesheet addition, and this
      was missed writing the code since the build (which only checks
      JS/JSX compiles) has no way to catch a missing stylesheet rule.
      Added `.llm-search*`/`.telemetry-panel*`/`.tel-*` rules to
      `index.css`, matching the existing theme's real CSS variables
      (`--bg`/`--surface`/`--border`/`--text`/`--muted`/`--accent`) rather
      than inventing new colors. `TelemetryPanel` positioned as a fixed
      bottom overlay (matching its own collapsible-bar design intent,
      which doesn't fit `.workspace`'s row-flex layout as a plain sibling).
      Rebuilt clean (CSS bundle 4.44kB -> 6.25kB, confirming the rules
      landed). This is precisely the kind of gap the "not browser-verified"
      caveat was flagging — found the moment a real person actually looked,
      not from any test that ran.

- [~] `GraphChat.jsx` + `POST /api/chat` — conversational graph assistant,
      user-requested 2026-08-11 as an evolution of `LLMSearch`. Unlike
      `/api/llm/navigate` (always forces exactly one node lookup, returns a
      bare node_id), this holds a conversation and lets Qwen decide per-turn
      whether to ground its reply in a real graph node or answer directly —
      always replying with an explanation, never a bare id. When it does
      ground, the graph pans to that node (reuses the same `navigateTo`
      path as the search bar).
      - Backend: refactored the node-index/keyword-matching logic that used
        to live only inside `llm_navigate` into shared helpers
        (`_load_node_index`, `_keyword_candidates`, `_node_ref`), since
        `/api/chat` needs the identical keyword pre-filter to build its
        candidate set before the one Qwen call per turn.
      - Security: candidate node data (CVE/ATT&CK descriptions — external,
        NVD/MITRE-sourced text) is XML-wrapped before entering the prompt
        via `_wrap_candidates_xml()`, the same prompt-injection defense
        already established in this codebase for untrusted content
        (`graphrange/scanner/repo_intake.py`'s `read_file_safe()`). The
        system preamble explicitly tells the model to treat that block as
        data, never as instructions.
      - Measurement: `eval/chat_grounding_eval.py` — precision/recall over
        the grounding decision (should this query have grounded in a node,
        and did it ground in the *right* one), scored via a confusion
        matrix over a small hand-labeled test set. A grounded reply citing
        the wrong node counts as a false positive, not a true positive —
        scoring "grounded at all" as success would hide that failure mode.
        Scoring math verified against synthetic data (not live calls);
        confirms TP/FP/FN/TN counts and precision/recall arithmetic are
        correct before spending any real GPU time running it for real.
        **Run for real, 2026-08-12** (via the Kaggle-tunnel acceleration
        below): TP=4 FP=1 FN=0 TN=3 -- Precision 0.80, Recall 1.00. The one
        false positive: "how does this dashboard work?" grounded in T1613
        (Container and Resource Discovery) -- "work" survived the stopword
        filter and weakly matched that node's description text. Consistent
        with the already-documented residual gap (stopword list can't be
        exhaustive); not a new bug.
      - UI: `GraphChat.jsx` — semi-transparent floating panel inside
        `GraphView.jsx`'s `.graph-wrap` (not the header, per the user's
        explicit placement request), right-aligned, ~30% width (within the
        requested 25–37.5% range). Collapsed to a small toggle button by
        default.
      - Real bug found and fixed while wiring this: `App.jsx`'s
        `handleNavigate` checked `node.node_id`, but both
        `/api/llm/navigate` and `/api/graph` return the field as `id` — so
        every successful search from the *previous* session's fix was
        silently a no-op in the browser (correct data reached the frontend,
        nothing happened on screen, no error shown). Never caught because
        verification up to that point was all `curl` against the API
        directly, never through the actual UI code path. Fixed, and
        `GraphView.jsx`'s `navigateTo` was made more robust at the same
        time — it now resolves any `{id, ...}` ref against live
        `graphData` internally instead of requiring the caller to have
        already resolved it.
      - **Cost reality, stated plainly**: unlike the search bar's exact/
        keyword fast path, *every* chat turn is a real Qwen generation —
        there's no zero-GPU shortcut for producing a conversational reply.
        Confirmed via one live smoke-test call. The full 8-case eval sweep
        was deliberately **not** run yet (could plausibly take 15–40+
        minutes at this hardware's observed per-call latency) — held for
        an explicit go-ahead, same GPU-checkpoint discipline as every other
        Qwen-calling addition this session.
      - **Not yet browser-verified**: same standing caveat as the rest of
        the dashboard — build/logic confirmed, actual in-browser behavior
        (panel positioning, scroll, pan-on-ground) not yet checked by a
        real person.

      **Real bugs found by the user actually using it, fixed same session
      (2026-08-11):**
      1. A broad natural-language query ("what around here mentions screen
         capture?") took long enough to exceed the original 300s Ollama
         timeout, crashing with a bare unhandled `ReadTimeout` → generic
         500. Bumped to 600s (this hardware's inference latency has real,
         observed variance — anywhere from ~1 to 5+ minutes for the same
         query shape across this session, plausibly worsened by thermal
         effects under sustained back-to-back use) and added explicit
         `except`/`HTTPException` handling so a timeout now returns a clear
         504 with an actual explanation instead of crashing. Factored into
         a shared `_call_ollama()` helper used by both `/api/chat` and
         `/api/llm/navigate`.
      2. **Grounding was unreliable** — the original design asked the model
         to end its reply with a plain-text marker line
         (`GROUNDED_NODE: <id>`), parsed out via regex. This worked in most
         tests but silently failed on a real user query: the model's reply
         that time didn't conform to the exact expected trailing-line
         format, the regex found no match, and the raw marker text leaked
         into the visible chat bubble instead of being stripped — with
         `grounded_node` staying `null`, so the graph never panned.
         Confirmed via live reproduction: the identical conversation
         succeeded once and failed once, proving the marker-line convention
         was genuinely non-deterministic, not a one-off fluke.
         **User-suggested fix, implemented as asked**: replaced the
         text-marker convention with a single structured JSON response
         (`{"reply": ..., "grounded_node": ...}`), using Ollama's
         `format: "json"` request field — this constrains token sampling to
         guarantee syntactically valid JSON, not just a prompt instruction
         the model might not follow. `grounded_node` is still validated
         against the real graph before use, and a JSON-parse failure falls
         back to showing the raw text with no grounding rather than
         crashing or leaking malformed output. Re-tested against the exact
         failing conversation afterward — clean plain-text reply, correct
         `grounded_node`.
      3. Candidates were capped to `cap` in whatever arbitrary order Neo4j
         returned them, not ranked by relevance — a query matching many
         nodes weakly on one word could push the actually-best match past
         the cap before the LLM ever saw it. Fixed by scoring candidates on
         number of matching words and sorting before capping. Verified live
         with "what around here is about screen capture" — the real answer
         (T1113, Screen Capture) now ranks #1 instead of relying on luck.
      4. Loose substring matching ("hi" matching "th**is**", "wh**i**ch",
         etc.) meant a plain greeting never actually produced zero
         candidates — it just matched noise, which (combined with chat's
         now-removed "dump everything if nothing matched" fallback,
         inherited from search but wrong for chat) meant even a bare "hi"
         got a large, slow, irrelevant prompt. Fixed with real word-
         boundary matching (a precomputed word-set per node), a stopword
         list (common English filler + "cve", present in every single
         vulnerability node's own id so it has zero discriminating power on
         its own), and a structured-ID regex (`CVE-\d{4}-\d{3,7}`,
         `T\d{4}(\.\d{3})?`, `TA\d{4}`) so an id embedded in a full sentence
         ("What is CVE-1999-1471?") resolves as a direct exact match
         instead of diluting into generic word overlap. "hi" dropped from
         52s (empty-ish prompt, but still a real generation call) to a
         clean zero-candidate path; a genuinely irrelevant single-candidate
         edge case ("thanks, that's helpful" weakly matching "helpful") was
         left as an accepted residual gap — a stopword list can't be
         exhaustive, and the system prompt already tells the model to
         decline an irrelevant candidate rather than force it.
      5. **Grounded but no navigation** — found via the user's own
         prompt-injection security test (asked the model to force-ground
         CVE-1999-1471; it did, and the reply correctly refused to leak the
         system prompt, but the graph never panned). Root cause:
         `/api/graph` only renders the 800 most-recently-updated nodes out
         of ~3672 real ones (a rendering-performance cap, not a bug) --
         confirmed live that CVE-1999-1471 (`last_updated` 2026-05-27) isn't
         in that top-800 slice, so `GraphView.jsx`'s `navigateToNode` found
         nothing to pan to and silently returned. Fixed by falling back to
         opening the node's detail sidebar (which fetches by id directly
         via `/api/node/{id}`, independent of what's rendered) instead of
         dropping the result on the floor when a grounded node isn't part
         of the currently-visible graph.

      **Injection test result, for the record**: the system-prompt-leak
      request was refused cleanly. The forced-grounding half is a genuine
      but ambiguous partial finding -- the injection text itself literally
      contained "CVE-1999-1471", which the retrieval layer's own
      structured-ID detection would surface as a legitimate candidate
      independent of any injection effect, so this doesn't cleanly
      demonstrate the model being manipulated into fabricating a grounding.
      A cleaner follow-up test would use an injection naming a *different*
      node than the one it's trying to force, to isolate retrieval-layer
      behavior from actual instruction-following compliance.

### Evaluation harness (`eval/`) — research tool, not part of the product
- [x] `ground_truth.py` — WebGoat GitHub advisories + `SECURITY.md` loader.
      Built and verified live 2026-08-10 against the real WebGoat repo (not
      mocked). **Real, substantive finding**: both spec-defined sources are
      currently empty for WebGoat specifically — the Security Advisories
      API returns `[]` (checked live), and `SECURITY.md` 404s at every
      candidate location tried (repo root and `.github/`, both on `main`,
      WebGoat's confirmed default branch). This isn't a bug — WebGoat is an
      intentionally vulnerable teaching application; its vulnerabilities
      are deliberately inserted lesson content, not accidentally-introduced
      flaws that go through responsible disclosure and get a CVE/GHSA
      assigned to the project itself. The spec's CVE-advisory ground-truth
      approach is a real mismatch for this specific target (though the code
      is still correct and would work against a repo with real published
      advisories — verified the parsing path separately with a
      schema-accurate synthetic response since no live repo checked had
      real data to test against). Handled gracefully, not silently: an
      empty ground truth writes a real `eval/ground_truth.md` explaining
      why, so comparison results don't look like a scanner failure when
      they're actually a ground-truth availability gap.

      **Generalized 2026-08-12** to take a target repo instead of assuming
      WebGoat, and a real working ground truth found: checked several real
      candidates live via the same API this module calls (`go-gitea/gitea`
      30 advisories, `strapi/strapi` 21, `grafana/grafana` 28,
      `nocodb/nocodb` 30 -- all real, but large platform repos that would
      take far longer to actually scan than the time is worth). Landed on
      `axios/axios`: 30 advisories, **every one with a real assigned CVE
      ID** (confirmed live, not assumed), small focused codebase, real
      vulnerability classes a code-level scanner should be able to pattern-
      match (prototype pollution, ReDoS via recursion, proxy-bypass,
      request-smuggling-adjacent bugs). Set as the new default target for
      `eval/run_eval.py`. Also fixed a real latent bug while generalizing:
      the original code hardcoded `main` as WebGoat's branch for SECURITY.md
      lookups -- axios's real default branch is `v1.x`, confirmed live; now
      resolved dynamically via the GitHub API instead of assumed.
- [x] `comparator.py` — Table A (CVE-joined) + Table B (code-level) + Qwen
      summary. Built and verified 2026-08-10 with realistic data — `compare()`'s
      core join/coverage logic confirmed correct (0.5 coverage on a 1-of-2
      real match, correct missed-CVE list). Found and fixed a real rendering
      bug: `_md_table()`'s column-to-dict-key mapping was auto-derived from
      the column display string (`"CVE".lower()` → `"cve"`), but the real
      key is `"cve_id"` — silently rendered an empty CVE column, confirmed
      via a real test before fixing with an explicit mapping.
      **Live-tested 2026-08-12** (Kaggle P100): the one Qwen summary call,
      given a realistic synthetic comparison result, produced a genuinely
      coherent 4-paragraph analysis (correctly reasoned about the 50%
      coverage, the code-only XSS finding, and the missed CVE), 25.9s.
- [x] `false_positive_analyzer.py` — classifies unvalidated Table A findings.
      Built and verified 2026-08-10 against real Neo4j data (a real node,
      `CVE-1999-0168`, used as a real example throughout this session).
      Found and fixed two real gaps: (1) the spec's `analyze(comparison)`
      signature doesn't take a `driver`, but its own docstring requires a
      real graph lookup — added an optional `driver` parameter that
      degrades gracefully when absent, rather than silently never doing the
      check the spec itself describes; (2) the reason message for "in graph
      but grain_confidence <=0.5" was misleadingly identical to "not
      checked at all" — confirmed live (the real node has grain_confidence
      0.4, correctly below the 0.5 bar, but the message claimed it was
      "not yet cross-checked" when it genuinely had been) — fixed to
      distinguish all three real cases (not real CVE format / in graph
      with sufficient confidence / in graph with low confidence / not in
      graph at all) rather than collapsing two different findings into one
      misleading message.
- [x] `defense_plan.py` — Claude Code prompt generator for `eval/defense_plan.md`.
      Built and verified 2026-08-10 — trivial by design (just prints a
      prompt), confirmed it runs and produces the real prompt text.
- [x] `run_eval.py` — orchestrator: `run_scanner()` on WebGoat → compare → report.
      Built 2026-08-10, full import chain verified clean (confirms
      `run_scanner`, `graphrange.telemetry`, and every eval module compose
      correctly together). Uses the real WebGoat GitHub URL directly rather
      than the spec's `WEBGOAT_CLONE="/tmp/webgoat"` pre-cloned-path
      assumption — `run_scanner()`'s real signature (this session's later
      repo_intake revision) takes a URL/path directly and stages it itself,
      so there's no separate clone step needed first. **Not yet
      live-tested end to end** — depends on `run_scanner()`, which depends
      on every GPU-touching module already flagged; same checkpoint.
- [x] `requirements.txt` — added `reportlab==4.1.0`, `tiktoken==0.7.0`,
      `pyyaml==6.0.3`; pinned `psutil==7.2.2` (the real already-installed
      version) instead of the spec's `5.9.8` guess.

---

*See [PLAN.md](PLAN.md) for the v0 definition of done and
[PRODUCT_HOSTING_HANDOFF.md](PRODUCT_HOSTING_HANDOFF.md) for the hosting strategy.*
