# The Scanner Saga — 2026-08-24 to 2026-08-27

A narrative account of what happened getting P2.1-P2.3 (live GraphRange
scenarios + the Scanner product against a real repo) from "coded but
untested" to "real, working, and understood." For the dense reference
version, see `ROADMAP.md`'s P2 section — this file is the story.

---

## Chapter 1 — P2.1: GraphRange goes live (2026-08-24)

Three real scenarios — MySQL, Cyrus, Apache — run end to end through
`run_one()` for the first time. Two real, pre-existing bugs found and
fixed along the way:

1. `run_one()` never actually called `spawn_scenario()`. It assumed
   containers already existed and just tried to `/exec` into them.
   They didn't exist. Every attempt failed with `supervisor_error`.
2. `supervisor.py` never called `load_dotenv()`, so it silently used a
   hardcoded `host.docker.internal` Neo4j address — correct only from
   inside a container, wrong for this project's actual host-native
   deployment. Every `/tool_request` call hung ~23 seconds on a real
   Windows connection-refused error before failing.

Fixed both. Reran. All three scenarios completed cleanly: real spawn,
real plan, real execution, real (if unexciting — `stalemate`, since red
only had a generic `nmap` scanner, not a weaponized exploit) outcome.
**P2.1: done.**

## Chapter 2 — Turning to P2.2/P2.3: the Scanner meets WebGoat

Next up: prove the Scanner product's still-unverified GPU-live paths
work — `file_scanner`, `victim_builder`'s compose inference, and
`scanner_red`/`scanner_blue`'s dynamic analysis — against a real,
external repo. WebGoat (OWASP's intentionally-vulnerable training app)
was the target, explicitly named in the roadmap alongside axios.

First real finding: `victim_builder._infer_compose_from_manifests()`
correctly identified WebGoat's ecosystem (`java_maven`) from its
`pom.xml`, but picked `openjdk:17` as the base image — a real,
deprecated, removed Docker Hub tag (verified live: 404 from Docker
Hub's own API). Not a fluke: across five separate live attempts, this
function failed **five different ways** — the deprecated image, a raw
`${project.version}` Maven property copied verbatim into an image tag,
a plain YAML syntax error, a plausible-but-wrong `owasp/webgoat` org
guess (the real one is `webgoat/webgoat`), and an attempt to `docker
build` from WebGoat's own Dockerfile without ever running the Maven
build it needs.

The fix that actually worked: **read the repo's own README first.**
WebGoat's README documents the real, correct way to run it —
`docker run ... webgoat/webgoat` — directly. Once that got fed to the
model as grounding context instead of leaving it to guess blind from a
bare manifest file, it got the image right on the very next attempt,
zero retries needed. A general fix, not a WebGoat hack: any
well-documented repo benefits the same way.

Also built along the way: a general "ask Qwen to fix its own compose
file, given the real failure" reconcile loop (deliberately *not*
hand-coding a fix for each failure mode discovered — that would only
ever cover cases already seen) with a hard exception carved out for
genuine safety-boundary violations (unsafe Docker flags, disallowed
registries), which never get "fixed," only rejected outright.

## Chapter 3 — Kaggle runs dry, Colab enters the story

Partway through scaling this up, Kaggle's weekly 30-hour GPU quota hit
its ceiling. Rather than wait, went looking for an alternative — and
found something genuinely new: Google shipped an **official** headless
CLI for Colab in June 2026 (`google-colab-cli`), well past training
data's knowledge. Real `colab new --gpu T4`, real SSH via
`colab ssh --proxy-mode`, no browser tab required to keep it alive.

Set it up through WSL2 Ubuntu (Windows isn't supported directly),
generated an SSH key, configured a `ProxyCommand`, and reached a real
Tesla T4 with 14.6 GiB VRAM. Installed Ollama (same `zstd`-missing
gotcha as the old Kaggle kernel), pulled `qwen3:8b`, and forwarded the
VM's port 11434 to local port 19434 via the SSH tunnel — reachable from
native Windows processes too, thanks to WSL2's default localhost
forwarding.

First real throughput lesson, learned the hard way: naive "3 workers
should mean 3x speed" was wrong **twice**, in opposite directions. First,
Ollama defaulted to `OLLAMA_NUM_PARALLEL=1`, so three "parallel" client
workers were just queuing behind each other — real pace ~27.7s/file
instead of the assumed ~17.6s/3-workers. Fixed that, bumped to
`NUM_PARALLEL=6`... and throughput got *worse* (142s for 6 concurrent
calls). A real sweep (N=1/2/4) found the actual story: a T4 is
compute-bound at ~2 concurrent 8B-model streams, not queue-bound —
13.1s → 8.6s → 8.5s (flat). `NUM_PARALLEL=2` was the real, measured
optimum, not a bigger number.

## Chapter 4 — The account-death saga

Then the sessions started dying. Not from anything we did — Colab's own
backend killing them mid-task, no warning, `colab status` sometimes not
even reflecting it (a stale-but-still-listed session, SSH endpoint
already gone). First death cost nothing serious. Second death, on a
different Google account, hit right as a real ~13-hour local WebGoat
scan was closing in on completion — total loss, since `scan_repo()` held
everything in memory with zero persistence.

That loss forced the first checkpoint: `scan_repo()` now saves completed
work units to disk every 10 completions, atomic writes, resumable
against the same staged path. `_merge_call()` also learned to catch a
dead connection and degrade to an unmerged flag instead of crashing the
whole pass — the exact failure that had just happened.

Reran locally (the only compute left once Kaggle *and* all three Colab
accounts had hit real limits the same day). Real, stable local pace:
~200-220s per reasoning call, checked for drift across the whole run —
genuinely flat, no thermal throttling, no speedup. 385 flags later
(~21 hours), Pass 2 finished... and revealed something worse than any
crash: **all 385 flags came back as "vulnerabilities."** Zero
filtering, anywhere in the pipeline. `reason_over_flags()` had no
concept of "this isn't real" — it just relabeled every static-analysis
guess as confirmed, and each one downstream costs 5-9x more compute
than the reasoning step alone. At that rate, full dynamic analysis on
all 385 was another ~109-192 hours. Killed it one item in.

## Chapter 5 — Four real fixes, not four hacks

The honest question: is the *productized* Scanner just never going to
be local-only viable at this rate? The answer led to actually fixing
the architecture instead of throwing more (or faster) hardware at it:

1. **Real triage** — `_reason_block()`'s prompt now asks Qwen to judge
   `is_genuine_finding`, and the code actually acts on it.
2. **Severity gate** — only `Critical`/`High` findings get the expensive
   dynamic analysis; everything else still appears in the report with
   real static detail, just no live exploit attempt.
3. **Scope reduction** — excluded documentation (WebGoat alone had 274
   `.adoc` lesson write-ups, each burning a full Qwen call for a
   guaranteed empty result) and test/spec directories, a general SAST
   convention.
4. **Deduplication** — Critical/High findings cluster by
   `(vuln_type, cwe)`; one real representative per cluster gets full
   dynamic verification, the rest honestly reference that result.

Each was unit-tested before trusting it on a real run — including
catching a real mistake along the way: an early version hardcoded "for
Java use eclipse-temurin" directly into the compose prompt. That would
have made the very next test look like it passed, while actually
proving nothing about whether the *general* reconcile mechanism worked.
Reverted it once that was clear, and let the general mechanism earn its
result honestly instead.

## Chapter 6 — Round two, checkpointed everywhere, still fighting Colab

With Pass 2 now also checkpointed (same atomic-write pattern, verified
live: a 2-call test where the second call resumed in 0.0 seconds), and
with the scope reduction cutting real work units from 1355 to 936 with
**zero loss of real findings**, the full run went again — this time on
a fresh Colab session, since checkpointing finally made the risk of
another death tolerable.

It died anyway. Four more times, across all three Google accounts,
session lifetimes ranging from 24 minutes to several hours with no
discernible pattern. But every death now cost only its own short
session's progress — the checkpoint held. Real, valuable data emerged
regardless: 190 of 385 flags reasoned over for real, clustering into 83
distinct vulnerability patterns, and — the genuinely good sign — that
cluster count is growing *sub-linearly* and slowing down (+8 clusters
for +23 flags, then +3 for +11): strong live evidence the dedup fix
works, projecting to roughly 112-122 total clusters for the full run,
not 385 individual analyses.

One more real bug surfaced in the wreckage: multiple copies of the same
script were found still running in the background, each one having
already printed "DONE" and been reported "completed" — but never
actually exiting. Root cause: `_analyze_finding()` started blue's
monitoring thread before calling red's analysis, but only stopped that
thread on the *success* path. Every time red's call failed (which, with
a dead tunnel, was every time), the function exited via the exception
without ever telling the monitor thread to stop — and a thread that's
never told to stop doesn't. It just keeps running, forever, blocking
the whole process from exiting, silently racing every other copy to
write the same checkpoint file. Fixed with a `finally` block.

## Chapter 7 — Where it stands

All three Colab accounts hit real per-day limits in the same session —
two "Service Unavailable," one a new error entirely,
`TooManyAssignmentsError`. Kaggle's weekly quota, checked again, is
still exhausted too. Real per-call rate comparison across the day's six
Colab sessions: Colab averages ~84s/call when it's actually available
(2.5x faster than local's steady ~200-220s), but "available" turned out
to be the real constraint all along, not speed.

Estimated work remaining: ~49-72 hours locally, or ~20-29 hours of raw
compute on Colab if a session survives long enough to use it — plus
real per-session setup overhead every time one dies. A live web search
turned up **Lightning AI** as an untested, genuinely different
candidate: real SSH terminal access (not adapted from a notebook UI),
80 free GPU hours/month, and critically, *persistent* storage — Ollama
and the model would survive between sessions instead of needing a full
reinstall every single time, the way Colab does. Not yet tried.

The honest throughline: every real number in this story came from
actually measuring, not assuming — and every time an assumption *did*
sneak in (the parallelism guess, the hardcoded compose-prompt hint, the
"it printed DONE so it's done" read on the zombie processes), it turned
out to be wrong in a way that only showed up once someone went and
checked.
