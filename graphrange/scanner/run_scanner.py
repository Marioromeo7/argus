"""
ARGUS-SCANNER: Full scanner pipeline. Entry point for the product. Takes a
GitHub URL or local repo path. Produces a vulnerability + mitigation
report. Synthesizes the base pipeline spec with its later revisions
(repo_intake as the mandatory first step, multi-container topology
replacing a single victim image, parallel red/blue execution coordinated
via a shared stop_event) into one final orchestrator.
"""

import json
import os
import threading

from graphrange.scanner.repo_intake import intake
from graphrange.scanner.victim_builder import build_victim_topology, teardown_victim_topology
from graphrange.scanner.file_scanner import scan_repo
from graphrange.scanner.vuln_reasoner import reason_over_flags
from graphrange.scanner.scanner_red import analyze as red_analyze
from graphrange.scanner.scanner_red import _find_hardcoded_credentials
from graphrange.scanner.scanner_blue import analyze as blue_analyze, monitor_topology
from graphrange.scanner.scanner_report import write_scanner_report
from graphrange.telemetry import print_summary
from graph.retrieval import get_driver

# See graphrange/run_scenario.py's SUPERVISOR_URL comment -- the spec's
# Docker-internal hostname doesn't resolve from the host, confirmed live.
SUPERVISOR_URL = "http://localhost:8000"
BLUE_JOIN_TIMEOUT = 30

# Only these severities get the expensive dynamic (red/blue) analysis --
# found live 2026-08-25 on a real WebGoat scan: every one of 385 identified
# vulnerabilities was getting the full treatment regardless of severity, at
# 5-9x the compute cost of reasoning alone. Lower-severity findings still
# appear in the report with their real static reasoning detail, just
# without a live exploit attempt.
_DYNAMIC_ANALYSIS_MIN_SEVERITY = {"Critical", "High"}


def _cluster_key(vc: dict) -> tuple:
    """ARGUS-SCANNER: Groups findings that are structurally the same
    pattern -- found live 2026-08-25: WebGoat (deliberately, as a training
    app) has many separate lesson variants of the same vuln_type/cwe. Only
    one real representative per (vuln_type, cwe) gets full dynamic
    verification; the rest reuse that real result by reference rather than
    re-paying the same cost for what's structurally the same finding."""
    return (vc.get("vuln_type", ""), vc.get("cwe", ""))


def _skipped_red(vc: dict, reason: str) -> dict:
    """ARGUS-SCANNER: A report-compatible placeholder matching
    scanner_red.analyze()'s real return shape, for a finding that never
    got dynamic analysis (low severity, or reusing a cluster
    representative's real result instead)."""
    return {
        "vuln_context": vc, "matched_technique_id": "", "matched_cve_id": "",
        "exploitation_path": "", "attack_steps": [], "attack_plan": {},
        "execution_result": {"status": "skipped", "reason": reason, "phases": [],
                              "kill_chain_complete": False, "final_service_reached": ""},
        "source": "scanner_red",
    }


def _skipped_blue(vc: dict) -> dict:
    """ARGUS-SCANNER: A report-compatible placeholder matching
    scanner_blue.analyze()'s real return shape, paired with _skipped_red."""
    return {
        "vuln_context": vc, "code_fix": "", "detection_rule": "",
        "static_advice": "", "execution_detected": False, "detection_events": [],
        "argus_mitigations": [], "priority": vc.get("severity", "Low"),
        "detected_overall": False, "phases_detected": [], "phases_missed": [],
        "missed_lateral": False, "source": "scanner_blue",
    }


def _check_range_health() -> bool:
    """ARGUS-SCANNER: Verifies the GraphRange supervisor is reachable --
    without it there's no sandbox, and every downstream step must degrade
    to static-analysis-only rather than pretend execution is available."""
    import requests
    try:
        return requests.get(f"{SUPERVISOR_URL}/health", timeout=5).status_code == 200
    except requests.RequestException:
        return False


def _dynamic_checkpoint_path(repo_path: str) -> str:
    return os.path.join(repo_path, ".argus_dynamic_checkpoint.json")


def _cluster_key_str(key: tuple) -> str:
    return "||".join(key)


def _load_dynamic_checkpoint(repo_path: str) -> dict:
    path = _dynamic_checkpoint_path(repo_path)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_dynamic_checkpoint(repo_path: str, checkpoint: dict) -> None:
    """Atomic write, same pattern as file_scanner.py/vuln_reasoner.py's
    checkpoints. Found live 2026-08-27: a Colab tunnel died at the exact
    moment Pass 2 finished and Pass 3 (dynamic red/blue analysis) began --
    every one of 128 cluster representatives failed with a connection
    error, and since this loop had no checkpoint, the whole pass (the
    single most expensive part of the pipeline, red+blue running live
    exploit attempts) had to be redone from zero. Each cluster's real
    result (plus its placeholder entries for duplicate group members) is
    now saved to disk the moment it completes -- one cluster lost to a
    dead tunnel now costs one cluster, not the whole pass."""
    path = _dynamic_checkpoint_path(repo_path)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(checkpoint, f)
    os.replace(tmp, path)


def run_dynamic_analysis(
    vuln_contexts: list, topology: dict, driver, sandbox: bool,
    repo_path: str | None = None,
) -> list:
    """
    ARGUS-SCANNER: Pass 3 -- severity-gates and clusters vuln_contexts,
    runs full red/blue dynamic analysis on one representative per
    (vuln_type, cwe) cluster, and builds placeholder entries for
    everything else (duplicate cluster members, and low-severity
    findings that never get dynamic analysis at all). Extracted out of
    run_scanner() so both the product entry point and any resume/repeat
    run against the same repo_path share one checkpointed implementation
    instead of two copies that can drift.

    Checkpointed to .argus_dynamic_checkpoint.json inside repo_path when
    repo_path is given (added 2026-08-27, see _save_dynamic_checkpoint's
    comment) -- keyed by the cluster's (vuln_type, cwe), each entry holds
    that cluster's full contribution to `findings` (the representative's
    real result plus its group's placeholder entries), so a resumed run
    just replays cached clusters instead of re-running red/blue on them.
    """
    checkpoint = _load_dynamic_checkpoint(repo_path) if repo_path else {}
    to_analyze, low_severity = [], []
    for vc in vuln_contexts:
        (to_analyze if vc.get("severity") in _DYNAMIC_ANALYSIS_MIN_SEVERITY
         else low_severity).append(vc)
    print(f"[Scanner] {len(to_analyze)}/{len(vuln_contexts)} are Critical/High "
          f"severity -- only these get full dynamic analysis")

    # Runs once per scan, over every finding (not just Critical/High) --
    # a hardcoded-credentials finding might be flagged at any severity.
    # The result is reused as the login for every cluster's exploitation
    # phases below, turning one already-detected finding into the key
    # that unlocks testing every other authenticated endpoint.
    known_credentials = _find_hardcoded_credentials(vuln_contexts, driver) if sandbox else {}
    if known_credentials:
        print(f"[Scanner] found real hardcoded credentials in-scan "
              f"(user: {known_credentials['username']!r}) -- reusing them "
              f"to authenticate red's exploitation attempts")

    clusters = {}
    for vc in to_analyze:
        clusters.setdefault(_cluster_key(vc), []).append(vc)
    print(f"[Scanner] {len(to_analyze)} Critical/High findings cluster into "
          f"{len(clusters)} distinct (vuln_type, cwe) pattern(s)")

    findings = []
    for i, (key, group) in enumerate(clusters.items()):
        representative = group[0]
        ckey = _cluster_key_str(key)
        if ckey in checkpoint:
            print(f"[Scanner] {i + 1}/{len(clusters)} pattern {key} -- "
                  f"resumed from checkpoint")
            findings.extend(checkpoint[ckey])
            continue

        print(f"[Scanner] {i + 1}/{len(clusters)} pattern {key} "
              f"({len(group)} similar finding(s)) -- analyzing "
              f"{representative.get('filepath', '?')}")
        # Same graceful-skip discipline as vuln_reasoner.py's
        # reason_over_flags() and file_scanner.py's scan_repo() -- one
        # finding's red/blue Ollama calls failing shouldn't crash the
        # whole scan and lose every finding already analyzed.
        try:
            result = _analyze_finding(representative, topology, driver, sandbox,
                                       known_credentials=known_credentials)
        except Exception as e:
            print(f"[Scanner]   skipping {representative.get('filepath', '?')}: {e}")
            continue
        cluster_findings = [result]
        for other in group[1:]:
            red = dict(_skipped_red(
                other, f"same pattern as {representative.get('filepath', '?')} "
                       f"({key[0]}/{key[1]}) -- reusing that finding's real "
                       f"dynamic-analysis result, not independently verified"))
            red["matched_technique_id"] = result["red"].get("matched_technique_id", "")
            red["matched_cve_id"] = result["red"].get("matched_cve_id", "")
            # Deliberately NOT overwriting execution_result with the
            # representative's real result -- found live 2026-08-29 on the
            # completed WebGoat report: doing that replaced _skipped_red()'s
            # "skipped, reason: same pattern as X" placeholder wholesale,
            # so every duplicate finding (~70 of 210 in that run) rendered
            # with the representative's real kill-chain table as if it had
            # been independently verified, with zero indication it was a
            # reused result. Leaving it as the skipped placeholder is what
            # actually makes write_scanner_report() show the disclosure.
            blue = dict(_skipped_blue(other))
            blue["code_fix"] = result["blue"].get("code_fix", "")
            blue["detection_rule"] = result["blue"].get("detection_rule", "")
            blue["static_advice"] = result["blue"].get("static_advice", "")
            cluster_findings.append({"vuln_context": other, "red": red, "blue": blue})

        findings.extend(cluster_findings)
        if repo_path:
            checkpoint[ckey] = cluster_findings
            _save_dynamic_checkpoint(repo_path, checkpoint)

    for vc in low_severity:
        findings.append({
            "vuln_context": vc,
            "red": _skipped_red(vc, f"severity {vc.get('severity', '?')} -- "
                                     f"static analysis only, no dynamic "
                                     f"verification attempted"),
            "blue": _skipped_blue(vc),
        })

    return findings


def _analyze_finding(vc: dict, topology: dict, driver, sandbox: bool,
                      known_credentials: dict | None = None) -> dict:
    """
    ARGUS-SCANNER: Runs red and blue in parallel for one VulnContext --
    blue's monitoring thread starts before red executes and only stops
    once red is done, so it actually observes red's activity rather than
    running sequentially after the fact.

    stop_event.set() + blue_thread.join() are in a finally block -- found
    live 2026-08-26/27: when red_analyze() raised (a dead Colab tunnel,
    repeatedly, across many failed cluster attempts in a row), the
    original code jumped straight out of this function on the exception,
    NEVER reaching stop_event.set(). monitor_topology()'s per-service
    threads only ever stop on that event, so each failed attempt left a
    full set of live, non-daemon threads behind forever -- these block
    the Python process from exiting even after the calling script prints
    "DONE" and returns, which is exactly what produced multiple lingering
    `resume_p2_3_webgoat.py` processes that looked "completed" (per their
    own log) but never actually terminated, and kept racing each other to
    write the same checkpoint file.
    """
    if not sandbox:
        red = red_analyze(vc, topology, driver, sandbox=False)
        blue = blue_analyze(vc, red, topology, driver, sandbox=False)
        return {"vuln_context": vc, "red": red, "blue": blue}

    monitor_result = {}
    stop_event = threading.Event()

    def _run_blue_monitor():
        monitor_result["events"] = monitor_topology(topology, SUPERVISOR_URL, stop_event)

    blue_thread = threading.Thread(target=_run_blue_monitor)
    blue_thread.start()

    try:
        red = red_analyze(vc, topology, driver, sandbox=True, supervisor_url=SUPERVISOR_URL,
                           known_credentials=known_credentials)
    finally:
        stop_event.set()
        blue_thread.join(timeout=BLUE_JOIN_TIMEOUT)
    shared_events = monitor_result.get("events", [])

    blue = blue_analyze(vc, red, topology, driver, sandbox=True, shared_events=shared_events)
    return {"vuln_context": vc, "red": red, "blue": blue}


def run_scanner(source: str, output_prefix: str = "reports/scanner") -> list:
    """
    ARGUS-SCANNER: Full pipeline.
    1. Stage and validate the repo (the mandatory first step -- no file
       reaches anything downstream without passing through repo_intake)
    2. Check sandbox health -> set sandbox flag
    3. Build victim topology from the staged repo
    4. Pass 1: scan_repo() -> flags
    5. Pass 2: reason_over_flags() -> vuln_contexts
    6. Red + blue in parallel per vuln_context
    7. write_scanner_report()
    8. print_summary() -- telemetry
    9. Teardown victim topology
    10. Return findings
    """
    os.makedirs("reports", exist_ok=True)
    driver = get_driver()

    print(f"[Scanner] Validating and staging repo from: {source}")
    try:
        repo_path = intake(source)
    except ValueError as e:
        print(f"[Scanner] Intake failed: {e}")
        driver.close()
        return []
    print(f"[Scanner] Staged to: {repo_path}")

    sandbox = _check_range_health()
    if not sandbox:
        print("[Scanner] Sandbox unavailable — static analysis only.")
        print("          Start range: docker compose --profile graphrange up -d")

    topology = None
    findings = []
    try:
        if sandbox:
            print(f"[Scanner] Building victim topology from {repo_path}...")
            topology = build_victim_topology(repo_path)
            print(f"[Scanner] {len(topology['services'])} services: "
                  f"{[s['name'] for s in topology['services']]}")
        else:
            topology = {"compose_file": "", "services": [], "network_map": {}}

        print("[Scanner] Pass 1 — scanning all files...")
        flags = scan_repo(repo_path)
        print(f"[Scanner] {len(flags)} flags found")

        print("[Scanner] Pass 2 — deep reasoning...")
        vuln_contexts = reason_over_flags(flags, repo_path=repo_path)
        print(f"[Scanner] {len(vuln_contexts)} genuine vulnerabilities identified")

        print("[Scanner] Pass 3 — dynamic red/blue analysis...")
        findings = run_dynamic_analysis(
            vuln_contexts, topology, driver, sandbox, repo_path=repo_path)

        write_scanner_report(findings, output_prefix)
        print_summary()
    finally:
        if topology and topology.get("compose_file"):
            teardown_victim_topology(topology)
        driver.close()

    return findings


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python -m graphrange.scanner.run_scanner <repo_url_or_path>")
        sys.exit(1)
    run_scanner(sys.argv[1])
