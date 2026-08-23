"""
ARGUS-SCANNER: Full scanner pipeline. Entry point for the product. Takes a
GitHub URL or local repo path. Produces a vulnerability + mitigation
report. Synthesizes the base pipeline spec with its later revisions
(repo_intake as the mandatory first step, multi-container topology
replacing a single victim image, parallel red/blue execution coordinated
via a shared stop_event) into one final orchestrator.
"""

import os
import threading

from graphrange.scanner.repo_intake import intake
from graphrange.scanner.victim_builder import build_victim_topology, teardown_victim_topology
from graphrange.scanner.file_scanner import scan_repo
from graphrange.scanner.vuln_reasoner import reason_over_flags
from graphrange.scanner.scanner_red import analyze as red_analyze
from graphrange.scanner.scanner_blue import analyze as blue_analyze, monitor_topology
from graphrange.scanner.scanner_report import write_scanner_report
from graphrange.telemetry import print_summary
from graph.retrieval import get_driver

# See graphrange/run_scenario.py's SUPERVISOR_URL comment -- the spec's
# Docker-internal hostname doesn't resolve from the host, confirmed live.
SUPERVISOR_URL = "http://localhost:8000"
BLUE_JOIN_TIMEOUT = 30


def _check_range_health() -> bool:
    """ARGUS-SCANNER: Verifies the GraphRange supervisor is reachable --
    without it there's no sandbox, and every downstream step must degrade
    to static-analysis-only rather than pretend execution is available."""
    import requests
    try:
        return requests.get(f"{SUPERVISOR_URL}/health", timeout=5).status_code == 200
    except requests.RequestException:
        return False


def _analyze_finding(vc: dict, topology: dict, driver, sandbox: bool) -> dict:
    """
    ARGUS-SCANNER: Runs red and blue in parallel for one VulnContext --
    blue's monitoring thread starts before red executes and only stops
    once red is done, so it actually observes red's activity rather than
    running sequentially after the fact.
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

    red = red_analyze(vc, topology, driver, sandbox=True, supervisor_url=SUPERVISOR_URL)

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
        vuln_contexts = reason_over_flags(flags)
        print(f"[Scanner] {len(vuln_contexts)} vulnerabilities identified")

        for i, vc in enumerate(vuln_contexts):
            print(f"[Scanner] {i + 1}/{len(vuln_contexts)} "
                  f"{vc.get('vuln_type', '?')} in {vc.get('filepath', '?')}")
            # Same graceful-skip discipline as vuln_reasoner.py's
            # reason_over_flags() and file_scanner.py's scan_repo() -- one
            # finding's red/blue Ollama calls failing shouldn't crash the
            # whole scan and lose every finding already analyzed.
            try:
                findings.append(_analyze_finding(vc, topology, driver, sandbox))
            except Exception as e:
                print(f"[Scanner] skipping {vc.get('filepath', '?')}: {e}")

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
