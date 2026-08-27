"""
ARGUS-LAYER-7: Scenario Runner (GraphRange Phase 7).
End-to-end orchestration -- wires plan_attack()/execute_attack() (red),
monitor()/assess_detection() (blue), and the graph updater into one real
scenario execution. This is the main entry point for GraphRange execution.
"""

import threading
import time
from datetime import datetime

import requests

from graphrange.scenario_generator import get_valid_scenarios, mark_scenario_complete
from graphrange.graph_updater import (
    write_scenario_run, write_outcome, update_technique_confidence,
    check_and_flag_conflict, update_scenario_run_status, hash_victim_config,
)
from agents.red import plan_attack, execute_attack
from agents.blue import monitor, assess_detection
from graph.retrieval import get_driver

# Spec text uses the Docker-internal hostname "gr-supervisor", which only
# resolves from inside a container on the same graphrange-public network.
# Every actual Python execution in this project runs on the host (all of
# this session's live Phase 4 tests connected via localhost successfully;
# confirmed live 2026-08-10 that "gr-supervisor" fails DNS resolution
# entirely from here) -- localhost is the value that's actually reachable.
SUPERVISOR_URL = "http://localhost:8000"
MONITOR_JOIN_TIMEOUT = 30  # seconds


def _check_plan_matches_scenario(engagement: dict, scenario: dict) -> dict:
    """D5 cross-check: does the chain red actually planned reference the CVE and
    technique of the scenario it was asked to test? A mismatch means "what red
    planned" and "what got measured" diverged -- recorded in the result, not
    raised. Chain hops are {node_id,label,type}; scenarios carry
    cve_id/technique_id."""
    chain = (engagement or {}).get("selected_chain") or []
    target_cve = (scenario or {}).get("cve_id", "")
    target_tech = (scenario or {}).get("technique_id", "")
    planned_cves = [h.get("node_id") for h in chain
                    if isinstance(h, dict) and h.get("type") == "vulnerability"]
    planned_techs = [h.get("node_id") for h in chain
                     if isinstance(h, dict) and h.get("type") == "technique"]
    cve_match = (target_cve in planned_cves) if target_cve else None
    tech_match = (target_tech in planned_techs) if target_tech else None
    return {
        "target_cve": target_cve, "target_technique": target_tech,
        "planned_cves": planned_cves, "planned_techniques": planned_techs,
        "cve_match": cve_match, "technique_match": tech_match,
        "matched": bool(cve_match) and bool(tech_match),
    }


def run_one(scenario: dict, driver) -> dict:
    """
    ARGUS-LAYER-7: Run a single scenario end to end:
    1. Write ScenarioRun node (status=running)
    2. Spawn red/blue/victim containers via the supervisor
    3. Start blue monitor thread
    4. Red: plan_attack() -> execute_attack()
    5. Stop blue monitor thread
    6. Assess detection
    7. Write Outcome node
    8. Update technique confidence
    9. Check for conflicts
    10. Update ScenarioRun status to completed/failed/stalemate
    11. Teardown containers
    12. Return summary dict

    D5 (2026-08-17): plan_attack() is now handed the target `scenario` so it
    plans FOR it (seeds the scenario's CVE first) instead of independently
    picking from the whole attack surface. After execution we cross-check the
    plan against the scenario (_check_plan_matches_scenario) and record whether
    "what red planned" actually matched "what got measured" -- a divergence is
    logged and surfaced as scenario_match in the returned dict, not silently
    ignored.

    Spawn/teardown added 2026-08-24, found missing via a real live P2.1 run:
    execute_attack() assumes containers named gr-red-{run_suffix}/
    gr-victim-{run_suffix} already exist, but nothing in this function ever
    called spawn_scenario() to create them -- every run failed with
    execution.status=supervisor_error (a real requests.RequestException from
    /exec targeting a nonexistent container), confirmed against
    results/p2_1_live_run.log before this fix. scenario["run_id"] is set
    ONCE, before spawning, and reused by both spawn_scenario() (whose own
    run_suffix defaults to "adhoc" if scenario has no run_id) and
    execute_attack() (whose run_suffix falls back to the engagement_id if
    scenario has none) -- setting it here is what keeps both sides naming
    the same containers.
    """
    run_id = f"RUN-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}"
    scenario = {**scenario, "run_id": run_id}
    t0 = time.time()
    write_scenario_run(driver, scenario, run_id)

    try:
        # 600s, not 180s -- found live 2026-08-24: a real MySQL-from-source
        # spawn (install+start) took ~4 min end to end, and a 180s client
        # timeout fired while the server was still working (confirmed via
        # the supervisor's own access log showing a 200 several minutes
        # later) -- the client gives up but the containers still get
        # created, orphaning them since /teardown is never reached.
        spawn_resp = requests.post(f"{SUPERVISOR_URL}/spawn_scenario", json=scenario,
                                    timeout=600)
        spawn_resp.raise_for_status()
        spawn_result = spawn_resp.json()
    except requests.RequestException as e:
        print(f"  [run_scenario] spawn_scenario failed: {e}")
        spawn_result = {}

    red_id = spawn_result.get("red_id")
    blue_id = spawn_result.get("blue_id")
    victim_id = spawn_result.get("victim_id")

    if not (red_id and blue_id and victim_id):
        # Never got containers -- an infrastructure failure, not a scenario
        # outcome. Mirrors exec_result.get("status") != "executed" below,
        # which already treats this class of failure as neither side "winning."
        update_scenario_run_status(driver, run_id, "failed", "", turn_count=0,
                                    duration_seconds=int(time.time() - t0))
        mark_scenario_complete(driver, scenario, run_id)
        return {
            "run_id": run_id, "outcome_id": None, "status": "failed", "winner": "",
            "execution": {"status": "spawn_failed", "spawn_result": spawn_result},
            "detection": {"detected": False, "detection_type": "", "turn_detected": -1},
            "scenario_match": {"matched": None},
        }

    monitor_result = {}
    stop_event = threading.Event()

    def _run_monitor():
        monitor_result["events"] = monitor(SUPERVISOR_URL, run_id, scenario, stop_event)

    monitor_thread = threading.Thread(target=_run_monitor)
    monitor_thread.start()

    try:
        plan_result = plan_attack(driver, scenario=scenario)
        engagement = plan_result.get("engagement") or {
            "engagement_id": run_id, "selected_chain": [], "confidence": 0.0,
            "reasoning": "no attack surface available", "preconditions": [],
        }

        exec_result = execute_attack(driver, SUPERVISOR_URL, scenario, engagement)
    finally:
        # Stop the monitor thread BEFORE tearing down containers -- it polls
        # blue/victim via /exec on its own timer (agents/blue.py monitor()),
        # so tearing down first would have it querying containers that no
        # longer exist.
        stop_event.set()
        monitor_thread.join(timeout=MONITOR_JOIN_TIMEOUT)
        try:
            requests.post(f"{SUPERVISOR_URL}/teardown",
                           json={"red_id": red_id, "blue_id": blue_id, "victim_id": victim_id},
                           timeout=60)
        except requests.RequestException as e:
            print(f"  [run_scenario] teardown failed: {e}")

    # D5 cross-check: confirm red actually planned for this scenario (targeting
    # can still miss if the LLM picks a different seeded chain). Recorded, not
    # raised.
    scenario_match = _check_plan_matches_scenario(engagement, scenario)
    if scenario_match.get("matched") is False:
        print(f"  [run_scenario] WARNING: red's plan diverged from the target "
              f"scenario -- planned techniques {scenario_match['planned_techniques']} "
              f"vs target {scenario_match['target_technique']!r}")

    detection_events = monitor_result.get("events", [])
    detection = assess_detection(detection_events, scenario)

    outcome_id = write_outcome(driver, run_id, scenario, exec_result, detection)
    result = "success" if exec_result.get("success") else "fail"
    technique_id = scenario.get("technique_id", "")
    if technique_id:
        cfg_hash = hash_victim_config(scenario.get("victim_cpe", ""))
        update_technique_confidence(driver, technique_id, result, cfg_hash)
        check_and_flag_conflict(driver, outcome_id, technique_id, cfg_hash, result)

    if exec_result.get("status") != "executed":
        # Never actually ran (supervisor unreachable, no tool available,
        # install failed) -- an infrastructure failure, not a scenario
        # outcome, so neither side "won."
        winner, status = "", "failed"
    elif exec_result.get("success") and not detection.get("detected"):
        winner, status = "red", "completed"
    elif detection.get("detected"):
        # Per the scenario's own win_conditions ("blue: technique_detected_
        # before_completion"), blue is scored on detection, not on whether
        # red's attempt also succeeded -- a detected success is still a
        # blue win under that definition.
        winner, status = "blue", "completed"
    else:
        winner, status = "", "stalemate"

    update_scenario_run_status(driver, run_id, status, winner, turn_count=1,
                                duration_seconds=int(time.time() - t0))
    mark_scenario_complete(driver, scenario, run_id)

    return {
        "run_id": run_id, "outcome_id": outcome_id, "status": status,
        "winner": winner, "execution": exec_result, "detection": detection,
        "scenario_match": scenario_match,
    }


def run_batch(limit: int = 10) -> None:
    """ARGUS-LAYER-7: Run up to `limit` valid scenarios sequentially. Never
    lets one scenario's exception stop the batch -- logs and continues."""
    driver = get_driver()
    try:
        scenarios = get_valid_scenarios(driver, limit=limit)
        print(f"[run_scenario] {len(scenarios)} valid scenarios")
        for i, scenario in enumerate(scenarios):
            print(f"[run_scenario] {i + 1}/{len(scenarios)}: "
                  f"{scenario['cve_id']} -> {scenario['technique_id']}")
            try:
                result = run_one(scenario, driver)
                print(f"  -> {result['status']} (winner={result['winner']}, "
                      f"run_id={result['run_id']})")
            except Exception as e:
                print(f"  FAILED: {e}")
            time.sleep(5)
    finally:
        driver.close()


if __name__ == "__main__":
    run_batch(limit=10)
