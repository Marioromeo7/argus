"""
ARGUS-SCANNER: Scanner Blue Agent.
Separate from agents/blue.py -- advises on code-level defenses and
monitors all victim services simultaneously during red execution. Does
NOT write to the ARGUS graph. Output goes to the report only. Synthesizes
GRAPHRANGE_SCANNER.md's base analyze() plus its multi-container monitoring
revision into one final implementation.
"""

import json
import re
import threading
from datetime import datetime

import requests

from graphrange.telemetry import track, count_tokens, patch_last_tokens_out
from config import OLLAMA_CHAT_URL as OLLAMA_URL

QWEN_MODEL = "qwen3:8b"
CALL_TIMEOUT = 600  # was 90s -- too tight given this hardware's real observed latency
MONITOR_POLL_SECONDS = 3
MONITOR_JOIN_TIMEOUT = 30


def _call_qwen(prompt: str, caller: str) -> str:
    """ARGUS-SCANNER: shared Ollama call helper, wired through telemetry.
    Not live-tested as of writing (2026-08-10) -- same checkpoint as the
    rest of this session's GPU-touching code."""
    tokens_in = count_tokens(prompt)
    with track(caller, model="qwen", tokens_in=tokens_in, tokens_out=0):
        resp = requests.post(
            OLLAMA_URL,
            json={"model": QWEN_MODEL,
                  "messages": [{"role": "user", "content": f"/no_think\n\n{prompt}"}],
                  "stream": False},
            timeout=CALL_TIMEOUT,
        )
        resp.raise_for_status()
        raw = resp.json()["message"]["content"].strip()
    patch_last_tokens_out(count_tokens(raw))
    return raw


def _parse_json(raw: str, default):
    raw = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw.strip())
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return default


def _monitor_service(service: dict, supervisor_url: str,
                      stop_event: threading.Event,
                      shared_events: list, lock: threading.Lock) -> None:
    """
    ARGUS-SCANNER: Monitors one victim service container, polling every
    MONITOR_POLL_SECONDS until stop_event is set. Same coarse-heuristic
    caveats as agents/blue.py's monitor() -- tcpdump runs with -nn (no
    name resolution) so activity can't be precisely attributed to this
    one service without a pre-attack baseline; treated as "activity
    observed", not "confirmed against this service specifically."
    """
    container_name = service.get("container_id") or service.get("name", "")
    while not stop_event.is_set():
        for command, event_type in (
            ("ss -tnp 2>/dev/null", "unexpected_connection"),
            ("tcpdump -i any -c 10 -nn 2>/dev/null", "port_scan"),
        ):
            try:
                resp = requests.post(
                    f"{supervisor_url}/exec",
                    json={"container": container_name, "command": command},
                    timeout=30,
                )
                stdout = resp.json().get("stdout", "") if resp.ok else ""
            except requests.RequestException:
                stdout = ""
            if stdout.strip() and ("ESTAB" in stdout or " IP " in stdout):
                with lock:
                    shared_events.append({
                        "timestamp": datetime.utcnow().isoformat(),
                        "service": service.get("name", ""),
                        "service_role": service.get("role", ""),
                        "type": event_type,
                        "detail": stdout[:300],
                    })
        stop_event.wait(MONITOR_POLL_SECONDS)


def monitor_topology(topology: dict, supervisor_url: str,
                      stop_event: threading.Event) -> list:
    """ARGUS-SCANNER: Spawns one monitoring thread per victim service, all
    feeding a single shared, lock-protected event list. Blocks until every
    thread returns (i.e. until stop_event is set and each thread's current
    poll cycle finishes), then returns the accumulated events."""
    shared_events = []
    lock = threading.Lock()
    threads = [
        threading.Thread(target=_monitor_service,
                          args=(service, supervisor_url, stop_event, shared_events, lock))
        for service in topology.get("services", [])
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=MONITOR_JOIN_TIMEOUT)
    return shared_events


def assess_detection(detection_events: list, attack_plan: dict) -> dict:
    """
    ARGUS-SCANNER: Assesses blue's detection across the full kill chain --
    which phases blue caught, which it missed, and whether a later pivot
    was missed even though the initial entry point was caught (a real,
    distinct failure mode: catching the front door but missing the
    attacker moving laterally afterward).
    """
    phases = attack_plan.get("attack_phases", [])
    detected_services = {e["service"] for e in detection_events}

    phases_detected = [p["service"] for p in phases if p["service"] in detected_services]
    phases_missed = [p["service"] for p in phases if p["service"] not in detected_services]
    first_detection = phases_detected[0] if phases_detected else None

    missed_lateral = False
    if phases_detected and phases_missed:
        detected_indices = [i for i, p in enumerate(phases) if p["service"] in detected_services]
        missed_indices = [i for i, p in enumerate(phases) if p["service"] not in detected_services]
        if detected_indices and missed_indices and min(detected_indices) < max(missed_indices):
            missed_lateral = True

    return {
        "detected_overall": bool(phases_detected),
        "phases_detected": phases_detected,
        "phases_missed": phases_missed,
        "first_detection": first_detection,
        "missed_lateral": missed_lateral,
        "detection_events": detection_events,
    }


def _argus_mitigation_lookup(technique_id: str, cwe: str, driver) -> list:
    """ARGUS-SCANNER: Zero-GPU graph lookup for mitigations tied to the
    matched technique and/or mentioning the CWE by name."""
    mitigations = []
    with driver.session() as session:
        if technique_id:
            cypher = """
            MATCH (m:Node {node_type: 'mitigation'})-[r:RELATION]->(t:Node {node_id: $tid})
            RETURN m.node_id AS node_id, m.label AS label,
                   m.properties AS properties, m.grain_confidence AS grain_confidence
            ORDER BY m.grain_confidence DESC LIMIT 5
            """
            mitigations.extend(dict(r) for r in session.run(cypher, tid=technique_id))
        if cwe:
            cypher2 = """
            MATCH (m:Node {node_type: 'mitigation'})
            WHERE toLower(m.properties) CONTAINS $cwe_term
            RETURN m.node_id AS node_id, m.label AS label, m.properties AS properties
            LIMIT 3
            """
            mitigations.extend(dict(r) for r in
                                session.run(cypher2, cwe_term=cwe.lower()))
    return mitigations


def analyze(vuln_context: dict, red_findings: dict, topology: dict,
            driver, sandbox: bool = False, shared_events: list = None) -> dict:
    """ARGUS-SCANNER: Full blue analysis for one VulnContext. `shared_events`
    is the event list `monitor_topology()` filled during red's execution --
    passed in by run_scanner.py's orchestration, not gathered here (blue's
    monitoring thread runs in parallel with red, not sequentially after)."""
    technique_id = red_findings.get("matched_technique_id", "")
    cwe = vuln_context.get("cwe", "")
    argus_mitigations = _argus_mitigation_lookup(technique_id, cwe, driver)

    prompt = (
        "You are a blue team security engineer. Given this vulnerability and "
        "the red team exploitation path, provide defensive recommendations.\n"
        f"Vulnerability: {vuln_context.get('description', '')}\n"
        f"File: {vuln_context.get('filepath', '')} "
        f"lines {vuln_context.get('line_start', '')}-{vuln_context.get('line_end', '')}\n"
        f"Exploitation path: {red_findings.get('exploitation_path', '')}\n"
        f"ARGUS mitigations: {json.dumps(argus_mitigations)}\n\n"
        "Return as JSON:\n"
        '{"code_fix": str, "detection_rule": str, '
        '"argus_mitigations_applied": [str], '
        '"priority": "Critical|High|Medium|Low", "static_advice": str}'
    )
    raw = _call_qwen(prompt, "scanner.scanner_blue.analyze")
    advice = _parse_json(raw, {
        "code_fix": "", "detection_rule": "", "argus_mitigations_applied": [],
        "priority": "Low", "static_advice": "",
    })

    if sandbox and shared_events is not None:
        detection = assess_detection(shared_events, red_findings.get("attack_plan", {}))
    else:
        detection = {
            "detected_overall": False, "phases_detected": [], "phases_missed": [],
            "first_detection": None, "missed_lateral": False, "detection_events": [],
        }

    return {
        "vuln_context": vuln_context,
        "code_fix": advice.get("code_fix", ""),
        "detection_rule": advice.get("detection_rule", ""),
        "static_advice": advice.get("static_advice", ""),
        "execution_detected": detection["detected_overall"],
        "detection_events": detection["detection_events"],
        "argus_mitigations": argus_mitigations,
        "priority": advice.get("priority", "Low"),
        "detected_overall": detection["detected_overall"],
        "phases_detected": detection["phases_detected"],
        "phases_missed": detection["phases_missed"],
        "missed_lateral": detection["missed_lateral"],
        "source": "scanner_blue",
    }
