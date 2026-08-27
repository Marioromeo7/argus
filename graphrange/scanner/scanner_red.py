"""
ARGUS-SCANNER: Scanner Red Agent.
Separate from agents/red.py -- reasons over code vulnerability context and
a real multi-container topology, planning and executing an attack path
across it. Does NOT write to the ARGUS graph. Output goes to the report
only. Synthesizes GRAPHRANGE_SCANNER.md's several layered revision passes
for this file (base analyze() -> topology-aware update -> revised
phase-aware tool request logic -> capability-cache gap closure ->
execution-primary dual assessment) into one final implementation, per
BACKLOG.md's own note that later passes supersede earlier ones.
"""

import json
import os
import re
from datetime import datetime

import requests

from graphrange.telemetry import track, count_tokens, patch_last_tokens_out
from graphrange.observer import normalize
from config import OLLAMA_CHAT_URL as OLLAMA_URL

QWEN_MODEL = "qwen3:8b"
CALL_TIMEOUT = 1800  # was 600s -- still too tight, found live 2026-08-25: a
                      # comparable-scale Qwen call on local hardware (RTX
                      # 3050, ~8 tok/s, the only compute left after Colab's
                      # quota ran out on all 3 accounts) exceeded 600s
                      # without finishing
TOOL_UNAVAILABLE_LOG = "logs/tool_unavailable.log"

SANDBOX_AVAILABLE = False  # set by run_scanner()'s health check

_HARD_FAILURE_MARKERS = (
    "connection refused", "permission denied", "command not found",
    "no route to host", "timed out",
)

_CAPABILITY_BROADEN_MAP = [
    (("scan", "discover", "enum"), "scanner"),
    (("exploit", "inject", "exec"), "exploitation"),
    (("privesc", "escalat"), "privilege_escalation"),
    (("lateral", "pivot", "move"), "lateral_movement"),
    (("exfil", "dump", "extract"), "exfiltration"),
    (("crack", "brute", "auth"), "credential_access"),
]


def _log_tool_unavailable(entry: str) -> None:
    os.makedirs("logs", exist_ok=True)
    with open(TOOL_UNAVAILABLE_LOG, "a", encoding="utf-8") as f:
        f.write(entry + "\n")


def _call_qwen(prompt: str, caller: str) -> str:
    """ARGUS-SCANNER: shared Ollama call helper, wired through telemetry.
    Not live-tested as of writing (2026-08-10) -- holding at the same
    live-GPU-call checkpoint as the rest of this session's GPU-touching code."""
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


def _broaden_to_category(capability: str) -> str:
    """ARGUS-SCANNER: Maps a specific capability to a broader category for
    cycle-3 tool-request broadening. Zero-GPU, pure lookup."""
    low = capability.lower()
    for keywords, category in _CAPABILITY_BROADEN_MAP:
        if any(k in low for k in keywords):
            return category
    return "network_tool"


def _plan_attack_path(topology: dict, driver) -> dict:
    """ARGUS-SCANNER: Red reasons over the full victim topology to plan its
    attack path across containers before execution begins."""
    prompt = (
        "You are a red team attacker. You have identified the following "
        "target infrastructure:\n"
        f"{json.dumps(topology['services'])}\n\n"
        "Network connectivity:\n"
        f"{json.dumps(topology['network_map'])}\n\n"
        "Plan your attack path:\n"
        "1. Which service do you attack first and why?\n"
        "2. What is your objective on that service?\n"
        "3. If you gain access, which service do you pivot to next?\n"
        "4. What is the end goal of the full attack chain?\n\n"
        "Return as JSON:\n"
        '{"entry_service": str, "entry_rationale": str, '
        '"pivot_sequence": [str], "end_goal": str, '
        '"attack_phases": [{"service": str, "objective": str, '
        '"capability_needed": str}]}'
    )
    raw = _call_qwen(prompt, "scanner.scanner_red._plan_attack_path")
    return _parse_json(raw, {
        "entry_service": "", "entry_rationale": "", "pivot_sequence": [],
        "end_goal": "", "attack_phases": [],
    })


def _deliver_tool(supervisor_url: str, container_name: str, tool_name: str,
                   install_from_cache: bool = False) -> bool:
    """ARGUS-SCANNER: Delivers a tool to a specific container. Cache hits
    skip the tool graph lookup entirely -- the name is already known from
    resolving this capability on an earlier container this scenario."""
    try:
        resp = requests.post(
            f"{supervisor_url}/deliver",
            json={"container": container_name, "tool_name": tool_name,
                  "install_from_cache": install_from_cache},
            timeout=60,
        )
        return resp.status_code == 200
    except requests.RequestException:
        return False


def _request_tool_for_phase(phase: dict, acquired_capabilities: dict,
                             supervisor_url: str, container_name: str,
                             max_cycles: int = 3) -> dict:
    """
    ARGUS-SCANNER: Requests a tool for the current attack phase.
    acquired_capabilities tracks capability -> tool_name across the whole
    scenario, not per-container -- a capability resolved on one service is
    re-delivered to a new one via the cache, never re-requested. Falls
    back through max_cycles of broadening, then substitution reasoning,
    then marks the phase blocked. Never stops the scenario.
    """
    capability = phase["capability_needed"]

    if capability in acquired_capabilities:
        known_tool = acquired_capabilities[capability]
        _deliver_tool(supervisor_url, container_name, known_tool, install_from_cache=True)
        return {"tool": known_tool, "status": "acquired",
                "installed_tool_used": None, "log_entry": None}

    broadening_terms = [
        capability,
        capability.split()[0] if capability.split() else capability,
        _broaden_to_category(capability),
    ]
    for term in broadening_terms[:max_cycles]:
        try:
            resp = requests.post(
                f"{supervisor_url}/tool_request",
                json={"agent": "red", "capability": term, "container": container_name},
                timeout=30,
            )
            resp.raise_for_status()
            result = resp.json()
        except requests.RequestException:
            continue
        if result.get("tool_name"):
            tool_name = result["tool_name"]
            acquired_capabilities[capability] = tool_name
            return {"tool": tool_name, "status": "acquired",
                    "installed_tool_used": None, "log_entry": None}

    installed_tools = list(acquired_capabilities.values())
    sub_prompt = (
        "You are a red team attacker. Your objective for this phase is:\n"
        f"{phase.get('objective', '')}\n"
        f"Capability you wanted: {capability}\n"
        f"Tools currently installed in your container: {installed_tools}\n\n"
        "Can you achieve this phase objective using any of the installed tools?\n"
        "Return ONLY a JSON object:\n"
        '{"can_substitute": bool, "tool_to_use": str, "reasoning": str}'
    )
    raw = _call_qwen(sub_prompt, "scanner.scanner_red._request_tool_for_phase.substitution")
    sub_result = _parse_json(raw, {"can_substitute": False, "tool_to_use": "", "reasoning": ""})

    if sub_result.get("can_substitute"):
        return {"tool": None, "status": "substituted",
                "installed_tool_used": sub_result.get("tool_to_use", ""),
                "log_entry": None}

    entry = (f"PHASE_BLOCKED | service: {container_name} | "
             f"phase_objective: {phase.get('objective', '')} | "
             f"capability: {capability} | cycles: {max_cycles} | "
             f"installed_tools: {installed_tools} | "
             f"timestamp: {datetime.utcnow().isoformat()}")
    _log_tool_unavailable(entry)
    return {"tool": None, "status": "blocked", "installed_tool_used": None,
            "log_entry": "logged to tool_unavailable.log"}


def _exec_in_container(supervisor_url: str, container_name: str, tool: str) -> str:
    """ARGUS-SCANNER: Runs the acquired/substituted tool in its target
    container and returns raw stdout."""
    try:
        resp = requests.post(
            f"{supervisor_url}/exec",
            json={"container": container_name, "command": tool},
            timeout=90,
        )
        resp.raise_for_status()
        return resp.json().get("stdout", "")
    except requests.RequestException as e:
        return f"EXEC_ERROR: {e}"


def _assess_objective(objective: str, observations: dict,
                       execution_stdout: str, driver) -> dict:
    """
    ARGUS-SCANNER: Assesses phase objective from two sources. Execution
    stdout is ground truth; Qwen's read is a secondary signal that never
    overrides real execution evidence -- if stdout has real content, the
    phase is scored achieved even if Qwen's read disagreed (logged as a
    conflict, not silently overridden).
    """
    stdout_low = execution_stdout.lower()
    execution_success = bool(execution_stdout.strip()) and not any(
        marker in stdout_low for marker in _HARD_FAILURE_MARKERS)

    prompt = (
        f"Phase objective: {objective}\n"
        f"Observations: {json.dumps(observations)}\n"
        "Did the attacker achieve the objective?\n"
        'Return ONLY: {"achieved": true} or {"achieved": false}'
    )
    raw = _call_qwen(prompt, "scanner.scanner_red._assess_objective")
    qwen_result = _parse_json(raw, {"achieved": False})
    qwen_achieved = bool(qwen_result.get("achieved"))

    conflict = False
    if not execution_success:
        achieved = False
    elif qwen_achieved:
        achieved = True
    else:
        achieved = True  # execution wins -- stdout had real content
        conflict = True
        print(f"[ScannerRed] OBJECTIVE_SIGNAL_CONFLICT | Qwen said not "
              f"achieved but execution produced output | phase: {objective}",
              flush=True)

    return {"achieved": achieved, "execution_evidence": execution_success,
            "qwen_signal": qwen_achieved, "conflict": conflict}


def _argus_lookup(terms: list, driver) -> list:
    """ARGUS-SCANNER: Zero-GPU graph lookup -- finds techniques/vulnerabilities
    whose label or properties mention any of the vuln context's query terms."""
    if not terms:
        return []
    cypher = """
    MATCH (n:Node)
    WHERE any(term IN $terms WHERE toLower(n.properties) CONTAINS term
           OR toLower(n.label) CONTAINS term)
    AND n.node_type IN ['technique', 'vulnerability']
    RETURN n.node_id AS node_id, n.node_type AS node_type,
           n.label AS label, n.grain_confidence AS grain_confidence
    ORDER BY n.grain_confidence DESC LIMIT 5
    """
    with driver.session() as session:
        return [dict(r) for r in session.run(cypher, terms=[t.lower() for t in terms])]


def analyze(vuln_context: dict, topology: dict, driver, sandbox: bool = False,
            supervisor_url: str = "http://localhost:8000") -> dict:
    """ARGUS-SCANNER: Full red analysis for one VulnContext. Default
    supervisor_url uses localhost, not the spec's Docker-internal
    "gr-supervisor" hostname -- see run_scenario.py's SUPERVISOR_URL
    comment for why (confirmed live: that hostname doesn't resolve from
    the host, which is where this code actually runs)."""
    matched = _argus_lookup(vuln_context.get("argus_query_terms", []), driver)
    matched_technique_id = next(
        (m["node_id"] for m in matched if m["node_type"] == "technique"), "")
    matched_cve_id = next(
        (m["node_id"] for m in matched if m["node_type"] == "vulnerability"), "")

    attack_plan = _plan_attack_path(topology, driver) if sandbox else {
        "entry_service": "", "entry_rationale": "", "pivot_sequence": [],
        "end_goal": "", "attack_phases": [],
    }

    prompt = (
        "You are a red team researcher. Given this vulnerability and related "
        "MITRE ATT&CK techniques from our knowledge graph:\n"
        f"Vulnerability: {vuln_context.get('description', '')}\n"
        f"Attack vector: {vuln_context.get('attack_vector', '')}\n"
        f"Matched techniques: {json.dumps(matched)}\n"
        f"Attack plan across topology: {json.dumps(attack_plan)}\n\n"
        "Describe the exploitation path:\n"
        '{"exploitation_path": str, "matched_technique_id": str, '
        '"matched_cve_id": str, "attack_steps": [str], '
        '"requires_auth": bool, "network_accessible": bool}'
    )
    raw = _call_qwen(prompt, "scanner.scanner_red.analyze")
    reasoning = _parse_json(raw, {
        "exploitation_path": "", "matched_technique_id": matched_technique_id,
        "matched_cve_id": matched_cve_id, "attack_steps": [],
        "requires_auth": False, "network_accessible": False,
    })

    if not sandbox:
        execution_result = {"status": "skipped", "reason": "sandbox_unavailable",
                             "phases": [], "kill_chain_complete": False,
                             "final_service_reached": ""}
    else:
        execution_result = _execute_attack_plan(attack_plan, topology, supervisor_url, driver)

    return {
        "vuln_context": vuln_context,
        "matched_technique_id": reasoning.get("matched_technique_id", matched_technique_id),
        "matched_cve_id": reasoning.get("matched_cve_id", matched_cve_id),
        "exploitation_path": reasoning.get("exploitation_path", ""),
        "attack_steps": reasoning.get("attack_steps", []),
        "attack_plan": attack_plan,
        "execution_result": execution_result,
        "source": "scanner_red",
    }


def _execute_attack_plan(attack_plan: dict, topology: dict,
                          supervisor_url: str, driver) -> dict:
    """ARGUS-SCANNER: Runs every phase in attack_plan, tracking acquired
    capabilities across the whole scenario. A blocked phase is skipped,
    never stops the scenario; only exhausting every phase (blocked or not)
    ends it."""
    acquired_capabilities = {}
    phase_results = []
    all_blocked = True
    service_by_name = {s["name"]: s for s in topology["services"]}
    phases = attack_plan.get("attack_phases", [])

    for phase in phases:
        container_name = phase.get("service", "")
        if container_name not in service_by_name:
            phase_results.append({
                "service": container_name, "tool": None, "status": "blocked",
                "result": "skipped", "execution_evidence": False,
                "qwen_signal": False, "conflict": False,
                "observations": {}, "pivoted": False,
            })
            continue

        tool_result = _request_tool_for_phase(
            phase, acquired_capabilities, supervisor_url, container_name)

        if tool_result["status"] == "blocked":
            phase_results.append({
                "service": container_name, "tool": None, "status": "blocked",
                "result": "skipped", "execution_evidence": False,
                "qwen_signal": False, "conflict": False,
                "observations": {}, "pivoted": False,
            })
            continue

        active_tool = (tool_result["tool"] if tool_result["status"] == "acquired"
                       else tool_result["installed_tool_used"])
        stdout = _exec_in_container(supervisor_url, container_name, active_tool)
        obs = normalize(stdout, phase.get("technique_id", ""), driver)
        assessment = _assess_objective(phase.get("objective", ""), obs, stdout, driver)

        all_blocked = False
        phase_results.append({
            "service": container_name, "tool": active_tool,
            "status": tool_result["status"],
            "result": "success" if assessment["achieved"] else "partial",
            "execution_evidence": assessment["execution_evidence"],
            "qwen_signal": assessment["qwen_signal"],
            "conflict": assessment["conflict"],
            "observations": obs,
            "pivoted": assessment["achieved"] and phase is not phases[-1],
        })

    kill_chain_complete = bool(
        not all_blocked and phase_results and phases and
        phase_results[-1]["result"] in ("success", "partial") and
        phase_results[-1]["service"] == phases[-1]["service"]
    )
    return {
        "status": "executed", "phases": phase_results,
        "kill_chain_complete": kill_chain_complete,
        "final_service_reached": phase_results[-1]["service"] if phase_results else "",
    }
