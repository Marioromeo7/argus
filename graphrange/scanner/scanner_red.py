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
import uuid
from datetime import datetime

import requests

from graphrange.telemetry import track, count_tokens, patch_last_tokens_out
from graphrange.observer import normalize
from graphrange.tool_graph import get_tool_by_name
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

_OPTION_LIST_STOPWORDS = frozenset({
    "usage", "available", "payload", "authors", "dependencies", "options",
})


def _extract_valid_options(stdout: str) -> list[str]:
    """ARGUS-SCANNER: Some CLI tools fail with a highly structured shape --
    an "Invalid <noun> '<value>'" line, followed by a table/list of the
    real valid values (ysoserial's payload-type table is exactly this).
    Found live 2026-09-03: a retry fed the raw failed stdout back to Qwen
    (which already includes this list), but Qwen still repeated a near-miss
    gadget name (`XStream1` instead of `XStream`) -- reading a table
    correctly inside a wall of text is a weaker signal than being handed the
    exact whitelist directly. This regex-extracts that whitelist so the
    retry prompt can say "pick one of these exact strings" instead of
    hoping the model parses it out unprompted. Returns [] if the output
    doesn't match this shape -- most tool failures won't, and that's fine,
    the plain retry-with-feedback still applies."""
    m = re.search(r"(?im)^\s*invalid\s+\S+.*$", stdout)
    if not m:
        return []
    options = []
    for line in stdout[m.end():].splitlines():
        stripped = line.strip()
        if not stripped:
            if options:
                break
            continue
        tok = re.match(r"^([A-Za-z][A-Za-z0-9_]{2,40})\b", stripped)
        if tok and tok.group(1).lower() not in _OPTION_LIST_STOPWORDS:
            options.append(tok.group(1))
    return options[:40]

_CAPABILITY_BROADEN_MAP = [
    (("scan", "discover", "enum"), "scanner"),
    (("exploit", "inject", "exec"), "exploitation"),
    (("privesc", "escalat"), "privilege_escalation"),
    (("lateral", "pivot", "move"), "lateral_movement"),
    (("exfil", "dump", "extract"), "exfiltration"),
    (("crack", "brute", "auth"), "credential_access"),
]

# ARGUS-SCANNER: technique-specific overrides, checked before the generic
# capability-category search. Found live 2026-08-31 auditing a completed
# WebGoat report: the tool graph's "exploitation" bucket alone holds 148
# tools all tied at the same crawled grain_confidence (0.8), so
# `ORDER BY grain_confidence DESC LIMIT 1` picks essentially arbitrarily
# among them -- 87% of real attack attempts in that report used a tool
# with zero relevance to the vulnerability under test (a code editor for
# an IDOR bypass, a Windows/AD credential tool for a CSRF forgery), not
# because the graph lacks good tools (it has real ones: sqlmap, xsser,
# commix, padbuster) but because nothing in the lookup discriminated among
# 148 tied candidates. Every tool name here was verified present in the
# live tool graph before being added (`graph/retrieval.py` query, not
# guessed). Matched against the phase's own objective/capability text,
# which `_plan_attack_path()` now grounds in the real vulnerability -- if
# none of these fire, the existing generic category search still runs
# unchanged, so this only narrows cases it can actually improve.
_TECHNIQUE_TOOL_OVERRIDES = [
    (("sql injection", "sqli"), "sqlmap"),
    (("cross-site scripting", "xss"), "xsser"),
    (("command injection", "os command injection"), "commix"),
    (("padding oracle",), "padbuster"),
    # These three have no apt package -- kali.org/tools/ (this project's
    # only crawl source) never had a chance to find them, even though
    # they're the real, standard tool for each technique. Added by hand
    # 2026-08-31 with real (non-apt) install commands; see tool_graph.py.
    (("jwt", "json web token"), "jwt_tool"),
    # Checked BEFORE the generic deserialization entry below -- confirmed
    # live 2026-09-04 via a complete, byte-verified ysoserial-all.jar
    # payload listing (18 real gadget types: CommonsCollections1-7,
    # Spring1/2, Groovy1, etc.) that ysoserial has no XStream gadget at
    # all and never did. That's not a naming mismatch to retry around --
    # ysoserial generates payloads for Java's native
    # ObjectInputStream.readObject() gadget chains, an entirely different
    # mechanism from XStream's own XML-based deserialization (exploited by
    # crafting XML that abuses XStream's type-converter/reflection
    # handling directly, e.g. CVE-2013-2170). Routed to curl instead, the
    # same "no dedicated tool, direct HTTP/payload construction" pattern
    # CSRF/IDOR already use below -- Qwen's own general knowledge of
    # XStream's well-documented public XML gadget syntax plus this
    # finding's real vuln_context is what builds the payload, not a tool.
    (("xstream",), "curl"),
    (("deserialization", "deserialize"), "ysoserial"),
    (("xxe", "xml external entity"), "xxeinjector"),
    # CSRF and IDOR have no dedicated tool anywhere in the security tooling
    # ecosystem, not just missing from this crawl -- a CSRF "exploit" is a
    # hand-crafted auto-submitting form/request using the target's own field
    # names, an IDOR "exploit" is just changing an ID in an otherwise-normal
    # request. Originally mapped to burpsuite (a real, already-crawled tool)
    # on the theory that both live as a *feature* of a general web proxy --
    # wrong in practice: burpsuite has no headless CLI mode that does this,
    # it's a GUI interception proxy, so mapping to it just swapped one
    # irrelevant tool for a different unrunnable one. Switched 2026-09-01 to
    # curl -- not a "tool" for this so much as direct HTTP request
    # construction, which is what both techniques actually are.
    (("csrf", "cross-site request forgery"), "curl"),
    (("idor", "insecure direct object reference"), "curl"),
]


def _technique_tool_override(phase: dict, driver) -> str | None:
    """ARGUS-SCANNER: Returns a verified tool name if the phase's own text
    names an attack technique this project's tool graph has a real,
    specific tool for -- confirmed present via a direct graph lookup
    (not assumed from the override table alone, in case the graph node
    was ever removed/renamed)."""
    text = f"{phase.get('objective', '')} {phase.get('capability_needed', '')}".lower()
    for keywords, tool_name in _TECHNIQUE_TOOL_OVERRIDES:
        if any(k in text for k in keywords) and get_tool_by_name(driver, tool_name):
            return tool_name
    return None


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


def _plan_attack_path(topology: dict, driver, vuln_context: dict) -> dict:
    """
    ARGUS-SCANNER: Red reasons over the full victim topology to plan its
    attack path across containers before execution begins.

    Takes vuln_context now -- found live 2026-08-29 reviewing a completed
    WebGoat report: this previously took only `topology`, so the resulting
    attack_phases were generic ("exploit a known vulnerability... to gain
    unauthorized access") and near-identical across every single finding in
    a scan, completely untethered from the specific vulnerability `analyze()`
    was actually called for. Each phase now also carries an
    `exploit_condition` -- a concrete, checkable description of what success
    evidence would actually look like for THIS vulnerability (e.g. "stdout
    contains the contents of a file outside the intended directory" for a
    path traversal), used by _assess_objective() instead of a vague restated
    objective.
    """
    prompt = (
        "You are a red team attacker. You have identified the following "
        "target infrastructure:\n"
        f"{json.dumps(topology['services'])}\n\n"
        "Network connectivity:\n"
        f"{json.dumps(topology['network_map'])}\n\n"
        "You are specifically investigating this vulnerability:\n"
        f"Type: {vuln_context.get('vuln_type', '?')} ({vuln_context.get('cwe', '?')})\n"
        f"Location: {vuln_context.get('filepath', '?')} lines "
        f"{vuln_context.get('line_start', '?')}-{vuln_context.get('line_end', '?')}\n"
        f"Description: {vuln_context.get('description', '')}\n"
        f"Attack vector: {vuln_context.get('attack_vector', '')}\n\n"
        "Plan an attack path that actually exercises THIS vulnerability, not "
        "a generic sweep of the topology:\n"
        "1. Which service do you attack first and why?\n"
        "2. What is your objective on that service, specific to this vulnerability?\n"
        "3. If you gain access, which service do you pivot to next?\n"
        "4. What is the end goal of the full attack chain?\n"
        "5. For each phase, what concrete evidence in the command output would "
        "actually prove this specific objective was met (not just that a "
        "command ran without error)?\n\n"
        "Return as JSON:\n"
        '{"entry_service": str, "entry_rationale": str, '
        '"pivot_sequence": [str], "end_goal": str, '
        '"attack_phases": [{"service": str, "objective": str, '
        '"capability_needed": str, "exploit_condition": str}]}'
    )
    raw = _call_qwen(prompt, "scanner.scanner_red._plan_attack_path")
    return _parse_json(raw, {
        "entry_service": "", "entry_rationale": "", "pivot_sequence": [],
        "end_goal": "", "attack_phases": [],
    })


def _deliver_tool(supervisor_url: str, container_name: str, install_command: str) -> bool:
    """ARGUS-SCANNER: Installs a tool into a container by exec'ing its real
    install_command via /exec -- the supervisor has no dedicated /deliver
    route (confirmed live 2026-09-03 via a raw 404); /exec's own handler
    special-cases any command containing "install" and runs it as a real
    install server-side instead of a literal shell command, mirroring
    agents/red.py's real, working delivery path exactly. This function
    previously POSTed {"tool_name": ...} to that nonexistent /deliver
    route, and every caller silently discarded its always-False return --
    so every technique-override tool (ysoserial, xxeinjector, jwt_tool,
    etc.) was never actually installed for this entire multi-day
    validation saga. Exploitation then failed for an infrastructure
    reason (tool missing), not a real exploit signal -- the AND-gate in
    _assess_objective() still scored it not-achieved, but for the wrong,
    undetectable reason, floor-capping every measured success rate at
    ~0% regardless of any other fix. Takes the install_command string
    directly (not a tool_name) -- callers that only have a tool_name look
    it up via get_tool_by_name() first, same as the pre-existing dirb call
    below already did correctly by passing a ready command."""
    try:
        resp = requests.post(
            f"{supervisor_url}/exec",
            json={"container": container_name, "command": install_command},
            # 450s, not 90s -- confirmed live 2026-09-03 that a genuinely cold
            # `apt-get update && apt-get install <pkg>` plus a jar download
            # can exceed 90s on real network conditions, timing out a request
            # that would otherwise have succeeded (ReadTimeout, not a real
            # install failure). Bumped twice more same day: isolated testing
            # showed ysoserial/padbuster/xxeinjector all genuinely need
            # 120-240s on a slow network day, and a direct exec_run (no
            # client timeout at all) proved default-jre-headless's install
            # for ysoserial can legitimately run 300-400s+ -- almost all of
            # it spent in ca-certificates-java's postinst re-processing the
            # entire system CA bundle, not the download itself. commix
            # remains heavy enough to exceed even this and is excluded from
            # the P2.3 representative sample rather than chasing an
            # ever-larger timeout for one outlier. One-time cost per
            # attacker-container-per-cluster, not a hot path, so the extra
            # headroom is cheap.
            timeout=450,
        )
        resp.raise_for_status()
        return bool(resp.json().get("success"))
    except requests.RequestException:
        return False


def _request_tool_for_phase(phase: dict, acquired_capabilities: dict,
                             supervisor_url: str, container_name: str,
                             driver, max_cycles: int = 3) -> dict:
    """
    ARGUS-SCANNER: Requests a tool for the current attack phase.
    acquired_capabilities tracks capability -> tool_name across the whole
    scenario, not per-container -- a capability resolved on one service is
    re-delivered to a new one via the cache, never re-requested. Checks
    _technique_tool_override() first (a specific, verified tool for a
    named attack technique) before falling back through max_cycles of
    generic category broadening, then substitution reasoning, then marks
    the phase blocked. Never stops the scenario.
    """
    capability = phase["capability_needed"]

    if capability in acquired_capabilities:
        known_tool = acquired_capabilities[capability]
        install_command = (get_tool_by_name(driver, known_tool) or {}) \
            .get("properties", {}).get("install_command", "")
        delivered = bool(install_command) and _deliver_tool(
            supervisor_url, container_name, install_command)
        return {"tool": known_tool, "status": "acquired" if delivered else "blocked",
                "installed_tool_used": None, "log_entry": None}

    override_tool = _technique_tool_override(phase, driver)
    if override_tool:
        install_command = (get_tool_by_name(driver, override_tool) or {}) \
            .get("properties", {}).get("install_command", "")
        delivered = bool(install_command) and _deliver_tool(
            supervisor_url, container_name, install_command)
        acquired_capabilities[capability] = override_tool
        return {"tool": override_tool, "status": "acquired" if delivered else "blocked",
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


def _assess_objective(objective: str, observations: dict, execution_stdout: str,
                       driver, exploit_condition: str = "") -> dict:
    """
    ARGUS-SCANNER: Assesses phase objective from two sources.

    Changed 2026-08-29 -- found live reviewing a completed WebGoat report:
    the previous version treated "stdout is non-empty and doesn't contain a
    hard-failure string" as ground truth that could never be overridden, even
    by Qwen's own dissenting read -- logged as a "conflict" but the dissent
    was discarded, not honored. That bar is trivial to clear (any tool that
    runs at all clears it) and it fired on 53% of phases in that report,
    including one where the tool that ran was a *code editor* against a
    Dockerfile-permissions objective -- "achieved" purely because it printed
    something. `exploit_condition` (from _plan_attack_path(), now grounded in
    the actual vulnerability) lets Qwen judge something falsifiable instead
    of a vague restated objective. Both signals must now agree for
    `achieved`: a non-empty stdout is necessary (rules out a call that
    produced nothing) but no longer sufficient on its own -- a disagreement
    is scored not-achieved and logged as a conflict, not silently overruled.
    """
    stdout_low = execution_stdout.lower()
    execution_success = bool(execution_stdout.strip()) and not any(
        marker in stdout_low for marker in _HARD_FAILURE_MARKERS)

    prompt = (
        f"Phase objective: {objective}\n"
        + (f"Concrete success condition: {exploit_condition}\n" if exploit_condition else "")
        + f"Observations: {json.dumps(observations)}\n"
        f"Raw command output:\n{execution_stdout[:2000]}\n\n"
        + ("Does the raw command output actually satisfy the concrete success "
           "condition above -- not just \"did a command run\"?\n"
           if exploit_condition else
           "Did the attacker achieve the objective, based on real evidence in "
           "the output, not just the absence of an error?\n")
        + 'Return ONLY: {"achieved": true} or {"achieved": false}'
    )
    raw = _call_qwen(prompt, "scanner.scanner_red._assess_objective")
    qwen_result = _parse_json(raw, {"achieved": False})
    qwen_achieved = bool(qwen_result.get("achieved"))

    achieved = execution_success and qwen_achieved
    conflict = execution_success != qwen_achieved
    if conflict:
        print(f"[ScannerRed] OBJECTIVE_SIGNAL_CONFLICT | execution={execution_success} "
              f"qwen={qwen_achieved} -> scored not-achieved | phase: {objective}",
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
            supervisor_url: str = "http://localhost:8000",
            known_credentials: dict | None = None) -> dict:
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

    attack_plan = _plan_attack_path(topology, driver, vuln_context) if sandbox else {
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
        execution_result = _execute_attack_plan(
            attack_plan, topology, supervisor_url, driver, vuln_context,
            credentials=known_credentials)

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


def _container_port(topology: dict, service_name: str) -> str:
    """ARGUS-SCANNER: Extracts the container-internal listening port for a
    topology service from its compose 'ports' strings (e.g. "8080:8080" ->
    "8080", bare "8080" -> "8080"). The attacker container reaches the
    victim over their shared Docker network via Compose's own service-name
    DNS alias, so it's the CONTAINER side of the mapping that matters --
    there's no host-port NAT to go through at all on a container-to-
    container hop. Defaults to "80" if nothing parses, same as a generic
    unconfigured web service would use."""
    for svc in topology.get("services", []):
        if svc.get("name") != service_name:
            continue
        for p in svc.get("ports", []):
            m = re.search(r":(\d+)(?:/\w+)?$", p)
            if m:
                return m.group(1)
            m = re.match(r"^(\d+)(?:/\w+)?$", p.strip())
            if m:
                return m.group(1)
        break
    return "80"


def _spawn_attacker(supervisor_url: str, target_services: list) -> str | None:
    """ARGUS-SCANNER: Asks the supervisor to spin up a real attacker
    container connected to every target service's Docker network(s) -- see
    supervisor.py's spawn_attacker_container() for why this replaced
    exec'ing tools directly inside the victim's own container."""
    if not target_services:
        return None
    try:
        resp = requests.post(
            f"{supervisor_url}/spawn_attacker",
            json={"targets": target_services, "run_id": uuid.uuid4().hex[:8]},
            timeout=60,
        )
        resp.raise_for_status()
        return resp.json().get("attacker_container")
    except requests.RequestException:
        return None


def _teardown_attacker(supervisor_url: str, attacker_container: str | None) -> None:
    """ARGUS-SCANNER: Tears down the per-cluster attacker container. Best
    effort -- a failed teardown leaks one throwaway container, not a
    correctness issue for the scan itself, so exceptions are swallowed
    rather than propagated."""
    if not attacker_container:
        return
    try:
        requests.post(f"{supervisor_url}/teardown_one",
                      json={"container": attacker_container}, timeout=30)
    except requests.RequestException:
        pass


def _build_invocation(tool_name: str, phase: dict, vuln_context: dict,
                       target_url: str, driver, cookie_jar: str = "",
                       path_hints: tuple = (), retry_feedback: str = "") -> str:
    """ARGUS-SCANNER: Builds the actual shell command to run in the attacker
    container.

    Added 2026-09-01, replacing a bare tool-name invocation -- found live
    investigating why every phase that acquired a real, correctly-mapped
    tool (post the 2026-08-31 tool-mapping fix) still scored not-achieved:
    `_exec_in_container` ran the tool by name alone (`sh -c sqlmap`, `sh -c
    jwt_tool`), which just prints that tool's own usage banner and exits --
    non-empty stdout, no hard-failure marker, so execution_success=True, but
    nothing was ever actually attempted against the target. The tool's own
    usage_pattern (stored once on its graph node, reused for every finding
    that tool is ever picked for -- not per-run, not part of tool
    selection) plus this specific finding's code/description let Qwen
    construct a real, armed command instead of guessing CLI syntax from
    scratch every time.

    cookie_jar (added same day, once _authenticate() proved a real login
    was achievable against a source-matched container) points at a
    already-populated curl cookie file inside the attacker container --
    most lesson/app endpoints require an authenticated session, so a
    command that doesn't attach it would hit an auth wall regardless of
    how correct the rest of the exploit is.

    path_hints (added same day) are real base-path candidates from
    topology's repo_name and/or _discover_routes -- given to Qwen as real
    signal alongside the code/description it was already inferring a
    route from blind, since a source snippet alone doesn't reveal an
    app's context path (WebGoat's /WebGoat prefix, confirmed live, is
    invisible in the vulnerable method's own code)."""
    tool_node = get_tool_by_name(driver, tool_name)
    usage_pattern = (tool_node or {}).get("properties", {}).get("usage_pattern", "")
    session_note = (
        f"\nAn authenticated session is available in this container as a "
        f"curl cookie jar at {cookie_jar} -- attach it with `-b {cookie_jar}` "
        f"(and `-c {cookie_jar}` if the tool needs to persist cookies back) "
        f"so the request reaches protected endpoints, not just public ones.\n"
        if cookie_jar else ""
    )
    hints_note = (
        f"\nReal base paths this application actually serves (from live "
        f"discovery, not a guess): {', '.join(path_hints)} -- the "
        f"vulnerable endpoint is very likely under one of these, not at "
        f"the target's bare root.\n"
        if path_hints else ""
    )
    prompt = (
        f"Tool: {tool_name}\n"
        f"How this tool is invoked: "
        f"{usage_pattern or '(no usage pattern on file -- use your own knowledge of this tool)'}\n"
        f"{session_note}"
        f"{hints_note}"
        + (f"\nRETRY -- your previous attempt did not work:\n{retry_feedback}\n"
           "Do not repeat the same command. Pick a different gadget/payload "
           "name, endpoint guess, or parameter -- something genuinely "
           "different, not a cosmetic rewording.\n" if retry_feedback else "")
        + f"\nVulnerability type: {vuln_context.get('vuln_type', '?')} ({vuln_context.get('cwe', '?')})\n"
        f"Vulnerable code:\n{vuln_context.get('code_block', '')}\n"
        f"Description: {vuln_context.get('description', '')}\n"
        f"Attack vector: {vuln_context.get('attack_vector', '')}\n"
        f"Phase objective: {phase.get('objective', '')}\n"
        f"Target base URL (reachable from this attacker container over the "
        f"real Docker network): {target_url}\n\n"
        "Infer the real HTTP endpoint path from the code/description (a "
        "route annotation, a filename convention, or the description's own "
        "wording) and construct ONE real shell command that actually "
        "exercises this vulnerability using this tool against this target "
        "-- a fully-armed command with real flags, the real target URL, and "
        "a real payload, not a bare tool name. You may chain multiple "
        "commands with && or $() in one string if the tool needs a "
        "separate delivery step (e.g. ysoserial only generates a payload; "
        "it must then be POSTed with curl).\n\n"
        "If the attack needs a value that only exists on the live target "
        "(a session token, a cookie, a CSRF token, an ID) and isn't given "
        "to you above, the command must actually CAPTURE it first with a "
        "real request chained via shell variable substitution -- e.g. "
        "`TOKEN=$(curl -s ... | grep -oP '...') && jwt_tool $TOKEN ...` -- "
        "never write a bracketed placeholder like <captured_token> or "
        "<cracked_secret> into the final command; the shell will try to "
        "execute that literally and it will fail immediately (`<x` is "
        "input redirection, not a value to fill in later). If the value "
        "you're capturing lives in a response HEADER (a Set-Cookie value, "
        "a token header, anything from `grep`-ing for a header name), "
        "plain `curl -s` is NOT enough -- it only returns the response "
        "body, never headers, so grepping it for a header name will always "
        "come back empty. Use `curl -s -D -` (or `-i`) to include headers "
        "in the output you then grep.\n"
        'Return ONLY: {"command": str}'
    )
    raw = _call_qwen(prompt, "scanner.scanner_red._build_invocation")
    result = _parse_json(raw, {"command": tool_name})
    return result.get("command") or tool_name


_CREDENTIAL_FINDING_MARKERS = (
    "hardcoded credential", "default credential", "hardcoded password",
    "default password", "hardcoded user", "hardcoded secret",
)


def _find_hardcoded_credentials(vuln_contexts: list, driver) -> dict:
    """ARGUS-SCANNER: Scans every finding in the scan (not just the current
    cluster) for a hardcoded/default-credentials finding and extracts a
    real username/password pair from its code_block -- reused as the login
    for every phase's exploitation across the whole scenario. Runs once
    per scan, not per cluster (credentials don't change per finding).

    A genuinely detected credential-exposure finding becomes the key that
    unlocks testing every other authenticated endpoint, rather than
    treating auth as a separate blocker each cluster would otherwise hit
    independently. Only reliable once the victim container actually
    matches the analyzed source (see victim_builder.py's
    _try_build_from_dockerfile, added the same day this was -- a
    version-mismatched container can flag a real hardcoded-credentials
    finding whose exact literal values were never true for whatever
    happens to be running)."""
    candidates = [
        vc for vc in vuln_contexts
        if vc.get("cwe", "") == "CWE-798"
        or any(marker in vc.get("vuln_type", "").lower()
               for marker in _CREDENTIAL_FINDING_MARKERS)
    ]
    for vc in candidates:
        prompt = (
            "The following code contains hardcoded or default credentials:\n"
            f"{vc.get('code_block', '')}\n\n"
            f"Description: {vc.get('description', '')}\n\n"
            "Extract the actual literal username and password STRING "
            "VALUES (not variable names). If no real login credential pair "
            "is extractable from this snippet, return empty strings.\n"
            'Return ONLY: {"username": str, "password": str}'
        )
        raw = _call_qwen(prompt, "scanner.scanner_red._find_hardcoded_credentials")
        result = _parse_json(raw, {"username": "", "password": ""})
        if result.get("username") and result.get("password"):
            return {"username": result["username"], "password": result["password"]}
    return {}


_LOGIN_PATHS = ("/login", "/signin", "/sign_in", "/auth/login", "/account/login", "/user/login")


def _discover_routes(supervisor_url: str, attacker_container: str, target_url: str) -> list[str]:
    """ARGUS-SCANNER: Real, general route discovery -- runs dirb (a
    content-discovery brute-forcer, not guessed CLI syntax: delivered via
    the normal tool graph) from the attacker container against the live
    target, so both _authenticate() and _build_invocation() can work from
    routes the app actually serves instead of inferring blind from a
    source snippet or a fixed guess list.

    Added 2026-09-01 as the general fallback for apps whose base path
    doesn't match their own project name (the cheaper signal
    _execute_attack_plan tries first, from topology's repo_name) -- e.g.
    WebGoat's own dirb wordlist has no entry for "webgoat" at all
    (confirmed live via a direct grep), so blind brute-force alone
    wouldn't have found /WebGoat either; the two signals are
    complementary, not redundant. Bounded to dirb's small.txt wordlist
    and a short timeout -- this runs once per scenario, not once per
    phase, so it doesn't need to be exhaustive, just fast enough not to
    dominate the scenario's wall-clock budget."""
    _deliver_tool(supervisor_url, attacker_container,
                  "which dirb || (apt-get update -qq && apt-get install -y -qq dirb)")
    cmd = (f"dirb {target_url} /usr/share/dirb/wordlists/small.txt "
           f"-r -S -w 2>&1 | head -100")
    output = _exec_in_container(supervisor_url, attacker_container, cmd)
    return re.findall(r"^\+\s+\S+?(/\S*)\s+\(CODE:", output, re.MULTILINE)


def _authenticate(supervisor_url: str, attacker_container: str,
                   target_url: str, credentials: dict,
                   path_hints: tuple = ()) -> str:
    """ARGUS-SCANNER: One-time-per-scenario login from the attacker
    container against the real target over the Docker network, using
    whatever credential pair _find_hardcoded_credentials extracted.
    Returns a cookie-jar path inside the attacker container (usable by
    later curl-based invocations via `-b <path>`) on success, or "" if
    every attempt fails -- a phase still gets tried unauthenticated in
    that case rather than being blocked outright.

    Tries a handful of common login paths and the two most common form
    field-name conventions (username/password, email/password) rather
    than assuming one framework's exact form -- general-purpose, not
    tuned to any specific app. Success is judged by the POST's redirect
    NOT going back to a path containing "error" or "login" a second time
    (confirmed live 2026-09-01 against a real, source-matched WebGoat
    container: a failed login redirects to .../login?error, a real one
    redirects to .../welcome.mvc).

    path_hints (added same day) are real base-path candidates from
    topology's repo_name and/or _discover_routes -- tried as a prefix on
    every login path before falling back to bare paths, since many
    self-hosted apps mount everything under their own project name as a
    context path (WebGoat's real login is /WebGoat/login, invisible to
    the bare-path list alone -- found live investigating exactly this)."""
    if not credentials.get("username"):
        return ""
    cookie_jar = "/tmp/argus_session.txt"
    prefixes = list(path_hints) + [""]
    login_candidates = [f"{prefix}{path}" for prefix in prefixes for path in _LOGIN_PATHS]
    for path in login_candidates:
        page = _exec_in_container(
            supervisor_url, attacker_container,
            f"curl -s -c {cookie_jar} -m 10 {target_url}{path}")
        if not page.strip():
            continue
        username = credentials["username"]
        password = credentials["password"]
        for user_field in ("username", "email", "user"):
            login_cmd = (
                f"curl -sD - -b {cookie_jar} -c {cookie_jar} -m 10 -o /dev/null "
                f"-X POST {target_url}{path} "
                f"-d '{user_field}={username}&password={password}'"
            )
            headers = _exec_in_container(supervisor_url, attacker_container, login_cmd)
            m = re.search(r"Location:\s*(\S+)", headers)
            if "30" in headers.split("\n", 1)[0] and m:
                location = m.group(1).lower()
                if "error" not in location and not location.rstrip("/").endswith(path):
                    return cookie_jar
    return ""


def _crawl_links(html: str) -> list[str]:
    """ARGUS-SCANNER: General, framework-agnostic route discovery -- parses
    an already-fetched HTML response for real hrefs/form actions/script
    srcs, instead of guessing or leaning on any one framework's own
    introspection endpoint (Spring's /actuator/mappings, Rails routes,
    Django's admin, etc. would each only work for that one stack, and this
    project stays general across whatever a scanned repo happens to use).
    Works identically no matter the backend language -- it only reads the
    rendered output, the same way a real attacker without source access
    would. Most server-rendered apps' own navigation IS the real route
    map; WebGoat in particular is a lesson-navigation UI, so this alone
    should surface most real lesson URLs directly."""
    paths = set()
    for m in re.finditer(r'(?:href|action|src)=["\']([^"\']+)["\']', html, re.IGNORECASE):
        url = m.group(1).strip()
        if not url or url.startswith(("#", "javascript:", "mailto:", "data:")):
            continue
        if "://" in url:
            continue  # same-origin paths only -- an absolute/external URL isn't a route on this app
        path = url.split("?")[0].split("#")[0]
        if path.startswith("/") and len(path) > 1:
            paths.add(path)
    return sorted(paths)


_LANDING_PAGE_CANDIDATES = ("/welcome.mvc", "/", "/home", "/dashboard", "/index")
_STATIC_ASSET_SUFFIXES = (".css", ".js", ".svg", ".ico", ".png", ".jpg", ".jpeg",
                           ".gif", ".woff", ".woff2", ".ttf", ".map")


def _crawl_authenticated_links(supervisor_url: str, attacker_container: str,
                                target_url: str, cookie_jar: str,
                                path_hints: tuple = ()) -> list[str]:
    """ARGUS-SCANNER: Fetches the real, authenticated landing page and
    crawls it for real links via _crawl_links() -- the cheapest, most
    accurate route-discovery signal available once a session exists,
    since it reads what the app itself actually links to rather than
    guessing or brute-forcing a wordlist. General across landing-page
    naming conventions (not just WebGoat's own /welcome.mvc) by trying a
    handful of common candidates with each known path prefix. -L is
    required -- confirmed live 2026-09-04 that a plain `curl -s` on a
    redirecting landing path returns an empty body (the redirect itself
    has none), silently producing zero links; -L follows it to the real
    rendered page. Does one more hop into the first few non-static
    same-origin links found, since a real landing/splash page often links
    to the actual navigation/menu page rather than containing every
    route itself (confirmed live: WebGoat's welcome.mvc links to
    start.mvc, not the lesson menu directly)."""
    candidates = [f"{prefix}{suffix}" for prefix in (list(path_hints) + [""])
                  for suffix in _LANDING_PAGE_CANDIDATES]
    all_links: set[str] = set()
    fetched: set[str] = set()
    for candidate in candidates:
        if candidate in fetched:
            continue
        fetched.add(candidate)
        html = _exec_in_container(supervisor_url, attacker_container,
                                   f"curl -s -L -b {cookie_jar} -m 10 {target_url}{candidate}")
        links = _crawl_links(html)
        if links:
            all_links.update(links)
            break
    hops = 0
    for link in sorted(all_links):
        if hops >= 3:
            break
        if link.endswith(_STATIC_ASSET_SUFFIXES) or link in fetched:
            continue
        fetched.add(link)
        html = _exec_in_container(supervisor_url, attacker_container,
                                   f"curl -s -L -b {cookie_jar} -m 10 {target_url}{link}")
        all_links.update(_crawl_links(html))
        hops += 1
    return sorted(all_links)


def _execute_attack_plan(attack_plan: dict, topology: dict,
                          supervisor_url: str, driver, vuln_context: dict,
                          credentials: dict | None = None) -> dict:
    """ARGUS-SCANNER: Runs every phase in attack_plan, tracking acquired
    capabilities across the whole scenario. A blocked phase is skipped,
    never stops the scenario; only exhausting every phase (blocked or not)
    ends it.

    Changed 2026-09-01: tools now run inside a real, separate attacker
    container (one per cluster, spawned before the phase loop and torn
    down after it in a finally block) connected to the target services'
    own Docker network(s), instead of being delivered into and exec'd
    inside the victim's own app container. `container_name` below still
    means the victim service -- it's still what phases target and how the
    real port/URL gets resolved -- but tool delivery and execution now go
    to `attacker_container` instead."""
    acquired_capabilities = {}
    phase_results = []
    all_blocked = True
    service_by_name = {s["name"]: s for s in topology["services"]}
    phases = attack_plan.get("attack_phases", [])

    # Docker container lookup needs the real container_id/full name -- the
    # bare compose service name ("webgoat") is only a network DNS alias,
    # not something `docker_client.containers.get()` resolves (confirmed
    # live 2026-09-01: raises NotFound). topology's container_id (from
    # `docker compose ps`, victim_builder.py:370) is the real one.
    target_container_ids = list({
        service_by_name[p["service"]]["container_id"] for p in phases
        if p.get("service", "") in service_by_name
        and service_by_name[p["service"]].get("container_id")
    })
    attacker_container = _spawn_attacker(supervisor_url, target_container_ids)

    cookie_jar = ""
    path_hints: list[str] = []
    repo_name = topology.get("repo_name", "")
    if repo_name:
        path_hints.append(f"/{repo_name}")

    if attacker_container and credentials and credentials.get("username") and phases:
        first_service = next((p["service"] for p in phases
                               if p.get("service", "") in service_by_name), None)
        if first_service:
            auth_port = _container_port(topology, first_service)
            target_url = f"http://{first_service}:{auth_port}"
            cookie_jar = _authenticate(
                supervisor_url, attacker_container, target_url, credentials,
                path_hints=tuple(path_hints))
            if not cookie_jar:
                # The cheap repo-name guess didn't pan out -- fall back to
                # real, general route discovery (dirb) rather than giving
                # up on authentication entirely.
                discovered = _discover_routes(supervisor_url, attacker_container, target_url)
                if discovered:
                    path_hints.extend(p for p in discovered if p not in path_hints)
                    cookie_jar = _authenticate(
                        supervisor_url, attacker_container, target_url, credentials,
                        path_hints=tuple(path_hints))
            if cookie_jar:
                crawled = _crawl_authenticated_links(
                    supervisor_url, attacker_container, target_url, cookie_jar,
                    path_hints=tuple(path_hints))
                path_hints.extend(p for p in crawled if p not in path_hints)

    try:
        for phase in phases:
            container_name = phase.get("service", "")
            if container_name not in service_by_name or not attacker_container:
                phase_results.append({
                    "service": container_name, "tool": None, "status": "blocked",
                    "result": "skipped", "execution_evidence": False,
                    "qwen_signal": False, "conflict": False,
                    "observations": {}, "pivoted": False,
                })
                continue

            tool_result = _request_tool_for_phase(
                phase, acquired_capabilities, supervisor_url, attacker_container, driver)

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
            port = _container_port(topology, container_name)
            target_url = f"http://{container_name}:{port}"
            command = _build_invocation(active_tool, phase, vuln_context, target_url,
                                         driver, cookie_jar=cookie_jar,
                                         path_hints=tuple(path_hints))
            stdout = _exec_in_container(supervisor_url, attacker_container, command)
            obs = normalize(stdout, phase.get("technique_id", ""), driver)
            assessment = _assess_objective(phase.get("objective", ""), obs, stdout, driver,
                                            exploit_condition=phase.get("exploit_condition", ""))

            # One bounded retry on any not-achieved result -- added
            # 2026-09-03 after live reproduction showed a real, low-
            # probability-but-real failure mode: Qwen picking a wrong
            # gadget/payload name (e.g. ysoserial's "XStream1" instead of
            # "XStream") rather than the exploit genuinely being
            # unreachable. A single retry, fed the prior command+stdout so
            # Qwen tries something actually different rather than repeating
            # itself, catches that class without letting a scenario loop
            # forever on a truly unexploitable finding.
            retried = False
            if not assessment["achieved"]:
                retried = True
                feedback = f"Command: {command}\nOutput: {stdout[:800]}"
                valid_options = _extract_valid_options(stdout)
                if valid_options:
                    feedback += (
                        f"\nThe tool's own output lists these EXACT valid "
                        f"values: {valid_options}. If your previous command "
                        f"used an invalid enum/type/payload name, you MUST "
                        f"pick one of these exact strings verbatim, not a "
                        f"variation of it.")
                command = _build_invocation(active_tool, phase, vuln_context, target_url,
                                             driver, cookie_jar=cookie_jar,
                                             path_hints=tuple(path_hints),
                                             retry_feedback=feedback)
                stdout = _exec_in_container(supervisor_url, attacker_container, command)
                obs = normalize(stdout, phase.get("technique_id", ""), driver)
                assessment = _assess_objective(
                    phase.get("objective", ""), obs, stdout, driver,
                    exploit_condition=phase.get("exploit_condition", ""))

            all_blocked = False
            phase_results.append({
                "service": container_name, "tool": active_tool,
                "status": tool_result["status"],
                # Was "partial" -- a misleading label with no real third
                # state (every not-achieved case hit it uniformly, whether
                # a genuine partial-progress attempt or a flat qwen=False
                # rejection). "not_achieved" says what actually happened.
                "result": "success" if assessment["achieved"] else "not_achieved",
                "execution_evidence": assessment["execution_evidence"],
                "qwen_signal": assessment["qwen_signal"],
                "conflict": assessment["conflict"],
                "observations": obs,
                "retried": retried,
                "pivoted": assessment["achieved"] and phase is not phases[-1],
            })
    finally:
        _teardown_attacker(supervisor_url, attacker_container)

    kill_chain_complete = bool(
        not all_blocked and phase_results and phases and
        phase_results[-1]["result"] in ("success", "not_achieved") and
        phase_results[-1]["service"] == phases[-1]["service"]
    )
    return {
        "status": "executed", "phases": phase_results,
        "kill_chain_complete": kill_chain_complete,
        "final_service_reached": phase_results[-1]["service"] if phase_results else "",
    }
