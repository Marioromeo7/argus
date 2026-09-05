"""
ARGUS Layer 5 — Red Agent
===========================
Discovers viable attack paths in the graph using Qwen3 /think
planning. Traverses CVE->technique->tactic chains, selects the
highest-confidence path given engagement context, and records
the engagement in Neo4j for the blue agent to respond to.

Co-evolutionary claim: attack_path_discovery_rate increases over
successive engagements as the graph gains more nodes and edges.
"""

import json
import re
import os
from datetime import datetime
import config  # noqa: F401 -- side effect: forces OLLAMA_HOST. Must import
                # before `ollama` -- that package reads OLLAMA_HOST once at
                # import time to build its default client, so importing
                # config afterward was too late (confirmed live: WinError
                # 10049, connecting to the stale pre-existing system value).
import requests
from dotenv import load_dotenv
from graph.retrieval import get_node

load_dotenv()

import time

MODEL = "qwen3:8b"
EXEC_TIMEOUT = 60  # seconds, per GRAPHRANGE.md Phase 4 spec
OLLAMA_CHAT_URL = f"{os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')}/api/chat"


# ── LLM helper ────────────────────────────────────────────────────────────────

def _think(prompt: str, max_retries: int = 3) -> str:
    """Call Qwen3 in thinking mode; strip <think> blocks from output.
    Retries on Cloudflare 524 (origin timeout), a request timeout, or a
    dropped connection -- all three real, not hypothetical: the old
    `timeout=None` ("let Kaggle inference run as long as needed", a Kaggle-era
    design) meant a genuine local Ollama server hang blocked forever with no
    retry and no way to distinguish a hang from legitimate slow inference.
    Confirmed live 2026-09-04/05: a real R2.3 150-cycle run hit this twice in
    under an hour, once silently for 1+ hour before being caught, once via a
    ConnectionResetError when Ollama was restarted mid-call, which propagated
    uncaught and crashed the whole run (see ROADMAP.md R2.3). 900s matches
    agents/narrowing.py's own documented real-world worst case for a /think
    call on this hardware (two pilot nodes exceeded 600s outright)."""
    for attempt in range(max_retries):
        try:
            r = requests.post(OLLAMA_CHAT_URL, json={
                "model": MODEL,
                "messages": [{"role": "user", "content": f"/think\n\n{prompt}"}],
                "stream": False,
            }, timeout=900)
            r.raise_for_status()
            text = r.json()["message"]["content"]
            return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 524 and attempt < max_retries - 1:
                wait_time = (2 ** attempt) * 30  # 30s, 60s, 120s
                print(f"  [RETRY] Cloudflare timeout on attempt {attempt+1}/{max_retries}, waiting {wait_time}s...")
                time.sleep(wait_time)
            else:
                raise
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            if attempt < max_retries - 1:
                wait_time = (2 ** attempt) * 30  # 30s, 60s, 120s
                print(f"  [RETRY] Ollama unresponsive ({type(e).__name__}) on attempt "
                      f"{attempt+1}/{max_retries}, waiting {wait_time}s...")
                time.sleep(wait_time)
            else:
                raise


# ── Graph queries ─────────────────────────────────────────────────────────────

def _get_attack_surface(driver) -> list[dict]:
    """ARGUS-LAYER-5: Find CVEs that have edges to known techniques."""
    cypher = """
    MATCH (v:Node {node_type: 'vulnerability'})-[r:RELATION]->(t:Node {node_type: 'technique'})
    RETURN v.node_id AS cve_id, v.label AS cve_label,
           t.node_id AS tech_id, t.label AS tech_label,
           r.confidence AS confidence
    ORDER BY r.confidence DESC
    LIMIT 10
    """
    with driver.session() as session:
        return [dict(r) for r in session.run(cypher)]


def _get_full_chains(driver, cve_id: str) -> list[list[dict]]:
    """ARGUS-LAYER-5: Get full CVE->technique->tactic chains from a starting CVE."""
    cypher = """
    MATCH (v:Node {node_id: $cve})-[:RELATION]->(t:Node {node_type: 'technique'})
          -[:RELATION]->(tac:Node {node_type: 'tactic'})
    RETURN v.node_id AS cve, v.label AS cve_label,
           t.node_id AS tech, t.label AS tech_label,
           tac.node_id AS tactic, tac.label AS tactic_label
    LIMIT 5
    """
    with driver.session() as session:
        rows = [dict(r) for r in session.run(cypher, cve=cve_id)]
    chains = []
    for row in rows:
        chains.append([
            {"node_id": row["cve"],    "label": row["cve_label"],    "type": "vulnerability"},
            {"node_id": row["tech"],   "label": row["tech_label"],   "type": "technique"},
            {"node_id": row["tactic"], "label": row["tactic_label"], "type": "tactic"},
        ])
    return chains


# ── Prompts & parsers ─────────────────────────────────────────────────────────

def _plan_prompt(chains: list, context: dict) -> str:
    context_str  = json.dumps(context, indent=2) if context else "{}"
    chains_str   = json.dumps(chains[:5], indent=2)
    lessons      = context.get("past_lessons", [])
    lessons_str  = ("\nPast lessons from prior engagements:\n" +
                    "\n".join(f"- {l}" for l in lessons[:3])) if lessons else ""
    return (
        "You are the ARGUS Red Agent planning a cyber attack simulation.\n\n"
        f"Attacker context:\n{context_str}{lessons_str}\n\n"
        f"Available attack chains (CVE->technique->tactic):\n{chains_str}\n\n"
        "Select the chain most likely to succeed given the context and past lessons.\n\n"
        "Reply in EXACTLY this format:\n"
        "CHAIN_INDEX: <0-based index of selected chain>\n"
        "CONFIDENCE: <float 0.0-1.0>\n"
        "REASONING: <one sentence>\n"
        "PRECONDITIONS: <comma-separated attacker prerequisites, or NONE>"
    )


def _parse_plan(text: str) -> dict:
    out = {"chain_index": 0, "confidence": 0.5, "reasoning": "", "preconditions": []}
    for line in text.splitlines():
        if line.startswith("CHAIN_INDEX:"):
            try:
                out["chain_index"] = int(line.split(":", 1)[1].strip())
            except ValueError:
                pass
        elif line.startswith("CONFIDENCE:"):
            try:
                out["confidence"] = max(0.0, min(1.0, float(line.split(":", 1)[1].strip())))
            except ValueError:
                pass
        elif line.startswith("REASONING:"):
            out["reasoning"] = line.split(":", 1)[1].strip()
        elif line.startswith("PRECONDITIONS:"):
            val = line.split(":", 1)[1].strip()
            if val and val.upper() != "NONE":
                out["preconditions"] = [p.strip() for p in val.split(",") if p.strip()]
    return out


# ── Graph writes ──────────────────────────────────────────────────────────────

def _write_engagement(driver, engagement: dict) -> None:
    """ARGUS-LAYER-5: Persist engagement record to Neo4j."""
    cypher = """
    MERGE (n:Node {node_id: $eid})
    SET n += $props
    SET n:Engagement
    """
    props = {
        "node_id":          engagement["engagement_id"],
        "label":            engagement["engagement_id"],
        "node_type":        "engagement",
        "properties":       json.dumps(engagement),
        "grain_confidence": float(engagement.get("confidence", 0.5)),
        "open_questions":   [],
        "challenger_log":   "[]",
        "source":           "agent_derived",
        "status":           engagement.get("status", "open"),
        "last_updated":     datetime.utcnow().isoformat(),
        "created_at":       datetime.utcnow().isoformat(),
    }
    with driver.session() as session:
        session.run(cypher, eid=engagement["engagement_id"], props=props)


def update_chain_confidence(driver, chain: list, succeeded: bool) -> None:
    """ARGUS-LAYER-5: Bayesian-style confidence update on each hop in a chain."""
    delta = 0.05 if succeeded else -0.05
    cypher = """
    MATCH (a:Node {node_id: $src})-[r:RELATION]->(b:Node {node_id: $tgt})
    SET r.confidence = CASE
        WHEN coalesce(r.confidence, 0.5) + $delta > 1.0 THEN 1.0
        WHEN coalesce(r.confidence, 0.5) + $delta < 0.0 THEN 0.0
        ELSE coalesce(r.confidence, 0.5) + $delta
    END,
    r.last_updated = $ts
    """
    ts = datetime.utcnow().isoformat()
    for i in range(len(chain) - 1):
        src = chain[i]["node_id"]
        tgt = chain[i + 1]["node_id"]
        with driver.session() as session:
            session.run(cypher, src=src, tgt=tgt, delta=delta, ts=ts)


# ── Main entrypoint ───────────────────────────────────────────────────────────

def plan_attack(driver, context: dict = None, max_chains: int = 5,
                scenario: dict = None) -> dict:
    """
    ARGUS-LAYER-5: Red agent attack planning loop.
    Finds CVE->technique->tactic chains, uses Qwen3 /think to select
    the best path, writes an engagement node to Neo4j.
    Returns {"status": ..., "engagement": ..., "all_chains": ...}.

    When `scenario` (from get_valid_scenarios()) is given, planning is TARGETED
    at it (GraphRange Phase 7, D5): the scenario's own CVE is seeded first so its
    CVE->technique->tactic chain is a candidate, and the target is surfaced in
    the plan prompt -- closing the "what red planned vs. what execute_attack
    measures can diverge" gap. run_scenario.run_one() re-verifies the match
    after execution. With scenario=None the original independent whole-surface
    behavior is unchanged (Layer 5 co-evolution use).

    NOTE: the scenario-targeting path is not yet live-validated -- added
    file-only 2026-08-17; needs the Phase 7 GPU run to confirm.
    """
    if context is None:
        context = {}

    target = None
    if scenario and scenario.get("cve_id"):
        target = {"cve_id": scenario.get("cve_id"),
                  "technique_id": scenario.get("technique_id")}
        context = {**context, "target_scenario": target}

    # Load red agent's past lessons to improve chain selection over cycles
    try:
        from memory.reflexion import get_recent_memories
        memories = get_recent_memories(driver, agent="red", limit=3)
        lessons  = [m.get("lesson", "") for m in memories if m.get("lesson")]
        if lessons:
            context = {**context, "past_lessons": lessons}
    except Exception:
        pass

    surface = _get_attack_surface(driver)
    if not surface and not target:
        return {"status": "no_attack_surface", "chains": [], "plan": None}

    # Seed the target scenario's CVE first (so its chain is a candidate the
    # LLM can select), then fill from the broader attack surface.
    seed_cves = []
    if target:
        seed_cves.append(target["cve_id"])
    seed_cves.extend(entry["cve_id"] for entry in surface[:3])

    all_chains = []
    seen_cves = set()
    for cve_id in seed_cves:
        if cve_id in seen_cves:
            continue
        seen_cves.add(cve_id)
        all_chains.extend(_get_full_chains(driver, cve_id))
        if len(all_chains) >= max_chains:
            break

    if not all_chains:
        return {"status": "no_chains", "chains": [], "plan": None}

    plan_text = _think(_plan_prompt(all_chains, context))
    plan      = _parse_plan(plan_text)

    idx            = min(plan["chain_index"], len(all_chains) - 1)
    selected_chain = all_chains[idx]

    engagement_id = f"ENG-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}"
    engagement = {
        "engagement_id":  engagement_id,
        "selected_chain": selected_chain,
        "confidence":     plan["confidence"],
        "reasoning":      plan["reasoning"],
        "preconditions":  plan["preconditions"],
        "target_scenario": target,
        "context":        context,
        "timestamp":      datetime.utcnow().isoformat(),
        "status":         "open",
    }

    _write_engagement(driver, engagement)
    print(f"  [RED] {engagement_id} — {len(selected_chain)}-hop chain, "
          f"confidence={plan['confidence']:.2f}")
    return {"status": "planned", "engagement": engagement, "all_chains": all_chains}


# ── Execution layer (GraphRange, Layer 7) ───────────────────────────────────────

def _map_observables_to_capability(observables: list) -> str:
    """ARGUS-LAYER-7: Rough mapping from a technique's expected_observables to
    a tool capability category the tool graph understands. Deliberately a
    small hardcoded rule set, not a model call — this is a coarse routing
    decision (which capability bucket to search), not a judgment worth
    spending GPU on."""
    text = " ".join(observables).lower()
    if any(k in text for k in ("credential", "password_hash", "password")):
        return "credential_access"
    if any(k in text for k in ("file_path", "registry_key")):
        return "discovery"
    if any(k in text for k in ("shell_access", "command_output")):
        return "exploitation"
    return "network_scanning"


def execute_attack(driver, supervisor_url: str, scenario: dict, engagement: dict) -> dict:
    """
    ARGUS-LAYER-7: Executes a planned attack in the Docker range. Called
    AFTER plan_attack() returns an engagement. Fails gracefully at every
    supervisor call — a Docker range being down should never crash the
    calling scenario loop.

    Real command construction is intentionally simple: `{tool} [json_flag]
    {target}`. This covers common CLI tools (nmap-shaped) but not every
    tool's actual argument order — a known simplification, not a claim of
    universal tool support.
    """
    from graphrange.tool_graph import get_tool_by_name
    from graphrange.observer import normalize, determine_success

    run_suffix = scenario.get("run_id") or engagement.get("engagement_id", "adhoc")
    red_container = f"gr-red-{run_suffix}"
    victim_container = f"gr-victim-{run_suffix}"

    capability = _map_observables_to_capability(scenario.get("expected_observables", []))
    try:
        resp = requests.post(f"{supervisor_url}/tool_request",
                              json={"agent": "red", "capability": capability},
                              timeout=EXEC_TIMEOUT)
        resp.raise_for_status()
        tool_info = resp.json()
    except requests.RequestException:
        return {"status": "supervisor_error"}

    tool_name = tool_info.get("tool_name")
    if not tool_name:
        return {"status": "no_tool_available", "capability": capability}
    install_command = tool_info.get("install_command")

    try:
        if install_command:
            resp = requests.post(f"{supervisor_url}/exec",
                                  json={"container": red_container, "command": install_command},
                                  timeout=EXEC_TIMEOUT)
            resp.raise_for_status()
            if not resp.json().get("success", False):
                return {"status": "install_failed", "tool_used": tool_name,
                        "install_command": install_command}

        tool_props = get_tool_by_name(driver, tool_name)
        props = (tool_props or {}).get("properties", {})
        if props.get("supports_json_output") and props.get("json_flag"):
            run_command = f"{tool_name} {props['json_flag']} {victim_container}"
        else:
            run_command = f"{tool_name} {victim_container}"

        resp = requests.post(f"{supervisor_url}/exec",
                              json={"container": red_container, "command": run_command},
                              timeout=EXEC_TIMEOUT)
        resp.raise_for_status()
        stdout = resp.json().get("stdout", "")
    except requests.RequestException:
        return {"status": "supervisor_error"}

    observations = normalize(stdout, scenario.get("technique_id", ""), driver)
    success = determine_success(observations, scenario)

    return {
        "status": "executed",
        "tool_used": tool_name,
        "raw_output": stdout,
        "observations": observations,
        "success": success,
    }
