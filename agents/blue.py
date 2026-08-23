"""
ARGUS Layer 5 — Blue Agent
============================
Receives a red agent's engagement plan, uses Qwen3 /think to propose 
concrete mitigations, and writes mitigation nodes and mitigates edges 
to Neo4j. Then marks the engagement as closed.

This script is the blue agent's mitigation planning loop. 
It receives a red agent's attack plan, uses Qwen3 /think to propose 
mitigations, writes mitigation node + mitigates edge to Neo4j, 
and marks the engagement closed.
"""

import json
import re
import os
import time
from datetime import datetime
import config  # noqa: F401 -- side effect: forces OLLAMA_HOST. Must import
                # before `ollama` -- see agents/red.py's comment on this.
import requests
from dotenv import load_dotenv

load_dotenv()

MODEL = "qwen3:8b"
EXEC_TIMEOUT = 60      # seconds, per GRAPHRANGE.md Phase 4 spec
MONITOR_POLL_SECONDS = 3
OLLAMA_CHAT_URL = f"{os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')}/api/chat"


# ── LLM helper ────────────────────────────────────────────────────────────────

def _think(prompt: str, max_retries: int = 3) -> str:
    """Call Qwen3 in thinking mode; strip <think> blocks from output.
    Retries on Cloudflare 524 (origin timeout) with exponential backoff."""
    for attempt in range(max_retries):
        try:
            r = requests.post(OLLAMA_CHAT_URL, json={
                "model": MODEL,
                "messages": [{"role": "user", "content": f"/think\n\n{prompt}"}],
                "stream": False,
            })  # no timeout — let Kaggle inference run as long as needed
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


# ── Prompts & parsers ─────────────────────────────────────────────────────────

def _mitigation_prompt(engagement: dict) -> str:
    chain        = engagement.get("selected_chain", [])
    chain_str    = json.dumps(chain, indent=2)
    lessons      = engagement.get("past_blue_lessons", [])
    lessons_str  = ("\nPast lessons from prior defenses:\n" +
                    "\n".join(f"- {l}" for l in lessons[:3])) if lessons else ""
    return (
        "You are the ARGUS Blue Agent responding to an updated adversarial attack plan.\n\n"
        f"Attack chain:\n{chain_str}\n\n"
        f"Attacker confidence: {engagement.get('confidence', 0.5)}\n"
        f"Red reasoning: {engagement.get('reasoning', '')}\n"
        f"Attacker preconditions: {engagement.get('preconditions', [])}\n"
        f"{lessons_str}\n"
        "Propose concrete mitigations for each step in the attack chain, "
        "incorporating lessons from prior defenses if available.\n\n"
        "Reply in EXACTLY this format:\n"
        "EFFECTIVENESS: <float 0.0-1.0>\n"
        "MITIGATION_STEPS: <semicolon-separated list of concrete defensive actions>\n"
        "PATCH_PRIORITY: <critical|high|medium|low>\n"
        "REASONING: <one sentence>\n"
        "ADDITIONAL_INFO: <any additional information>"
    )


def _parse_mitigation(text: str) -> dict:
    out = {"effectiveness": 0.5, "steps": [], "priority": "medium", "reasoning": "", "additional_info": ""}
    for line in text.splitlines():
        if line.startswith("EFFECTIVENESS:"):
            try:
                out["effectiveness"] = max(0.0, min(1.0, float(line.split(":", 1)[1].strip())))
            except ValueError:
                pass
        elif line.startswith("MITIGATION_STEPS:"):
            val = line.split(":", 1)[1].strip()
            out["steps"] = [s.strip() for s in val.split(";") if s.strip()]
        elif line.startswith("PATCH_PRIORITY:"):
            out["priority"] = line.split(":", 1)[1].strip().lower()
        elif line.startswith("REASONING:"):
            out["reasoning"] = line.split(":", 1)[1].strip()
        elif line.startswith("ADDITIONAL_INFO:"):
            out["additional_info"] = line.split(":", 1)[1].strip()
    return out


# ── Graph writes ──────────────────────────────────────────────────────────────

def _write_mitigation_node(driver, mitigation: dict) -> None:
    """ARGUS-LAYER-5: Persist mitigation record to Neo4j."""
    cypher = """
    MERGE (n:Node {node_id: $mid})
    SET n += $props
    SET n:Mitigation
    """
    props = {
        "node_id":          mitigation["mitigation_id"],
        "label":            mitigation["mitigation_id"],
        "node_type":        "mitigation",
        "properties":       json.dumps(mitigation),
        "grain_confidence": float(mitigation.get("effectiveness", 0.5)),
        "open_questions":   [],
        "challenger_log":   "[]",
        "source":           "agent_derived",
        "last_updated":     datetime.utcnow().isoformat(),
        "created_at":       datetime.utcnow().isoformat(),
        "additional_info": mitigation.get("additional_info", "")
    }
    with driver.session() as session:
        session.run(cypher, mid=mitigation["mitigation_id"], props=props)


def _write_mitigates_edge(driver, mitigation_id: str, engagement_id: str,
                           effectiveness: float) -> None:
    """ARGUS-LAYER-5: Link mitigation node to the engagement it addresses."""
    cypher = """
    MATCH (m:Node {node_id: $mid}), (e:Node {node_id: $eid})
    MERGE (m)-[r:RELATION {edge_id: $edge_id}]->(e)
    SET r.relation_type      = 'mitigates',
        r.confidence         = $conf,
        r.context_conditions = [],
        r.directionality     = 'unidirectional',
        r.source             = 'agent_derived',
        r.last_updated       = $ts
    """
    with driver.session() as session:
        session.run(
            cypher,
            mid=mitigation_id,
            eid=engagement_id,
            edge_id=f"{mitigation_id}_mitigates_{engagement_id}",
            conf=effectiveness,
            ts=datetime.utcnow().isoformat(),
        )


def _close_engagement(driver, engagement_id: str) -> None:
    """ARGUS-LAYER-5: Mark engagement as mitigated in Neo4j."""
    with driver.session() as session:
        session.run(
            "MATCH (n:Node {node_id: $eid}) "
            "SET n.status = 'mitigated', n.last_updated = $ts",
            eid=engagement_id,
            ts=datetime.utcnow().isoformat(),
        )


# ── Main entrypoint ───────────────────────────────────────────────────────────

def plan_mitigation(driver, attack_plan: dict, context: dict = None) -> dict:
    """
    ARGUS-LAYER-5: Blue agent mitigation planning loop.
    Receives a red agent's engagement plan, uses Qwen3 /think to propose 
    concrete mitigations, and writes mitigation nodes and mitigates edges 
    to Neo4j. Then marks the engagement as closed.
    Returns {"status": ..., "mitigation": ...}.
    """
    engagement = attack_plan.get("engagement")
    if not engagement:
        return {"status": "no_engagement", "mitigation": None}

    # Load blue agent's past lessons to improve mitigation over cycles
    try:
        from memory.reflexion import get_recent_memories
        memories = get_recent_memories(driver, agent="blue", limit=3)
        lessons  = [m.get("lesson", "") for m in memories if m.get("lesson")]
        if lessons:
            engagement = {**engagement, "past_blue_lessons": lessons}
    except Exception:
        pass

    mit_text = _think(_mitigation_prompt(engagement))
    mit      = _parse_mitigation(mit_text)

    mitigation_id = f"MIT-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}"
    mitigation = {
        "mitigation_id":  mitigation_id,
        "engagement_id":  engagement["engagement_id"],
        "effectiveness":  mit["effectiveness"],
        "steps":          mit["steps"],
        "priority":       mit["priority"],
        "reasoning":      mit["reasoning"],
        "timestamp":      datetime.utcnow().isoformat(),
    }

    _write_mitigation_node(driver, mitigation)
    _write_mitigates_edge(driver, mitigation_id, engagement["engagement_id"],
                          mit["effectiveness"])
    _close_engagement(driver, engagement["engagement_id"])

    print(f"  [BLUE] {mitigation_id} — effectiveness={mit['effectiveness']:.2f}, "
          f"priority={mit['priority']}, {len(mit['steps'])} steps")
    return {"status": "mitigated", "mitigation": mitigation}


# ── Execution layer (GraphRange, Layer 7) ───────────────────────────────────────

def monitor(supervisor_url: str, run_suffix: str, scenario: dict, stop_event) -> list:
    """
    ARGUS-LAYER-7: Blue daemon that runs in a thread during red execution,
    polling the range for anomalies while red attacks. `run_suffix` must
    match the value used when the scenario's containers were spawned (see
    agents/red.py's execute_attack() and supervisor.py's spawn_scenario()) --
    containers are actually named gr-{role}-{run_suffix}, not the literal
    "blue"/"victim" placeholder strings GRAPHRANGE.md's spec text used.
    stop_event: threading.Event, set by the caller when red is done.

    Both checks below are deliberately coarse heuristics, not precise
    attribution: tcpdump runs with -nn (no name/DNS resolution, per spec),
    so there's no way to match captured traffic to the victim container by
    name from this data alone -- any non-trivial capture during the window
    is treated as "network activity observed," not "activity confirmed
    to/from the victim specifically." Likewise, `ss -tnp` on the victim
    reports ANY established connection, not just attacker-originated ones --
    a real deployment would diff against a pre-attack baseline; this doesn't
    have one to diff against yet.
    """
    blue_container = f"gr-blue-{run_suffix}"
    victim_container = f"gr-victim-{run_suffix}"
    events = []

    while not stop_event.is_set():
        try:
            resp = requests.post(
                f"{supervisor_url}/exec",
                json={"container": blue_container,
                      "command": "tcpdump -i any -c 10 -nn 2>/dev/null"},
                timeout=EXEC_TIMEOUT,
            )
            tcpdump_out = resp.json().get("stdout", "") if resp.ok else ""
        except requests.RequestException:
            tcpdump_out = ""
        if tcpdump_out.strip():
            events.append({
                "timestamp": datetime.utcnow().isoformat(),
                "type": "unexpected_connection",
                "detail": tcpdump_out[:300],
            })

        try:
            resp = requests.post(
                f"{supervisor_url}/exec",
                json={"container": victim_container, "command": "ss -tnp 2>/dev/null"},
                timeout=EXEC_TIMEOUT,
            )
            ss_out = resp.json().get("stdout", "") if resp.ok else ""
        except requests.RequestException:
            ss_out = ""
        if "ESTAB" in ss_out:
            events.append({
                "timestamp": datetime.utcnow().isoformat(),
                "type": "port_scan",
                "detail": ss_out[:300],
            })

        stop_event.wait(MONITOR_POLL_SECONDS)

    return events


def assess_detection(detection_events: list, scenario: dict) -> dict:
    """
    ARGUS-LAYER-7: After a scenario ends, assess whether blue detected the
    attack. Simple heuristic per spec -- any detection event during the
    window counts as detected. `turn_detected` uses the event's index in
    the list as a proxy for "which poll cycle first saw it" -- there's no
    formal turn/round concept threaded through yet (that's Phase 7's
    run_scenario.py orchestration, not built at this point).
    """
    if not detection_events:
        return {"detected": False, "detection_type": "", "turn_detected": -1}
    first = detection_events[0]
    return {
        "detected": True,
        "detection_type": first.get("type", ""),
        "turn_detected": 0,
    }
