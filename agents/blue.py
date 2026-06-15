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
from datetime import datetime
import ollama
from dotenv import load_dotenv

load_dotenv()

MODEL = "qwen3:8b"


# ── LLM helper ────────────────────────────────────────────────────────────────

def _think(prompt: str) -> str:
    """Call Qwen3 in thinking mode; strip <think> blocks from output."""
    resp = ollama.chat(
        model=MODEL,
        messages=[{"role": "user", "content": f"/think\n\n{prompt}"}],
    )
    text = resp["message"]["content"]
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


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
