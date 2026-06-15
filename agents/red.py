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
import ollama
from dotenv import load_dotenv
from graph.retrieval import get_node

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

def plan_attack(driver, context: dict = None, max_chains: int = 5) -> dict:
    """
    ARGUS-LAYER-5: Red agent attack planning loop.
    Finds CVE->technique->tactic chains, uses Qwen3 /think to select
    the best path, writes an engagement node to Neo4j.
    Returns {"status": ..., "engagement": ..., "all_chains": ...}.
    """
    if context is None:
        context = {}

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
    if not surface:
        return {"status": "no_attack_surface", "chains": [], "plan": None}

    all_chains = []
    for entry in surface[:3]:
        chains = _get_full_chains(driver, entry["cve_id"])
        all_chains.extend(chains)
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
        "context":        context,
        "timestamp":      datetime.utcnow().isoformat(),
        "status":         "open",
    }

    _write_engagement(driver, engagement)
    print(f"  [RED] {engagement_id} — {len(selected_chain)}-hop chain, "
          f"confidence={plan['confidence']:.2f}")
    return {"status": "planned", "engagement": engagement, "all_chains": all_chains}
