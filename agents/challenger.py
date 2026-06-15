"""
ARGUS Layer 3 — Challenger Agent
==================================
THE NOVEL PART. Evaluates every node's grain_confidence through
an adversarial Socratic loop: the challenger (Qwen3 /think mode)
probes for ambiguity; the primary (Qwen3 fast mode) accepts or
rejects refinement proposals; grain_confidence is updated based
on the outcome and logged to challenger_log.

This is the mechanism that makes ARGUS nodes self-aware of what
they don't know about themselves.
"""

import re
import json
from datetime import datetime
import ollama
from graph.retrieval import get_low_grain_nodes, get_node

MODEL = "qwen3:8b"


# ── LLM helpers ──────────────────────────────────────────────────────────────

def _think(prompt: str) -> str:
    """Call Qwen3 in thinking mode; strip <think> blocks from output."""
    resp = ollama.chat(
        model=MODEL,
        messages=[{"role": "user", "content": f"/think\n\n{prompt}"}],
    )
    text = resp["message"]["content"]
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


def _fast(prompt: str) -> str:
    """Call Qwen3 in standard mode (no chain-of-thought)."""
    resp = ollama.chat(
        model=MODEL,
        messages=[{"role": "user", "content": f"/no_think\n\n{prompt}"}],
    )
    return resp["message"]["content"].strip()


# ── Prompt builders ───────────────────────────────────────────────────────────

def _challenger_prompt(node: dict) -> str:
    """Build the challenger's evaluation prompt."""
    return (
        "You are the ARGUS Challenger Agent evaluating a cybersecurity knowledge "
        "graph node for epistemic grain — how specific and unambiguous it is.\n\n"
        f"Node ID:           {node['node_id']}\n"
        f"Type:              {node['node_type']}\n"
        f"Properties:        {node.get('properties', '{}')}\n"
        f"grain_confidence:  {node['grain_confidence']} "
        "(0.0=undefined blob, 1.0=maximally specific)\n"
        f"Open questions:    {node.get('open_questions', [])}\n\n"
        "Determine whether this node is too coarse for precise attack-path reasoning.\n\n"
        "Reply in EXACTLY this format (no extra text):\n"
        "ASSESSMENT: <too_coarse|adequate|maximally_specific>\n"
        "QUESTION: <one probing question that would expose ambiguity>\n"
        "PROPOSAL: <specific refinement that would raise grain_confidence>\n"
        "NEW_GRAIN: <your float estimate 0.0-1.0 after applying the proposal>"
    )


def _primary_prompt(node: dict, question: str, proposal: str) -> str:
    """Build the primary agent's response prompt."""
    return (
        "You are a cybersecurity expert evaluating a refinement proposal "
        "for a knowledge graph node.\n\n"
        f"Node: {node['node_id']} ({node['node_type']})\n"
        f"Properties: {node.get('properties', '{}')}\n\n"
        f"Challenger question: {question}\n"
        f"Challenger proposal: {proposal}\n\n"
        "Reply in EXACTLY this format (no extra text):\n"
        "ACCEPTED: <yes|no>\n"
        "REASON: <one sentence>\n"
        "UPDATED_GRAIN: <float 0.0-1.0 reflecting grain after this interaction>"
    )


# ── Response parsers ──────────────────────────────────────────────────────────

def _parse_challenger(text: str) -> dict:
    """Parse challenger output into structured dict."""
    out = {"assessment": "adequate", "question": "", "proposal": "", "new_grain": 0.4}
    for line in text.splitlines():
        if line.startswith("ASSESSMENT:"):
            out["assessment"] = line.split(":", 1)[1].strip().lower()
        elif line.startswith("QUESTION:"):
            out["question"]   = line.split(":", 1)[1].strip()
        elif line.startswith("PROPOSAL:"):
            out["proposal"]   = line.split(":", 1)[1].strip()
        elif line.startswith("NEW_GRAIN:"):
            try:
                out["new_grain"] = max(0.0, min(1.0, float(line.split(":", 1)[1].strip())))
            except ValueError:
                pass
    return out


def _parse_primary(text: str) -> dict:
    """Parse primary agent output into structured dict."""
    out = {"accepted": False, "reason": "", "updated_grain": None}
    for line in text.splitlines():
        if line.startswith("ACCEPTED:"):
            out["accepted"]      = "yes" in line.lower()
        elif line.startswith("REASON:"):
            out["reason"]        = line.split(":", 1)[1].strip()
        elif line.startswith("UPDATED_GRAIN:"):
            try:
                out["updated_grain"] = max(0.0, min(1.0, float(line.split(":", 1)[1].strip())))
            except ValueError:
                pass
    return out


# ── Neo4j persistence ─────────────────────────────────────────────────────────

def _persist(driver, node_id: str, grain: float,
             open_questions: list, log: list) -> None:
    """ARGUS-LAYER-3: Write challenger results back to Neo4j."""
    cypher = """
    MATCH (n:Node {node_id: $nid})
    SET n.grain_confidence = $grain,
        n.open_questions   = $oq,
        n.challenger_log   = $log,
        n.last_updated     = $ts
    """
    with driver.session() as session:
        session.run(cypher,
                    nid=node_id,
                    grain=grain,
                    oq=open_questions,
                    log=json.dumps(log),
                    ts=datetime.utcnow().isoformat())


# ── Core challenger loop ──────────────────────────────────────────────────────

def challenge_node(driver, node: dict, rounds: int = 2) -> dict:
    """
    ARGUS-LAYER-3: Run the Socratic pushback loop on a single node.
    challenger (think) → primary (fast) → update grain → repeat.
    grain_confidence is monotonically non-decreasing per round.
    Returns updated node dict.
    """
    grain    = float(node.get("grain_confidence", 0.1))
    oq       = list(node.get("open_questions") or [])
    log      = []
    cur_node = dict(node)

    for i in range(rounds):
        # Challenger evaluates with deep reasoning
        c_text = _think(_challenger_prompt(cur_node))
        c      = _parse_challenger(c_text)

        if c["assessment"] == "maximally_specific":
            grain = min(1.0, grain + 0.05)
            break

        # Primary responds quickly
        p_text = _fast(_primary_prompt(cur_node, c["question"], c["proposal"]))
        p      = _parse_primary(p_text)

        # Update grain — monotonically non-decreasing
        if p["accepted"] and p["updated_grain"] is not None:
            grain = max(grain, p["updated_grain"])
        elif p["accepted"]:
            grain = max(grain, min(1.0, (grain + c["new_grain"]) / 2))
        else:
            grain = min(1.0, grain + 0.05)

        if c["question"] and c["question"] not in oq:
            oq.append(c["question"])

        log.append({
            "round":     i + 1,
            "question":  c["question"],
            "proposal":  c["proposal"],
            "accepted":  p["accepted"],
            "reason":    p["reason"],
            "new_grain": grain,
            "timestamp": datetime.utcnow().isoformat(),
        })

        cur_node = {**cur_node, "grain_confidence": grain}
        if grain >= 0.8:
            break

    _persist(driver, node["node_id"], grain, oq, log)
    return {**node, "grain_confidence": grain, "open_questions": oq, "challenger_log": log}


def assess_proposal(node_dict: dict) -> dict:
    """
    ARGUS-LAYER-4: Pre-write grain assessment for a proposed node (not yet in graph).
    Called by the crawler before any node is written to Neo4j.
    Runs one thinking-mode evaluation; returns updated dict with grain + open_questions.
    """
    c_text = _think(_challenger_prompt(node_dict))
    c      = _parse_challenger(c_text)

    grain = float(node_dict.get("grain_confidence", 0.1))
    if c["assessment"] == "maximally_specific":
        grain = min(1.0, grain + 0.1)
    elif c["assessment"] == "adequate":
        grain = max(grain, 0.4)
    else:
        grain = max(grain, min(c["new_grain"], grain + 0.2))

    oq = list(node_dict.get("open_questions") or [])
    if c["question"] and c["question"] not in oq:
        oq.append(c["question"])

    return {
        **node_dict,
        "grain_confidence": grain,
        "open_questions":   oq,
        "challenger_log": [{
            "round":     0,
            "question":  c["question"],
            "proposal":  c["proposal"],
            "accepted":  None,
            "timestamp": datetime.utcnow().isoformat(),
        }],
    }


def run_challenger(driver, threshold: float = 0.4,
                   limit: int = 3, rounds: int = 2) -> list[dict]:
    """
    ARGUS-LAYER-3: Batch challenger run over low-grain nodes.
    Finds nodes below threshold, runs pushback loop on each.
    Returns list of updated node dicts.
    """
    candidates = get_low_grain_nodes(driver, threshold=threshold, limit=limit)
    print(f"[ARGUS] Challenger: {len(candidates)} nodes below grain={threshold}")
    results = []
    for node in candidates:
        before = float(node["grain_confidence"])
        print(f"  {node['node_id']} (grain={before:.2f})", end="", flush=True)
        updated = challenge_node(driver, node, rounds=rounds)
        after   = updated["grain_confidence"]
        print(f" -> {after:.2f}  ({after - before:+.2f})")
        results.append(updated)
    return results
