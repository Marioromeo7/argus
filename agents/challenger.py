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

SUPERSEDED as the system default 2026-08-19 (ROADMAP R1.3) by
agents/narrowing.py's challenge_node_v2() — an asker/answerer split fixing
this module's self-graded bias (the same model proposing AND judging its own
refinement), now validated (ROADMAP R1.1/R1.2). This module is kept for
`assess_proposal()` (still used by agents/crawler.py's pre-write gate, a
separate mechanism from grain refinement) and as a reference implementation;
its own smoke test (scripts/test_challenger.py) still legitimately exercises
it. New grain-refinement call sites should use challenge_node_v2, not
challenge_node/run_challenger below. See THESIS.md and ROADMAP.md.
"""

import re
import json
import os
import time
from datetime import datetime
import config  # noqa: F401 -- side effect: loads .env + forces OLLAMA_HOST.
                # Must import before `ollama` -- see agents/red.py's comment.
import requests
from graph.retrieval import get_low_grain_nodes, get_node
from dotenv import load_dotenv

load_dotenv()

MODEL = "qwen3:8b"
OLLAMA_CHAT_URL = f"{os.getenv('OLLAMA_BASE_URL', 'http://localhost:11434')}/api/chat"


# ── LLM helpers ──────────────────────────────────────────────────────────────

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
                wait_time = (2 ** attempt) * 30
                print(f"  [RETRY] Cloudflare timeout on attempt {attempt+1}/{max_retries}, waiting {wait_time}s...")
                time.sleep(wait_time)
            else:
                raise


def _fast(prompt: str, max_retries: int = 3) -> str:
    """Call Qwen3 in standard mode (no chain-of-thought).
    Retries on Cloudflare 524 with exponential backoff."""
    for attempt in range(max_retries):
        try:
            r = requests.post(OLLAMA_CHAT_URL, json={
                "model": MODEL,
                "messages": [{"role": "user", "content": f"/no_think\n\n{prompt}"}],
                "stream": False,
            })
            r.raise_for_status()
            return r.json()["message"]["content"].strip()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 524 and attempt < max_retries - 1:
                wait_time = (2 ** attempt) * 30
                print(f"  [RETRY] Cloudflare timeout on attempt {attempt+1}/{max_retries}, waiting {wait_time}s...")
                time.sleep(wait_time)
            else:
                raise


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
