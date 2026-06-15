"""
ARGUS Layer 6 — Reflexion Memory
===================================
Post-engagement self-reflection stored as episodic context.
After each red-blue cycle, both agents' reasoning is critiqued
by Qwen3 /think mode, producing structured lessons that are
written back to the graph as memory nodes.

Implements the Reflexion pattern: engage -> reflect -> store ->
improve. The stored memories bias future engagements, enabling
the co-evolutionary improvement claim of the paper.

Diversity controls (added after reflexion analysis showed 7.6% waste):
  Fix 2 — last 3 lessons injected into prompt; LLM instructed not to repeat
  Fix 3 — lesson embedded before write; skipped if cosine ≥ 0.93 against
           last 5 memories for that agent; skips logged to
           results/reflexion_skips.jsonl
"""

import json
import re
import os
from datetime import datetime

import numpy as np
import ollama
from dotenv import load_dotenv

load_dotenv()

MODEL               = "qwen3:8b"
DUPLICATE_THRESHOLD = 0.93   # skip write if lesson is this similar to recent ones
SKIP_LOG            = os.path.join("results", "reflexion_skips.jsonl")


# ── LLM helper ────────────────────────────────────────────────────────────────

def _think(prompt: str) -> str:
    """Call Qwen3 in thinking mode; strip <think> blocks from output."""
    resp = ollama.chat(
        model=MODEL,
        messages=[{"role": "user", "content": f"/think\n\n{prompt}"}],
    )
    text = resp["message"]["content"]
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


# ── Embedding & dedup helpers ─────────────────────────────────────────────────

def _embed(text: str) -> np.ndarray:
    """Embed text with nomic-embed-text on CPU (avoids VRAM conflict with Qwen3)."""
    resp = ollama.embeddings(
        model="nomic-embed-text",
        prompt=text[:512],
        options={"num_gpu": 0},
    )
    return np.array(resp["embedding"], dtype=np.float32)


def _cosine(a: np.ndarray, b: np.ndarray) -> float:
    denom = np.linalg.norm(a) * np.linalg.norm(b)
    return float(np.dot(a, b) / denom) if denom > 1e-9 else 0.0


def _get_recent_lessons(driver, agent: str, limit: int = 5) -> list[str]:
    """Fetch the lesson strings from the most recent memory nodes for an agent."""
    import ast as _ast
    with driver.session() as s:
        rows = list(s.run(
            "MATCH (n:Node {node_type: 'memory'}) "
            "WHERE n.properties CONTAINS $agent "
            "RETURN n.properties AS props "
            "ORDER BY n.created_at DESC LIMIT $lim",
            agent=agent, lim=limit,
        ))
    lessons = []
    for r in rows:
        raw = r["props"]
        try:
            props = json.loads(raw) if isinstance(raw, str) else (raw or {})
        except Exception:
            try:
                props = _ast.literal_eval(raw)
            except Exception:
                props = {}
        lesson = props.get("lesson", "").strip()
        if lesson:
            lessons.append(lesson)
    return lessons


def _is_duplicate(lesson: str, recent_lessons: list[str]) -> tuple[bool, float]:
    """
    Embed lesson and compare against recent lesson embeddings.
    Returns (is_duplicate, max_similarity).
    If recent_lessons is empty, always returns (False, 0.0).
    """
    if not recent_lessons or not lesson:
        return False, 0.0
    emb = _embed(lesson)
    sims = [_cosine(emb, _embed(r)) for r in recent_lessons]
    max_sim = max(sims)
    return max_sim >= DUPLICATE_THRESHOLD, max_sim


def _log_skip(agent: str, lesson: str, most_similar: str, sim: float) -> None:
    """Append a skipped duplicate entry to the skip log."""
    os.makedirs("results", exist_ok=True)
    entry = {
        "timestamp":    datetime.utcnow().isoformat(),
        "agent":        agent,
        "lesson":       lesson,
        "most_similar": most_similar,
        "sim":          round(sim, 4),
    }
    with open(SKIP_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


# ── Prompt builders ───────────────────────────────────────────────────────────

def _red_reflection_prompt(engagement: dict, mitigation: dict,
                            past_lessons: list[str] | None = None) -> str:
    chain_str = json.dumps(engagement.get("selected_chain", []), indent=2)

    diversity_block = ""
    if past_lessons:
        formatted = "\n".join(f"  - {l}" for l in past_lessons)
        diversity_block = (
            f"\nYour last {len(past_lessons)} lessons (do NOT repeat these — "
            "generate a genuinely new insight):\n"
            f"{formatted}\n"
        )

    return (
        "You are the ARGUS Red Agent reviewing a completed engagement.\n\n"
        f"Attack chain used:\n{chain_str}\n\n"
        f"Your confidence: {engagement.get('confidence', 0.5)}\n"
        f"Your reasoning: {engagement.get('reasoning', '')}\n\n"
        f"Blue's mitigation effectiveness: {mitigation.get('effectiveness', 0.5)}\n"
        f"Blue's steps: {mitigation.get('steps', [])}\n"
        f"{diversity_block}\n"
        "Reflect on this engagement from the attacker's perspective.\n\n"
        "Reply in EXACTLY this format:\n"
        "LESSON: <one concrete lesson for future attacks — must be distinct from past lessons above>\n"
        "BLIND_SPOT: <what the red agent missed>\n"
        "NEXT_STRATEGY: <how to improve the attack next time>\n"
        "CONFIDENCE_DELTA: <float -0.2 to +0.2, how to adjust confidence calibration>"
    )


def _blue_reflection_prompt(engagement: dict, mitigation: dict,
                             past_lessons: list[str] | None = None) -> str:
    steps_str = json.dumps(mitigation.get("steps", []), indent=2)

    diversity_block = ""
    if past_lessons:
        formatted = "\n".join(f"  - {l}" for l in past_lessons)
        diversity_block = (
            f"\nYour last {len(past_lessons)} lessons (do NOT repeat these — "
            "generate a genuinely new insight):\n"
            f"{formatted}\n"
        )

    return (
        "You are the ARGUS Blue Agent reviewing a completed engagement.\n\n"
        f"Red's attack chain: {json.dumps(engagement.get('selected_chain', []))}\n"
        f"Red's confidence: {engagement.get('confidence', 0.5)}\n\n"
        f"Your mitigation steps:\n{steps_str}\n"
        f"Your effectiveness rating: {mitigation.get('effectiveness', 0.5)}\n"
        f"Your priority: {mitigation.get('priority', 'medium')}\n"
        f"{diversity_block}\n"
        "Reflect on this engagement from the defender's perspective.\n\n"
        "Reply in EXACTLY this format:\n"
        "LESSON: <one concrete lesson for future defense — must be distinct from past lessons above>\n"
        "COVERAGE_GAP: <what the defense failed to address>\n"
        "NEXT_STRATEGY: <how to improve the mitigation next time>\n"
        "EFFECTIVENESS_DELTA: <float -0.2 to +0.2, how to adjust effectiveness calibration>"
    )


# ── Response parsers ──────────────────────────────────────────────────────────

def _parse_reflection(text: str, delta_key: str) -> dict:
    out = {"lesson": "", "gap": "", "next_strategy": "", "delta": 0.0}
    for line in text.splitlines():
        if line.startswith("LESSON:"):
            out["lesson"] = line.split(":", 1)[1].strip()
        elif line.startswith(("BLIND_SPOT:", "COVERAGE_GAP:")):
            out["gap"] = line.split(":", 1)[1].strip()
        elif line.startswith("NEXT_STRATEGY:"):
            out["next_strategy"] = line.split(":", 1)[1].strip()
        elif line.startswith(delta_key):
            try:
                out["delta"] = max(-0.2, min(0.2, float(line.split(":", 1)[1].strip())))
            except ValueError:
                pass
    return out


# ── Graph writes ──────────────────────────────────────────────────────────────

def _write_memory_node(driver, memory: dict) -> None:
    """ARGUS-LAYER-6: Persist episodic memory node to Neo4j."""
    cypher = """
    MERGE (n:Node {node_id: $mid})
    SET n += $props
    SET n:Memory
    """
    props = {
        "node_id":          memory["memory_id"],
        "label":            memory["memory_id"],
        "node_type":        "memory",
        "properties":       json.dumps(memory),
        "grain_confidence": 0.7,
        "open_questions":   [],
        "challenger_log":   "[]",
        "source":           "agent_derived",
        "last_updated":     datetime.utcnow().isoformat(),
        "created_at":       datetime.utcnow().isoformat(),
    }
    with driver.session() as session:
        session.run(cypher, mid=memory["memory_id"], props=props)


def _write_reflects_on_edge(driver, memory_id: str, engagement_id: str) -> None:
    """ARGUS-LAYER-6: Link memory node to the engagement it reflects on."""
    cypher = """
    MATCH (m:Node {node_id: $mid}), (e:Node {node_id: $eid})
    MERGE (m)-[r:RELATION {edge_id: $edge_id}]->(e)
    SET r.relation_type      = 'reflects_on',
        r.confidence         = 0.9,
        r.context_conditions = [],
        r.directionality     = 'unidirectional',
        r.source             = 'agent_derived',
        r.last_updated       = $ts
    """
    with driver.session() as session:
        session.run(
            cypher,
            mid=memory_id,
            eid=engagement_id,
            edge_id=f"{memory_id}_reflects_{engagement_id}",
            ts=datetime.utcnow().isoformat(),
        )


def _maybe_write(driver, memory: dict, agent: str, engagement_id: str) -> bool:
    """
    ARGUS-LAYER-6: Write memory node only if lesson is not a near-duplicate.
    Returns True if written, False if skipped.
    Fix 3: embed lesson, check cosine against last 5 memories, skip if ≥ 0.93.
    """
    lesson = memory.get("lesson", "")
    recent = _get_recent_lessons(driver, agent, limit=5)
    is_dup, max_sim = _is_duplicate(lesson, recent)

    if is_dup:
        most_similar = recent[0] if recent else ""
        _log_skip(agent, lesson, most_similar, max_sim)
        print(f"  [REFLEXION] SKIP {agent} lesson (sim={max_sim:.3f} ≥ {DUPLICATE_THRESHOLD}) — duplicate")
        return False

    _write_memory_node(driver, memory)
    _write_reflects_on_edge(driver, memory["memory_id"], engagement_id)
    return True


# ── Episodic context retrieval ────────────────────────────────────────────────

def get_recent_memories(driver, agent: str, limit: int = 5) -> list[dict]:
    """
    ARGUS-LAYER-6: Fetch recent episodic memories for an agent.
    Used to bias future planning with learned lessons.
    """
    cypher = """
    MATCH (n:Node {node_type: 'memory'})
    WHERE n.properties CONTAINS $agent
    RETURN n
    ORDER BY n.created_at DESC
    LIMIT $lim
    """
    with driver.session() as session:
        rows = list(session.run(cypher, agent=agent, lim=limit))
    memories = []
    for r in rows:
        node = dict(r["n"])
        try:
            props = json.loads(node.get("properties", "{}"))
        except (json.JSONDecodeError, TypeError):
            props = {}
        memories.append({**node, **props})
    return memories


# ── Main entrypoint ───────────────────────────────────────────────────────────

def reflect(driver, engagement: dict, mitigation: dict) -> dict:
    """
    ARGUS-LAYER-6: Post-engagement reflexion loop.
    Both red and blue agents critique the completed cycle.
    Applies Fix 2 (past-lesson injection) and Fix 3 (dedup before write).
    Returns {"red_memory": ..., "blue_memory": ..., "red_written": bool, "blue_written": bool}.
    """
    engagement_id = engagement.get("engagement_id", "unknown")

    # Red agent reflects — Fix 2: inject last 3 red lessons
    red_past   = _get_recent_lessons(driver, "red", limit=3)
    red_text   = _think(_red_reflection_prompt(engagement, mitigation, past_lessons=red_past))
    red_ref    = _parse_reflection(red_text, "CONFIDENCE_DELTA:")

    red_memory_id = f"MEM-RED-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}"
    red_memory = {
        "memory_id":     red_memory_id,
        "agent":         "red",
        "engagement_id": engagement_id,
        "lesson":        red_ref["lesson"],
        "blind_spot":    red_ref["gap"],
        "next_strategy": red_ref["next_strategy"],
        "delta":         red_ref["delta"],
        "timestamp":     datetime.utcnow().isoformat(),
    }
    # Fix 3: dedup check before write
    red_written = _maybe_write(driver, red_memory, "red", engagement_id)
    if red_written:
        print(f"  [REFLEXION] {red_memory_id} — red lesson: {red_ref['lesson'][:60]}...")

    # Blue agent reflects — Fix 2: inject last 3 blue lessons
    blue_past  = _get_recent_lessons(driver, "blue", limit=3)
    blue_text  = _think(_blue_reflection_prompt(engagement, mitigation, past_lessons=blue_past))
    blue_ref   = _parse_reflection(blue_text, "EFFECTIVENESS_DELTA:")

    blue_memory_id = f"MEM-BLUE-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}"
    blue_memory = {
        "memory_id":     blue_memory_id,
        "agent":         "blue",
        "engagement_id": engagement_id,
        "lesson":        blue_ref["lesson"],
        "coverage_gap":  blue_ref["gap"],
        "next_strategy": blue_ref["next_strategy"],
        "delta":         blue_ref["delta"],
        "timestamp":     datetime.utcnow().isoformat(),
    }
    # Fix 3: dedup check before write
    blue_written = _maybe_write(driver, blue_memory, "blue", engagement_id)
    if blue_written:
        print(f"  [REFLEXION] {blue_memory_id} — blue lesson: {blue_ref['lesson'][:60]}...")

    return {
        "red_memory":   red_memory,
        "blue_memory":  blue_memory,
        "red_written":  red_written,
        "blue_written": blue_written,
    }


def run_full_cycle(driver, context: dict = None) -> dict:
    """
    ARGUS-LAYER-6: Complete red->blue->reflexion engagement cycle.
    Orchestrates all three phases and returns the full cycle record.
    """
    from agents.red import plan_attack
    from agents.blue import plan_mitigation

    print("[ARGUS] Starting full engagement cycle...")
    attack = plan_attack(driver, context=context or {})
    if attack["status"] != "planned":
        return {"status": attack["status"], "cycle": None}

    mitigation_result = plan_mitigation(driver, attack)
    engagement  = attack["engagement"]
    mitigation  = mitigation_result["mitigation"]

    memories = reflect(driver, engagement, mitigation)

    cycle = {
        "engagement_id":             engagement["engagement_id"],
        "mitigation_id":             mitigation["mitigation_id"],
        "red_memory_id":             memories["red_memory"]["memory_id"],
        "blue_memory_id":            memories["blue_memory"]["memory_id"],
        "red_written":               memories["red_written"],
        "blue_written":              memories["blue_written"],
        "attack_confidence":         engagement["confidence"],
        "mitigation_effectiveness":  mitigation["effectiveness"],
        "timestamp":                 datetime.utcnow().isoformat(),
    }
    print(f"[ARGUS] Cycle complete — "
          f"attack conf={engagement['confidence']:.2f}, "
          f"mitigation eff={mitigation['effectiveness']:.2f}")
    return {"status": "complete", "cycle": cycle}
