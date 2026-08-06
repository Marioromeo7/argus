"""
ARGUS Layer 7 — Narrowing Engine (asker/answerer, replaces the self-graded Challenger)
==========================================================================================
See THESIS.md for the full design. Splits the old Challenger loop into an ASKER
(Qwen3 /think, generates open_questions) and an ANSWERER (Mistral — independent
weights from the asker — structured ANSWER/EVIDENCE/COMMITS reply), so
grain_confidence stops being a model's self-report and becomes a counted,
sourced fraction.

Three answer states, not a binary:
  provisional — model claim exists, gated but unverified.      weight = BETA
  contested   — a later check disagrees with a prior claim.    weight = 0
  trusted     — execution-corroborated (needs GraphRange Phase 1, not built
                yet) or a direct citation of an original NVD/ATT&CK ingested
                field.                                         weight = 1.0

GraphRange execution doesn't exist yet, so this module only reaches `trusted`
via the provenance path today. The execution path is a clear extension point
(_check_execution_trust) — nothing here fakes evidence that doesn't exist.

This is a dry-run pilot: run_narrowing() never writes to Neo4j. It returns a
report for inspection, same spirit as agents/challenger.py's assess_proposal()
(pre-write check, no graph mutation) before this mechanism is trusted enough
to replace the live Challenger loop.
"""

import re
import math
import ast
import requests as _http
from graph.retrieval import get_node

ASKER_MODEL    = "qwen3:8b"
ASKER_URL      = "http://localhost:11434/api/chat"
ANSWERER_MODEL = "mistral:latest"
ANSWERER_URL   = "http://127.0.0.1:11435/api/chat"   # separate Ollama instance serving D:\ollama_models
EMBED_MODEL    = "nomic-embed-text"
EMBED_URL      = "http://localhost:11434/api/embeddings"

ALPHA = 0.5     # cumulative vs this-round-freshness weight in grain_confidence
BETA  = 0.5     # weight of a provisional (model-sourced, unverified) answer
PATIENCE = 3
MAX_ROUNDS = 10
DUP_SIMILARITY_THRESHOLD = 0.90        # candidate question too similar to an existing one
EVIDENCE_SIMILARITY_THRESHOLD = 0.30   # EVIDENCE text vs the cited node's actual content
# Recalibrated from the 8-node pilot (2026-08-06): the original 0.55 guess was
# too high. Real short-claim-vs-description cosine similarities via
# nomic-embed-text clustered at 0.38/0.40/0.41 depending on the node — every
# rejection in the pilot topped out at 0.41, never near 0.55. This new value
# is still a guess, just a better-informed one — it hasn't been validated
# against real fabricated-vs-genuine examples, only against the ceiling of
# what got (probably wrongly) rejected. See results/narrowing_pilot.jsonl and
# THESIS.md.

# Fields actually written by ingestion (graph/ingestion/nvd.py, attack.py) — the
# only fields eligible for trusted-by-provenance. Anything else on an nvd/attack
# node (grain_confidence, expected_observables, open_questions, challenger_log...)
# was added later by an agent and does NOT inherit provenance trust.
PROVENANCE_FIELDS = {
    "nvd":    {"description", "cvss_score", "affected"},
    "attack": {"name", "tactics", "is_subtechnique", "platforms", "description"},
}


# ── LLM + embedding plumbing ──────────────────────────────────────────────────

def _post_with_retry(url: str, payload: dict, timeout: int, retries: int = 1):
    """ARGUS-LAYER-7: One retry on timeout — a single slow draw shouldn't kill
    an entire node's multi-hour run. Re-raises on the final attempt."""
    last_exc = None
    for attempt in range(retries + 1):
        try:
            r = _http.post(url, json=payload, timeout=timeout)
            r.raise_for_status()
            return r
        except _http.exceptions.Timeout as e:
            last_exc = e
            continue
    raise last_exc


def _asker_call(prompt: str) -> str:
    """ARGUS-LAYER-7: Qwen3 /think — the asker never answers, only probes."""
    r = _post_with_retry(ASKER_URL, {
        "model": ASKER_MODEL,
        "messages": [{"role": "user", "content": f"/think\n\n{prompt}"}],
        "stream": False,
    }, timeout=900)  # empirically 225-450s+ with real variance; two pilot nodes exceeded 600s outright
    text = r.json()["message"]["content"]
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


def _answerer_call(prompt: str) -> str:
    """ARGUS-LAYER-7: Mistral — independent weights from the asker."""
    r = _post_with_retry(ANSWERER_URL, {
        "model": ANSWERER_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
    }, timeout=900)  # same reasoning as the asker — this hardware runs think/generation slowly
    return r.json()["message"]["content"].strip()


def _embed(text: str) -> list:
    """ARGUS-LAYER-7: nomic-embed-text, CPU-only per CONTEXT.md's Ollama quirks."""
    r = _http.post(EMBED_URL, json={
        "model": EMBED_MODEL,
        "prompt": text[:2000],
        "options": {"num_gpu": 0},
    }, timeout=60)
    r.raise_for_status()
    return r.json()["embedding"]


def _cosine(a: list, b: list) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def _parse_properties(node: dict) -> dict:
    raw = node.get("properties", {})
    try:
        return ast.literal_eval(raw) if isinstance(raw, str) else (raw or {})
    except (ValueError, SyntaxError, TypeError):
        return {}


# ── Asker ──────────────────────────────────────────────────────────────────────

def _asker_prompt(node: dict, existing_questions: list) -> str:
    props = _parse_properties(node)
    return (
        "You are the ARGUS Asker. Your only job is to find the sharpest question "
        "that would expose ambiguity or gaps in this node. You never answer your "
        "own question.\n\n"
        f"Node: {node['node_id']} ({node['node_type']})\n"
        f"Properties: {props}\n"
        f"Questions already asked: {existing_questions or 'none yet'}\n\n"
        "Ask ONE new question that is not a rephrasing of one already asked. "
        "If there is genuinely nothing left worth asking, reply with exactly: NONE\n\n"
        "Reply with ONLY the question, or NONE. No explanation."
    )


def ask(node: dict, existing_questions: list) -> str:
    """
    ARGUS-LAYER-7: Returns a new question, or None if the asker found nothing new.
    "New" is checked mechanically via embedding similarity against
    existing_questions — never by trusting the asker's own claim of novelty.
    """
    raw = _asker_call(_asker_prompt(node, existing_questions))
    if not raw.strip() or raw.strip().upper() == "NONE":
        return None
    candidate = raw.strip()
    if existing_questions:
        cand_vec = _embed(candidate)
        for q in existing_questions:
            if _cosine(cand_vec, _embed(q)) >= DUP_SIMILARITY_THRESHOLD:
                return None  # rephrasing of an old question — doesn't count as new
    return candidate


# ── Answerer ───────────────────────────────────────────────────────────────────

def _answerer_prompt(question: str, node: dict) -> str:
    props = _parse_properties(node)
    return (
        "You are answering a question about a cybersecurity knowledge graph node. "
        "Reply in EXACTLY this format, no extra text:\n"
        "ANSWER: <a specific claim that answers the question - no hedging>\n"
        "EVIDENCE: <cite in the form node_id:property_name, e.g. "
        f"{node['node_id']}:description - or write 'insufficient evidence'>\n"
        "COMMITS: <yes or no - did you actually commit to a specific claim?>\n\n"
        f"Node: {node['node_id']} ({node['node_type']})\n"
        f"Properties: {props}\n"
        f"Question: {question}"
    )


def _parse_answer(raw: str) -> dict:
    """
    ARGUS-LAYER-7: tolerant of minor formatting drift (markdown bolding like
    **ANSWER:**, stray leading punctuation) — a strict startswith() check
    silently dropped well-formed replies in the pilot, letting them fall
    through with an empty answer instead of being caught here.
    """
    out = {"answer": "", "evidence": "", "commits": False}
    for line in raw.splitlines():
        stripped = re.sub(r"^[\s*_#>-]+", "", line).strip()
        upper = stripped.upper()
        if upper.startswith("ANSWER:"):
            out["answer"] = stripped.split(":", 1)[1].strip(" *_")
        elif upper.startswith("EVIDENCE:"):
            out["evidence"] = stripped.split(":", 1)[1].strip(" *_")
        elif upper.startswith("COMMITS:"):
            out["commits"] = stripped.split(":", 1)[1].strip(" *_").lower().startswith("y")
    return out


def _unanswered(reason: str) -> dict:
    return {"status": "unanswered", "weight": 0.0, "resolved_by": "",
            "answer_text": "", "reason": reason}


def _check_provenance(cited_node: dict, field: str) -> bool:
    """ARGUS-LAYER-7: True only if `field` is an original ingested field
    (not agent-added) on a node whose source is nvd or attack."""
    source = str(cited_node.get("source", ""))
    return field in PROVENANCE_FIELDS.get(source, set())


def _check_execution_trust(question: str, node_id: str, driver) -> dict:
    """
    ARGUS-LAYER-7: STUB. Once GraphRange Phase 1 (Docker execution) exists,
    this checks for 3 consistent agreeing Outcome nodes on this question and
    returns a "trusted" or "contested" result. Returns None today — nothing
    here fakes execution evidence that doesn't exist. See THESIS.md,
    GRAPHRANGE.md Phase 6 (check_and_flag_conflict).
    """
    return None


def answer(question: str, node: dict, driver) -> dict:
    """
    ARGUS-LAYER-7: Full answerer pipeline for one question.
    Returns {"status": "unanswered"|"provisional"|"trusted"|"contested",
             "weight": float, "resolved_by": str, "answer_text": str, "reason": str}
    Gated mechanically per THESIS.md Decision 2 — never trusts the model's own
    self-assessment of whether its answer is good.
    """
    raw = _answerer_call(_answerer_prompt(question, node))
    parsed = _parse_answer(raw)

    if not parsed["commits"]:
        return _unanswered("hedge — COMMITS=no")
    if not parsed["answer"]:
        return _unanswered("ANSWER line missing or unparseable — not a fabrication, a parse failure")
    if not parsed["evidence"] or parsed["evidence"].lower() == "insufficient evidence":
        return _unanswered("no evidence cited")

    cite_node_id, _, cite_field = parsed["evidence"].partition(":")
    cite_node_id, cite_field = cite_node_id.strip(), cite_field.strip()
    cited = get_node(driver, cite_node_id)
    if cited is None:
        return _unanswered(f"cited node {cite_node_id!r} does not exist — fabricated citation")

    cited_props = _parse_properties(cited)
    cited_field_text = str(cited_props.get(cite_field, ""))
    if cited_field_text:
        # Compare the CLAIM to the source, not the citation label to the source —
        # a short "node_id:field" pointer will never resemble a paragraph regardless
        # of whether the underlying claim is any good. Confirmed bug from the pilot:
        # every rejection compared parsed["evidence"] (the label) instead of
        # parsed["answer"] (the actual content), producing near-identical low scores
        # per node independent of question content. See THESIS.md pilot results.
        sim = _cosine(_embed(parsed["answer"]), _embed(cited_field_text))
        if sim < EVIDENCE_SIMILARITY_THRESHOLD:
            return _unanswered(
                f"cites real node {cite_node_id} but the claim doesn't match its "
                f"actual content (similarity {sim:.2f})"
            )

    exec_result = _check_execution_trust(question, node["node_id"], driver)
    if exec_result is not None:
        return exec_result

    if _check_provenance(cited, cite_field):
        return {
            "status": "trusted", "weight": 1.0,
            "resolved_by": f"provenance:{cite_node_id}.{cite_field}",
            "answer_text": parsed["answer"], "reason": "authoritative source field",
        }

    return {
        "status": "provisional", "weight": BETA,
        "resolved_by": f"model:{ANSWERER_MODEL}",
        "answer_text": parsed["answer"], "reason": "model-sourced, awaiting execution",
    }


# ── Confidence + stopping ──────────────────────────────────────────────────────

def compute_confidence(log_by_question: dict, new_questions: set) -> float:
    """
    ARGUS-LAYER-7: grain_confidence = alpha*(cumulative) + (1-alpha)*(freshness)
    log_by_question: {question: latest_result_dict} — the cumulative ledger of
    every distinct question ever asked on this node.
    new_questions: question strings first asked THIS round.
    0/0 := 0 for both terms independently, per THESIS.md.
    """
    if not log_by_question:
        return 0.0
    total = len(log_by_question)
    answered_total = sum(r["weight"] for r in log_by_question.values())
    cumulative = answered_total / total if total else 0.0

    new_total = len(new_questions)
    if new_total == 0:
        freshness = 0.0
    else:
        answered_new = sum(log_by_question[q]["weight"] for q in new_questions)
        freshness = answered_new / new_total

    return ALPHA * cumulative + (1 - ALPHA) * freshness


def should_stop(history: list) -> tuple:
    """
    ARGUS-LAYER-7: patience=3 on the raw (trusted_count, total_count) tuple,
    not the grain_confidence ratio — the ratio can hold steady while the
    underlying counts are still moving. max_rounds=10 catches oscillation
    patience alone would miss.
    "resolved" = patience triggered (the asker genuinely ran out of new
    questions — whatever confidence level that leaves the node at).
    "stalled"  = hit the round ceiling without ever settling (divergence, or
    an asker that never stabilizes within budget).
    Returns (stop: bool, status: "resolved"|"stalled"|"running").
    """
    if len(history) >= PATIENCE and len(set(history[-PATIENCE:])) == 1:
        return True, "resolved"
    if len(history) >= MAX_ROUNDS:
        return True, "stalled"
    return False, "running"


# ── Main loop ──────────────────────────────────────────────────────────────────

def run_narrowing(driver, node_id: str) -> dict:
    """
    ARGUS-LAYER-7: Runs the asker/answerer loop on one node until patience=3
    or max_rounds=10. Dry-run only — never writes to Neo4j. Never mutates
    grain_confidence via a self-reported float, only via compute_confidence().
    """
    node = get_node(driver, node_id)
    if node is None:
        raise ValueError(f"no such node: {node_id}")

    log_by_question = {}
    open_questions = []
    history = []
    rounds_detail = []
    last_active_confidence = 0.0

    round_num = 0
    while True:
        round_num += 1
        new_this_round = set()

        candidate = ask(node, list(log_by_question.keys()))
        if candidate is not None:
            new_this_round.add(candidate)
            result = answer(candidate, node, driver)
            log_by_question[candidate] = result
            if result["status"] != "trusted":
                open_questions.append(candidate)
            rounds_detail.append({"round": round_num, "question": candidate, **result})
            last_active_confidence = compute_confidence(log_by_question, new_this_round)

        trusted_count = sum(1 for r in log_by_question.values() if r["status"] == "trusted")
        total = len(log_by_question)
        history.append((trusted_count, total))

        stop, status = should_stop(history)
        if stop:
            return {
                "node_id": node_id,
                "status": status,
                "rounds_run": round_num,
                "grain_confidence": round(last_active_confidence, 4),
                "total_questions": total,
                "trusted": trusted_count,
                "open_questions": open_questions,
                "history": history,
                "log": log_by_question,
                "rounds_detail": rounds_detail,
            }
