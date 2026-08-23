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
import json
import math
import ast
from datetime import datetime
import requests as _http
from graph.retrieval import get_node
from config import OLLAMA_CHAT_URL, OLLAMA_EMBED_URL

ASKER_MODEL    = "qwen3:8b"
ASKER_URL      = OLLAMA_CHAT_URL
ANSWERER_MODEL = "mistral:latest"
ANSWERER_URL   = OLLAMA_CHAT_URL   # consolidated onto the same Ollama instance as
                                    # the asker (2026-08-09) — both models now live
                                    # in the default model dir; running two
                                    # uncoordinated servers on one 4GB card was
                                    # itself a source of hangs. See THESIS.md.
EMBED_MODEL    = "nomic-embed-text"
EMBED_URL      = OLLAMA_EMBED_URL

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


# Descriptions are no longer truncated at ingestion (graph/ingestion/attack.py) —
# real corpus check: p99 full description length is ~3553 chars (~900 tokens).
# Neither model call previously set num_ctx, so it silently ran on Ollama's
# runtime default rather than the model's real capability (qwen3:8b=40960,
# mistral=32768) — invisible while everything was capped at 500 chars, but
# now worth pinning explicitly rather than trusting an unverified default,
# since the KV cache shares the same tight 4GB VRAM budget as everything else.
_NUM_CTX = 4096


def _asker_call(prompt: str) -> str:
    """ARGUS-LAYER-7: Qwen3 /think — the asker never answers, only probes."""
    r = _post_with_retry(ASKER_URL, {
        "model": ASKER_MODEL,
        "messages": [{"role": "user", "content": f"/think\n\n{prompt}"}],
        "stream": False,
        "options": {"num_ctx": _NUM_CTX},
    }, timeout=900)  # empirically 225-450s+ with real variance; two pilot nodes exceeded 600s outright
    text = r.json()["message"]["content"]
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


def _answerer_call(prompt: str) -> str:
    """ARGUS-LAYER-7: Mistral — independent weights from the asker."""
    r = _post_with_retry(ANSWERER_URL, {
        "model": ANSWERER_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
        "options": {"num_ctx": _NUM_CTX},
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
    """
    ARGUS-LAYER-7: XML-wraps the source and explicitly forbids outside
    knowledge — not a prompt-injection defense (that's a different problem;
    the model was never confused about what's data here), but a grounding
    constraint. This is a soft instruction and is NOT the actual gate — the
    per-clause verification in answer() is what carries the weight, since a
    prompt instruction can simply be ignored. See THESIS.md discussion.
    """
    props = _parse_properties(node)
    return (
        "You are answering a question about a cybersecurity knowledge graph node.\n\n"
        f'<source node_id="{node["node_id"]}">\n{props}\n</source>\n\n'
        "Only state claims that are directly and explicitly present in <source> "
        "above. Do not add anything from general/outside knowledge, even if you "
        "believe it is true. But DO still attempt to answer whenever <source> "
        "contains information relevant to the question, even if it is not "
        "worded identically — restating or paraphrasing what IS in <source> is "
        "exactly what is wanted, and does not count as guessing. Reserve "
        "COMMITS: \"no\" for when <source> is genuinely silent on the topic, "
        "not merely differently worded.\n\n"
        "Reply in EXACTLY this format, no extra text:\n"
        "ANSWER: <a specific claim that answers the question - no hedging>\n"
        "EVIDENCE: <cite in the form node_id:property_name, e.g. "
        f"{node['node_id']}:description - or write 'insufficient evidence'>\n"
        "COMMITS: <yes or no - did you actually commit to a specific claim?>\n\n"
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


def _unanswered(reason: str, spawned_questions: list = None, attempted: str = "") -> dict:
    """`attempted` preserves whatever claim the model actually produced, even
    on rejection — previously always discarded, which made it impossible to
    tell a correct rejection from a false negative without a live re-query.
    See THESIS.md (2026-08-09/10 entry)."""
    return {"status": "unanswered", "weight": 0.0, "resolved_by": "",
            "answer_text": "", "reason": reason, "attempted_answer": attempted,
            "spawned_questions": spawned_questions or []}


# ── Per-clause verification ─────────────────────────────────────────────────────
# Fixes two failure patterns found by manually inspecting the 8-node pilot that
# the whole-answer similarity check missed: (1) a compound claim with one true
# clause and one fabricated clause passing because the average similarity was
# high enough, and (2) a short, single-clause claim citing a real but wrong
# node (topically adjacent, doesn't actually contain the claim) passing because
# both texts share vocabulary about the same general subject. Splitting into
# clauses and checking each one's specific named terms against the source
# catches both — see THESIS.md and the per-clause design discussion.

_STOPWORDS = {
    "the", "a", "an", "and", "or", "but", "of", "to", "in", "on", "for", "with",
    "by", "is", "are", "was", "were", "be", "been", "may", "can", "could",
    "might", "will", "would", "this", "that", "these", "those", "as", "its",
    "their", "it", "they", "also", "such", "when", "which", "how", "what",
    "does", "do", "did", "other", "than", "not", "no", "yes", "if", "so",
    "adversaries", "adversary", "technique", "techniques",
}

# Short (<=2-3 char), high-value acronyms common in this exact domain that a
# blind length cutoff silently drops — "IP" and "C2" are 2 characters but
# are load-bearing terms in security content (C2 = command-and-control,
# literally one of T1205.002's own tactics). Confirmed bug: "IP" never
# became a checkable term at all under the old >=3-char rule. Expanding
# known acronyms to their full-word form, rather than just lowering the
# length threshold generally, targets the specific terms that matter
# without flooding matching with noise from ordinary short words.
_ACRONYM_EXPANSIONS = {
    "ip": "internet protocol", "c2": "command and control",
    "os": "operating system", "id": "identifier",
    "ui": "user interface", "vm": "virtual machine",
    "ai": "artificial intelligence", "ml": "machine learning",
    "2fa": "two factor authentication", "mfa": "multi factor authentication",
    "iam": "identity access management",
}


def _expand_acronyms(text: str) -> str:
    """ARGUS-LAYER-7: appends full-word expansions for known acronyms so a
    match works regardless of which side — the clause or the cited source —
    uses the abbreviated form and which uses the spelled-out form. Applied
    to both clause and source before comparison in _clause_supported."""
    words = re.findall(r"[A-Za-z0-9]+", text.lower())
    additions = [_ACRONYM_EXPANSIONS[w] for w in words if w in _ACRONYM_EXPANSIONS]
    return text + " " + " ".join(additions) if additions else text


_spacy_nlp = None


def _get_spacy():
    """ARGUS-LAYER-7: lazy-loaded, module-cached spaCy model. CPU-only, no
    GPU/Ollama involvement — loaded once per process."""
    global _spacy_nlp
    if _spacy_nlp is None:
        import spacy
        _spacy_nlp = spacy.load("en_core_web_sm")
    return _spacy_nlp


# Prepositions that, when attached directly to the main verb, typically
# introduce a separately-checkable purpose/manner/exception tail rather than
# core clause structure (unlike "under"/"of"/"as", which stay attached).
# Deliberately narrow — verified against the real fabricated tails found
# 2026-08-09/10 (THESIS.md): "for privilege escalation", "without requiring
# user interaction", "by running a process under..." all isolate correctly
# under this set; a bare "in" was excluded (too common/ambiguous — handled
# separately as the fixed "in order to" phrase instead).
_SPACY_SPLIT_PREPS = {"for", "without", "by", "despite", "except", "unless"}


def _spacy_split_points(text: str) -> list:
    """ARGUS-LAYER-7: character offsets where a real dependency parse says a
    new independently-checkable clause begins — `mark` tokens (subordinating
    conjunctions: since, because, although...) always split, since that
    dependency relation IS the "this starts a subordinate clause" signal;
    `prep` tokens only split when in the curated purpose/manner/exception
    set above, keeping core structural prepositions ("under X", "of Y")
    attached to their main clause instead of over-fragmenting it."""
    doc = _get_spacy()(text)
    points = []
    for tok in doc:
        if tok.head.pos_ not in ("VERB", "AUX"):
            continue
        if tok.dep_ == "mark":
            points.append(tok.idx)
        elif tok.dep_ == "prep" and tok.text.lower() in _SPACY_SPLIT_PREPS:
            points.append(tok.idx)
        elif tok.text.lower() == "in" and text[tok.idx:].lower().startswith("in order to "):
            points.append(tok.idx)
    return sorted(set(points))


def _split_clauses(text: str) -> list:
    """ARGUS-LAYER-7: union of a coarse regex split (sentence boundaries,
    coordinating conjunctions and semicolons — cheap, catches the common
    cases) and a spaCy dependency-parse split (catches trailing
    purpose/manner/exception phrases the regex has no pattern for — found
    via manual audit smuggling fabricated content past the old, coarser
    splitter, see THESIS.md). Neither alone is complete; the union is what's
    actually being relied on. Both are pure CPU/text operations — no model
    call, so being this thorough costs nothing against the GPU budget.

    Regex runs first (sentence/conjunction boundaries), then spaCy runs
    independently on each resulting fragment — simpler and more robust than
    tracking character offsets back into the original sentence, at the cost
    of spaCy seeing each fragment in isolation rather than full sentence
    context. Matches exactly what was spot-checked before wiring this in."""
    sentences = re.split(r"(?<=[.!?])\s+", text.strip())
    clauses = []
    for s in sentences:
        if not s:
            continue
        regex_parts = [p.strip() for p in
                       re.split(r",\s*(?:and|but|while|whereas)\s+|;\s+", s) if p.strip()]
        for part in regex_parts:
            split_at = [p for p in _spacy_split_points(part) if 0 < p < len(part)]
            start = 0
            for p in split_at:
                piece = part[start:p].strip()
                if piece:
                    clauses.append(piece)
                start = p
            tail = part[start:].strip()
            if tail:
                clauses.append(tail)
    return clauses if clauses else [text.strip()]


def _salient_terms(clause: str) -> list:
    """ARGUS-LAYER-7: extracts the specific/technical terms in a clause worth
    verifying against the source — capitalized tokens, acronyms, and longer
    non-stopword words. A clause with no salient terms is too generic to
    check this way and falls back to embedding similarity.

    Acronyms are expanded first (see _expand_acronyms) so that a 2-char term
    like "IP" — too short for the >=3-char token regex, but load-bearing in
    security text — contributes its full-word form ("internet protocol") as
    checkable terms instead of being silently dropped.

    Trailing punctuation is stripped from each token — the regex's character
    class allows internal periods (needed for real tokens like technique IDs
    "T1055.011" or filenames), but that let end-of-sentence periods ride
    along as part of the last word ("screenshots." never matches source's
    "screenshot"), a real false-negative found 2026-08-10 auditing T1113."""
    tokens = re.findall(r"[A-Za-z][A-Za-z0-9_\-\.]{2,}", _expand_acronyms(clause))
    terms = []
    for t in tokens:
        t = t.rstrip(".,;:!?")
        if not t:
            continue
        low = t.lower()
        if low in _STOPWORDS:
            continue
        if t[0].isupper() or t.isupper() or len(t) >= 6:
            terms.append(t)
    return terms


def _term_in_text(term: str, text_low: str) -> bool:
    """ARGUS-LAYER-7: literal match, tolerant of simple English plural/
    singular mismatch (e.g. clause says "screenshots", source says
    "screenshot") — a real false negative found auditing T1113, where a
    plainly true claim failed purely because term-overlap does no stemming.
    Deliberately minimal (just a trailing 's'), not a full stemmer — matches
    the scope of what was actually observed breaking, not a general NLP
    dependency."""
    low = term.lower()
    if low in text_low:
        return True
    if low.endswith("s") and len(low) > 3 and low[:-1] in text_low:
        return True
    if not low.endswith("s") and (low + "s") in text_low:
        return True
    return False


def _clause_supported(clause: str, source_text: str, cited_node_id: str = "",
                       sibling_text: str = "") -> bool:
    """
    ARGUS-LAYER-7: True if the clause's specific claims are traceable to
    source_text. Two modes:
    (a) clause has extractable salient terms (names, acronyms, specific
        technical words) — require most of them to literally appear in the
        source. This is what catches both the AES/MD5/credential-manager
        style fabrication and the DCOM-cited-to-the-wrong-node miscitation —
        neither "AES" nor "DCOM" appears in the actual cited text.
    (b) clause is too generic to have salient terms (e.g. "Yes, this is
        possible") — fall back to embedding similarity, same mechanism as
        before, just scoped to one clause instead of the whole answer.
    0.6 is a starting threshold, not validated against labeled examples —
    same status as ALPHA/BETA/EVIDENCE_SIMILARITY_THRESHOLD: calibrate once
    real data exists.

    `cited_node_id`: excluded from required terms — a description never
    self-references its own technique ID, so requiring it to appear in
    itself is a guaranteed, meaningless failure (found auditing T1113: a
    plainly true claim mentioning "T1113" by name got penalized for it).

    `sibling_text`: the cited node's OTHER field values (not the one
    actually cited), concatenated. If a term fails against source_text but
    IS found here, that's confirmed evidence of citing the wrong field, not
    an ordinary miss — hard veto regardless of overall ratio. Real case
    (T1687): "IaaS" was absent from `description` (source_text) but present
    in `platforms` (a sibling field); the surrounding sentence was otherwise
    93% correct, so the ratio alone passed it (14/15). A single diluted
    fabrication hiding in a mostly-true sentence is exactly what a pure
    ratio threshold cannot catch — this closes that specific, confirmed gap
    without needing the full NLI-classifier upgrade (still logged in
    BACKLOG.md for the broader entailment-vs-overlap ceiling this doesn't
    fully close).
    """
    if not source_text:
        return False
    terms = _salient_terms(clause)
    if cited_node_id:
        terms = [t for t in terms if t.lower() != cited_node_id.lower()]
    if terms:
        # Deduplicate before ratio calc — a clause that repeats a word already
        # trivially likely to match source (e.g. the node's own technique name
        # appearing 3x in one sentence) was padding both numerator and
        # denominator, inflating a genuinely-failing ratio into a passing one.
        # Real case: "EWM injection...memory injection...APC injection..."
        # scored 8/13=61.5% (passes) raw vs the correct 6/11=54.5% (fails)
        # deduplicated — let a fabricated comparison ("APC injection",
        # "thread hijacking", neither in source) through as trusted. Found
        # 2026-08-10 auditing the v4 run itself, see THESIS.md.
        unique_terms = list(dict.fromkeys(t.lower() for t in terms))
        source_low = _expand_acronyms(source_text).lower()
        sibling_low = _expand_acronyms(sibling_text).lower() if sibling_text else ""

        found = []
        for t in unique_terms:
            if _term_in_text(t, source_low):
                found.append(t)
            elif sibling_low and _term_in_text(t, sibling_low):
                return False  # confirmed wrong-field citation — hard veto

        return (len(found) / len(unique_terms)) >= 0.6
    sim = _cosine(_embed(clause), _embed(source_text))
    return sim >= EVIDENCE_SIMILARITY_THRESHOLD


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
             "weight": float, "resolved_by": str, "answer_text": str,
             "reason": str, "spawned_questions": list}
    Gated mechanically per THESIS.md Decision 2 — never trusts the model's own
    self-assessment of whether its answer is good.

    Per-clause, not whole-answer: a compound claim is split, and each clause
    is checked against the cited source independently. Clauses that don't
    hold up aren't just discarded — they become spawned_questions, new and
    sharper open questions for the caller to add to the node's queue, per
    the "what slips is now an open question" design. Only an answer with
    zero unsupported clauses can reach `trusted`; any unsupported clause
    caps the result at `provisional` at best, using only the verified
    portion as the answer text.
    """
    raw = _answerer_call(_answerer_prompt(question, node))
    parsed = _parse_answer(raw)

    if not parsed["commits"]:
        return _unanswered("hedge — COMMITS=no", attempted=parsed["answer"] or raw)
    if not parsed["answer"]:
        return _unanswered("ANSWER line missing or unparseable — not a fabrication, a parse failure",
                            attempted=raw)
    if not parsed["evidence"] or parsed["evidence"].lower() == "insufficient evidence":
        return _unanswered("no evidence cited", attempted=parsed["answer"])

    # EVIDENCE is specified as a single "node_id:property_name" citation (per
    # the prompt), but the model doesn't always stop there — sometimes it
    # cites two fields at once ("node:platforms, node:description"),
    # sometimes it appends a whole justification sentence after the field
    # name ("node:description mentions that WMIC will be replaced by..."),
    # both found via manual audit (THESIS.md). Either way, everything past
    # the field name is free text, not part of the field name — naive
    # partition(":") on the whole string corrupted it into a garbage dict
    # key that then read back "empty" with a misleading reason. Take only
    # the leading identifier-like token: stops at the first character that
    # isn't part of a real property name, whether that's a comma or a space.
    # Checking against the union of multiple cited fields, or doing anything
    # smarter with the trailing commentary, is a possible future
    # improvement, not built here.
    first_citation = parsed["evidence"].split(",")[0].strip()
    cite_node_id, _, cite_field_raw = first_citation.partition(":")
    cite_node_id = cite_node_id.strip()
    field_match = re.match(r"[A-Za-z_][A-Za-z0-9_]*", cite_field_raw.strip())
    cite_field = field_match.group(0) if field_match else cite_field_raw.strip()
    cited = get_node(driver, cite_node_id)
    if cited is None:
        return _unanswered(f"cited node {cite_node_id!r} does not exist — fabricated citation",
                            attempted=parsed["answer"])

    cited_props = _parse_properties(cited)
    cited_field_text = str(cited_props.get(cite_field, ""))
    if not cited_field_text:
        return _unanswered(f"cited field {cite_node_id}:{cite_field} is empty — nothing to verify against",
                            attempted=parsed["answer"])

    # Other fields on the same cited node, concatenated — lets _clause_supported
    # hard-veto a term that's absent from the cited field but present
    # elsewhere on the node (confirmed wrong-field citation, e.g. "IaaS"
    # cited against :description but actually from :platforms), instead of
    # letting it get diluted into a passing ratio by the rest of a mostly-
    # true sentence. See _clause_supported's docstring for the real case.
    sibling_text = " ".join(
        str(v) for k, v in cited_props.items() if k != cite_field
    )

    clauses = _split_clauses(parsed["answer"])
    supported, unsupported = [], []
    for clause in clauses:
        ok = _clause_supported(clause, cited_field_text,
                                cited_node_id=cite_node_id, sibling_text=sibling_text)
        (supported if ok else unsupported).append(clause)

    spawned_questions = [
        f"Is it actually true that {c.rstrip(' .')}, or was this asserted "
        f"without support from {cite_node_id}:{cite_field}?"
        for c in unsupported
    ]

    if not supported:
        return _unanswered(
            f"cites real node {cite_node_id} but no clause of the claim is traceable "
            f"to its actual content",
            spawned_questions=spawned_questions,
            attempted=parsed["answer"],
        )

    verified_answer_text = " ".join(supported)

    exec_result = _check_execution_trust(question, node["node_id"], driver)
    if exec_result is not None:
        exec_result.setdefault("spawned_questions", spawned_questions)
        return exec_result

    if not unsupported and _check_provenance(cited, cite_field):
        # trusted requires every clause to hold up — one bad clause caps the
        # result at provisional even if the field itself is provenance-eligible
        return {
            "status": "trusted", "weight": 1.0,
            "resolved_by": f"provenance:{cite_node_id}.{cite_field}",
            "answer_text": verified_answer_text, "reason": "authoritative source field",
            "spawned_questions": spawned_questions,
        }

    return {
        "status": "provisional", "weight": BETA,
        "resolved_by": f"model:{ANSWERER_MODEL}",
        "answer_text": verified_answer_text,
        "reason": "model-sourced, awaiting execution" if not unsupported
                  else "partially supported — unsupported clauses spawned as new questions",
        "spawned_questions": spawned_questions,
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
    confidence_components = []
    last_active_confidence = 0.0

    round_num = 0
    while True:
        round_num += 1
        new_this_round = set()
        round_cumulative = None
        round_freshness = None

        candidate = ask(node, list(log_by_question.keys()))
        if candidate is not None:
            new_this_round.add(candidate)
            result = answer(candidate, node, driver)
            spawned = result.get("spawned_questions", [])
            log_by_question[candidate] = result
            if result["status"] != "trusted":
                open_questions.append(candidate)
            rounds_detail.append({"round": round_num, "question": candidate, **result})

            # Unsupported clauses don't vanish — they re-enter the same pool as
            # any other open question, weight 0 until something (a future round,
            # or eventually GraphRange execution) actually resolves them.
            for sq in spawned:
                if sq not in log_by_question:
                    log_by_question[sq] = _unanswered("spawned from an unverified clause, not yet re-asked")
                    open_questions.append(sq)
                    new_this_round.add(sq)

            last_active_confidence = compute_confidence(log_by_question, new_this_round)

            # R1.2 recalibration finding (2026-08-19): compute_confidence() blends
            # cumulative and freshness with ALPHA and only the blended result was
            # ever persisted (grain_confidence) -- meaning no historical log could
            # test an alternative ALPHA without a live re-run. Recomputing the same
            # two terms compute_confidence() derives internally, purely for logging,
            # closes that gap for every run from here on (zero behavioral change --
            # last_active_confidence above still drives the real return value).
            _total = len(log_by_question)
            _answered_total = sum(r["weight"] for r in log_by_question.values())
            round_cumulative = _answered_total / _total if _total else 0.0
            _new_total = len(new_this_round)
            round_freshness = (
                sum(log_by_question[q]["weight"] for q in new_this_round) / _new_total
                if _new_total else 0.0
            )

        trusted_count = sum(1 for r in log_by_question.values() if r["status"] == "trusted")
        total = len(log_by_question)
        history.append((trusted_count, total))
        confidence_components.append({
            "round": round_num, "cumulative": round_cumulative,
            "freshness": round_freshness, "new_questions": len(new_this_round),
            # Same value as last_active_confidence at this point in the loop --
            # stored per-round (not just the final one) so a caller comparing
            # confidence across rounds (e.g. eval_grain.py) has one source of
            # truth instead of re-deriving the ALPHA blend itself.
            "confidence": round(last_active_confidence, 4) if round_cumulative is not None else None,
        })

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
                "confidence_components": confidence_components,
            }


# ── Live wiring (drop-in alternative to agents.challenger.challenge_node) ───────

def _persist(driver, node_id: str, report: dict) -> None:
    """
    ARGUS-LAYER-7: Writes a run_narrowing() report to Neo4j in the same shape
    agents/challenger.py's challenge_node() writes — grain_confidence,
    open_questions, challenger_log — so this is a genuine drop-in, not a
    parallel schema. challenger_log entries here are richer than the old
    format (carry resolved_by/status per THESIS.md's ChallengerLogEntry
    fields); old-format entries lacking those fields still read fine since
    they're plain dicts either way.
    """
    log = [
        {
            "question":         q,
            "proposal":         r.get("answer_text", ""),
            "accepted":         r["status"] == "trusted",
            "resolved_by":      r.get("resolved_by", ""),
            "status":           r["status"],
            # `reason`/`attempted_answer` added 2026-08-19 (ROADMAP R1.3 live
            # verification) -- previously dropped on write, which meant a live
            # (persisted) run's rejections could never be hand-audited after
            # the fact, only a dry-run's (results/*.jsonl keeps the full dict).
            # Found by hitting exactly this wall trying to audit a real live
            # T1053.005 run's low-confidence result.
            "reason":           r.get("reason", ""),
            "attempted_answer": r.get("attempted_answer", ""),
            "timestamp":        datetime.utcnow().isoformat(),
        }
        for q, r in report["log"].items()
    ]
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
                    grain=report["grain_confidence"],
                    oq=report["open_questions"],
                    log=json.dumps(log),
                    ts=datetime.utcnow().isoformat())


def challenge_node_v2(driver, node_id: str) -> dict:
    """
    ARGUS-LAYER-7: Replaces agents.challenger.challenge_node() as the system's
    default grain-refinement mechanism (flipped 2026-08-19, ROADMAP R1.3) —
    the asker/answerer engine (THESIS.md) instead of the self-graded loop.
    Validated: R1.1 (3 fresh nodes hand-audited clause-by-clause against live
    source text, plus the existing 8-node v5 chain) and R1.2 (thresholds
    recalibrated against real data) both landed 2026-08-19 — see ROADMAP.md.

    Same persisted fields (grain_confidence, open_questions, challenger_log),
    but this is NOT a pure drop-in for every caller: the old challenge_node()
    took a rounds count and ran ONE external round per call, expecting the
    caller to loop for multi-round tracking; this takes only a node_id and
    runs its OWN complete patience-bounded loop (up to MAX_ROUNDS) internally
    in a single call. A caller that tracked confidence across external rounds
    (e.g. scripts/eval_grain.py, pre-2026-08-19) needs to read the per-round
    trajectory from this call's own `confidence_components`/`rounds_detail`
    instead of calling this function repeatedly — genuinely different usage,
    not just a renamed import.

    agents/challenger.py is NOT deleted — it's retained for `assess_proposal()`
    (still used by agents/crawler.py's pre-write gate, an unrelated mechanism)
    and as a reference implementation; `scripts/test_challenger.py` still
    legitimately tests it as its own unit.
    """
    report = run_narrowing(driver, node_id)
    _persist(driver, node_id, report)
    return report
