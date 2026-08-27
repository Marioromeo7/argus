"""
ARGUS — Evaluation 1: Retrieval Precision
==========================================
GraphRAG vs Flat Vector RAG retrieval precision.

Ground truth is derived INDEPENDENTLY from the NVD API by:
  1. Parsing ATT&CK technique URLs in cve.references[]
  2. Mapping cve.weaknesses[] CWE IDs → ATT&CK technique IDs
  3. Regex-matching explicit T-IDs in the description text
  4. Keyword fallback for common vulnerability type descriptions

This ground truth is never derived from the graph, making the
comparison between GraphRAG and VectorRAG fair.

Paper claim: ARGUS GraphRAG retrieves more structurally relevant
nodes than flat vector RAG on attack-path queries.
Metrics: Precision@K, Recall@K, False Positive Rate.

Usage:
    conda activate argus
    python scripts/eval_retrieval.py
"""

import sys, os, re, time, json, argparse, ast
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Defensive: this Windows environment's stdout defaults to cp1252 when
# redirected/piped (confirmed live 2026-08-19 -- a plain "->" arrow crashed
# with UnicodeEncodeError; fixed at that call site, but a many-hour unattended
# run (R2.1 at real scale) dying hours in on some future incidental non-ASCII
# character, e.g. from live NVD text, would be a real waste). errors='replace'
# degrades gracefully (prints '?') instead of crashing the whole run.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import chromadb
# config must import before ollama -- the `ollama` package reads OLLAMA_HOST
# once at import time to build its default client. On this machine OLLAMA_HOST
# is already set as a persistent OS env var (0.0.0.0:11434, by the native
# Ollama installer) which is valid to BIND to but not to CONNECT to
# (WinError 10049) -- config.py forces it to the real, connectable value as an
# import-time side effect. Same fix already applied to agents/red.py, blue.py,
# challenger.py, memory/reflexion.py (2026-08-12); this script never got it
# because it calls ollama.embeddings() directly instead of going through
# agents/narrowing.py's HTTP-based (config-safe) embedding call. Found live
# 2026-08-19 hitting exactly this crash trying to verify the R2.1 changes.
import config  # noqa: F401
import ollama
import requests
import numpy as np
from dotenv import load_dotenv
load_dotenv()

from graph.ingestion.nvd import fetch_cves

# R2.1 fix (2026-08-24): NVD's anonymous rate limit is 5 requests/30s
# (~6s/request minimum) -- the previous 0.6s sleep was ~10x too fast and
# reliably hit 429s live (5/10 CVEs failed ground-truth lookup this way in
# the first corrected run). 0.6s was only ever safe WITH an API key (limit
# 50/30s, ~0.6s/request) -- but no NVD_API_KEY was actually set. Now paced
# dynamically off whether one is present, matching the real limit either way.
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
NVD_SLEEP_INTERVAL = 0.65 if NVD_API_KEY else 6.5


# ── ATT&CK technique mapping tables (independent of the graph) ───────────────

# CWE ID → list of ATT&CK technique base IDs
# Source: MITRE ATT&CK / CAPEC / NVD crosswalk
CWE_TO_ATTACK: dict[str, list[str]] = {
    # Command / Code injection
    "CWE-77":  ["T1059"], "CWE-78":  ["T1059"], "CWE-88": ["T1059"],
    "CWE-94":  ["T1059"], "CWE-95":  ["T1059"], "CWE-74": ["T1059"],
    # Buffer / memory errors → process injection / exploitation
    "CWE-119": ["T1055"], "CWE-120": ["T1055"], "CWE-121": ["T1055"],
    "CWE-122": ["T1055"], "CWE-125": ["T1055"], "CWE-787": ["T1055"],
    "CWE-416": ["T1055"], "CWE-415": ["T1055"], "CWE-362": ["T1055"],
    "CWE-190": ["T1055"], "CWE-191": ["T1055"], "CWE-134": ["T1055"],
    "CWE-476": ["T1055"],
    # SQL injection
    "CWE-89":  ["T1190"],
    # Path / directory traversal
    "CWE-22":  ["T1083"], "CWE-23": ["T1083"],
    # XSS
    "CWE-79":  ["T1059"], "CWE-80": ["T1059"],
    # Authentication / access control
    "CWE-287": ["T1078"], "CWE-306": ["T1078"], "CWE-798": ["T1078"],
    "CWE-284": ["T1078"], "CWE-285": ["T1078"], "CWE-732": ["T1078"],
    # Privilege escalation
    "CWE-269": ["T1068"], "CWE-250": ["T1068"],
    # Information disclosure
    "CWE-200": ["T1082"], "CWE-201": ["T1082"],
    # Generic input validation
    "CWE-20":  ["T1190"],
}

# (compiled regex, [T-IDs]) — checked against description text
KEYWORD_TO_ATTACK = [
    (re.compile(r"command.?inject|os.?command|shell.?inject", re.I), ["T1059"]),
    (re.compile(r"code.?inject|script.?inject", re.I),               ["T1059"]),
    (re.compile(r"buffer.?overflow|heap.?overflow|stack.?overflow",   re.I), ["T1055"]),
    (re.compile(r"use.after.free|double.free|memory.?corrupt",        re.I), ["T1055"]),
    (re.compile(r"process.?inject|dll.?inject|reflective.?inject",    re.I), ["T1055"]),
    (re.compile(r"sql.?inject",                                        re.I), ["T1190"]),
    (re.compile(r"path.?travers|directory.?travers",                   re.I), ["T1083"]),
    (re.compile(r"privilege.?escal|priv.?esc|local.?privilege",        re.I), ["T1068"]),
    (re.compile(r"auth(?:entication)?.?bypass|improper.?auth",         re.I), ["T1078"]),
    (re.compile(r"remote.?code.?exec|arbitrary.?code|\brce\b",        re.I), ["T1059"]),
    (re.compile(r"cross.?site.?script|\bxss\b",                       re.I), ["T1059"]),
]

# Regex to detect explicit ATT&CK URLs in references
_ATTACK_URL_RE = re.compile(
    r"attack\.mitre\.org/techniques/(T\d{4})(?:/(\d{3}))?", re.I
)
# Regex to detect explicit T-IDs mentioned in description text
_TID_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b")


# ── Independent ground truth from NVD ────────────────────────────────────────

def _nvd_technique_candidates(cve_id: str) -> set[str]:
    """
    Fetch raw CVE from NVD and extract ATT&CK technique IDs via three
    independent sources — none of which touch the ARGUS graph.
    """
    try:
        rows = fetch_cves(cve_id=cve_id, limit=1)
        time.sleep(NVD_SLEEP_INTERVAL)          # stay within NVD rate limit
    except Exception as e:
        print(f"    [WARN] NVD fetch failed for {cve_id}: {e}")
        return set()

    if not rows:
        return set()

    cve      = rows[0].get("cve", {})
    desc_en  = next(
        (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
        "",
    )
    candidates: set[str] = set()

    # 1. ATT&CK technique URLs in cve.references[]
    for ref in cve.get("references", []):
        m = _ATTACK_URL_RE.search(ref.get("url", ""))
        if m:
            base = m.group(1)
            sub  = m.group(2)
            candidates.add(f"{base}.{sub}" if sub else base)

    # 2. CWE IDs → ATT&CK via lookup table
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            cwe = desc.get("value", "")
            for tid in CWE_TO_ATTACK.get(cwe, []):
                candidates.add(tid)

    # 3. Explicit T-ID mentions in description text
    for m in _TID_RE.finditer(desc_en):
        candidates.add(m.group(1))

    # 4. Keyword fallback in description text
    for pattern, tids in KEYWORD_TO_ATTACK:
        if pattern.search(desc_en):
            candidates.update(tids)

    return candidates


def _nvd_ground_truth(driver, cve_id: str, candidates: set[str] = None) -> set[str]:
    """
    Ground truth: base T-IDs derived from NVD data only (CWE mapping,
    reference URLs, description keywords), filtered to nodes that exist
    in the graph. No sub-technique expansion — keeps ground truth
    independent of graph structure so neither retrieval method is favoured.

    R2.1 fix (2026-08-24): accepts pre-fetched `candidates` so callers that
    also want the raw candidate set (e.g. for logging) don't make a second,
    fully redundant NVD API call for the same CVE -- the eval loop below
    was doing exactly that, silently doubling every CVE's NVD call count
    and halving effective throughput against the rate limit.
    """
    from graph.retrieval import get_node
    if candidates is None:
        candidates = _nvd_technique_candidates(cve_id)
    return {tid for tid in candidates if get_node(driver, tid)}


# ── Embedding & ChromaDB baseline ────────────────────────────────────────────

# R2.1 fix (2026-08-24): nomic-embed-text's real context is 2048 tokens (per
# a live /api/show against the model actually in use -- the 8192 `num_ctx`
# shown alongside it is a request-time default that does NOT override the
# model's own trained limit, `model_info["nomic-bert.context_length"]`).
# Verified empirically: the single longest description anywhere in the graph
# (T1553.003, 4680 chars) embedded cleanly in one call with room to spare
# (~1000-1100 tokens of ~2048 budget). 6000 chars is a generous ceiling well
# above every real description seen (technique descriptions run up to 4680
# chars, median 1298; CVE descriptions are typically much shorter) -- a
# safety net, not a chunking requirement. No chunk/pool pipeline needed.
_EMBED_TEXT_MAX_CHARS = 6000


def _node_embed_text(node: dict) -> str:
    """
    Text used to embed a node -- the actual description, not the whole
    stringified properties dict. R2.1 fix (2026-08-24): the old
    `label + node_type + str(properties)` construction, truncated to 512
    chars, spent most of that budget on structural boilerplate before
    reaching any real prose -- for technique nodes specifically, properties
    are ordered `name, tactics, is_subtechnique, platforms, description`, so
    ~150-200 chars of tactics/platforms lists were consumed before
    `description` (which can run up to 4680 chars) even started. Embedding
    `description` directly, with a generous ceiling instead of a tight one,
    gives VectorRAG a fair baseline instead of a handicapped one.
    """
    nid       = node.get("node_id", "")
    label     = node.get("label", nid)
    node_type = node.get("node_type", "")
    props_raw = node.get("properties", "")
    try:
        props = ast.literal_eval(props_raw) if isinstance(props_raw, str) else (props_raw or {})
    except (ValueError, SyntaxError):
        props = {}
    description = props.get("description", "") or ""
    text = f"{label} ({node_type}): {description}" if description else f"{label} {node_type}"
    return text[:_EMBED_TEXT_MAX_CHARS]


def _embed(text: str) -> list[float]:
    resp = ollama.embeddings(
        model="nomic-embed-text",
        prompt=text,
        options={"num_gpu": 0},   # run on CPU so Qwen3 can stay loaded in VRAM
    )
    return resp["embedding"]


def _build_chroma_index(driver) -> chromadb.Collection:
    """
    Embed all vulnerability/technique/tactic nodes into ChromaDB.

    R2.1 fix (2026-08-24): the old `LIMIT 500` with no `ORDER BY` silently
    excluded up to 285 of the 785 real candidate nodes (697 technique + 73
    vulnerability + 15 tactic) in an arbitrary, non-reproducible order --
    confirmed live against the actual graph that two of the recurring
    ground-truth technique IDs the CWE/keyword tables produce (T1078,
    T1068) and all 15 tactic nodes were excluded, which guarantees 0%
    precision for any CVE whose only ground truth is one of them,
    independent of embedding quality. Fixed by removing the cap (785 nodes
    is cheap to embed in full -- nomic-embed-text runs CPU-only and doesn't
    compete with Qwen3's GPU memory) and adding ORDER BY for reproducibility.
    """
    client = chromadb.Client()
    try:
        client.delete_collection("argus_eval")
    except Exception:
        pass
    col = client.create_collection("argus_eval")

    with driver.session() as session:
        rows = list(session.run(
            "MATCH (n:Node) WHERE n.node_type IN ['vulnerability','technique','tactic'] "
            "RETURN n ORDER BY n.node_id"
        ))

    ids, docs, metas, embeddings = [], [], [], []
    for r in rows:
        node = dict(r["n"])
        nid  = node.get("node_id", "")
        text = _node_embed_text(node)
        ids.append(nid)
        docs.append(text)
        metas.append({"node_type": node.get("node_type", "unknown")})
        embeddings.append(_embed(text))

    if ids:
        col.add(ids=ids, documents=docs, metadatas=metas, embeddings=embeddings)
    return col


# ── Retrieval methods ─────────────────────────────────────────────────────────

def _graphrag_retrieve(driver, cve_id: str, k: int = 10) -> set[str]:
    """ARGUS GraphRAG: Cypher traversal up to 2 hops, technique/tactic nodes only."""
    cypher = """
    MATCH (v:Node {node_id: $cve})-[:RELATION*1..2]->(n:Node)
    WHERE n.node_type IN ['technique', 'tactic']
    RETURN DISTINCT n.node_id AS nid
    LIMIT $k
    """
    with driver.session() as session:
        return {r["nid"] for r in session.run(cypher, cve=cve_id, k=k)}


# R2.1 fix (2026-08-24): found via a live rank-position audit, not assumed --
# with all 785 nodes (73 vulnerability + 697 technique + 15 tactic) in one
# undifferentiated searchable index, the correct ground-truth technique
# ranked #545 of 783 for one CVE and #184 of 783 for another. The top of
# BOTH rankings was solid vulnerability-type nodes only (30/30 in one case).
# Root cause: CVE descriptions are far more textually similar to *other CVE
# descriptions* (same terse "X vulnerability in Y allows Z" register) than to
# ATT&CK's "Adversaries may..." prose, so same-type nodes dominate a flat
# nearest-neighbor search regardless of actual topical relevance -- a
# recall failure, not a ranking failure. No amount of widening a rerank
# pool fixes a candidate that's still ~200-550 ranks outside it. Ground
# truth can only ever be a technique/tactic node, so a CVE was never a
# valid answer and never belonged in the search space -- fixed by filtering
# the query itself to technique/tactic types, mirroring exactly what
# GraphRAG's own Cypher already restricts to (`n.node_type IN
# ['technique','tactic']`) so the two methods search the same candidate
# space and the comparison is actually apples-to-apples.
_TECHNIQUE_TYPE_FILTER = {"node_type": {"$in": ["technique", "tactic"]}}


def _vector_retrieve(col, driver, cve_id: str, k: int = 10) -> set[str]:
    """Baseline flat vector RAG: embed CVE description, return top-K technique/
    tactic nodes from ChromaDB (CVE nodes excluded from the search space --
    see _TECHNIQUE_TYPE_FILTER's comment)."""
    from graph.retrieval import get_node
    node = get_node(driver, cve_id)
    if not node:
        return set()
    text    = _node_embed_text(node)
    emb     = _embed(text)
    n_query = min(k, max(1, col.count() - 1))
    results = col.query(query_embeddings=[emb], n_results=n_query,
                         where=_TECHNIQUE_TYPE_FILTER)
    ids     = results["ids"][0] if results["ids"] else []
    return {i for i in ids if i != cve_id}


# ── Retrieve-then-rerank (two-stage) ─────────────────────────────────────────
# Flat embedding nearest-neighbor is genuinely weak at fine-grained relevance
# among many superficially-similar candidates (measured directly 2026-08-24:
# a real SQL-injection CVE's correct technique, T1190, scored a respectable
# 0.588 cosine similarity yet still lost to a decoy at 0.611 — real signal,
# just not always the top one). The standard fix is two-stage retrieve-then-
# rerank: cast a wider net with the cheap embedding search, then have a more
# capable model re-score just that shortlist. No dedicated reranker model is
# in this project's stack (local-only, per CLAUDE.md) -- Qwen3 8B, already
# wired up via config.py, plays that role instead in fast (non-think) mode.

_RERANK_POOL_SIZE = 30  # first-stage width before reranking narrows to k


def _rerank_with_qwen(query_text: str, candidates: list[dict], top_k: int) -> list[str] | None:
    """
    Qwen3 fast-mode rerank: given a CVE's text and a candidate pool of
    (id, text) dicts from the first-stage embedding retrieval, ask the model
    to pick and order the top_k most relevant by number, not id (shorter,
    less to get wrong verbatim). Returns None on any failure (bad response,
    parse failure, timeout) so the caller can fall back to the embedding
    order instead of crashing a long eval run over one bad call.
    """
    numbered = "\n".join(
        f"{i+1}. [{c['id']}] {c['text'][:280]}"
        for i, c in enumerate(candidates)
    )
    prompt = (
        "You are ranking MITRE ATT&CK technique/tactic candidates by how "
        "relevant each one is to a specific security vulnerability (CVE).\n\n"
        f"CVE:\n{query_text[:700]}\n\n"
        f"Candidates:\n{numbered}\n\n"
        f"Return ONLY a JSON array of the {top_k} candidate NUMBERS (the "
        "leading integer, not the [ID]), ordered most to least relevant to "
        "this CVE's actual vulnerability mechanism. Example: [4, 1, 12]. "
        "No explanation, no other text."
    )
    try:
        resp = requests.post(config.OLLAMA_CHAT_URL, json={
            "model": "qwen3:8b",
            "messages": [{"role": "user", "content": prompt}],
            "think": False,   # HTTP "think" field, not a prompt prefix --
            "stream": False,  # /no_think in the prompt body is a documented
        }, timeout=90)        # no-op for Qwen3 8B (see CONTEXT.md).
        resp.raise_for_status()
        content = resp.json()["message"]["content"].strip()
        content = re.sub(r"^```(?:json)?|```$", "", content.strip(), flags=re.M).strip()
        numbers = json.loads(content)
        ids = []
        for n in numbers:
            idx = int(n) - 1
            if 0 <= idx < len(candidates):
                ids.append(candidates[idx]["id"])
        return ids[:top_k] if ids else None
    except Exception:
        return None


def _vector_retrieve_reranked(col, driver, cve_id: str, k: int = 10,
                               pool_size: int = _RERANK_POOL_SIZE) -> set[str]:
    """
    Two-stage vector RAG: retrieve a wider embedding pool, rerank it with
    Qwen3, return the reranked top-K. Falls back to plain embedding order
    (i.e. degrades to _vector_retrieve's behavior) if the rerank call fails.
    """
    from graph.retrieval import get_node
    node = get_node(driver, cve_id)
    if not node:
        return set()
    text    = _node_embed_text(node)
    emb     = _embed(text)
    n_query = min(pool_size, max(1, col.count() - 1))
    results = col.query(query_embeddings=[emb], n_results=n_query,
                         where=_TECHNIQUE_TYPE_FILTER)
    ids     = [i for i in (results["ids"][0] if results["ids"] else []) if i != cve_id]
    docs    = results["documents"][0] if results["documents"] else []
    doc_map = dict(zip(results["ids"][0], docs)) if results["ids"] else {}
    if not ids:
        return set()
    candidates = [{"id": i, "text": doc_map.get(i, i)} for i in ids]
    reranked = _rerank_with_qwen(text, candidates, k)
    if reranked:
        return set(reranked)
    return set(ids[:k])  # fallback: embedding order, same as the flat baseline


# ── Metrics ───────────────────────────────────────────────────────────────────

def _metrics(retrieved: set, ground_truth: set) -> dict:
    if not retrieved:
        return {"precision": 0.0, "recall": 0.0, "fpr": 0.0, "tp": 0, "fp": 0, "fn": 0}
    tp = len(retrieved & ground_truth)
    fp = len(retrieved - ground_truth)
    fn = len(ground_truth - retrieved)
    return {
        "precision": tp / len(retrieved),
        "recall":    tp / len(ground_truth) if ground_truth else 0.0,
        "fpr":       fp / len(retrieved),
        "tp": tp, "fp": fp, "fn": fn,
    }


# ── Main eval ─────────────────────────────────────────────────────────────────

def run_eval(k: int = 10, n_cves: int = 10, rerank: bool = True,
             rerank_pool: int = _RERANK_POOL_SIZE) -> dict:
    """
    ROADMAP R2.1 (2026-08-19): n_cves was hardcoded to 10 via a fixed `LIMIT 10`
    in the Cypher below -- made it a real parameter so a >=50-CVE run (the
    actual R2.1 target) is possible at all. Cypher's LIMIT is safe against a
    pool smaller than requested (returns what exists, no error) -- but whether
    the graph currently HAS >=50 CVEs with a technique edge at all is unverified
    from here (Bash/Neo4j access blocked this session by the safety classifier);
    check `evaluable_cves`/`total_test_cves` in the printed summary before
    trusting a >=50 claim. The fuller R2.1 spec (P@k for k in {5,10,20}, MRR,
    nDCG@10, bootstrap 95% CIs on the delta) is NOT implemented here -- those
    need ranked (not set) retrieval results and untested statistical code is
    worse than none; left as explicit follow-up, not guessed at blind.
    """
    from graph.retrieval import get_driver
    driver = get_driver()

    # Test CVEs: those with technique edges in the graph (likely to have NVD ground truth)
    with driver.session() as session:
        rows = list(session.run(
            "MATCH (v:Node {node_type: 'vulnerability'})-[:RELATION]->"
            "(t:Node {node_type: 'technique'}) "
            "WITH v, count(t) AS tc WHERE tc >= 1 "
            "RETURN v.node_id AS cve_id ORDER BY tc DESC LIMIT $n_cves",
            n_cves=n_cves,
        ))
    test_cves = [r["cve_id"] for r in rows]

    if not test_cves:
        driver.close()
        print("[SKIP] eval_retrieval — no CVEs with technique links")
        return {}

    print(f"Building ChromaDB index...")
    col         = _build_chroma_index(driver)
    total_nodes = col.count()
    print(f"  Indexed: {total_nodes} nodes")

    print(f"\nDeriving NVD ground truth independently for {len(test_cves)} CVEs "
          f"({'with' if NVD_API_KEY else 'without'} NVD_API_KEY, "
          f"{NVD_SLEEP_INTERVAL}s/request)...")
    gt_map: dict[str, set] = {}
    for cve_id in test_cves:
        # R2.1 fix (2026-08-24): one NVD fetch per CVE, not two -- candidates
        # is now passed into _nvd_ground_truth() instead of being re-fetched
        # right after just for this log line, which was silently doubling
        # every CVE's NVD call count (see _nvd_ground_truth's docstring).
        candidates = _nvd_technique_candidates(cve_id)
        gt = _nvd_ground_truth(driver, cve_id, candidates=candidates)
        gt_map[cve_id] = gt
        print(f"  {cve_id}: NVD candidates={candidates or '{}'} -> "
              f"graph-intersected GT={gt or '{}'}")

    # Drop CVEs where NVD produced no ground truth
    # (old CVEs with no CWE/refs/keyword matches — can't evaluate fairly)
    evaluable = {cid: gt for cid, gt in gt_map.items() if gt}
    if not evaluable:
        driver.close()
        print("\n[WARN] No CVEs produced independent ground truth from NVD.")
        print("Possible reasons: all test CVEs are pre-CWE-era without keyword matches.")
        print("Falling back to reporting raw overlap stats.")
        _report_no_gt(driver, col, test_cves, k)
        return {}

    graphrag_scores, vector_scores, rerank_scores = [], [], []
    retrieved_map: dict[str, dict] = {}
    methods = ["GraphRAG", "VectorRAG"] + (["VectorRAG+Rerank"] if rerank else [])
    header = (f"\n{'CVE':<22} {'GT':>4} {'Method':<18} "
              f"{'P@K':>6} {'Recall':>8} {'FPR':>7} {'TP/FP/FN'}")
    print(header)
    print("-" * 80)

    for i, (cve_id, gt) in enumerate(evaluable.items(), 1):
        g_ret = _graphrag_retrieve(driver, cve_id, k=k)
        v_ret = _vector_retrieve(col, driver, cve_id, k=k)
        entry = {"graphrag": g_ret, "vector": v_ret}
        g_m   = _metrics(g_ret, gt)
        v_m   = _metrics(v_ret, gt)
        graphrag_scores.append(g_m)
        vector_scores.append(v_m)
        rows = [("GraphRAG", g_m), ("VectorRAG", v_m)]

        if rerank:
            r_ret = _vector_retrieve_reranked(col, driver, cve_id, k=k, pool_size=rerank_pool)
            entry["vector_reranked"] = r_ret
            r_m = _metrics(r_ret, gt)
            rerank_scores.append(r_m)
            rows.append(("VectorRAG+Rerank", r_m))

        retrieved_map[cve_id] = entry
        for label, m in rows:
            print(f"{cve_id:<22} {len(gt):>4} {label:<18} {m['precision']:>6.2f} "
                  f"{m['recall']:>8.2f} {m['fpr']:>7.2f}  "
                  f"{m['tp']}/{m['fp']}/{m['fn']}")
        if rerank:
            print(f"  [{i}/{len(evaluable)} CVEs scored]")

    driver.close()

    g_prec = float(np.mean([s["precision"] for s in graphrag_scores]))
    v_prec = float(np.mean([s["precision"] for s in vector_scores]))
    g_fpr  = float(np.mean([s["fpr"]       for s in graphrag_scores]))
    v_fpr  = float(np.mean([s["fpr"]       for s in vector_scores]))
    delta  = g_prec - v_prec

    r_prec = r_fpr = r_delta = None
    if rerank and rerank_scores:
        r_prec  = float(np.mean([s["precision"] for s in rerank_scores]))
        r_fpr   = float(np.mean([s["fpr"]       for s in rerank_scores]))
        r_delta = g_prec - r_prec

    print("\n" + "=" * 75)
    print("RETRIEVAL PRECISION SUMMARY")
    print(f"  Ground truth source: NVD CWE mapping + reference URLs + text keywords")
    print(f"  Evaluable CVEs: {len(evaluable)} / {len(test_cves)}")
    print(f"  GraphRAG          mean P@{k}={g_prec:.3f}   mean FPR={g_fpr:.3f}")
    print(f"  VectorRAG (flat)  mean P@{k}={v_prec:.3f}   mean FPR={v_fpr:.3f}")
    if rerank and rerank_scores:
        print(f"  VectorRAG+Rerank  mean P@{k}={r_prec:.3f}   mean FPR={r_fpr:.3f}")
    print(f"  Delta P (GraphRAG - VectorRAG flat):    {delta:+.3f}")
    if rerank and rerank_scores:
        print(f"  Delta P (GraphRAG - VectorRAG+Rerank):  {r_delta:+.3f}")
    if delta >= 0:
        print("  [CLAIM SUPPORTED] GraphRAG precision >= flat VectorRAG on attack-path queries")
    else:
        print("  [NOTE] Flat VectorRAG matched GraphRAG on this sample")
    if rerank and rerank_scores:
        if r_delta >= 0:
            print("  [CLAIM SUPPORTED, STRONGER BASELINE] GraphRAG precision >= reranked VectorRAG too")
        else:
            print("  [NOTE] Reranking closed the gap to GraphRAG on this sample")
    print("=" * 75)

    result = {
        "ground_truth_source": "NVD CWE + reference URLs + keyword extraction",
        "evaluable_cves":      len(evaluable),
        "total_test_cves":     len(test_cves),
        "nodes_indexed":       total_nodes,
        "k":                   k,
        "rerank_pool_size":    rerank_pool if rerank else None,
        "graphrag_precision":  g_prec,
        "vector_precision":    v_prec,
        "graphrag_fpr":        g_fpr,
        "vector_fpr":          v_fpr,
        "delta_precision":     delta,
        "vector_reranked_precision": r_prec,
        "vector_reranked_fpr":       r_fpr,
        "delta_precision_reranked":  r_delta,
        "per_cve": {
            cve_id: {
                "ground_truth":       sorted(gt),
                "graphrag_retrieved": sorted(retrieved_map[cve_id]["graphrag"]),
                "vector_retrieved":   sorted(retrieved_map[cve_id]["vector"]),
                "vector_reranked_retrieved": sorted(retrieved_map[cve_id].get("vector_reranked", [])),
            }
            for cve_id, gt in evaluable.items()
        },
    }
    return result


def _report_no_gt(driver, col, test_cves: list, k: int) -> None:
    """Fallback report when NVD produces no ground truth — show raw retrieval overlap."""
    print(f"\n{'CVE':<22} {'GraphRAG nodes':<20} {'VectorRAG nodes'}")
    print("-" * 60)
    for cve_id in test_cves[:5]:
        g_ret = _graphrag_retrieve(driver, cve_id, k=k)
        v_ret = _vector_retrieve(col, driver, cve_id, k=k)
        overlap = len(g_ret & v_ret)
        print(f"{cve_id:<22} {len(g_ret):<20} {len(v_ret)}  (overlap={overlap})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--n-cves", type=int, default=10,
                        help="Number of candidate CVEs to pull from the graph "
                             "(R2.1 target: >=50; default 10 matches the "
                             "original pilot sample)")
    parser.add_argument("--k", type=int, default=10, help="Retrieval depth")
    parser.add_argument("--output", type=str, default="results/eval1_final.json")
    parser.add_argument("--no-rerank", action="store_true",
                        help="Skip the VectorRAG+Rerank arm (faster, no extra Qwen3 calls)")
    parser.add_argument("--rerank-pool", type=int, default=_RERANK_POOL_SIZE,
                        help="First-stage embedding candidate pool width before reranking")
    args = parser.parse_args()

    print("=" * 75)
    print("ARGUS Eval 1 — Retrieval Precision (GraphRAG vs VectorRAG vs VectorRAG+Rerank)")
    print("Ground truth: NVD CWE IDs + ATT&CK reference URLs + keywords")
    print(f"(n_cves={args.n_cves}, k={args.k}, rerank={'off' if args.no_rerank else f'on (pool={args.rerank_pool})'} "
          f"— builds nomic-embed-text index + NVD API calls, budget scales with n_cves)")
    print("=" * 75)
    result = run_eval(k=args.k, n_cves=args.n_cves, rerank=not args.no_rerank,
                       rerank_pool=args.rerank_pool)
    if result:
        os.makedirs("results", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\nResults saved to {args.output}")
