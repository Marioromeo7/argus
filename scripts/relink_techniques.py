"""
ARGUS — Technique Re-linker
==============================
Adds technique edges to existing CVE nodes that have none.
Uses Qwen3 /no_think (fast) for entity extraction.

Usage:
    conda activate argus
    python -u scripts/relink_techniques.py
"""

import sys, os, ast, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()


def _p(msg):
    print(msg, flush=True)


def run_relink():
    from graph.retrieval import get_driver
    from agents.crawler import _extract_entities, _write_technique_edges

    t0 = time.time()
    driver = get_driver()

    cypher = """
    MATCH (v:Node {node_type: 'vulnerability'})
    WHERE NOT (v)-[:RELATION]->(:Node {node_type: 'technique'})
    RETURN v.node_id AS nid, v.properties AS props
    ORDER BY v.node_id
    """
    with driver.session() as session:
        rows = list(session.run(cypher))

    total = len(rows)
    _p(f"CVEs without technique links: {total}")

    # ── Phase 1: parse properties, classify each row ──────────────────────────
    _p("\n[Phase 1] Parsing properties...")
    parsed = []
    no_props, no_desc = 0, 0
    for row in rows:
        raw = row["props"]
        try:
            props = ast.literal_eval(raw) if isinstance(raw, str) else (raw or {})
        except (ValueError, SyntaxError, TypeError):
            props = {}
            no_props += 1
        desc = props.get("description", "")
        parsed.append({"nid": row["nid"], "desc": desc})
        if not desc:
            no_desc += 1

    has_desc = total - no_desc
    _p(f"  parse failures:      {no_props}")
    _p(f"  empty descriptions:  {no_desc}")
    _p(f"  have descriptions:   {has_desc}  ← these will call Qwen3")

    # ── Phase 2: spot-check one description to confirm format ─────────────────
    sample = next((p for p in parsed if p["desc"]), None)
    if sample:
        _p(f"\n[Phase 2] Sample description ({sample['nid']}):")
        _p(f"  \"{sample['desc'][:120]}\"")

    # ── Phase 3: LLM extraction with per-call timing ──────────────────────────
    _p(f"\n[Phase 3] Entity extraction — {has_desc} CVEs to process")
    _p(f"  (timing each call to estimate finish time)\n")

    call_times = []
    linked = 0
    skipped_no_tech = 0
    skipped_no_edge = 0
    idx = 0

    for item in parsed:
        if not item["desc"]:
            continue
        idx += 1
        nid = item["nid"]

        t_call = time.time()
        entities   = _extract_entities(item["desc"])
        elapsed    = time.time() - t_call
        call_times.append(elapsed)
        techniques = entities.get("techniques", [])

        # Rolling ETA
        avg_sec  = sum(call_times) / len(call_times)
        remaining = has_desc - idx
        eta_sec  = avg_sec * remaining
        eta_min  = eta_sec / 60

        if not techniques:
            skipped_no_tech += 1
            _p(f"  [{idx:>3}/{has_desc}] {nid}  {elapsed:.1f}s  "
               f"→ no techniques  "
               f"(avg {avg_sec:.1f}s, ETA ~{eta_min:.1f} min)")
            continue

        count = _write_technique_edges(driver, nid, techniques)
        if count:
            linked += 1
            _p(f"  [{idx:>3}/{has_desc}] {nid}  {elapsed:.1f}s  "
               f"→ {techniques}  {count} edge(s) written  "
               f"(avg {avg_sec:.1f}s, ETA ~{eta_min:.1f} min)")
        else:
            skipped_no_edge += 1
            _p(f"  [{idx:>3}/{has_desc}] {nid}  {elapsed:.1f}s  "
               f"→ {techniques}  (no matching graph nodes)  "
               f"(avg {avg_sec:.1f}s, ETA ~{eta_min:.1f} min)")

    # ── Final summary ─────────────────────────────────────────────────────────
    with driver.session() as session:
        rec = session.run(
            "MATCH (v:Node {node_type: 'vulnerability'})-[:RELATION]->"
            "(t:Node {node_type: 'technique'}) "
            "WITH v, count(t) AS tc RETURN count(v) AS linked, sum(tc) AS edges"
        ).single()
        linked_total = rec["linked"] if rec else 0
        edges_total  = rec["edges"]  if rec else 0

    driver.close()
    total_elapsed = time.time() - t0
    avg_call = sum(call_times) / len(call_times) if call_times else 0

    _p(f"\n{'='*60}")
    _p(f"RE-LINK SUMMARY")
    _p(f"  Total elapsed:                {total_elapsed/60:.1f} min")
    _p(f"  Avg Qwen3 call time:          {avg_call:.1f}s")
    _p(f"  Newly linked CVEs:            {linked}")
    _p(f"  Skipped (no techniques):      {skipped_no_tech}")
    _p(f"  Skipped (no graph nodes):     {skipped_no_edge}")
    _p(f"  Total CVEs with tech links:   {linked_total}")
    _p(f"  Total technique edges:        {edges_total}")
    if linked_total >= 20:
        _p(f"  [OK] >= 20 CVEs linked — corpus ready for evaluation")
    else:
        _p(f"  [WARN] Only {linked_total} CVEs linked — need 20")
    _p(f"{'='*60}")


if __name__ == "__main__":
    _p("=" * 60)
    _p("ARGUS — Technique Re-linker (traced)")
    _p("=" * 60)
    run_relink()
