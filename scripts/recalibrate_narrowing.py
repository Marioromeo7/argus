"""
ARGUS-LAYER-7 — R1.2: recalibrate ALPHA, BETA, EVIDENCE_SIMILARITY_THRESHOLD,
and the (undocumented-in-ROADMAP but code-flagged) 0.6 term-overlap ratio in
_clause_supported, against real post-fix narrowing data.

Data sources: results/narrowing_v5_full.jsonl (8 nodes, 2026-08-10, hand-audited
per SCHEDULE.md) + the 3 fresh 2026-08-19 spot-check nodes (T1055.011, T1687,
T1113) from results/narrowing_pilot_postfix.jsonl -- filtered to only their
LATEST entries, since that file also holds 8 stale pre-v3 entries from an
earlier, less-fixed code state (2026-08-09 11:15, before the comma-dilution/
T1113/T1687 fixes) that must NOT be mixed into a post-fix calibration set.

What this recovers vs what it can't (an honest instrumentation limit, not
worked around): TRUSTED entries store resolved_by="provenance:NODE.FIELD",
so the exact cited field is recoverable and its clause-level term-match ratio
can be recomputed exactly via the real _salient_terms/_term_in_text functions.
PROVISIONAL entries only store resolved_by="model:<name>" -- the cited
node/field was never persisted, so their ratios are NOT recoverable from
historical logs alone. UNANSWERED-for-content-reasons entries embed the cited
node_id in their reason string (regex-extractable) but not the field.

Usage:
    conda activate argus
    python scripts/recalibrate_narrowing.py
"""
import sys, os, json, re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from graph.retrieval import get_driver, get_node
from agents.narrowing import (
    _split_clauses, _salient_terms, _term_in_text, _expand_acronyms,
    _parse_properties, ALPHA, BETA, EVIDENCE_SIMILARITY_THRESHOLD,
    compute_confidence,
)

RESULTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")


def load_nodes():
    nodes = {}
    with open(os.path.join(RESULTS_DIR, "narrowing_v5_full.jsonl")) as f:
        for line in f:
            d = json.loads(line)
            nodes[d["node_id"]] = d
    fresh_ids = {"T1055.011", "T1687", "T1113"}
    latest = {}
    with open(os.path.join(RESULTS_DIR, "narrowing_pilot_postfix.jsonl")) as f:
        for line in f:
            d = json.loads(line)
            if d["node_id"] in fresh_ids:
                latest[d["node_id"]] = d  # keep overwriting -> last occurrence wins
    nodes.update(latest)
    return nodes


def ratio_for_clause(clause: str, source_text: str, cited_node_id: str, sibling_text: str):
    """Re-implements _clause_supported's INTERNAL ratio computation (which the
    real function only returns as a bool) so we can see how far above/below
    threshold each real, already-classified clause actually falls."""
    terms = _salient_terms(clause)
    if cited_node_id:
        terms = [t for t in terms if t.lower() != cited_node_id.lower()]
    if not terms:
        return None  # fell back to embedding-similarity path, not the ratio path
    unique_terms = list(dict.fromkeys(t.lower() for t in terms))
    source_low = _expand_acronyms(source_text).lower()
    sibling_low = _expand_acronyms(sibling_text).lower() if sibling_text else ""
    found = 0
    vetoed = False
    for t in unique_terms:
        if _term_in_text(t, source_low):
            found += 1
        elif sibling_low and _term_in_text(t, sibling_low):
            vetoed = True
    return {"ratio": found / len(unique_terms), "n_terms": len(unique_terms),
            "sibling_vetoed": vetoed}


def main():
    driver = get_driver()
    nodes = load_nodes()
    print(f"Loaded {len(nodes)} post-fix nodes: {sorted(nodes.keys())}\n")

    trusted_ratios = []
    unanswered_content_ratios = []

    for node_id, d in nodes.items():
        for q, entry in d["log"].items():
            status = entry.get("status")
            resolved_by = entry.get("resolved_by", "")

            if status == "trusted" and resolved_by.startswith("provenance:"):
                ref = resolved_by[len("provenance:"):]
                cite_node_id, _, cite_field = ref.rpartition(".")
                cited = get_node(driver, cite_node_id)
                if cited is None:
                    continue
                props = _parse_properties(cited)
                field_text = str(props.get(cite_field, ""))
                sibling_text = " ".join(str(v) for k, v in props.items() if k != cite_field)
                for clause in _split_clauses(entry["answer_text"]):
                    r = ratio_for_clause(clause, field_text, cite_node_id, sibling_text)
                    if r is not None:
                        trusted_ratios.append({"node": node_id, "clause": clause[:70], **r})

            elif status == "unanswered":
                reason = entry.get("reason", "")
                m = re.match(r"cites real node (\S+) but no clause", reason)
                attempted = entry.get("attempted_answer", "")
                if m and attempted:
                    cite_node_id = m.group(1)
                    cited = get_node(driver, cite_node_id)
                    if cited is None:
                        continue
                    props = _parse_properties(cited)
                    # field unknown for this class -- try every provenance-eligible
                    # field and report the BEST (most generous) ratio found, so we
                    # see the hardest case for the threshold, not an undercount.
                    best = None
                    for field, text in props.items():
                        text = str(text)
                        if not text:
                            continue
                        sibling_text = " ".join(str(v) for k, v in props.items() if k != field)
                        for clause in _split_clauses(attempted):
                            r = ratio_for_clause(clause, text, cite_node_id, sibling_text)
                            if r is not None and (best is None or r["ratio"] > best["ratio"]):
                                best = {"node": node_id, "clause": clause[:70], "field": field, **r}
                    if best:
                        unanswered_content_ratios.append(best)

    print("=" * 70)
    print(f"TRUSTED clauses (confirmed-good, n={len(trusted_ratios)}) -- ratio distribution")
    print("=" * 70)
    if trusted_ratios:
        ratios = sorted(r["ratio"] for r in trusted_ratios)
        print(f"  min={ratios[0]:.3f}  p10={ratios[len(ratios)//10]:.3f}  "
              f"median={ratios[len(ratios)//2]:.3f}  max={ratios[-1]:.3f}")
        near_floor = [r for r in trusted_ratios if r["ratio"] < 0.6 + 0.15]
        print(f"  clauses within 0.15 of the 0.6 threshold ({len(near_floor)}):")
        for r in sorted(near_floor, key=lambda x: x["ratio"])[:10]:
            veto = " [SIBLING-VETO FIRED -- should NOT be trusted!]" if r["sibling_vetoed"] else ""
            print(f"    {r['ratio']:.3f}  n_terms={r['n_terms']:2d}  {r['node']:12s} {r['clause']!r}{veto}")
    else:
        print("  (none recovered)")

    print()
    print("=" * 70)
    print(f"REJECTED clauses citing a real node, best-case ratio "
          f"(n={len(unanswered_content_ratios)}) -- how close to wrongly passing?")
    print("=" * 70)
    if unanswered_content_ratios:
        ratios = sorted(r["ratio"] for r in unanswered_content_ratios)
        print(f"  min={ratios[0]:.3f}  median={ratios[len(ratios)//2]:.3f}  max={ratios[-1]:.3f}")
        near_ceiling = [r for r in unanswered_content_ratios if r["ratio"] > 0.6 - 0.15]
        print(f"  clauses within 0.15 of the 0.6 threshold ({len(near_ceiling)}):")
        for r in sorted(near_ceiling, key=lambda x: -x["ratio"])[:10]:
            veto = " [sibling-veto fired, correctly rejected despite ratio]" if r["sibling_vetoed"] else ""
            print(f"    {r['ratio']:.3f}  n_terms={r['n_terms']:2d}  {r['node']:12s} {r['clause']!r}{veto}")
    else:
        print("  (none recovered)")

    print()
    print("=" * 70)
    print("BETA sensitivity -- cumulative trust ratio per node under alternative")
    print("provisional-answer weights (the honestly recoverable half of this check)")
    print("=" * 70)
    betas = [0.0, 0.3, 0.5, 0.7, 1.0]
    print("  " + f"{'node':12s}" + "".join(f"  beta={b:.1f}" for b in betas))
    for node_id, d in nodes.items():
        log = d["log"]
        total = len(log)
        row = f"  {node_id:12s}"
        for b in betas:
            answered_total = sum(
                (b if r["status"] == "provisional" else r["weight"])
                for r in log.values()
            )
            cumulative = answered_total / total if total else 0.0
            row += f"  {cumulative:9.3f}"
        print(row)
    print("\n  ALPHA is NOT sensitivity-tested here, on purpose: grain_confidence =")
    print("  alpha*cumulative + (1-alpha)*freshness, and 'freshness' is defined over")
    print("  only the questions asked in the FINAL round -- that per-round split isn't")
    print("  preserved in the stored log dict (it only has 'history', a list of")
    print("  (trusted,total) tuples per round, not which questions were new each round).")
    print("  A true ALPHA sensitivity check needs live re-runs with instrumentation")
    print("  added, not historical logs -- reporting a fabricated number here would be")
    print("  worse than reporting nothing.")

    driver.close()


if __name__ == "__main__":
    main()
