"""
ARGUS Layer 7 (ROADMAP R3.1) -- Groundedness gate evaluation
==============================================================
Benchmarks the current term-overlap groundedness check
(agents.narrowing._clause_supported) against the hand-labeled audit set
(results/narrowing_gate_labeled_audit.jsonl, 27 examples from the v4/v5
narrowing runs), then runs the same benchmark for a small local NLI
classifier (agents.narrowing._clause_supported_nli), so the two can be
compared on identical ground truth before any default gate is changed.
Per EVALUATION_PLAN.md #R3.1: "Measure current gate precision ... first."

Ground truth: verdict "good" or "false_rejection" -> the clause IS grounded
in its cited source ("false_rejection" specifically records a case where
the CURRENT term-overlap gate wrongly said no -- same ground truth as
"good", kept as a distinct label because it's what originally motivated
this item). verdict "bad" -> the clause is NOT grounded (fabricated,
miscited, or otherwise unsupported).

Usage:
    conda activate argus
    python scripts/eval_groundedness_gate.py
"""

import sys, os, json, ast
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from collections import defaultdict
from dotenv import load_dotenv
load_dotenv()

import config  # noqa: F401 -- OLLAMA_HOST fix, see eval_retrieval.py's same import for why

AUDIT_FILE = os.path.join("results", "narrowing_gate_labeled_audit.jsonl")


def _load_audit() -> list[dict]:
    rows = []
    with open(AUDIT_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _parse_properties(node: dict) -> dict:
    raw = node.get("properties", {})
    try:
        return ast.literal_eval(raw) if isinstance(raw, str) else (raw or {})
    except (ValueError, SyntaxError, TypeError):
        return {}


def _fetch_sources(driver, rows: list[dict]) -> dict:
    """One Neo4j fetch per distinct (node_id, field) pair, not per audit row --
    several rows cite the same node/field repeatedly."""
    from graph.retrieval import get_node
    cache = {}
    for r in rows:
        node_id, _, field = r["source_field"].partition(":")
        key = (node_id, field)
        if key in cache:
            continue
        node = get_node(driver, node_id)
        if node is None:
            cache[key] = ("", "")
            continue
        props = _parse_properties(node)
        source_text = str(props.get(field, ""))
        sibling_text = " ".join(str(v) for k, v in props.items() if k != field)
        cache[key] = (source_text, sibling_text)
    return cache


def _ground_truth_grounded(verdict: str) -> bool:
    return verdict in ("good", "false_rejection")


def _confusion(rows: list[dict], sources: dict, predict_fn) -> dict:
    tp = fp = tn = fn = 0
    per_category = defaultdict(lambda: {"tp": 0, "fp": 0, "tn": 0, "fn": 0})
    details = []
    for r in rows:
        node_id, _, field = r["source_field"].partition(":")
        source_text, sibling_text = sources.get((node_id, field), ("", ""))
        truth = _ground_truth_grounded(r["verdict"])
        pred, extra = predict_fn(r["clause"], source_text, node_id, sibling_text)
        cat = r.get("bug_category") or "none"

        if truth and pred:
            tp += 1; per_category[cat]["tp"] += 1
        elif (not truth) and pred:
            fp += 1; per_category[cat]["fp"] += 1
        elif (not truth) and (not pred):
            tn += 1; per_category[cat]["tn"] += 1
        else:
            fn += 1; per_category[cat]["fn"] += 1

        details.append({"node_id": node_id, "verdict": r["verdict"], "bug_category": cat,
                         "ground_truth_grounded": truth, "predicted_grounded": pred, **extra})

    n = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    accuracy = (tp + tn) / n if n else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "n": n,
            "precision": precision, "recall": recall, "accuracy": accuracy, "f1": f1,
            "per_category": dict(per_category), "details": details}


def _print_confusion(label: str, result: dict) -> None:
    print(f"\n  {label}  (n={result['n']})")
    print(f"    TP={result['tp']}  FP={result['fp']}  TN={result['tn']}  FN={result['fn']}")
    print(f"    accuracy={result['accuracy']:.3f}  precision={result['precision']:.3f}  "
          f"recall={result['recall']:.3f}  f1={result['f1']:.3f}")
    print(f"    (n=27 total, small-sample -- treat point estimates as directional, not final)")
    if result["fp"]:
        print("    False positives (gate said grounded, audit says bad -- the dangerous direction):")
        for d in result["details"]:
            if (not d["ground_truth_grounded"]) and d["predicted_grounded"]:
                print(f"      [{d['node_id']}] {d['bug_category']}")
    if result["fn"]:
        print("    False negatives (gate said not grounded, audit says good/false_rejection):")
        for d in result["details"]:
            if d["ground_truth_grounded"] and not d["predicted_grounded"]:
                print(f"      [{d['node_id']}] {d['bug_category']} (verdict={d['verdict']})")


def run_eval() -> dict:
    from agents.narrowing import _clause_supported, _clause_supported_nli
    from graph.retrieval import get_driver

    rows = _load_audit()
    print(f"Loaded {len(rows)} labeled audit examples from {AUDIT_FILE}")
    n_good = sum(1 for r in rows if r["verdict"] == "good")
    n_bad = sum(1 for r in rows if r["verdict"] == "bad")
    n_fr = sum(1 for r in rows if r["verdict"] == "false_rejection")
    print(f"  verdict counts: good={n_good}  bad={n_bad}  false_rejection={n_fr}")

    driver = get_driver()
    sources = _fetch_sources(driver, rows)
    driver.close()

    def _term_overlap_predict(clause, source_text, node_id, sibling_text):
        pred = _clause_supported(clause, source_text, cited_node_id=node_id, sibling_text=sibling_text)
        return pred, {}

    def _nli_predict(clause, source_text, node_id, sibling_text):
        pred, score = _clause_supported_nli(clause, source_text)
        return pred, {"nli_entailment_score": score}

    def _and_predict(clause, source_text, node_id, sibling_text):
        term_pred = _clause_supported(clause, source_text, cited_node_id=node_id, sibling_text=sibling_text)
        nli_pred, score = _clause_supported_nli(clause, source_text)
        return (term_pred and nli_pred), {"nli_entailment_score": score}

    def _or_predict(clause, source_text, node_id, sibling_text):
        term_pred = _clause_supported(clause, source_text, cited_node_id=node_id, sibling_text=sibling_text)
        nli_pred, score = _clause_supported_nli(clause, source_text)
        return (term_pred or nli_pred), {"nli_entailment_score": score}

    print("\n" + "=" * 70)
    print("GROUNDEDNESS GATE COMPARISON (R3.1)")
    print("=" * 70)

    term_overlap_result = _confusion(rows, sources, _term_overlap_predict)
    _print_confusion("Current gate: term-overlap ratio (+ sibling-veto)", term_overlap_result)

    nli_result = _confusion(rows, sources, _nli_predict)
    _print_confusion("Candidate gate: NLI classifier (cross-encoder/nli-deberta-v3-small, "
                      "argmax==entailment)", nli_result)

    and_result = _confusion(rows, sources, _and_predict)
    _print_confusion("Ensemble AND (grounded only if BOTH agree -- strictest, minimizes FP)", and_result)

    or_result = _confusion(rows, sources, _or_predict)
    _print_confusion("Ensemble OR (grounded if EITHER agrees -- loosest, minimizes FN)", or_result)

    print("\n" + "=" * 70)
    output = {
        "audit_file": AUDIT_FILE,
        "n_examples": len(rows),
        "verdict_counts": {"good": n_good, "bad": n_bad, "false_rejection": n_fr},
        "term_overlap_gate": term_overlap_result,
        "and_ensemble_gate": and_result,
        "or_ensemble_gate": or_result,
        "nli_gate": nli_result,
    }
    os.makedirs("results", exist_ok=True)
    out_path = os.path.join("results", "r3_1_groundedness_gate_comparison.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    print(f"Results saved to {out_path}")
    return output


if __name__ == "__main__":
    run_eval()
