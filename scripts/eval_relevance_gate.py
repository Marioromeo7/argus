"""
ARGUS Layer 7 (ROADMAP R3.2) -- Relevance/answering gate evaluation
======================================================================
Benchmarks agents.narrowing._answer_addresses_question (cosine similarity
between question and answer, distinct from groundedness) against
results/narrowing_relevance_audit.jsonl.

Honesty note: this seed set has n=2 (one on-topic, one off-topic pair,
both real -- recovered from actual narrowing-engine run logs, not
fabricated). This is a sanity check that the mechanism separates the one
confirmed real case correctly, NOT a validated benchmark the way R3.1's
27-example groundedness comparison is. Growing this set with more real,
hand-verified (question, answer, verdict) triples is R3.3's natural next
extension -- not done here.

Usage:
    conda activate argus
    python scripts/eval_relevance_gate.py
"""

import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import config  # noqa: F401 -- OLLAMA_HOST fix, see eval_retrieval.py's same import

AUDIT_FILE = os.path.join("results", "narrowing_relevance_audit.jsonl")


def _load_audit() -> list[dict]:
    rows = []
    with open(AUDIT_FILE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def run_eval() -> dict:
    from agents.narrowing import _answer_addresses_question

    rows = _load_audit()
    print(f"Loaded {len(rows)} labeled relevance examples from {AUDIT_FILE}")
    print("(n is small and hand-curated -- see this script's docstring)\n")

    results = []
    correct = 0
    for r in rows:
        pred, sim = _answer_addresses_question(r["question"], r["answer_text"])
        truth = r["verdict"] == "on_topic"
        ok = pred == truth
        correct += int(ok)
        results.append({
            "node_id": r["node_id"], "verdict": r["verdict"],
            "predicted_on_topic": pred, "similarity": sim, "correct": ok,
        })
        print(f"  [{r['node_id']}] verdict={r['verdict']:<10} "
              f"predicted_on_topic={pred!s:<5} sim={sim:.4f}  "
              f"{'OK' if ok else 'MISMATCH'}")

    accuracy = correct / len(rows) if rows else 0.0
    print(f"\nAccuracy on this seed set: {correct}/{len(rows)} = {accuracy:.3f}")
    print("(n too small for a real precision/recall table -- see R3.3)")

    output = {"audit_file": AUDIT_FILE, "n_examples": len(rows),
              "accuracy": accuracy, "results": results}
    os.makedirs("results", exist_ok=True)
    out_path = os.path.join("results", "r3_2_relevance_gate_comparison.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    print(f"Results saved to {out_path}")
    return output


if __name__ == "__main__":
    run_eval()
