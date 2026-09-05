"""
ARGUS — R2.5: Seed variance for a headline number
======================================================
Local LLM inference is not fully deterministic under default sampling
(temperature 0.6, top_p 0.95, top_k 20, no seed -- see PAPER_DRAFT.md
Section 5.6). This script runs ONE real headline computation -- R2.1's
Qwen3 rerank step -- across >=3 explicit seeds and reports how much the
resulting P@10/MRR actually vary, using Ollama's `options.seed` (confirmed
live 2026-09-05: identical output for repeated same-seed calls, different
output across seeds).

Scope, stated plainly: this is a small, proportionate check on ONE headline
number (R2.1's rerank), not the full battery. Re-running R2.2's 73-node
grain sweep or R2.3's 100+-cycle co-evolution run three times each with
different seeds is a real multi-day compute commitment (each already took
many hours once) -- out of scope for this pass, logged as still-open in
ROADMAP R2.5 / PAPER_DRAFT.md Section 7, not silently skipped.

Usage:
    conda activate argus
    python scripts/eval_seed_variance.py --n-cves 5 --seeds 1,2,3
"""

import sys, os, json, argparse
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import numpy as np
import config  # noqa: F401
from dotenv import load_dotenv
load_dotenv()

from eval_retrieval import (
    _build_chroma_index, _nvd_technique_candidates, _nvd_ground_truth,
    _vector_retrieve_reranked_ranked, _precision_at_k, _reciprocal_rank,
    _ndcg_at_k, K_MAX_BATTERY,
)


def run_eval(n_cves: int, seeds: list) -> dict:
    from graph.retrieval import get_driver
    driver = get_driver()

    with driver.session() as session:
        rows = list(session.run(
            "MATCH (v:Node {node_type: 'vulnerability'})-[:RELATION]->"
            "(t:Node {node_type: 'technique'}) "
            "WITH v, count(t) AS tc WHERE tc >= 1 "
            "RETURN v.node_id AS cve_id ORDER BY tc DESC LIMIT $n_cves",
            n_cves=n_cves * 2,  # over-fetch, some will lack NVD ground truth
        ))
    candidate_cves = [r["cve_id"] for r in rows]

    print(f"Building ChromaDB index...")
    col = _build_chroma_index(driver)
    print(f"  Indexed: {col.count()} nodes")

    print(f"\nDeriving NVD ground truth for up to {n_cves} CVEs...")
    evaluable = {}
    for cve_id in candidate_cves:
        if len(evaluable) >= n_cves:
            break
        candidates = _nvd_technique_candidates(cve_id)
        gt = _nvd_ground_truth(driver, cve_id, candidates=candidates)
        if gt:
            evaluable[cve_id] = gt
            print(f"  {cve_id}: GT={gt}")

    print(f"\nRunning rerank across seeds {seeds} for {len(evaluable)} CVEs...")
    per_cve_seed = {}  # cve_id -> seed -> {p10, mrr, ndcg10}
    for cve_id, gt in evaluable.items():
        per_cve_seed[cve_id] = {}
        for seed in seeds:
            ranked = _vector_retrieve_reranked_ranked(col, driver, cve_id,
                                                       k=K_MAX_BATTERY, seed=seed)
            row = {"p10": _precision_at_k(ranked, gt, 10),
                   "mrr": _reciprocal_rank(ranked, gt),
                   "ndcg10": _ndcg_at_k(ranked, gt, 10)}
            per_cve_seed[cve_id][seed] = row
            print(f"  {cve_id} seed={seed}: P@10={row['p10']:.3f} "
                  f"MRR={row['mrr']:.3f} nDCG@10={row['ndcg10']:.3f}")

    driver.close()

    # Per-metric variance across seeds, both per-CVE and on the seed-mean
    metrics = ["p10", "mrr", "ndcg10"]
    per_cve_stats = {}
    for cve_id, by_seed in per_cve_seed.items():
        per_cve_stats[cve_id] = {
            m: {"values": [by_seed[s][m] for s in seeds],
                "std": float(np.std([by_seed[s][m] for s in seeds]))}
            for m in metrics
        }

    seed_means = {m: [np.mean([per_cve_seed[c][s][m] for c in evaluable]) for s in seeds]
                  for m in metrics}
    aggregate_stats = {m: {"seed_means": seed_means[m],
                           "mean": float(np.mean(seed_means[m])),
                           "std": float(np.std(seed_means[m]))}
                       for m in metrics}

    print("\n" + "=" * 70)
    print("SEED VARIANCE SUMMARY (R2.5)")
    print(f"  n_cves={len(evaluable)}  seeds={seeds}")
    for m in metrics:
        s = aggregate_stats[m]
        print(f"  {m}: seed means={[f'{v:.3f}' for v in s['seed_means']]}  "
              f"mean={s['mean']:.3f}  std_across_seeds={s['std']:.4f}")
    print("=" * 70)

    result = {"n_cves": len(evaluable), "seeds": seeds,
              "per_cve_seed": per_cve_seed, "per_cve_stats": per_cve_stats,
              "aggregate_stats": aggregate_stats}
    os.makedirs("results", exist_ok=True)
    out_path = os.path.join("results", "r2_5_seed_variance.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print(f"Results saved to {out_path}")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--n-cves", type=int, default=5)
    parser.add_argument("--seeds", type=str, default="1,2,3")
    args = parser.parse_args()
    seed_list = [int(s) for s in args.seeds.split(",")]
    run_eval(n_cves=args.n_cves, seeds=seed_list)
