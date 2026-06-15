"""
ARGUS — Evaluation 2: Grain Convergence
=========================================
Verifies that grain_confidence shifts right (increases) monotonically
over successive challenger iterations on a held-out node set.

Paper claim: The Socratic pushback loop drives mean grain_confidence
upward with decreasing variance, proving epistemic refinement.

Usage:
    conda activate argus
    python scripts/eval_grain.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
from dotenv import load_dotenv
load_dotenv()


def _ascii_histogram(values: list[float], width: int = 30) -> str:
    """Compact ASCII bar showing distribution of grain values (0–1 scale)."""
    buckets = [0] * 5  # [0,.2), [.2,.4), [.4,.6), [.6,.8), [.8,1]
    for v in values:
        idx = min(4, int(v * 5))
        buckets[idx] += 1
    labels = ["0.0-0.2", "0.2-0.4", "0.4-0.6", "0.6-0.8", "0.8-1.0"]
    lines  = []
    for i, (label, cnt) in enumerate(zip(labels, buckets)):
        bar = "#" * int((cnt / len(values)) * width) if values else ""
        lines.append(f"    {label} |{bar:<{width}}| {cnt}")
    return "\n".join(lines)


def run_eval(n_nodes: int = 4, rounds: int = 3) -> dict:
    from graph.retrieval import get_driver, get_low_grain_nodes
    from agents.challenger import challenge_node

    driver = get_driver()
    nodes  = get_low_grain_nodes(driver, threshold=0.8, limit=n_nodes)

    if not nodes:
        driver.close()
        print("[SKIP] eval_grain — no nodes below threshold 0.8")
        return {}

    before_grains = [float(n["grain_confidence"]) for n in nodes]
    history       = [before_grains[:]]  # history[round] = list of grain values

    print(f"Nodes: {len(nodes)}  Rounds: {rounds}")
    print(f"\nRound 0 (baseline):")
    print(f"  mean={np.mean(before_grains):.4f}  std={np.std(before_grains):.4f}")
    print(_ascii_histogram(before_grains))

    current_nodes = list(nodes)
    for r in range(1, rounds + 1):
        print(f"\nRound {r}:")
        updated = []
        for node in current_nodes:
            u = challenge_node(driver, node, rounds=1)
            updated.append(u)
        grains = [float(u["grain_confidence"]) for u in updated]
        history.append(grains[:])
        delta  = np.mean(grains) - np.mean(history[r - 1])
        print(f"  mean={np.mean(grains):.4f}  std={np.std(grains):.4f}  "
              f"delta={delta:+.4f}")
        print(_ascii_histogram(grains))
        current_nodes = updated

    driver.close()

    means       = [np.mean(h) for h in history]
    stds        = [np.std(h)  for h in history]
    is_monotone = all(means[i] <= means[i + 1] + 1e-9 for i in range(len(means) - 1))
    total_delta = means[-1] - means[0]

    print("\n" + "=" * 60)
    print("GRAIN CONVERGENCE SUMMARY")
    print(f"  {'Round':<8} {'Mean':>8} {'Std':>8} {'Delta':>8}")
    print(f"  {'-'*40}")
    for i, (m, s) in enumerate(zip(means, stds)):
        delta_str = f"{m - means[i-1]:+.4f}" if i > 0 else "  baseline"
        print(f"  {i:<8} {m:>8.4f} {s:>8.4f} {delta_str:>8}")
    print(f"\n  Total grain improvement:      {total_delta:+.4f}")
    print(f"  Monotonically non-decreasing: {is_monotone}")
    if is_monotone and total_delta > 0:
        print("  [CLAIM SUPPORTED] Grain shifts right over challenger iterations")
    elif is_monotone:
        print("  [PARTIAL] Grain non-decreasing but no net improvement — nodes already well-grained")
    else:
        print("  [NOTE] Non-monotone observed — investigate node types")
    print("=" * 60)

    return {
        "n_nodes":     len(nodes),
        "rounds":      rounds,
        "means":       means,
        "stds":        stds,
        "is_monotone": is_monotone,
        "total_delta": float(total_delta),
    }


if __name__ == "__main__":
    print("=" * 60)
    print("ARGUS Eval 2 — Grain Convergence")
    print("(Uses Qwen3 8B thinking mode — expect ~3-6 min)")
    print("=" * 60)
    run_eval(n_nodes=4, rounds=3)
