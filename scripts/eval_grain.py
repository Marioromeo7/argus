"""
ARGUS — Evaluation 2: Grain Convergence
=========================================
Verifies that grain_confidence shifts right (increases) monotonically
over successive narrowing-engine rounds on a held-out node set.

Paper claim: the asker/answerer pushback loop drives mean grain_confidence
upward with decreasing variance, proving epistemic refinement.

R1.3 (2026-08-19, ROADMAP): switched from agents.challenger.challenge_node()
(self-graded, superseded) to agents.narrowing.challenge_node_v2() (validated,
ROADMAP R1.1/R1.2). Not a simple import swap -- the old challenger took a
rounds count and ran ONE external round per call, so this script called it
repeatedly and tracked grain across those outer calls. challenge_node_v2()
instead runs its own complete patience-bounded loop internally in ONE call, so
convergence is now read from that single call's own confidence_components
(added specifically for this) rather than from external repeated calls. Nodes
can stop at different round counts (patience=3 triggers "resolved" early); a
node's last real confidence value is carried forward for any later round
another node reached, so the cross-node mean/std at each round stays a valid
comparison.

R2.2 prep (2026-08-19): added --resume/checkpointing (results/grain_sweep_
checkpoint.json by default), matching scripts/eval_coevolution.py's pattern --
a >=73-node unattended sweep (each node ~20-60 min) with no crash recovery
would lose everything on any single failure. The target node_id list is fixed
and persisted on the FIRST run and reused verbatim on --resume, deliberately
NOT re-queried from get_low_grain_nodes() on resume -- challenge_node_v2()
writes grain_confidence back to Neo4j as it runs, so a live re-query mid-sweep
could drift (a completed node's grain rising above the threshold would silently
drop it from a fresh query), corrupting which nodes "the sweep" actually means.
NOT live-verified this session (no Bash available) -- read carefully before
trusting on a real run.

Usage:
    conda activate argus
    python scripts/eval_grain.py --n-nodes 73
    python scripts/eval_grain.py --n-nodes 73 --resume   # resume after a crash
"""

import sys, os, json, argparse
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Defensive: same cp1252-on-Windows-when-piped issue that crashed
# eval_retrieval.py 2026-08-19 (a "->" arrow character wasn't in cp1252's
# charset). Nothing in this file currently hits it, but a 73-node unattended
# sweep dying hours in on incidental non-ASCII would be a real waste.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import numpy as np
from dotenv import load_dotenv
load_dotenv()

CHECKPOINT_FILE = os.path.join("results", "grain_sweep_checkpoint.json")


def _load_checkpoint(path: str) -> dict:
    if os.path.exists(path):
        with open(path) as f:
            data = json.load(f)
        print(f"[RESUME] Loaded checkpoint: {len(data.get('reports', []))} "
              f"nodes completed of {len(data.get('node_ids', []))} planned")
        return data
    return {"node_ids": [], "before_grains": {}, "reports": []}


def _save_checkpoint(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


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


def run_eval(n_nodes: int = 4, resume: bool = False,
             checkpoint_path: str = None) -> dict:
    from graph.retrieval import get_driver, get_low_grain_nodes
    from agents.narrowing import challenge_node_v2

    checkpoint_path = checkpoint_path or CHECKPOINT_FILE
    ckpt = _load_checkpoint(checkpoint_path) if resume else \
           {"node_ids": [], "before_grains": {}, "reports": []}

    driver = get_driver()

    if ckpt["node_ids"]:
        # Resuming: reuse the EXACT node set from the first run (see module
        # docstring on why this must not be a fresh get_low_grain_nodes() call).
        node_ids = ckpt["node_ids"]
    else:
        nodes = get_low_grain_nodes(driver, threshold=0.8, limit=n_nodes)
        if not nodes:
            driver.close()
            print("[SKIP] eval_grain — no nodes below threshold 0.8")
            return {}
        node_ids = [n["node_id"] for n in nodes]
        ckpt["node_ids"] = node_ids
        ckpt["before_grains"] = {n["node_id"]: float(n["grain_confidence"]) for n in nodes}
        _save_checkpoint(checkpoint_path, ckpt)

    before_grains = [ckpt["before_grains"][nid] for nid in node_ids]
    already_done = {r["node_id"] for r in ckpt["reports"]}

    print(f"Nodes: {len(node_ids)}"
          + (f"  ({len(already_done)} already completed, resuming)" if already_done else ""))
    print(f"\nRound 0 (baseline):")
    print(f"  mean={np.mean(before_grains):.4f}  std={np.std(before_grains):.4f}")
    print(_ascii_histogram(before_grains))

    reports = list(ckpt["reports"])
    for node_id in node_ids:
        if node_id in already_done:
            continue
        print(f"\nRunning {node_id}...")
        report = challenge_node_v2(driver, node_id)
        reports.append(report)
        print(f"  -> {report['status']}, {report['rounds_run']} rounds, "
              f"final grain={report['grain_confidence']}")
        ckpt["reports"] = reports
        _save_checkpoint(checkpoint_path, ckpt)
        print(f"  [CHECKPOINT] Saved ({len(reports)}/{len(node_ids)})")

    driver.close()

    # Cross-node round alignment: nodes can stop at different round counts
    # (patience=3 triggers early "resolved"). Carry each node's last real
    # confidence forward for any later round another node reached, so every
    # round's mean/std is still a valid n_nodes-wide comparison.
    max_rounds = max(r["rounds_run"] for r in reports)
    history = [before_grains[:]]
    for round_idx in range(1, max_rounds + 1):
        round_vals = []
        for r in reports:
            comps = r["confidence_components"]
            entry = next((c for c in comps if c["round"] == round_idx), None)
            if entry is not None and entry["confidence"] is not None:
                val = entry["confidence"]
            else:
                past = [c for c in comps
                        if c["round"] < round_idx and c["confidence"] is not None]
                val = past[-1]["confidence"] if past else 0.0
            round_vals.append(val)
        history.append(round_vals)

    means       = [np.mean(h) for h in history]
    stds        = [np.std(h)  for h in history]
    is_monotone = all(means[i] <= means[i + 1] + 1e-9 for i in range(len(means) - 1))
    total_delta = means[-1] - means[0]

    print("\n" + "=" * 60)
    print("GRAIN CONVERGENCE SUMMARY (narrowing engine, ROADMAP R1.3)")
    print(f"  {'Round':<8} {'Mean':>8} {'Std':>8} {'Delta':>8}")
    print(f"  {'-'*40}")
    for i, (m, s) in enumerate(zip(means, stds)):
        delta_str = f"{m - means[i-1]:+.4f}" if i > 0 else "  baseline"
        print(f"  {i:<8} {m:>8.4f} {s:>8.4f} {delta_str:>8}")
        print(_ascii_histogram(history[i]))
    print(f"\n  Total grain improvement:      {total_delta:+.4f}")
    print(f"  Monotonically non-decreasing: {is_monotone}")
    if is_monotone and total_delta > 0:
        print("  [CLAIM SUPPORTED] Grain shifts right over narrowing-engine rounds")
    elif is_monotone:
        print("  [PARTIAL] Grain non-decreasing but no net improvement — nodes already well-grained")
    else:
        print("  [NOTE] Non-monotone observed — investigate node types")
    print("=" * 60)

    return {
        "n_nodes":     len(node_ids),
        "max_rounds":  max_rounds,
        "means":       means,
        "stds":        stds,
        "is_monotone": is_monotone,
        "total_delta": float(total_delta),
        "reports":     reports,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--n-nodes", type=int, default=4,
                        help="Number of low-grain nodes to sweep "
                             "(R2.2 target: all 73+ CVE nodes)")
    parser.add_argument("--resume", action="store_true",
                        help="Resume from checkpoint, reusing the original node set")
    parser.add_argument("--output", type=str, default=None,
                        help="Override checkpoint path "
                             "(default: results/grain_sweep_checkpoint.json)")
    args = parser.parse_args()

    print("=" * 60)
    print(f"ARGUS Eval 2 — Grain Convergence (narrowing engine, n_nodes={args.n_nodes})")
    print("(Uses Qwen3 8B /think + Mistral — each node runs to its own")
    print(" patience/round limit; budget ~20-60 min per node)")
    print("=" * 60)
    run_eval(n_nodes=args.n_nodes, resume=args.resume, checkpoint_path=args.output)
