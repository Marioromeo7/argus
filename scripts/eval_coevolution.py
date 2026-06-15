"""
ARGUS — Evaluation 3: Co-evolutionary Improvement
====================================================
Runs N full engagement cycles and measures whether both agents
improve over successive rounds as the reflexion memory accumulates.

Paper claim: Attack confidence and mitigation effectiveness trend
upward over N cycles (p < 0.05) as agents incorporate past lessons
from the episodic memory graph.

Checkpoints every 10 cycles to results/coevolution_50.json so the
run can be resumed if interrupted.

Usage:
    conda activate argus
    python scripts/eval_coevolution.py
    python scripts/eval_coevolution.py --resume   # resume from checkpoint
"""

import sys, os, json, argparse
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
from scipy import stats
from dotenv import load_dotenv
load_dotenv()

CHECKPOINT_FILE  = os.path.join("results", "coevolution_50.json")
CHECKPOINT_EVERY = 10


def _set_checkpoint(path: str) -> None:
    global CHECKPOINT_FILE
    CHECKPOINT_FILE = path


def _load_checkpoint() -> dict:
    if os.path.exists(CHECKPOINT_FILE):
        with open(CHECKPOINT_FILE) as f:
            data = json.load(f)
        print(f"[RESUME] Loaded checkpoint: {len(data['attack_confs'])} cycles completed")
        return data
    return {"attack_confs": [], "mit_effs": [], "memory_counts": [], "cycles_completed": 0}


def _save_checkpoint(data: dict) -> None:
    os.makedirs("results", exist_ok=True)
    with open(CHECKPOINT_FILE, "w") as f:
        json.dump(data, f, indent=2)


def _trend_label(slope: float) -> str:
    if slope >  0.001: return "improving (+)"
    if slope < -0.001: return "declining (-)"
    return "stable (~)"


def _sparkline(values: list[float]) -> str:
    chars = " ▁▂▃▄▅▆▇█"
    if not values:
        return ""
    return "".join(chars[min(8, int(v * 8))] for v in values)


def _regression(values: list[float]) -> dict:
    """Linear regression with p-value using scipy.stats.linregress."""
    if len(values) < 3:
        return {"slope": 0.0, "intercept": 0.0, "r2": 0.0, "p_value": 1.0, "stderr": 0.0}
    x      = np.arange(len(values), dtype=float)
    result = stats.linregress(x, values)
    return {
        "slope":     float(result.slope),
        "intercept": float(result.intercept),
        "r2":        float(result.rvalue ** 2),
        "p_value":   float(result.pvalue),
        "stderr":    float(result.stderr),
    }


def run_eval(n_cycles: int = 50, resume: bool = False) -> dict:
    from graph.retrieval import get_driver
    from memory.reflexion import run_full_cycle

    data = _load_checkpoint() if resume else {
        "attack_confs": [], "mit_effs": [], "memory_counts": [], "cycles_completed": 0
    }
    start_cycle = data["cycles_completed"]
    remaining   = n_cycles - start_cycle

    if remaining <= 0:
        print(f"[INFO] Already completed {start_cycle} cycles. Nothing to run.")
    else:
        driver = get_driver()
        print(f"Running cycles {start_cycle + 1}–{n_cycles}...\n")
        print(f"  {'Cycle':<7} {'Atk':>6} {'Mit':>6} {'Memories':>10}")
        print(f"  {'-'*35}")

        for i in range(remaining):
            cycle_num = start_cycle + i + 1
            result    = run_full_cycle(driver)
            if result["status"] != "complete":
                print(f"  {cycle_num:<7} SKIPPED ({result['status']})")
                continue

            cycle = result["cycle"]
            data["attack_confs"].append(cycle["attack_confidence"])
            data["mit_effs"].append(cycle["mitigation_effectiveness"])

            with driver.session() as session:
                rec     = session.run(
                    "MATCH (n:Node {node_type: 'memory'}) RETURN count(n) AS cnt"
                ).single()
                mem_cnt = rec["cnt"] if rec else 0
            data["memory_counts"].append(mem_cnt)
            data["cycles_completed"] = cycle_num

            print(f"  {cycle_num:<7} {cycle['attack_confidence']:>6.2f} "
                  f"{cycle['mitigation_effectiveness']:>6.2f} {mem_cnt:>10}")

            if cycle_num % CHECKPOINT_EVERY == 0:
                _save_checkpoint(data)
                print(f"  [CHECKPOINT] Saved at cycle {cycle_num}")

        driver.close()
        _save_checkpoint(data)

    # ── Analysis ──────────────────────────────────────────────────────────────
    attack_confs = data["attack_confs"]
    mit_effs     = data["mit_effs"]
    n_complete   = len(attack_confs)

    if n_complete < 3:
        print("\n[SKIP] Not enough completed cycles for regression")
        return data

    atk_reg = _regression(attack_confs)
    mit_reg = _regression(mit_effs)

    print("\n" + "=" * 65)
    print("CO-EVOLUTION SUMMARY")
    print(f"  Cycles completed: {n_complete} / {n_cycles}")

    print(f"\n  Attack confidence  [{_sparkline(attack_confs[-20:])}]")
    print(f"    mean={np.mean(attack_confs):.3f}  std={np.std(attack_confs):.3f}")
    print(f"    slope={atk_reg['slope']:+.5f}/cycle  "
          f"R²={atk_reg['r2']:.3f}  "
          f"p={atk_reg['p_value']:.4f}  "
          f"{_trend_label(atk_reg['slope'])}")
    if atk_reg['p_value'] < 0.05:
        print(f"    [p < 0.05 ✓] Attack confidence improvement is statistically significant")

    print(f"\n  Mitigation effectiveness  [{_sparkline(mit_effs[-20:])}]")
    print(f"    mean={np.mean(mit_effs):.3f}  std={np.std(mit_effs):.3f}")
    print(f"    slope={mit_reg['slope']:+.5f}/cycle  "
          f"R²={mit_reg['r2']:.3f}  "
          f"p={mit_reg['p_value']:.4f}  "
          f"{_trend_label(mit_reg['slope'])}")
    if mit_reg['p_value'] < 0.05:
        print(f"    [p < 0.05 ✓] Mitigation effectiveness improvement is statistically significant")

    mem_total = data["memory_counts"][-1] if data["memory_counts"] else 0
    print(f"\n  Episodic memories accumulated: {mem_total} (2 per cycle)")

    both_sig = atk_reg['p_value'] < 0.05 and mit_reg['p_value'] < 0.05
    either_improving = atk_reg['slope'] > 0 or mit_reg['slope'] > 0
    print()
    if both_sig:
        print("  [CLAIM FULLY SUPPORTED] Both agents show p < 0.05 improvement")
    elif either_improving:
        print("  [CLAIM PARTIALLY SUPPORTED] At least one agent improving")
        print("  Note: more cycles needed for both agents to reach p < 0.05")
    else:
        print("  [NOTE] No significant trend — agents may have saturated the graph")
    print("=" * 65)

    output = {
        "cycles_completed":    n_complete,
        "attack_confidences":  attack_confs,
        "mitigation_effs":     mit_effs,
        "memory_counts":       data["memory_counts"],
        "attack_regression":   atk_reg,
        "mit_regression":      mit_reg,
        "memory_total":        mem_total,
        "both_p_lt_005":       both_sig,
    }

    os.makedirs("results", exist_ok=True)
    with open(CHECKPOINT_FILE, "w") as f:
        json.dump({**data, **output}, f, indent=2)
    print(f"\nResults saved to {CHECKPOINT_FILE}")
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--resume", action="store_true",
                        help="Resume from checkpoint")
    parser.add_argument("--cycles", type=int, default=50,
                        help="Total number of cycles to run (default: 50)")
    parser.add_argument("--output", type=str, default=None,
                        help="Override checkpoint JSON path (default: results/coevolution_50.json)")
    parser.add_argument("--txt", type=str, default=None,
                        help="Also save printed output to this .txt file")
    args = parser.parse_args()

    if args.output:
        _set_checkpoint(args.output)

    header_lines = [
        "=" * 65,
        f"ARGUS Eval 3 — Co-evolutionary Improvement ({args.cycles} cycles)",
        "(scipy linear regression + p-value; checkpoints every 10 cycles)",
        "=" * 65,
    ]
    for line in header_lines:
        print(line)

    # Capture stdout to txt file if requested
    if args.txt:
        import io
        _orig_stdout = sys.stdout
        _buf = io.StringIO()

        class _Tee:
            def write(self, s):
                try:
                    _orig_stdout.write(s)
                except (UnicodeEncodeError, UnicodeDecodeError):
                    _orig_stdout.write(s.encode("ascii", errors="replace").decode("ascii"))
                _buf.write(s)
            def flush(self):
                _orig_stdout.flush()

        sys.stdout = _Tee()

    run_eval(n_cycles=args.cycles, resume=args.resume)

    if args.txt:
        sys.stdout = _orig_stdout
        os.makedirs("results", exist_ok=True)
        with open(args.txt, "w", encoding="utf-8") as f:
            f.write("\n".join(header_lines) + "\n")
            f.write(_buf.getvalue())
        print(f"Text output saved to {args.txt}")
