"""
ARGUS-LAYER-7 — Narrowing Engine, single-node runner
========================================================
Runs exactly ONE node through the (post-bugfix) narrowing engine, dry-run
only (no Neo4j writes) — same run_narrowing() the original pilot used.
Deliberately not a loop: each node is a separate, explicitly-launched
command so nothing runs unattended for hours without a checkpoint.

Appends to results/narrowing_pilot_postfix.jsonl — kept separate from the
pre-fix results/narrowing_pilot.jsonl so the before/after comparison stays
clean.

Usage:
    conda activate argus
    python -u scripts/run_narrowing_single.py <node_id>
"""

import sys, os, json, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

RESULT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "results", "narrowing_pilot_postfix.jsonl")


def _p(msg):
    print(msg, flush=True)


def run(node_id: str):
    from graph.retrieval import get_driver
    from agents.narrowing import run_narrowing

    os.makedirs(os.path.dirname(RESULT_PATH), exist_ok=True)
    driver = get_driver()

    _p(f"Starting {node_id}...")
    t0 = time.time()
    try:
        report = run_narrowing(driver, node_id)
    except Exception as e:
        report = {"node_id": node_id, "error": str(e)}
    elapsed = time.time() - t0

    with open(RESULT_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(report, default=str) + "\n")

    if "error" in report:
        _p(f"FAILED  node={node_id}  elapsed={elapsed/60:.1f}min  error={report['error']}")
    else:
        _p(f"DONE    node={node_id}  elapsed={elapsed/60:.1f}min  "
           f"status={report['status']}  rounds={report['rounds_run']}  "
           f"confidence={report['grain_confidence']}  "
           f"trusted={report['trusted']}/{report['total_questions']}")
        for rd in report["rounds_detail"]:
            _p(f"  round {rd['round']}: [{rd['status']}] {rd['question'][:90]}")

    driver.close()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        _p("usage: python -u scripts/run_narrowing_single.py <node_id>")
        sys.exit(1)
    run(sys.argv[1])
