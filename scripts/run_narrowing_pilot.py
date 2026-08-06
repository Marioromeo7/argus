"""
ARGUS-LAYER-7 — Narrowing Engine Pilot
==========================================
Runs agents/narrowing.run_narrowing() against a small set of technique nodes.
Dry-run only — no Neo4j writes. Validates the asker/answerer mechanism from
THESIS.md before deciding whether to invest in GraphRange execution.

Each node's full report is appended to results/narrowing_pilot.jsonl as soon
as it completes, so a multi-hour run's progress survives even if interrupted.

Usage:
    conda activate argus
    python -u scripts/run_narrowing_pilot.py
"""

import sys, os, json, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

PILOT_SIZE  = 8
RESULT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "results", "narrowing_pilot.jsonl")


def _p(msg):
    print(msg, flush=True)


def run():
    from graph.retrieval import get_driver, get_nodes_by_type
    from agents.narrowing import run_narrowing

    os.makedirs(os.path.dirname(RESULT_PATH), exist_ok=True)
    driver = get_driver()

    nodes = get_nodes_by_type(driver, "technique", limit=PILOT_SIZE)
    _p(f"Pilot nodes ({len(nodes)}): {[n['node_id'] for n in nodes]}")

    t0 = time.time()
    with open(RESULT_PATH, "a", encoding="utf-8") as f:
        for i, n in enumerate(nodes, 1):
            node_id = n["node_id"]
            _p(f"\n[{i}/{len(nodes)}] {node_id} — starting...")
            t_node = time.time()
            try:
                report = run_narrowing(driver, node_id)
            except Exception as e:
                _p(f"  FAILED: {e}")
                f.write(json.dumps({"node_id": node_id, "error": str(e)}) + "\n")
                f.flush()
                continue

            elapsed = time.time() - t_node
            _p(f"  status={report['status']}  rounds={report['rounds_run']}  "
               f"confidence={report['grain_confidence']}  "
               f"trusted={report['trusted']}/{report['total_questions']}  "
               f"({elapsed/60:.1f} min)")
            for rd in report["rounds_detail"]:
                _p(f"    round {rd['round']}: [{rd['status']}] {rd['question'][:90]}")

            f.write(json.dumps(report, default=str) + "\n")
            f.flush()

    total_elapsed = time.time() - t0
    _p(f"\n{'='*60}")
    _p("NARROWING PILOT SUMMARY")
    _p(f"  Nodes run:      {len(nodes)}")
    _p(f"  Total elapsed:  {total_elapsed/60:.1f} min")
    _p(f"  Results:        {RESULT_PATH}")
    _p(f"{'='*60}")
    driver.close()


if __name__ == "__main__":
    _p("=" * 60)
    _p("ARGUS-LAYER-7 — narrowing engine pilot")
    _p("=" * 60)
    run()
