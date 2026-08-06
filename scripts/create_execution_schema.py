"""
ARGUS-LAYER-7 — GraphRange Phase 0.2: Execution History Schema
==================================================================
Creates constraints and indexes for ScenarioRun and Outcome nodes.
Schema only — no data. Data is written at runtime by graph_updater.py.

Usage:
    conda activate argus
    python -u scripts/create_execution_schema.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()


def _p(msg):
    print(msg, flush=True)


STATEMENTS = [
    (
        "scenario_run_id (unique node_id)",
        """
        CREATE CONSTRAINT scenario_run_id IF NOT EXISTS
        FOR (n:Node) REQUIRE n.node_id IS UNIQUE
        """,
    ),
    (
        "scenario_run_type (index on node_type)",
        """
        CREATE INDEX scenario_run_type IF NOT EXISTS
        FOR (n:Node) ON (n.node_type)
        """,
    ),
    (
        "outcome_run_id (index on run_id)",
        """
        CREATE INDEX outcome_run_id IF NOT EXISTS
        FOR (n:Node) ON (n.run_id)
        """,
    ),
]


def run():
    from graph.retrieval import get_driver

    driver = get_driver()
    with driver.session() as session:
        for name, cypher in STATEMENTS:
            session.run(cypher)
            _p(f"  [OK] {name}")

        _p("\nCurrent constraints/indexes:")
        for rec in session.run("SHOW CONSTRAINTS"):
            _p(f"  constraint: {dict(rec)}")
        for rec in session.run("SHOW INDEXES"):
            info = dict(rec)
            if info.get("name") in ("scenario_run_type", "outcome_run_id"):
                _p(f"  index: {info.get('name')} -> {info.get('properties')}")

    driver.close()


if __name__ == "__main__":
    _p("=" * 60)
    _p("ARGUS-LAYER-7 — create_execution_schema")
    _p("=" * 60)
    run()
    _p("\nDone. ScenarioRun/Outcome node types are ready to write to.")
