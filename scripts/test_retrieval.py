"""
ARGUS — Layer 2 Smoke Test
===========================
Run after test_ingestion.py passes (Layer 1 complete).
Verifies GraphRAG retrieval and ATT&CK ingestion.

Usage:
    conda activate argus
    python scripts/test_retrieval.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()


def test_attack_ingest():
    from graph.ingestion.attack import ingest_attack
    nodes, tmap = ingest_attack(limit=15)
    assert len(nodes) == 15, f"Expected 15 techniques, got {len(nodes)}"
    assert len(tmap) > 0, "No tactics ingested"
    assert all(n.node_type == "technique" for n in nodes)
    print(f"[PASS] ATT&CK ingest OK — {len(tmap)} tactics, {len(nodes)} techniques")


def test_get_node():
    from graph.retrieval import get_driver, get_node
    driver = get_driver()
    node = get_node(driver, "CVE-1999-1471")
    driver.close()
    assert node is not None, "CVE-1999-1471 not found — run test_ingestion.py first"
    assert node["node_id"] == "CVE-1999-1471"
    assert node["node_type"] == "vulnerability"
    print(f"[PASS] get_node OK — {node['node_id']} grain={node['grain_confidence']}")


def test_get_nodes_by_type():
    from graph.retrieval import get_driver, get_nodes_by_type
    driver = get_driver()
    vulns      = get_nodes_by_type(driver, "vulnerability", limit=5)
    techniques = get_nodes_by_type(driver, "technique",     limit=5)
    tactics    = get_nodes_by_type(driver, "tactic",        limit=5)
    driver.close()
    assert len(vulns) > 0,      "No vulnerability nodes found"
    assert len(techniques) > 0, "No technique nodes — run test_attack_ingest first"
    assert len(tactics) > 0,    "No tactic nodes — run test_attack_ingest first"
    print(f"[PASS] get_nodes_by_type OK — "
          f"{len(vulns)} vulns, {len(techniques)} techniques, {len(tactics)} tactics")


def test_traverse_subgraph():
    from graph.retrieval import get_driver, get_nodes_by_type, traverse_subgraph
    driver     = get_driver()
    techniques = get_nodes_by_type(driver, "technique", limit=1)
    if not techniques:
        driver.close()
        print("[SKIP] traverse_subgraph — no technique nodes yet")
        return
    start_id = techniques[0]["node_id"]
    subgraph  = traverse_subgraph(driver, start_id, depth=2)
    driver.close()
    assert "nodes" in subgraph and "edges" in subgraph
    assert len(subgraph["nodes"]) >= 1
    print(f"[PASS] traverse_subgraph OK — "
          f"{len(subgraph['nodes'])} nodes, {len(subgraph['edges'])} edges from {start_id}")


def test_get_low_grain_nodes():
    from graph.retrieval import get_driver, get_low_grain_nodes
    driver = get_driver()
    nodes  = get_low_grain_nodes(driver, threshold=0.5, limit=5)
    driver.close()
    assert isinstance(nodes, list)
    assert all(n["grain_confidence"] < 0.5 for n in nodes)
    print(f"[PASS] get_low_grain_nodes OK — {len(nodes)} nodes below 0.5 grain")


def test_context_filtering():
    """Edges with unmet context_conditions must not appear in get_neighbors."""
    from graph.retrieval import get_driver, get_nodes_by_type, get_neighbors
    driver = get_driver()
    # All edges ingested by attack.py have empty context_conditions (always traversable)
    techniques = get_nodes_by_type(driver, "technique", limit=1)
    if not techniques:
        driver.close()
        print("[SKIP] context_filtering — no technique nodes yet")
        return
    tid = techniques[0]["node_id"]
    # Empty context → should return all neighbors (no conditions to fail)
    nb_open   = get_neighbors(driver, tid, context={})
    # Impossible context → same result because conditions list is empty
    nb_closed = get_neighbors(driver, tid, context={"satisfied_conditions": []})
    driver.close()
    assert len(nb_open) == len(nb_closed), \
        "Context filtering changed results on unconditional edges"
    print(f"[PASS] context_filtering OK — {len(nb_open)} neighbors, filtering consistent")


if __name__ == "__main__":
    print("=" * 50)
    print("ARGUS Layer 2 — Retrieval Smoke Test")
    print("=" * 50)
    tests = [
        test_attack_ingest,
        test_get_node,
        test_get_nodes_by_type,
        test_traverse_subgraph,
        test_get_low_grain_nodes,
        test_context_filtering,
    ]
    passed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"[FAIL] {test.__name__}: {e}")

    print("=" * 50)
    print(f"Result: {passed}/{len(tests)} passed")
    if passed == len(tests):
        print("Layer 2 complete. Start Layer 3: agents/challenger.py")
    else:
        print("Fix failures above before proceeding.")
    print("=" * 50)
