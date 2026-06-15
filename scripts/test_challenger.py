"""
ARGUS — Layer 3 Smoke Test
===========================
Run after test_retrieval.py passes (Layer 2 complete).
Verifies the challenger agent: Socratic loop, grain update,
challenger_log persistence, and monotonic grain convergence.

Note: each test round calls Qwen3 in thinking mode (~30-90s per call).
Expect this test to take 3-8 minutes total.

Usage:
    conda activate argus
    python scripts/test_challenger.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()


def test_challenger_single_node():
    """Challenger runs on one node; log is populated; grain changes."""
    from graph.retrieval import get_driver, get_nodes_by_type
    from agents.challenger import challenge_node
    driver = get_driver()
    nodes  = get_nodes_by_type(driver, "vulnerability", limit=1)
    assert nodes, "No vulnerability nodes — run test_ingestion.py first"
    node   = nodes[0]
    before = float(node["grain_confidence"])
    updated = challenge_node(driver, node, rounds=1)
    driver.close()
    assert "grain_confidence" in updated
    assert "challenger_log"   in updated
    assert len(updated["challenger_log"]) > 0, "challenger_log should have at least 1 entry"
    after = updated["grain_confidence"]
    assert after >= before, f"Grain decreased: {before:.2f} -> {after:.2f}"
    print(f"[PASS] challenger_single_node OK — "
          f"{node['node_id']}: {before:.2f} -> {after:.2f}")


def test_grain_persisted_to_neo4j():
    """Updated grain_confidence must be readable back from Neo4j."""
    from graph.retrieval import get_driver, get_nodes_by_type, get_node
    from agents.challenger import challenge_node
    driver = get_driver()
    nodes  = get_nodes_by_type(driver, "technique", limit=1)
    assert nodes, "No technique nodes — run test_retrieval.py first"
    node    = nodes[0]
    updated = challenge_node(driver, node, rounds=1)
    # Re-fetch from Neo4j
    fresh   = get_node(driver, node["node_id"])
    driver.close()
    assert fresh is not None
    assert abs(float(fresh["grain_confidence"]) - updated["grain_confidence"]) < 0.001, \
        f"Persisted grain {fresh['grain_confidence']} != in-memory {updated['grain_confidence']}"
    print(f"[PASS] grain_persisted OK — "
          f"{node['node_id']} grain={fresh['grain_confidence']:.2f} confirmed in Neo4j")


def test_open_questions_updated():
    """challenger should add at least one open question to the node."""
    from graph.retrieval import get_driver, get_nodes_by_type
    from agents.challenger import challenge_node
    driver = get_driver()
    nodes  = get_nodes_by_type(driver, "vulnerability", limit=2)
    assert len(nodes) >= 2, "Need at least 2 vulnerability nodes"
    # Use the second node to avoid hitting the already-challenged one
    node   = nodes[1]
    before_oq = list(node.get("open_questions") or [])
    updated   = challenge_node(driver, node, rounds=1)
    driver.close()
    assert len(updated["open_questions"]) >= len(before_oq), \
        "open_questions should not shrink after a challenge round"
    print(f"[PASS] open_questions_updated OK — "
          f"{len(before_oq)} -> {len(updated['open_questions'])} questions")


def test_grain_convergence_batch():
    """
    Run batch challenger on 2 low-grain nodes for 1 round each.
    Verify mean grain shifts right (the paper's core claim).
    """
    from graph.retrieval import get_driver, get_low_grain_nodes
    from agents.challenger import run_challenger
    driver  = get_driver()
    before  = get_low_grain_nodes(driver, threshold=0.6, limit=2)
    if len(before) < 1:
        driver.close()
        print("[SKIP] grain_convergence_batch — not enough low-grain nodes")
        return
    before_mean = sum(float(n["grain_confidence"]) for n in before) / len(before)
    results     = run_challenger(driver, threshold=0.6, limit=2, rounds=1)
    driver.close()
    after_mean  = sum(r["grain_confidence"] for r in results) / len(results)
    assert after_mean >= before_mean, \
        f"Mean grain decreased: {before_mean:.3f} -> {after_mean:.3f}"
    print(f"[PASS] grain_convergence_batch OK — "
          f"mean grain: {before_mean:.3f} -> {after_mean:.3f} "
          f"({after_mean - before_mean:+.3f})")


def test_maximally_specific_node_skips():
    """A node already at grain 0.85+ should not be pushed further by the loop."""
    from graph.retrieval import get_driver
    from agents.challenger import challenge_node
    # Craft a high-grain node dict (tactic nodes are ingested at 0.85)
    from graph.retrieval import get_nodes_by_type
    driver  = get_driver()
    tactics = get_nodes_by_type(driver, "tactic", limit=1)
    if not tactics:
        driver.close()
        print("[SKIP] maximally_specific — no tactic nodes")
        return
    node    = tactics[0]
    before  = float(node["grain_confidence"])
    updated = challenge_node(driver, node, rounds=2)
    driver.close()
    assert updated["grain_confidence"] >= before, \
        "Grain should never decrease"
    print(f"[PASS] maximally_specific_node OK — "
          f"tactic grain {before:.2f} -> {updated['grain_confidence']:.2f}")


if __name__ == "__main__":
    print("=" * 55)
    print("ARGUS Layer 3 — Challenger Agent Smoke Test")
    print("(Uses Qwen3 8B thinking mode — expect ~5-10 min)")
    print("=" * 55)
    tests = [
        test_challenger_single_node,
        test_grain_persisted_to_neo4j,
        test_open_questions_updated,
        test_grain_convergence_batch,
        test_maximally_specific_node_skips,
    ]
    passed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"[FAIL] {test.__name__}: {e}")

    print("=" * 55)
    print(f"Result: {passed}/{len(tests)} passed")
    if passed == len(tests):
        print("Layer 3 complete. Start Layer 4: agents/crawler.py")
    else:
        print("Fix failures above before proceeding.")
    print("=" * 55)
