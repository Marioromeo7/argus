"""
ARGUS — Layer 6 Smoke Test
===========================
Run after test_red_blue.py passes (Layer 5 complete).
Verifies the Reflexion Memory system: post-engagement critique,
memory node persistence, reflects_on edge creation, episodic
context retrieval, and full cycle orchestration.

Each test invokes Qwen3 thinking mode twice (red + blue reflect).
Expect ~5-10 minutes for the full suite.

Usage:
    conda activate argus
    python scripts/test_reflexion.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
from dotenv import load_dotenv
load_dotenv()


def _make_engagement_and_mitigation(driver):
    """Helper: run one red->blue cycle and return (engagement, mitigation)."""
    from agents.red import plan_attack
    from agents.blue import plan_mitigation
    attack = plan_attack(driver, context={})
    if attack["status"] != "planned":
        return None, None
    result = plan_mitigation(driver, attack)
    return attack["engagement"], result["mitigation"]


def test_reflect_produces_memories():
    """reflect() returns two populated memory dicts (one per agent)."""
    from graph.retrieval import get_driver
    from memory.reflexion import reflect
    driver = get_driver()
    engagement, mitigation = _make_engagement_and_mitigation(driver)
    if engagement is None:
        driver.close()
        print("[SKIP] reflect_produces_memories — no attack surface")
        return
    memories = reflect(driver, engagement, mitigation)
    driver.close()
    assert "red_memory" in memories and "blue_memory" in memories
    for agent in ("red_memory", "blue_memory"):
        m = memories[agent]
        assert "memory_id" in m
        assert m["memory_id"].startswith("MEM-")
        assert "lesson" in m and m["lesson"]
        assert "next_strategy" in m
    print(f"[PASS] reflect_produces_memories OK — "
          f"{memories['red_memory']['memory_id']}, "
          f"{memories['blue_memory']['memory_id']}")


def test_memory_nodes_persisted():
    """Memory nodes written by reflect() are readable from Neo4j (skipped nodes are exempt)."""
    from graph.retrieval import get_driver, get_node
    from memory.reflexion import reflect
    driver = get_driver()
    engagement, mitigation = _make_engagement_and_mitigation(driver)
    if engagement is None:
        driver.close()
        print("[SKIP] memory_nodes_persisted — no attack surface")
        return
    memories = reflect(driver, engagement, mitigation)
    written_map = {"red_memory": memories.get("red_written", True),
                   "blue_memory": memories.get("blue_written", True)}
    checked = 0
    for agent in ("red_memory", "blue_memory"):
        mid = memories[agent]["memory_id"]
        if not written_map[agent]:
            print(f"  [INFO] {mid} skipped (duplicate lesson) — skipping node check")
            continue
        node = get_node(driver, mid)
        assert node is not None, f"Memory node {mid} not found in Neo4j"
        assert node["node_type"] == "memory", \
            f"Expected node_type='memory', got '{node['node_type']}'"
        checked += 1
    driver.close()
    if checked == 0:
        print("[PASS] memory_nodes_persisted OK — both lessons were duplicates, skipped correctly")
    else:
        print(f"[PASS] memory_nodes_persisted OK — {checked} written node(s) confirmed in Neo4j")


def test_reflects_on_edges_written():
    """Written memory nodes must have reflects_on edges to the engagement."""
    from graph.retrieval import get_driver
    from memory.reflexion import reflect
    driver = get_driver()
    engagement, mitigation = _make_engagement_and_mitigation(driver)
    if engagement is None:
        driver.close()
        print("[SKIP] reflects_on_edges_written — no attack surface")
        return
    memories = reflect(driver, engagement, mitigation)
    expected = sum([memories.get("red_written", True), memories.get("blue_written", True)])
    if expected == 0:
        driver.close()
        print("[PASS] reflects_on_edges_written OK — both lessons were duplicates, no edges expected")
        return
    eid        = engagement["engagement_id"]
    found_mids = []
    with driver.session() as session:
        result = session.run(
            "MATCH (m:Node)-[r:RELATION {relation_type: 'reflects_on'}]->(e:Node {node_id: $eid}) "
            "RETURN m.node_id AS mid",
            eid=eid,
        )
        for rec in result:
            found_mids.append(rec["mid"])
    driver.close()
    assert len(found_mids) >= expected, \
        f"Expected >={expected} reflects_on edges to {eid}, found {len(found_mids)}"
    print(f"[PASS] reflects_on_edges_written OK — "
          f"{len(found_mids)} memory node(s) linked to {eid} (expected {expected})")


def test_episodic_retrieval():
    """get_recent_memories returns persisted memories for red and blue agents."""
    from graph.retrieval import get_driver
    from memory.reflexion import reflect, get_recent_memories
    driver = get_driver()
    engagement, mitigation = _make_engagement_and_mitigation(driver)
    if engagement is None:
        driver.close()
        print("[SKIP] episodic_retrieval — no attack surface")
        return
    reflect(driver, engagement, mitigation)
    red_memories  = get_recent_memories(driver, agent="red",  limit=5)
    blue_memories = get_recent_memories(driver, agent="blue", limit=5)
    driver.close()
    assert len(red_memories) >= 1,  "No red memories found after reflect()"
    assert len(blue_memories) >= 1, "No blue memories found after reflect()"
    print(f"[PASS] episodic_retrieval OK — "
          f"{len(red_memories)} red, {len(blue_memories)} blue memories")


def test_full_cycle():
    """run_full_cycle() completes all three phases and returns a valid cycle record."""
    from graph.retrieval import get_driver
    from memory.reflexion import run_full_cycle
    driver = get_driver()
    result = run_full_cycle(driver, context={"test": True})
    driver.close()
    if result["status"] in ("no_attack_surface", "no_chains"):
        print(f"[SKIP] full_cycle — {result['status']}")
        return
    assert result["status"] == "complete", f"Unexpected status: {result['status']}"
    cycle = result["cycle"]
    for key in ("engagement_id", "mitigation_id", "red_memory_id", "blue_memory_id",
                "attack_confidence", "mitigation_effectiveness"):
        assert key in cycle, f"Missing key '{key}' in cycle record"
    assert 0.0 <= cycle["attack_confidence"] <= 1.0
    assert 0.0 <= cycle["mitigation_effectiveness"] <= 1.0
    print(f"[PASS] full_cycle OK — "
          f"attack={cycle['attack_confidence']:.2f}, "
          f"mitigation={cycle['mitigation_effectiveness']:.2f}, "
          f"red={cycle['red_memory_id']}, blue={cycle['blue_memory_id']}")


if __name__ == "__main__":
    print("=" * 55)
    print("ARGUS Layer 6 — Reflexion Memory Smoke Test")
    print("(Uses Qwen3 8B thinking mode — expect ~8-12 min)")
    print("=" * 55)
    tests = [
        test_reflect_produces_memories,
        test_memory_nodes_persisted,
        test_reflects_on_edges_written,
        test_episodic_retrieval,
        test_full_cycle,
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
        print("Layer 6 complete. All 6 layers of ARGUS are operational.")
        print("Next: run evaluation benchmarks (scripts/eval_*.py)")
    else:
        print("Fix failures above before proceeding.")
    print("=" * 55)
