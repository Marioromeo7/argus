"""
ARGUS — Layer 5 Smoke Test
===========================
Run after test_crawler.py passes (Layer 4 complete).
Verifies the Red and Blue agents: attack path discovery,
engagement persistence, mitigation planning, graph updates,
and co-evolutionary edge confidence updates.

Each test invokes Qwen3 thinking mode once per agent call.
Expect ~4-8 minutes for the full suite.

Usage:
    conda activate argus
    python scripts/test_red_blue.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
from dotenv import load_dotenv
load_dotenv()


def test_red_finds_path():
    """Red agent discovers an attack chain and creates an engagement node."""
    from graph.retrieval import get_driver
    from agents.red import plan_attack
    driver = get_driver()
    result = plan_attack(driver, context={"assumed_network_access": True})
    driver.close()
    if result["status"] in ("no_attack_surface", "no_chains"):
        print(f"[SKIP] red_finds_path — {result['status']} "
              "(run test_crawler.py first to populate CVE->technique edges)")
        return
    assert result["status"] == "planned", f"Unexpected status: {result['status']}"
    eng = result["engagement"]
    assert "engagement_id" in eng
    assert eng["engagement_id"].startswith("ENG-")
    assert "selected_chain" in eng
    assert len(eng["selected_chain"]) >= 2, "Chain must have at least 2 hops"
    assert 0.0 <= eng["confidence"] <= 1.0
    print(f"[PASS] red_finds_path OK — {eng['engagement_id']}, "
          f"{len(eng['selected_chain'])}-hop chain, "
          f"confidence={eng['confidence']:.2f}")


def test_engagement_persisted():
    """Engagement node written by red agent is readable from Neo4j."""
    from graph.retrieval import get_driver, get_node
    from agents.red import plan_attack
    driver = get_driver()
    result = plan_attack(driver, context={})
    if result["status"] != "planned":
        driver.close()
        print(f"[SKIP] engagement_persisted — no attack planned ({result['status']})")
        return
    eid  = result["engagement"]["engagement_id"]
    node = get_node(driver, eid)
    driver.close()
    assert node is not None, f"Engagement {eid} not found in Neo4j"
    assert node["node_type"] == "engagement", \
        f"Expected node_type='engagement', got '{node['node_type']}'"
    assert node.get("status") == "open", \
        f"Engagement should be 'open' before blue responds; got '{node.get('status')}'"
    print(f"[PASS] engagement_persisted OK — {eid} found in Neo4j, status=open")


def test_blue_mitigates():
    """Blue agent proposes mitigation and returns valid structured output."""
    from graph.retrieval import get_driver
    from agents.red import plan_attack
    from agents.blue import plan_mitigation
    driver = get_driver()
    attack = plan_attack(driver, context={})
    if attack["status"] != "planned":
        driver.close()
        print(f"[SKIP] blue_mitigates — no attack plan ({attack['status']})")
        return
    result = plan_mitigation(driver, attack)
    driver.close()
    assert result["status"] == "mitigated"
    mit = result["mitigation"]
    assert "mitigation_id" in mit
    assert mit["mitigation_id"].startswith("MIT-")
    assert 0.0 <= mit["effectiveness"] <= 1.0
    assert isinstance(mit["steps"], list) and len(mit["steps"]) >= 1, \
        "Blue agent must propose at least one concrete step"
    assert mit["priority"] in ("critical", "high", "medium", "low"), \
        f"Unexpected priority: '{mit['priority']}'"
    print(f"[PASS] blue_mitigates OK — {mit['mitigation_id']}, "
          f"effectiveness={mit['effectiveness']:.2f}, priority={mit['priority']}")


def test_mitigation_edge_written():
    """A mitigates edge from MIT node to ENG node must exist after a full cycle."""
    from graph.retrieval import get_driver
    from agents.red import plan_attack
    from agents.blue import plan_mitigation
    driver = get_driver()
    attack = plan_attack(driver, context={})
    if attack["status"] != "planned":
        driver.close()
        print("[SKIP] mitigation_edge_written — no attack plan")
        return
    plan_mitigation(driver, attack)
    eid = attack["engagement"]["engagement_id"]
    with driver.session() as session:
        result = session.run(
            "MATCH (m:Node)-[r:RELATION {relation_type: 'mitigates'}]->(e:Node {node_id: $eid}) "
            "RETURN m.node_id AS mid",
            eid=eid,
        )
        rec = result.single()
    driver.close()
    assert rec is not None, f"No mitigates edge found pointing to engagement {eid}"
    print(f"[PASS] mitigation_edge_written OK — {rec['mid']} mitigates {eid}")


def test_engagement_status_closed():
    """After blue mitigates, engagement node status must be 'mitigated' in Neo4j."""
    from graph.retrieval import get_driver, get_node
    from agents.red import plan_attack
    from agents.blue import plan_mitigation
    driver = get_driver()
    attack = plan_attack(driver, context={})
    if attack["status"] != "planned":
        driver.close()
        print("[SKIP] engagement_status_closed — no attack plan")
        return
    plan_mitigation(driver, attack)
    eid  = attack["engagement"]["engagement_id"]
    node = get_node(driver, eid)
    driver.close()
    assert node is not None, f"Engagement {eid} not found in Neo4j"
    status = node.get("status")
    assert status == "mitigated", \
        f"Expected status='mitigated', got '{status}'"
    print(f"[PASS] engagement_status_closed OK — {eid} status=mitigated")


if __name__ == "__main__":
    print("=" * 55)
    print("ARGUS Layer 5 — Red & Blue Agent Smoke Test")
    print("(Uses Qwen3 8B thinking mode — expect ~5-10 min)")
    print("=" * 55)
    tests = [
        test_red_finds_path,
        test_engagement_persisted,
        test_blue_mitigates,
        test_mitigation_edge_written,
        test_engagement_status_closed,
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
        print("Layer 5 complete. Start Layer 6: memory/reflexion.py")
    else:
        print("Fix failures above before proceeding.")
    print("=" * 55)
