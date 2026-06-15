"""
ARGUS — Layer 4 Smoke Test
===========================
Run after test_challenger.py passes (Layer 3 complete).
Verifies the Isekai Web Agent: NVD crawl, entity extraction,
technique edge creation, and challenger pre-write validation.

Each NVD crawl call hits the NVD API and runs Qwen3 thinking
mode once per CVE. Expect ~2-4 minutes for the full suite.

Usage:
    conda activate argus
    python scripts/test_crawler.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()


def test_nvd_crawl_new_nodes():
    """Crawler fetches new CVEs and writes them to Neo4j."""
    from graph.retrieval import get_driver
    from agents.crawler import crawl_nvd
    driver = get_driver()
    nodes  = crawl_nvd(driver, keyword="use after free", limit=2)
    driver.close()
    assert len(nodes) >= 1, "Crawler should write at least 1 new node"
    assert all("node_id" in n for n in nodes)
    assert all(n["node_id"].startswith("CVE-") for n in nodes)
    print(f"[PASS] nvd_crawl_new_nodes OK — {len(nodes)} new CVE nodes written")


def test_no_write_without_validation():
    """Every node the crawler writes must have a challenger_log entry."""
    from graph.retrieval import get_driver, get_node
    from agents.crawler import crawl_nvd
    driver = get_driver()
    nodes  = crawl_nvd(driver, keyword="privilege escalation", limit=1)
    if not nodes:
        driver.close()
        print("[SKIP] no_write_without_validation — no new CVEs found")
        return
    # Re-read from Neo4j to confirm persisted properties
    fresh = get_node(driver, nodes[0]["node_id"])
    driver.close()
    assert fresh is not None
    log = fresh.get("challenger_log", "")
    assert log and log != "[]", \
        f"Node {nodes[0]['node_id']} written without challenger_log"
    print(f"[PASS] no_write_without_validation OK — "
          f"{nodes[0]['node_id']} has challenger_log in Neo4j")


def test_entity_extraction():
    """Entity extractor pulls ATT&CK technique IDs from CVE text."""
    from agents.crawler import _extract_entities
    # A description that should yield technique IDs
    text = (
        "An attacker can exploit this vulnerability to execute arbitrary commands "
        "via command injection (T1059) or use process injection (T1055) to gain "
        "elevated privileges on the target system."
    )
    entities = _extract_entities(text)
    assert "techniques" in entities
    assert "vuln_type" in entities
    # Should extract at least one of the explicitly mentioned techniques
    techs = entities["techniques"]
    assert any(t.startswith("T") for t in techs), \
        f"No technique IDs extracted. Got: {techs}"
    print(f"[PASS] entity_extraction OK — techniques={techs}, vuln_type={entities['vuln_type']}")


def test_technique_edges_written():
    """If a CVE's description mentions a known technique, an edge is created."""
    from graph.retrieval import get_driver, get_nodes_by_type
    from agents.crawler import _write_technique_edges, _extract_entities
    driver = get_driver()

    # Check if we have any technique nodes to link to
    techniques = get_nodes_by_type(driver, "technique", limit=1)
    if not techniques:
        driver.close()
        print("[SKIP] technique_edges_written — no technique nodes in graph")
        return

    known_tid   = techniques[0]["node_id"]
    fake_cve_id = "CVE-2024-TESTCRAWL"

    # Write a dummy CVE node first
    with driver.session() as session:
        session.run(
            "MERGE (n:Node {node_id: $nid}) SET n.node_type='vulnerability', "
            "n.grain_confidence=0.2, n.label=$nid",
            nid=fake_cve_id,
        )

    count = _write_technique_edges(driver, fake_cve_id, [known_tid])
    # Verify edge exists
    with driver.session() as session:
        result = session.run(
            "MATCH (a:Node {node_id: $cve})-[r:RELATION]->(b:Node {node_id: $tid}) RETURN r",
            cve=fake_cve_id, tid=known_tid,
        )
        edge_found = result.single() is not None
    # Cleanup
    with driver.session() as session:
        session.run("MATCH (n:Node {node_id: $nid}) DETACH DELETE n", nid=fake_cve_id)
    driver.close()

    assert count == 1 and edge_found, \
        f"Edge {fake_cve_id}-[enables]->{known_tid} not written"
    print(f"[PASS] technique_edges_written OK — edge to {known_tid} created and verified")


def test_deduplication():
    """Nodes already in the graph must not be written again by the crawler."""
    from graph.retrieval import get_driver
    from agents.crawler import crawl_nvd
    driver = get_driver()

    first_run = crawl_nvd(driver, keyword="cross site scripting", limit=1)
    if not first_run:
        driver.close()
        print("[SKIP] deduplication — no new nodes available")
        return

    written_id = first_run[0]["node_id"]
    # Second crawl — same keyword. The written_id must not appear again.
    second_run = crawl_nvd(driver, keyword="cross site scripting", limit=2)
    driver.close()

    second_ids = [n["node_id"] for n in second_run]
    assert written_id not in second_ids, \
        f"{written_id} was written again on second crawl — dedup failed"
    print(f"[PASS] deduplication OK — {written_id} correctly skipped on second crawl")


if __name__ == "__main__":
    print("=" * 55)
    print("ARGUS Layer 4 — Isekai Web Agent Smoke Test")
    print("(Hits NVD API + Qwen3 — expect ~3-5 min)")
    print("=" * 55)
    tests = [
        test_nvd_crawl_new_nodes,
        test_no_write_without_validation,
        test_entity_extraction,
        test_technique_edges_written,
        test_deduplication,
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
        print("Layer 4 complete. Start Layer 5: agents/red.py + agents/blue.py")
    else:
        print("Fix failures above before proceeding.")
    print("=" * 55)
