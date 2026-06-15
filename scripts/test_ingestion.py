"""
ARGUS — Layer 1 Smoke Test
===========================
Run this after Neo4j Desktop is running and .env is configured.
If this passes, Layer 1 is done. Start Layer 2.

Usage:
    conda activate argus
    python scripts/test_ingestion.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

def test_neo4j_connection():
    from neo4j import GraphDatabase
    uri  = os.getenv("NEO4J_URI", "bolt://localhost:7400")
    user = os.getenv("NEO4J_USER", "neo4j")
    pw   = os.getenv("NEO4J_PASSWORD", "argus1234")
    driver = GraphDatabase.driver(uri, auth=(user, pw))
    with driver.session() as session:
        result = session.run("RETURN 1 AS n")
        assert result.single()["n"] == 1
    driver.close()
    print("[PASS] Neo4j connection OK")

def test_ollama_connection():
    import requests
    resp = requests.get("http://localhost:11434/api/tags", timeout=5)
    models = [m["name"] for m in resp.json().get("models", [])]
    assert any("qwen3" in m for m in models), \
        f"qwen3:8b not found. Run: ollama pull qwen3:8b\nFound: {models}"
    assert any("nomic" in m for m in models), \
        f"nomic-embed-text not found. Run: ollama pull nomic-embed-text\nFound: {models}"
    print(f"[PASS] Ollama OK — models: {models}")

def test_qwen3_thinking():
    """Verify Qwen3 thinking mode works — critical for challenger agent."""
    import ollama
    response = ollama.chat(
        model="qwen3:8b",
        messages=[{"role": "user", "content": "/think\n\nIn one sentence: what is a heap overflow?"}]
    )
    text = response["message"]["content"]
    assert len(text) > 10, "Qwen3 returned empty response"
    print(f"[PASS] Qwen3 thinking mode OK — response length: {len(text)} chars")

def test_node_schema():
    from graph.schema import Node, Edge, NodeSource
    n = Node(
        node_id="CVE-2024-TEST",
        label="CVE-2024-TEST",
        node_type="vulnerability",
        properties={"description": "test"},
        grain_confidence=0.2,
        open_questions=["What type of vulnerability is this?"],
        source=NodeSource.NVD,
    )
    assert n.needs_refinement(threshold=0.6)
    assert not n.needs_refinement(threshold=0.1)
    serialized = n.to_neo4j()
    assert serialized["node_id"] == "CVE-2024-TEST"
    print("[PASS] Node schema OK")

def test_edge_schema():
    from graph.schema import Edge, NodeSource
    e = Edge(
        edge_id="test-edge-001",
        source_id="CVE-2024-TEST",
        target_id="Apache-2.4",
        relation_type="exploits",
        context_conditions=["pre-auth", "remote"],
        confidence=0.7,
    )
    ctx_match = {"satisfied_conditions": ["pre-auth", "remote"]}
    ctx_miss  = {"satisfied_conditions": ["pre-auth"]}
    assert e.is_traversable(ctx_match)
    assert not e.is_traversable(ctx_miss)
    e.update_confidence(traversal_succeeded=True)
    assert e.confidence > 0.7
    print("[PASS] Edge schema OK")

def test_nvd_fetch():
    from graph.ingestion.nvd import fetch_cves, cve_to_node
    raw = fetch_cves(keyword="heap overflow", limit=1)
    assert len(raw) >= 1
    node = cve_to_node(raw[0])
    assert node.node_id.startswith("CVE-")
    assert node.grain_confidence == 0.2
    assert len(node.open_questions) > 0
    print(f"[PASS] NVD fetch OK — got {node.node_id}")

def test_nvd_ingest():
    from graph.ingestion.nvd import ingest_cves
    from neo4j import GraphDatabase
    nodes = ingest_cves(keyword="buffer overflow", limit=2)
    assert len(nodes) == 2
    driver = GraphDatabase.driver(
        os.getenv("NEO4J_URI"), auth=(os.getenv("NEO4J_USER"), os.getenv("NEO4J_PASSWORD"))
    )
    with driver.session() as session:
        result = session.run("MATCH (n:Node) RETURN count(n) AS cnt")
        cnt = result.single()["cnt"]
        assert cnt >= 2
    driver.close()
    print(f"[PASS] NVD ingest OK — {len(nodes)} nodes in Neo4j")


if __name__ == "__main__":
    print("=" * 50)
    print("ARGUS Layer 1 — Smoke Test")
    print("=" * 50)
    tests = [
        test_neo4j_connection,
        test_ollama_connection,
        test_qwen3_thinking,
        test_node_schema,
        test_edge_schema,
        test_nvd_fetch,
        test_nvd_ingest,
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
        print("Layer 1 complete. Start Layer 2: graph/retrieval.py")
    else:
        print("Fix failures above before proceeding.")
    print("=" * 50)
