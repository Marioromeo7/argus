"""
ARGUS Layer 1 — NVD Ingestion
==============================
Fetches CVEs from the NVD API and writes them as Socratic Nodes
to Neo4j. Each CVE becomes a node with grain_confidence=0.2 and
a seed open_question to kick off the challenger loop.
"""

import os
import uuid
import requests
from datetime import datetime
from dotenv import load_dotenv
from neo4j import GraphDatabase
from graph.schema import Node, NodeSource

load_dotenv()

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NEO4J_URI    = os.getenv("NEO4J_URI", "bolt://localhost:7400")
NEO4J_USER   = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS   = os.getenv("NEO4J_PASSWORD", "argus1234")
NVD_API_KEY  = os.getenv("NVD_API_KEY", "")


def fetch_cves(keyword: str = None, cve_id: str = None, limit: int = 10) -> list[dict]:
    """
    ARGUS-LAYER-1: Fetch CVEs from NVD API.
    Pass keyword for keyword search, or cve_id for a specific CVE.
    """
    params = {"resultsPerPage": limit, "startIndex": 0}
    if keyword:
        params["keywordSearch"] = keyword
    if cve_id:
        params["cveId"] = cve_id

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    resp = requests.get(NVD_BASE_URL, params=params, headers=headers, timeout=15)
    resp.raise_for_status()
    return resp.json().get("vulnerabilities", [])


def cve_to_node(raw: dict) -> Node:
    """
    ARGUS-LAYER-1: Convert raw NVD CVE dict to ARGUS Node.
    Sets grain_confidence low (0.2) because CVE descriptions
    are often too broad — challenger will refine them.
    """
    cve = raw.get("cve", {})
    cve_id = cve.get("id", str(uuid.uuid4()))

    # Extract description
    descriptions = cve.get("descriptions", [])
    description  = next((d["value"] for d in descriptions if d["lang"] == "en"), "")

    # Extract CVSS score if available
    metrics = cve.get("metrics", {})
    cvss_score = None
    if "cvssMetricV31" in metrics:
        cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
    elif "cvssMetricV30" in metrics:
        cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
    elif "cvssMetricV2" in metrics:
        cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

    # Extract affected software
    affected = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if match.get("vulnerable"):
                    affected.append(match.get("criteria", ""))

    # Seed open question — challenger will refine this
    seed_question = (
        f"What specific type of vulnerability is {cve_id}? "
        f"Is it memory corruption, injection, authentication bypass, or other?"
    )

    return Node(
        node_id=cve_id,
        label=cve_id,
        node_type="vulnerability",
        properties={
            "description":   description,
            "cvss_score":    cvss_score,
            "affected":      affected[:10],  # cap at 10 for storage
            "published":     cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
        },
        grain_confidence=0.2,   # low — needs challenger refinement
        open_questions=[seed_question],
        source=NodeSource.NVD,
    )


def write_node_to_neo4j(driver, node: Node) -> None:
    """ARGUS-LAYER-1: Upsert a Node into Neo4j."""
    cypher = """
    MERGE (n:Node {node_id: $node_id})
    SET n += $props
    SET n:Vulnerability
    """
    props = node.to_neo4j()
    with driver.session() as session:
        session.run(cypher, node_id=node.node_id, props=props)


def ingest_cves(keyword: str = None, cve_id: str = None, limit: int = 10) -> list[Node]:
    """
    ARGUS-LAYER-1: Full pipeline — fetch from NVD, convert, write to Neo4j.
    Returns list of Node objects that were written.
    """
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    raw_cves = fetch_cves(keyword=keyword, cve_id=cve_id, limit=limit)

    nodes = []
    for raw in raw_cves:
        node = cve_to_node(raw)
        write_node_to_neo4j(driver, node)
        nodes.append(node)
        print(f"  [+] Ingested {node.node_id} (grain={node.grain_confidence})")

    driver.close()
    print(f"\n[ARGUS] Ingested {len(nodes)} CVE nodes into Neo4j.")
    return nodes


if __name__ == "__main__":
    # Quick smoke test: ingest 3 recent memory corruption CVEs
    print("[ARGUS] Running NVD ingestion smoke test...")
    nodes = ingest_cves(keyword="heap overflow", limit=3)
    for n in nodes:
        print(f"  Node: {n.node_id} | grain={n.grain_confidence} | q={n.open_questions[0][:60]}...")
