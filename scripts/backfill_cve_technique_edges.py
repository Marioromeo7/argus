"""
ARGUS Layer 1 — CVE→Technique Backfill
========================================
Maps existing CVEs to MITRE techniques using NVD CWE data.
CWE→MITRE mapping is hardcoded based on known relationships.
"""

import os
import sys
import requests
from neo4j import GraphDatabase
from dotenv import load_dotenv

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + '/..')

load_dotenv()

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7400")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASSWORD", "argus1234")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

# CWE → MITRE Technique mappings (common attack vectors)
CWE_TO_TECHNIQUES = {
    "CWE-79": ["T1059", "T1190"],  # XSS → Command Injection, Exploit
    "CWE-89": ["T1190"],            # SQL Injection → Exploit
    "CWE-20": ["T1190", "T1203"],   # Improper Input → Exploit, Abuse
    "CWE-78": ["T1059"],            # OS Command Injection → Command Execution
    "CWE-94": ["T1059"],            # Code Injection → Command Execution
    "CWE-190": ["T1190"],           # Integer Overflow → Exploit
    "CWE-200": ["T1005", "T1592"],  # Information Disclosure → Collection
    "CWE-434": ["T1204"],           # Unrestricted File Upload → User Execution
    "CWE-276": ["T1548"],           # Incorrect Default Permissions → Privilege Escalation
    "CWE-287": ["T1110"],           # Improper Authentication → Brute Force
    "CWE-295": ["T1557"],           # Improper Certificate Validation → Man-in-the-Middle
    "CWE-306": ["T1078"],           # Missing Authentication → Valid Accounts
    "CWE-307": ["T1110"],           # Improper Restriction of Input → Brute Force
    "CWE-330": ["T1005"],           # Use of Weak RNG → Information Gathering
    "CWE-338": ["T1005"],           # Use of Cryptographically Weak PRNG → Collection
    "CWE-352": ["T1566"],           # Cross-Site Request Forgery → Phishing
    "CWE-426": ["T1195"],           # Untrusted Search Path → Supply Chain
    "CWE-434": ["T1204"],           # Unrestricted Upload → User Execution
    "CWE-476": ["T1190"],           # NULL Pointer Dereference → Exploit
    "CWE-502": ["T1190"],           # Deserialization → Exploit
    "CWE-611": ["T1190"],           # XXE → Exploit
}

def fetch_cve_with_cwe(cve_id: str) -> dict:
    """Fetch CVE from NVD and extract CWEs."""
    params = {"cveId": cve_id, "resultsPerPage": 1}
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    try:
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params=params, headers=headers, timeout=15
        )
        resp.raise_for_status()
        vulns = resp.json().get("vulnerabilities", [])
        if not vulns:
            return {}

        cve = vulns[0].get("cve", {})
        cwes = []
        for weakness in cve.get("weaknesses", []):
            for desc in weakness.get("description", []):
                cwe_id = desc.get("value", "")
                if cwe_id and cwe_id not in cwes:
                    cwes.append(cwe_id)

        return {"cve_id": cve_id, "cwes": cwes}
    except Exception as e:
        print(f"    [!] Failed to fetch {cve_id}: {e}")
        return {}

def cwe_to_techniques(cwe_id: str) -> list[str]:
    """Map CWE to MITRE techniques."""
    # Extract numeric part
    cwe_num = cwe_id.split("-")[1] if "-" in cwe_id else cwe_id
    full_cwe = f"CWE-{cwe_num}"
    return CWE_TO_TECHNIQUES.get(full_cwe, [])

def backfill_cve_technique_edges(limit: int = 100) -> int:
    """Backfill all CVEs with CWE→Technique edges."""
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))

    # Get all CVEs from graph
    with driver.session() as session:
        result = session.run(
            "MATCH (n:Node {node_type: 'vulnerability'}) RETURN n.node_id as cve_id LIMIT $lim",
            lim=limit
        )
        cve_ids = [r["cve_id"] for r in result]

    print(f"[ARGUS] Backfilling {len(cve_ids)} CVEs with CWE->Technique mappings...")
    edges_written = 0

    for i, cve_id in enumerate(cve_ids):
        cve_data = fetch_cve_with_cwe(cve_id)
        if not cve_data or not cve_data.get("cwes"):
            continue

        techniques = set()
        for cwe in cve_data["cwes"]:
            techniques.update(cwe_to_techniques(cwe))

        if techniques:
            with driver.session() as session:
                for tech_id in techniques:
                    # Check if technique exists in graph
                    check = session.run(
                        "MATCH (n:Node {node_id: $tid}) RETURN COUNT(*) as cnt",
                        tid=tech_id
                    ).single()

                    if check["cnt"] > 0:
                        # Write edge
                        cypher = """
                        MATCH (c:Node {node_id: $cve}), (t:Node {node_id: $tech})
                        MERGE (c)-[r:RELATION {edge_id: $eid}]->(t)
                        SET r += $props
                        """
                        edge_id = f"{cve_id}_enables_{tech_id}"
                        props = {
                            "edge_id": edge_id,
                            "relation_type": "enables",
                            "confidence": 0.7,
                            "context_conditions": [],
                            "source": "cwe_mapping",
                            "directionality": "unidirectional",
                        }
                        try:
                            session.run(cypher, cve=cve_id, tech=tech_id, eid=edge_id, props=props)
                            edges_written += 1
                        except Exception as e:
                            print(f"    [!] Failed to write edge {cve_id}->{tech_id}: {e}")

        if (i + 1) % 10 == 0:
            print(f"  [{i+1}/{len(cve_ids)}] {edges_written} edges written")

    driver.close()
    print(f"\n[ARGUS] Backfill complete: {edges_written} CVE→Technique edges written")
    return edges_written

if __name__ == "__main__":
    backfill_cve_technique_edges(limit=100)
