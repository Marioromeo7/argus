"""
ARGUS Layer 1 — MITRE ATT&CK Ingestion
========================================
Downloads MITRE ATT&CK enterprise STIX data and writes
techniques and tactics as Socratic Nodes to Neo4j, with
enables/requires edges connecting them.
"""

import os
import uuid
import requests
from dotenv import load_dotenv
from neo4j import GraphDatabase
from mitreattack.stix20 import MitreAttackData
from graph.schema import Node, Edge, NodeSource

load_dotenv()

ATTACK_URL  = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
NEO4J_URI   = os.getenv("NEO4J_URI",      "bolt://localhost:7400")
NEO4J_USER  = os.getenv("NEO4J_USER",     "neo4j")
NEO4J_PASS  = os.getenv("NEO4J_PASSWORD", "argus1234")
STIX_CACHE  = os.path.join(os.path.dirname(__file__), "..", "..", "data", "enterprise_attack.json")


def _download_stix() -> str:
    """Download and cache the ATT&CK STIX bundle (~14 MB)."""
    os.makedirs(os.path.dirname(STIX_CACHE), exist_ok=True)
    if os.path.exists(STIX_CACHE):
        return STIX_CACHE
    print("[ARGUS] Downloading MITRE ATT&CK STIX (~14 MB)...")
    resp = requests.get(ATTACK_URL, timeout=60)
    resp.raise_for_status()
    with open(STIX_CACHE, "w", encoding="utf-8") as f:
        f.write(resp.text)
    return STIX_CACHE


def _attack_id(obj) -> str:
    """Extract ATT&CK ID (T1059, TA0001, …) from external_references."""
    for ref in getattr(obj, "external_references", []):
        src = getattr(ref, "source_name", None) or ref.get("source_name", "")
        eid = getattr(ref, "external_id",  None) or ref.get("external_id",  "")
        if src == "mitre-attack" and eid:
            return eid
    return ""


def tactic_to_node(tactic) -> Node:
    """ARGUS-LAYER-1: Convert STIX x-mitre-tactic to ARGUS Node."""
    tid = _attack_id(tactic) or getattr(tactic, "x_mitre_shortname", str(uuid.uuid4())[:8])
    return Node(
        node_id=tid,
        label=tid,
        node_type="tactic",
        properties={
            "name":      tactic.name,
            "shortname": getattr(tactic, "x_mitre_shortname", ""),
            "description": getattr(tactic, "description", "")[:500],
        },
        grain_confidence=0.85,
        open_questions=[],
        source=NodeSource.ATTACK,
    )


def technique_to_node(technique) -> Node:
    """ARGUS-LAYER-1: Convert STIX attack-pattern to ARGUS Node."""
    tid = _attack_id(technique) or str(technique.id)[:16]
    tactics = [p.phase_name for p in getattr(technique, "kill_chain_phases", [])]
    return Node(
        node_id=tid,
        label=tid,
        node_type="technique",
        properties={
            "name":            technique.name,
            "tactics":         tactics,
            "is_subtechnique": getattr(technique, "x_mitre_is_subtechnique", False),
            "platforms":       getattr(technique, "x_mitre_platforms", []),
            "description":     getattr(technique, "description", "")[:500],
        },
        grain_confidence=0.3,
        open_questions=[
            f"What are the precise preconditions for {tid} ({technique.name})?"
        ],
        source=NodeSource.ATTACK,
    )


def _write_node(driver, node: Node, extra_label: str) -> None:
    """ARGUS-LAYER-1: Upsert node with an extra Neo4j label."""
    cypher = f"""
    MERGE (n:Node {{node_id: $node_id}})
    SET n += $props
    SET n:{extra_label}
    """
    with driver.session() as session:
        session.run(cypher, node_id=node.node_id, props=node.to_neo4j())


def _write_edge(driver, edge: Edge) -> None:
    """ARGUS-LAYER-1: Upsert a RELATION edge between two nodes."""
    cypher = """
    MATCH (a:Node {node_id: $src}), (b:Node {node_id: $tgt})
    MERGE (a)-[r:RELATION {edge_id: $eid}]->(b)
    SET r += $props
    """
    with driver.session() as session:
        session.run(cypher, src=edge.source_id, tgt=edge.target_id,
                    eid=edge.edge_id, props=edge.to_neo4j())


def _ingest_tactics(driver, attack: MitreAttackData) -> dict:
    """ARGUS-LAYER-1: Write all tactics; return {shortname: node_id} map."""
    tmap = {}
    for tactic in attack.get_tactics():
        node = tactic_to_node(tactic)
        _write_node(driver, node, "Tactic")
        shortname = node.properties.get("shortname", "")
        if shortname:
            tmap[shortname] = node.node_id
    print(f"  [+] Ingested {len(tmap)} tactics")
    return tmap


def _ingest_techniques(driver, attack: MitreAttackData,
                       tactic_map: dict, limit: int = None) -> list[Node]:
    """ARGUS-LAYER-1: Write techniques and technique-enables-tactic edges."""
    techniques = attack.get_techniques(remove_revoked_deprecated=True)
    if limit:
        techniques = techniques[:limit]
    nodes = []
    for tech in techniques:
        node = technique_to_node(tech)
        _write_node(driver, node, "Technique")
        nodes.append(node)
        for phase in getattr(tech, "kill_chain_phases", []):
            tactic_id = tactic_map.get(phase.phase_name)
            if tactic_id:
                edge = Edge(
                    edge_id=f"{node.node_id}_enables_{tactic_id}",
                    source_id=node.node_id,
                    target_id=tactic_id,
                    relation_type="enables",
                    confidence=0.9,
                    context_conditions=[],
                )
                _write_edge(driver, edge)
    print(f"  [+] Ingested {len(nodes)} techniques with tactic edges")
    return nodes


def ingest_attack(limit: int = None) -> tuple[list[Node], dict]:
    """
    ARGUS-LAYER-1: Full ATT&CK pipeline — download STIX, convert, write to Neo4j.
    limit caps technique count (None = all ~700).
    Returns (technique_nodes, tactic_map).
    """
    stix_path = _download_stix()
    attack    = MitreAttackData(stix_path)
    driver    = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
    try:
        tactic_map      = _ingest_tactics(driver, attack)
        technique_nodes = _ingest_techniques(driver, attack, tactic_map, limit=limit)
    finally:
        driver.close()
    print(f"[ARGUS] ATT&CK ingestion complete.")
    return technique_nodes, tactic_map


if __name__ == "__main__":
    print("[ARGUS] Running ATT&CK ingestion (limit=20 for smoke test)...")
    nodes, tmap = ingest_attack(limit=20)
    print(f"  Tactics:    {len(tmap)}")
    print(f"  Techniques: {len(nodes)}")
