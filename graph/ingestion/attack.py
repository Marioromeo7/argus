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
            "description": getattr(tactic, "description", ""),
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
            "description":     getattr(technique, "description", ""),
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


def group_to_node(group) -> Node:
    """ARGUS-LAYER-1: Convert STIX intrusion-set to ARGUS Node."""
    gid = _attack_id(group) or str(group.id)[:16]
    return Node(
        node_id=gid,
        label=group.name,
        node_type="group",
        properties={
            "name":        group.name,
            "aliases":     getattr(group, "aliases", []),
            "description": getattr(group, "description", ""),
        },
        grain_confidence=0.5,
        open_questions=[],
        source=NodeSource.ATTACK,
    )


def software_to_node(software) -> Node:
    """ARGUS-LAYER-1: Convert STIX malware/tool to ARGUS Node."""
    sid = _attack_id(software) or str(software.id)[:16]
    return Node(
        node_id=sid,
        label=software.name,
        node_type="software",
        properties={
            "name":            software.name,
            "software_type":   getattr(software, "type", ""),  # "malware" | "tool"
            "platforms":       getattr(software, "x_mitre_platforms", []),
            "description":     getattr(software, "description", ""),
        },
        grain_confidence=0.5,
        open_questions=[],
        source=NodeSource.ATTACK,
    )


def mitigation_to_node(mitigation) -> Node:
    """ARGUS-LAYER-1: Convert STIX course-of-action to ARGUS Node."""
    mid = _attack_id(mitigation) or str(mitigation.id)[:16]
    return Node(
        node_id=mid,
        label=mitigation.name,
        node_type="mitigation",
        properties={
            "name":        mitigation.name,
            "description": getattr(mitigation, "description", ""),
        },
        grain_confidence=0.5,
        open_questions=[],
        source=NodeSource.ATTACK,
    )


def datacomponent_to_node(dc) -> Node:
    """ARGUS-LAYER-1: Convert STIX x-mitre-data-component to ARGUS Node.
    Kept as reference content (still real ATT&CK taxonomy, 109 objects in the
    bundle) but NOT wired to techniques via a "detects" edge — see
    detection_strategy_to_node()'s docstring for why: this bundle's actual
    technique-level detection coverage lives on x-mitre-detection-strategy
    objects now, and no direct data-component-detects-technique relationship
    exists in the raw STIX data to wire honestly."""
    did = _attack_id(dc) or str(dc.id)[:16]
    return Node(
        node_id=did,
        label=dc.name,
        node_type="detection_component",
        properties={
            "name":        dc.name,
            "description": getattr(dc, "description", ""),
        },
        grain_confidence=0.5,
        open_questions=[],
        source=NodeSource.ATTACK,
    )


def detection_strategy_to_node(obj: dict, attack: MitreAttackData) -> Node:
    """ARGUS-LAYER-1: Convert STIX x-mitre-detection-strategy to ARGUS Node.

    MITRE ATT&CK moved detection coverage onto x-mitre-detection-strategy
    objects (699 in this bundle) that "detect" techniques directly — this
    supersedes the older data-component-detects-technique model the
    `mitreattack` library's own get_datacomponents_detecting_technique()
    convenience method still assumes. Confirmed by inspecting the raw STIX
    bundle directly: 697 real "detects" relationships exist, all with
    source type x-mitre-detection-strategy, zero with source type
    x-mitre-data-component — the library method wasn't wrong about there
    being no data, it was checking the wrong (now-legacy) object type for
    this schema version. get_related() reaches the real relationships."""
    did = attack.get_attack_id(obj["id"]) or str(obj["id"])[:24]
    return Node(
        node_id=did,
        label=obj.get("name", did),
        node_type="detection_strategy",
        properties={
            "name":        obj.get("name", ""),
            "description": obj.get("description") or "",
        },
        grain_confidence=0.5,
        open_questions=[],
        source=NodeSource.ATTACK,
    )


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


def _ingest_groups(driver, attack: MitreAttackData) -> dict:
    """ARGUS-LAYER-1: Write all non-revoked/deprecated groups; return {stix_id: node_id} map."""
    gmap = {}
    for g in attack.get_groups(remove_revoked_deprecated=True):
        node = group_to_node(g)
        _write_node(driver, node, "Group")
        gmap[g.id] = node.node_id
    print(f"  [+] Ingested {len(gmap)} groups")
    return gmap


def _ingest_software(driver, attack: MitreAttackData) -> dict:
    """ARGUS-LAYER-1: Write all non-revoked/deprecated software; return {stix_id: node_id} map."""
    smap = {}
    for s in attack.get_software(remove_revoked_deprecated=True):
        node = software_to_node(s)
        _write_node(driver, node, "Software")
        smap[s.id] = node.node_id
    print(f"  [+] Ingested {len(smap)} software")
    return smap


def _ingest_mitigations(driver, attack: MitreAttackData) -> dict:
    """ARGUS-LAYER-1: Write all non-revoked/deprecated mitigations; return {stix_id: node_id} map."""
    mmap = {}
    for m in attack.get_mitigations(remove_revoked_deprecated=True):
        node = mitigation_to_node(m)
        _write_node(driver, node, "Mitigation")
        mmap[m.id] = node.node_id
    print(f"  [+] Ingested {len(mmap)} mitigations")
    return mmap


def _ingest_datacomponents(driver, attack: MitreAttackData) -> dict:
    """ARGUS-LAYER-1: Write all non-revoked/deprecated detection data components;
    return {stix_id: node_id} map."""
    dmap = {}
    for d in attack.get_datacomponents(remove_revoked_deprecated=True):
        node = datacomponent_to_node(d)
        _write_node(driver, node, "DetectionComponent")
        dmap[d.id] = node.node_id
    print(f"  [+] Ingested {len(dmap)} detection components")
    return dmap


def _write_relationship_edge(driver, source_id: str, target_id: str,
                              relation_type: str, relationships: list) -> None:
    """ARGUS-LAYER-1: One edge per (source, target, relation_type). Each real
    STIX relationship's own description — a specific documented procedure
    example with citations, e.g. "Gamaredon Group has used VNC tools,
    including UltraVNC..." — becomes a context_conditions entry, not a flat
    "uses" label with nothing behind it. Per CLAUDE.md: the structure IS the
    contribution, so the evidence goes on the edge, not just its existence."""
    conditions = [r.description for r in relationships if getattr(r, "description", "")]
    edge = Edge(
        edge_id=f"{source_id}_{relation_type}_{target_id}",
        source_id=source_id,
        target_id=target_id,
        relation_type=relation_type,
        context_conditions=conditions,
        confidence=0.8,
        source=NodeSource.ATTACK,
    )
    _write_edge(driver, edge)


def _ingest_technique_relationships(driver, attack: MitreAttackData, techniques: list,
                                     group_map: dict, software_map: dict,
                                     mitigation_map: dict) -> dict:
    """ARGUS-LAYER-1: For every technique, write uses/mitigates edges from the
    groups/software/mitigations that reference it in the STIX bundle. This is
    real-world procedure and coverage data that already exists in the
    downloaded bundle but was previously never written (see BACKLOG.md).
    Detection coverage ("detects") is handled separately by
    _ingest_detection_strategies() — see that function's docstring for why
    it isn't a per-technique lookup like the other three."""
    counts = {"uses_group": 0, "uses_software": 0, "mitigates": 0}
    for tech in techniques:
        tid = _attack_id(tech)
        if not tid:
            continue
        for item in attack.get_groups_using_technique(tech.id):
            gid = group_map.get(item["object"].id)
            if gid:
                _write_relationship_edge(driver, gid, tid, "uses", item["relationships"])
                counts["uses_group"] += 1
        for item in attack.get_software_using_technique(tech.id):
            sid = software_map.get(item["object"].id)
            if sid:
                _write_relationship_edge(driver, sid, tid, "uses", item["relationships"])
                counts["uses_software"] += 1
        for item in attack.get_mitigations_mitigating_technique(tech.id):
            mid = mitigation_map.get(item["object"].id)
            if mid:
                _write_relationship_edge(driver, mid, tid, "mitigates", item["relationships"])
                counts["mitigates"] += 1
    print(f"  [+] Ingested relationship edges: {counts}")
    return counts


def _ingest_detection_strategies(driver, attack: MitreAttackData) -> dict:
    """ARGUS-LAYER-1: Write detection-strategy nodes and their real
    detects-technique edges, using get_related() directly instead of the
    library's stale get_datacomponents_detecting_technique() convenience
    method — see detection_strategy_to_node()'s docstring for the schema
    mismatch this works around. get_related() is keyed by source (strategy),
    not by technique, so this doesn't fit the per-technique loop the other
    three relationship types use."""
    strategy_map = attack.get_related("x-mitre-detection-strategy", "detects", "attack-pattern")
    node_count, edge_count = 0, 0
    for strategy_stix_id, detected in strategy_map.items():
        obj = attack.get_object_by_stix_id(strategy_stix_id)
        if obj is None:
            continue
        node = detection_strategy_to_node(obj, attack)
        _write_node(driver, node, "DetectionStrategy")
        node_count += 1
        for item in detected:
            tid = _attack_id(item["object"])
            if tid:
                _write_relationship_edge(driver, node.node_id, tid, "detects", item["relationships"])
                edge_count += 1
    print(f"  [+] Ingested {node_count} detection strategies, {edge_count} detects edges")
    return {"detection_strategies": node_count, "detects": edge_count}


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

        group_map      = _ingest_groups(driver, attack)
        software_map   = _ingest_software(driver, attack)
        mitigation_map = _ingest_mitigations(driver, attack)
        _ingest_datacomponents(driver, attack)
        _ingest_detection_strategies(driver, attack)

        techniques_raw = attack.get_techniques(remove_revoked_deprecated=True)
        if limit:
            techniques_raw = techniques_raw[:limit]
        _ingest_technique_relationships(driver, attack, techniques_raw,
                                         group_map, software_map, mitigation_map)
    finally:
        driver.close()
    print(f"[ARGUS] ATT&CK ingestion complete.")
    return technique_nodes, tactic_map


if __name__ == "__main__":
    print("[ARGUS] Running ATT&CK ingestion (limit=20 for smoke test)...")
    nodes, tmap = ingest_attack(limit=20)
    print(f"  Tactics:    {len(tmap)}")
    print(f"  Techniques: {len(nodes)}")
