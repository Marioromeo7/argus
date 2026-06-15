"""
ARGUS Layer 2 — GraphRAG Retrieval
=====================================
Traverse the knowledge graph using Cypher — edges, not
semantic guessing. Every retrieval primitive is context-aware:
it filters edges by context_conditions and grain_confidence,
so multi-hop chains only propagate through edges that actually
hold in the current engagement context.
"""

import os
from neo4j import GraphDatabase
from dotenv import load_dotenv

load_dotenv()

NEO4J_URI  = os.getenv("NEO4J_URI",      "bolt://localhost:7400")
NEO4J_USER = os.getenv("NEO4J_USER",     "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASSWORD", "argus1234")


def get_driver():
    """Return a Neo4j driver using env config."""
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))


def get_node(driver, node_id: str) -> dict | None:
    """ARGUS-LAYER-2: Fetch a single node by ID."""
    with driver.session() as session:
        result = session.run(
            "MATCH (n:Node {node_id: $node_id}) RETURN n",
            node_id=node_id,
        )
        rec = result.single()
        return dict(rec["n"]) if rec else None


def get_nodes_by_type(driver, node_type: str, limit: int = 20) -> list[dict]:
    """ARGUS-LAYER-2: Return nodes matching a node_type (vulnerability, technique, tactic…)."""
    with driver.session() as session:
        result = session.run(
            "MATCH (n:Node) WHERE n.node_type = $t RETURN n LIMIT $lim",
            t=node_type, lim=limit,
        )
        return [dict(r["n"]) for r in result]


def get_neighbors(driver, node_id: str,
                  relation_types: list[str] | None = None,
                  context: dict | None = None) -> list[dict]:
    """
    ARGUS-LAYER-2: Return nodes directly reachable from node_id.
    relation_types filters by r.relation_type if provided.
    context filters edges whose context_conditions aren't satisfied.
    """
    if relation_types:
        cypher = (
            "MATCH (n:Node {node_id: $nid})-[r:RELATION]->(m:Node) "
            "WHERE r.relation_type IN $rtypes "
            "RETURN m, r.relation_type AS rel, r.context_conditions AS conds, r.confidence AS conf"
        )
        params = {"nid": node_id, "rtypes": relation_types}
    else:
        cypher = (
            "MATCH (n:Node {node_id: $nid})-[r:RELATION]->(m:Node) "
            "RETURN m, r.relation_type AS rel, r.context_conditions AS conds, r.confidence AS conf"
        )
        params = {"nid": node_id}

    satisfied = set((context or {}).get("satisfied_conditions", []))
    neighbors = []
    with driver.session() as session:
        for rec in session.run(cypher, **params):
            conds = rec["conds"] or []
            if conds and not all(c in satisfied for c in conds):
                continue
            neighbors.append({
                "node":          dict(rec["m"]),
                "relation_type": rec["rel"],
                "confidence":    rec["conf"],
            })
    return neighbors


def traverse_subgraph(driver, start_id: str,
                      depth: int = 2,
                      context: dict | None = None) -> dict:
    """
    ARGUS-LAYER-2: BFS from start_id up to `depth` hops.
    Returns {"nodes": [...], "edges": [...]}.
    Context-conditions are checked at every hop.
    """
    visited, queue = set(), [start_id]
    nodes, edges = {}, []

    start_node = get_node(driver, start_id)
    if start_node:
        nodes[start_id] = start_node

    for _ in range(depth):
        next_queue = []
        for nid in queue:
            if nid in visited:
                continue
            visited.add(nid)
            for nb in get_neighbors(driver, nid, context=context):
                tid = nb["node"].get("node_id")
                edges.append({
                    "source":        nid,
                    "target":        tid,
                    "relation_type": nb["relation_type"],
                    "confidence":    nb["confidence"],
                })
                if tid and tid not in visited:
                    nodes[tid] = nb["node"]
                    next_queue.append(tid)
        queue = next_queue

    return {"nodes": list(nodes.values()), "edges": edges}


def find_attack_paths(driver, source_id: str, target_id: str,
                      max_hops: int = 4) -> list[list[dict]]:
    """
    ARGUS-LAYER-2: Find all directed paths from source to target within max_hops.
    Used by the red agent to discover multi-step attack chains.
    """
    cypher = (
        "MATCH path = (a:Node {node_id: $src})-[:RELATION*1..$hops]->(b:Node {node_id: $tgt}) "
        "RETURN [n IN nodes(path) | n.node_id] AS nids, "
        "       [r IN relationships(path) | r.relation_type] AS rels"
    )
    paths = []
    with driver.session() as session:
        for rec in session.run(cypher, src=source_id, tgt=target_id, hops=max_hops):
            path = []
            for i, nid in enumerate(rec["nids"]):
                step = {"node_id": nid}
                if i < len(rec["rels"]):
                    step["via"] = rec["rels"][i]
                path.append(step)
            paths.append(path)
    return paths


def get_low_grain_nodes(driver, threshold: float = 0.4,
                        limit: int = 10) -> list[dict]:
    """
    ARGUS-LAYER-2: Return nodes below grain_confidence threshold.
    These are the primary targets for the challenger agent (Layer 3).
    """
    with driver.session() as session:
        result = session.run(
            "MATCH (n:Node) WHERE n.grain_confidence < $t "
            "RETURN n ORDER BY n.grain_confidence ASC LIMIT $lim",
            t=threshold, lim=limit,
        )
        return [dict(r["n"]) for r in result]
