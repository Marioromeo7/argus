"""
ARGUS Dashboard API
===================
Read-only FastAPI backend. Queries Neo4j and serves the React build.
The system (agents, crawler, challenger) writes to Neo4j; this only reads.
"""

import ast
import os
from datetime import datetime

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from neo4j import GraphDatabase

NEO4J_URI  = os.getenv("NEO4J_URI",      "bolt://host.docker.internal:7400")
NEO4J_USER = os.getenv("NEO4J_USER",     "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASSWORD", "argus1234")

app = FastAPI(title="ARGUS Dashboard API", docs_url="/api/docs")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)


def _driver():
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))


@app.get("/api/health")
def health():
    try:
        d = _driver()
        d.verify_connectivity()
        d.close()
        return {"status": "ok", "neo4j": "connected"}
    except Exception as e:
        return {"status": "error", "neo4j": str(e)}


@app.get("/api/graph")
def graph():
    """
    Returns all nodes and edges for the force graph.
    Nodes capped at 800, edges at 2000.
    """
    d = _driver()
    try:
        with d.session() as s:
            nodes_raw = list(s.run(
                "MATCH (n:Node) "
                "RETURN n.node_id AS id, n.node_type AS type, "
                "       n.label AS label, n.grain_confidence AS grain, "
                "       n.last_updated AS updated "
                "ORDER BY n.last_updated DESC LIMIT 800"
            ))
            edges_raw = list(s.run(
                "MATCH (a:Node)-[r:RELATION]->(b:Node) "
                "RETURN a.node_id AS source, b.node_id AS target, "
                "       r.relation_type AS relation, r.confidence AS confidence "
                "LIMIT 2000"
            ))
            counts_raw = list(s.run(
                "MATCH (n:Node) "
                "RETURN n.node_type AS type, count(*) AS cnt "
                "ORDER BY cnt DESC"
            ))
            edge_total = s.run(
                "MATCH ()-[r:RELATION]->() RETURN count(r) AS c"
            ).single()
    finally:
        d.close()

    node_ids = {r["id"] for r in nodes_raw if r["id"]}

    return {
        "nodes": [
            {
                "id":      r["id"],
                "type":    r["type"]  or "unknown",
                "label":   r["label"] or r["id"],
                "grain":   float(r["grain"]) if r["grain"] is not None else 0.0,
                "updated": r["updated"],
            }
            for r in nodes_raw if r["id"]
        ],
        "edges": [
            {
                "source":     r["source"],
                "target":     r["target"],
                "relation":   r["relation"]    or "",
                "confidence": float(r["confidence"]) if r["confidence"] is not None else 0.5,
            }
            for r in edges_raw
            if r["source"] in node_ids and r["target"] in node_ids
        ],
        "type_counts":  {r["type"]: r["cnt"] for r in counts_raw if r["type"]},
        "total_nodes":  len(node_ids),
        "total_edges":  edge_total["c"] if edge_total else 0,
        "fetched_at":   datetime.utcnow().isoformat() + "Z",
    }


@app.get("/api/node/{node_id:path}")
def node_detail(node_id: str):
    """Full node detail including properties, open_questions, challenger_log."""
    d = _driver()
    try:
        with d.session() as s:
            row = s.run(
                "MATCH (n:Node {node_id: $id}) RETURN n", id=node_id
            ).single()
            if not row:
                raise HTTPException(status_code=404, detail="node not found")
            node = dict(row["n"])

            neighbors_raw = list(s.run(
                "MATCH (n:Node {node_id: $id})-[r:RELATION]-(m:Node) "
                "RETURN m.node_id AS nid, m.node_type AS type, "
                "       r.relation_type AS rel, r.confidence AS conf "
                "LIMIT 20",
                id=node_id,
            ))
    finally:
        d.close()

    props = node.get("properties", {})
    if isinstance(props, str):
        try:
            props = ast.literal_eval(props)
        except Exception:
            props = {"raw": props}

    open_q = node.get("open_questions", [])
    if isinstance(open_q, str):
        try:
            open_q = ast.literal_eval(open_q)
        except Exception:
            open_q = [open_q]

    challenger = node.get("challenger_log", "[]")
    if isinstance(challenger, str):
        try:
            import json
            challenger = json.loads(challenger)
        except Exception:
            challenger = []

    return {
        "node_id":          node.get("node_id"),
        "label":            node.get("label"),
        "node_type":        node.get("node_type"),
        "grain_confidence": node.get("grain_confidence"),
        "source":           node.get("source"),
        "last_updated":     node.get("last_updated"),
        "properties":       props,
        "open_questions":   open_q,
        "challenger_log":   challenger,
        "neighbors": [
            {"id": r["nid"], "type": r["type"], "relation": r["rel"], "confidence": r["conf"]}
            for r in neighbors_raw
        ],
    }


# Serve React build — must be registered last so /api/* routes take precedence
_UI_DIR = os.path.join(os.path.dirname(__file__), "..", "ui", "dist")
if os.path.isdir(_UI_DIR):
    app.mount("/", StaticFiles(directory=_UI_DIR, html=True), name="ui")
