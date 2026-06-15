"""
ARGUS Layer 4 — Isekai Web Agent
===================================
Crawls NVD and ATT&CK for new data, extracts entities,
proposes graph updates, and passes every proposal through
the challenger before writing. Nothing enters the graph
without epistemic evaluation.

"Isekai" — the agent travels to the outside world and
brings back knowledge, transformed for the graph's schema.
"""

import json
import os
import requests as _http
from datetime import datetime
import ollama
from dotenv import load_dotenv
from neo4j import GraphDatabase
from graph.schema import Edge, NodeSource
from graph.retrieval import get_node
from graph.ingestion.nvd import fetch_cves, cve_to_node
from agents.challenger import assess_proposal

load_dotenv()

NEO4J_URI  = os.getenv("NEO4J_URI",      "bolt://localhost:7400")
NEO4J_USER = os.getenv("NEO4J_USER",     "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASSWORD", "argus1234")
MODEL      = "qwen3:8b"


# ── Serialization ─────────────────────────────────────────────────────────────

def _node_to_dict(node) -> dict:
    """Convert a Node object to a plain dict for the crawler/challenger pipeline."""
    return {
        "node_id":          node.node_id,
        "label":            node.label,
        "node_type":        node.node_type,
        "properties":       node.properties,
        "grain_confidence": node.grain_confidence,
        "open_questions":   node.open_questions,
        "challenger_log":   node.challenger_log,
        "source":           str(node.source),
    }


def _write_node(driver, node_dict: dict, label: str) -> None:
    """ARGUS-LAYER-4: Write a challenger-validated node dict to Neo4j."""
    props = {
        "node_id":          node_dict["node_id"],
        "label":            node_dict.get("label", node_dict["node_id"]),
        "node_type":        node_dict.get("node_type", "unknown"),
        "properties":       str(node_dict.get("properties", {})),
        "grain_confidence": float(node_dict.get("grain_confidence", 0.1)),
        "open_questions":   list(node_dict.get("open_questions") or []),
        "challenger_log":   json.dumps(node_dict.get("challenger_log", [])),
        "source":           str(node_dict.get("source", "web")),
        "last_updated":     datetime.utcnow().isoformat(),
        "created_at":       datetime.utcnow().isoformat(),
    }
    cypher = f"""
    MERGE (n:Node {{node_id: $node_id}})
    SET n += $props
    SET n:{label}
    """
    with driver.session() as session:
        session.run(cypher, node_id=node_dict["node_id"], props=props)


# ── Entity extraction ─────────────────────────────────────────────────────────

def _extract_entities(text: str) -> dict:
    """ARGUS-LAYER-4: Extract ATT&CK technique IDs and vuln type from text.
    Uses Ollama HTTP API with think=False to skip reasoning tokens (~44s vs ~265s)."""
    prompt = (
        f"Extract cybersecurity entities from this text.\n\n"
        f"Text: {text[:800]}\n\n"
        "Reply in EXACTLY this format:\n"
        "TECHNIQUES: <comma-separated ATT&CK IDs like T1059 or NONE>\n"
        "VULN_TYPE: <one category like heap_overflow, sql_injection, auth_bypass or NONE>"
    )
    try:
        r = _http.post(
            "http://localhost:11434/api/chat",
            json={
                "model": MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "think": False,
                "stream": False,
            },
            timeout=120,
        )
        r.raise_for_status()
        content = r.json().get("message", {}).get("content", "")
    except Exception:
        # Fallback to ollama library if HTTP call fails
        resp = ollama.chat(
            model=MODEL,
            messages=[{"role": "user", "content": f"/no_think\n\n{prompt}"}],
        )
        content = resp["message"]["content"]
    return _parse_entities(content)


def _parse_entities(text: str) -> dict:
    """Parse entity extraction response."""
    out = {"techniques": [], "vuln_type": ""}
    for line in text.splitlines():
        if line.startswith("TECHNIQUES:"):
            val = line.split(":", 1)[1].strip()
            if val.upper() != "NONE":
                out["techniques"] = [
                    t.strip() for t in val.split(",")
                    if t.strip() and t.strip().upper() != "NONE"
                ]
        elif line.startswith("VULN_TYPE:"):
            val = line.split(":", 1)[1].strip()
            if val.upper() != "NONE":
                out["vuln_type"] = val
    return out


# ── Edge writing ──────────────────────────────────────────────────────────────

def _resolve_technique_ids(driver, base_tid: str) -> list[str]:
    """
    ARGUS-LAYER-4: Resolve a base T-ID (T1059) to graph nodes.
    Returns exact match if present, otherwise expands to all matching
    sub-techniques (T1059.001, T1059.002 …) that exist in the graph.
    ATT&CK ingestion at low limits writes sub-techniques before base nodes,
    so this ensures entity-extracted base IDs still produce edges.
    """
    if get_node(driver, base_tid):
        return [base_tid]
    with driver.session() as session:
        rows = session.run(
            "MATCH (n:Node) WHERE n.node_id STARTS WITH $prefix "
            "AND n.node_type = 'technique' RETURN n.node_id AS nid LIMIT 10",
            prefix=base_tid + ".",
        )
        return [r["nid"] for r in rows]


def _write_technique_edges(driver, cve_id: str, technique_ids: list[str]) -> int:
    """ARGUS-LAYER-4: Write CVE-[enables]->technique edges for known techniques.
    Expands base T-IDs to sub-techniques when the base node is not in the graph."""
    written = 0
    for base_tid in technique_ids:
        for tid in _resolve_technique_ids(driver, base_tid):
            edge = Edge(
                edge_id=f"{cve_id}_enables_{tid}",
                source_id=cve_id,
                target_id=tid,
                relation_type="enables",
                confidence=0.6,
                context_conditions=[],
                source=NodeSource.WEB,
            )
            cypher = """
            MATCH (a:Node {node_id: $src}), (b:Node {node_id: $tgt})
            MERGE (a)-[r:RELATION {edge_id: $eid}]->(b)
            SET r += $props
            """
            with driver.session() as session:
                session.run(cypher, src=cve_id, tgt=tid,
                            eid=edge.edge_id, props=edge.to_neo4j())
            written += 1
    return written


# ── Main crawl pipelines ──────────────────────────────────────────────────────

def crawl_nvd(driver, keyword: str = "remote code execution",
              limit: int = 3) -> list[dict]:
    """
    ARGUS-LAYER-4: Fetch new CVEs from NVD, validate with challenger, write to graph.
    Skips CVEs already in graph. Returns list of written node dicts.
    """
    raw_cves = fetch_cves(keyword=keyword, limit=limit + 5)
    written  = []

    for raw in raw_cves:
        node = cve_to_node(raw)

        if get_node(driver, node.node_id):
            continue                          # already in graph

        node_dict = _node_to_dict(node)
        assessed  = assess_proposal(node_dict)   # challenger validates first
        _write_node(driver, assessed, "Vulnerability")
        print(f"  [+] {node.node_id} (grain {node.grain_confidence:.2f} -> {assessed['grain_confidence']:.2f})")

        desc       = node.properties.get("description", "")
        entities   = _extract_entities(desc) if desc else {}
        edge_count = _write_technique_edges(driver, node.node_id,
                                            entities.get("techniques", []))
        if edge_count:
            print(f"      {edge_count} technique edge(s) written")

        written.append(assessed)
        if len(written) >= limit:
            break

    print(f"[ARGUS] Crawler: {len(written)} new CVE nodes written.")
    return written


def crawl_attack_updates(driver, limit: int = 5) -> list[dict]:
    """
    ARGUS-LAYER-4: Check ATT&CK for techniques not yet in graph; validate and write.
    Returns list of newly written technique node dicts.
    """
    from graph.ingestion.attack import _download_stix, _attack_id, technique_to_node
    from mitreattack.stix20 import MitreAttackData

    stix_path = _download_stix()
    attack    = MitreAttackData(stix_path)
    written   = []

    for tech in attack.get_techniques(remove_revoked_deprecated=True):
        tid = _attack_id(tech)
        if not tid or get_node(driver, tid):
            continue

        node      = technique_to_node(tech)
        node_dict = _node_to_dict(node)
        assessed  = assess_proposal(node_dict)
        _write_node(driver, assessed, "Technique")
        print(f"  [+] {tid} (grain {node.grain_confidence:.2f} -> {assessed['grain_confidence']:.2f})")

        written.append(assessed)
        if len(written) >= limit:
            break

    print(f"[ARGUS] Crawler: {len(written)} new ATT&CK technique nodes written.")
    return written
