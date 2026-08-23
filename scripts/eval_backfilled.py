"""
ARGUS Eval 1b — Retrieval Precision on Backfilled CVEs
Evaluate GraphRAG vs VectorRAG on the 12 CVEs we backfilled with manual CVE->Technique edges.
Uses cached ground truth (no NVD API calls needed).
"""

import json
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + '/..')

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import chromadb
import config  # noqa: F401 — must import before ollama to fix OLLAMA_HOST
import ollama
from dotenv import load_dotenv
from neo4j import GraphDatabase

load_dotenv()

# Ground truth: CVE->Technique mappings from backfill_simple.py
CVE_GT = {
    'CVE-2001-1472': {'T1190'},
    'CVE-2001-1402': {'T1059', 'T1190'},
    'CVE-2001-1379': {'T1190'},
    'CVE-1999-0023': {'T1055'},
    'CVE-2006-6308': {'T1068'},
    'CVE-1999-0085': {'T1055', 'T1059'},
    'CVE-2002-0645': {'T1190'},
    'CVE-2000-1205': {'T1059'},
    'CVE-2007-6645': {'T1068'},
    'CVE-2001-1460': {'T1190'},
    'CVE-2000-0746': {'T1059'},
    'CVE-2008-0415': {'T1059', 'T1068'},
}

def _embed(text: str) -> list[float]:
    """Embed text using nomic-embed-text."""
    resp = ollama.embeddings(
        model="nomic-embed-text",
        prompt=text[:512],
        options={"num_gpu": 0},
    )
    return resp["embedding"]

def build_chroma_index(driver) -> chromadb.Collection:
    """Embed all vulnerability/technique/tactic nodes into ChromaDB."""
    client = chromadb.Client()
    try:
        client.delete_collection("argus_eval_backfilled")
    except Exception:
        pass
    col = client.create_collection("argus_eval_backfilled")

    with driver.session() as session:
        rows = list(session.run(
            "MATCH (n:Node) WHERE n.node_type IN ['vulnerability','technique','tactic'] "
            "RETURN n LIMIT 500"
        ))

    ids, docs, metas, embeddings = [], [], [], []
    for r in rows:
        node = dict(r["n"])
        nid  = node.get("node_id", "")
        text = (f"{node.get('label', nid)} {node.get('node_type', '')} "
                f"{str(node.get('properties', ''))}")
        ids.append(nid)
        docs.append(text[:512])
        metas.append({"node_type": node.get("node_type", "unknown")})
        embeddings.append(_embed(text[:512]))

    if ids:
        col.add(ids=ids, documents=docs, metadatas=metas, embeddings=embeddings)
    return col

def retrieve_graphrag(driver, cve_id, k=10):
    """GraphRAG: Cypher edge traversal."""
    with driver.session() as session:
        result = session.run("""
            MATCH (v:Node {node_id: $cve})-[:RELATION*1..2]->(n:Node)
            WHERE n.node_type IN ['technique', 'tactic']
            RETURN DISTINCT n.node_id AS nid
            LIMIT $k
        """, cve=cve_id, k=k)
        return [r['nid'] for r in result]

def retrieve_vector(col, driver, cve_id: str, k: int = 10):
    """VectorRAG: embed CVE, return top-K from ChromaDB."""
    from graph.retrieval import get_node
    node = get_node(driver, cve_id)
    if not node:
        return []
    text = (f"{node.get('label', cve_id)} {node.get('node_type', '')} "
            f"{str(node.get('properties', ''))}")
    emb     = _embed(text[:512])
    n_query = min(k, max(1, col.count() - 1))
    results = col.query(query_embeddings=[emb], n_results=n_query)
    ids     = results["ids"][0] if results["ids"] else []
    return [i for i in ids if i != cve_id]

def precision_at_k(retrieved, ground_truth, k=10):
    """Precision @ k."""
    retrieved = retrieved[:k]
    if not retrieved:
        return 0.0
    matches = sum(1 for r in retrieved if r in ground_truth)
    return matches / len(retrieved)

print("="*60)
print("ARGUS Eval 1b — Retrieval Precision (Backfilled CVEs)")
print("="*60)
print(f"CVEs: {len(CVE_GT)}")
print()

driver = GraphDatabase.driver(os.getenv("NEO4J_URI", "bolt://localhost:7400"),
                              auth=(os.getenv("NEO4J_USER", "neo4j"),
                                    os.getenv("NEO4J_PASSWORD", "argus1234")))

# Build ChromaDB index
print("Building ChromaDB index...")
col = build_chroma_index(driver)
print(f"  Indexed: {col.count()} nodes")
print()

results = {
    "graphrag_precision": 0.0,
    "vector_precision": 0.0,
    "evaluable_cves": 0,
    "per_cve": []
}

for cve_id, gt in CVE_GT.items():
    # GraphRAG
    graphrag_ret = retrieve_graphrag(driver, cve_id, k=10)
    graphrag_p = precision_at_k(graphrag_ret, gt, k=10)

    # VectorRAG
    vector_ret = retrieve_vector(col, driver, cve_id, k=10)
    vector_p = precision_at_k(vector_ret, gt, k=10)

    results["per_cve"].append({
        "cve_id": cve_id,
        "gt": list(gt),
        "graphrag_retrieved": graphrag_ret,
        "graphrag_precision": graphrag_p,
        "vector_retrieved": vector_ret,
        "vector_precision": vector_p,
    })

    results["graphrag_precision"] += graphrag_p
    results["vector_precision"] += vector_p
    results["evaluable_cves"] += 1

    print(f"{cve_id}:")
    print(f"  GT: {gt}")
    print(f"  GraphRAG P@10={graphrag_p:.3f} retrieved={graphrag_ret[:3]}...")
    print(f"  VectorRAG P@10={vector_p:.3f} retrieved={vector_ret[:3]}...")
    print()

results["graphrag_precision"] /= max(1, results["evaluable_cves"])
results["vector_precision"] /= max(1, results["evaluable_cves"])

print("="*60)
print(f"GraphRAG Mean P@10: {results['graphrag_precision']:.4f}")
print(f"VectorRAG Mean P@10: {results['vector_precision']:.4f}")
print(f"Delta: +{results['graphrag_precision'] - results['vector_precision']:.4f}")
print(f"Evaluable CVEs: {results['evaluable_cves']}/12")
print("="*60)

# Save results
with open('results/r2_1_backfilled.json', 'w') as f:
    json.dump(results, f, indent=2)
print("Results saved to results/r2_1_backfilled.json")

driver.close()
