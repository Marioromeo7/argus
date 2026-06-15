"""
ARGUS — NVD Corpus Expansion
==============================
Crawls NVD across 8 vulnerability type keywords to build a corpus
of 50+ CVEs with diverse technique links. Verifies at least 20
CVEs have edges to ATT&CK techniques before exiting.

Usage:
    conda activate argus
    python scripts/expand_nvd.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

KEYWORDS = [
    ("memory corruption",     8),
    ("buffer overflow",       8),
    ("use after free",        8),
    ("command injection",     8),
    ("privilege escalation",  8),
    ("authentication bypass", 6),
    ("SQL injection",         6),
    ("path traversal",        6),
]
TARGET_TOTAL   = 50
TARGET_LINKED  = 20


def run_expansion():
    from graph.retrieval import get_driver
    from agents.crawler import crawl_nvd

    driver      = get_driver()
    total_written = 0

    print(f"Expanding NVD corpus (target: {TARGET_TOTAL}+ CVEs)...\n")

    for keyword, limit in KEYWORDS:
        print(f"[{keyword}] fetching up to {limit} new CVEs...")
        try:
            written = crawl_nvd(driver, keyword=keyword, limit=limit)
            total_written += len(written)
            print(f"  -> {len(written)} new nodes written (running total: {total_written})")
        except Exception as e:
            print(f"  [WARN] {keyword}: {e}")

    # Count CVEs with technique links
    with driver.session() as session:
        rec = session.run(
            "MATCH (v:Node {node_type: 'vulnerability'})-[:RELATION]->"
            "(t:Node {node_type: 'technique'}) "
            "WITH v, count(t) AS tc RETURN count(v) AS linked_cves, sum(tc) AS total_edges"
        ).single()
        linked_cves  = rec["linked_cves"]  if rec else 0
        total_edges  = rec["total_edges"]  if rec else 0

    with driver.session() as session:
        rec = session.run(
            "MATCH (n:Node {node_type: 'vulnerability'}) RETURN count(n) AS cnt"
        ).single()
        total_cves = rec["cnt"] if rec else 0

    driver.close()

    print(f"\n{'='*55}")
    print(f"CORPUS SUMMARY")
    print(f"  Total CVE nodes in graph:    {total_cves}")
    print(f"  CVEs with technique links:   {linked_cves}")
    print(f"  Total technique edges:       {total_edges}")
    print(f"  New CVEs added this run:     {total_written}")

    if total_cves >= TARGET_TOTAL:
        print(f"  [OK] Total CVEs >= {TARGET_TOTAL}")
    else:
        print(f"  [WARN] Total CVEs {total_cves} < {TARGET_TOTAL} target")

    if linked_cves >= TARGET_LINKED:
        print(f"  [OK] CVEs with technique links >= {TARGET_LINKED}")
        print(f"\nCorpus ready for evaluation.")
    else:
        print(f"  [WARN] Only {linked_cves} CVEs have technique links — "
              f"need {TARGET_LINKED}.")
        print("  Try running again or add more keywords.")
    print(f"{'='*55}")


if __name__ == "__main__":
    print("=" * 55)
    print("ARGUS — NVD Corpus Expansion")
    print("(Hits NVD API + Qwen3 — expect ~15-30 min)")
    print("=" * 55)
    run_expansion()
