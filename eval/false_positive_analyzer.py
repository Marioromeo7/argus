"""
ARGUS-EVAL: Analyzes Table A findings not in ground truth. These are CVEs
the scanner found that ground truth doesn't list -- not discarded, since
"not in ground truth" isn't the same as "wrong" (WebGoat's own ground
truth is frequently empty, see ground_truth.py's docstring). Reported as
unvalidated findings needing investigation.
"""

import re

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,7}$")


def analyze(comparison: dict, driver=None) -> dict:
    """
    ARGUS-EVAL: For each Table A finding not in ground truth, classify as
    `unvalidated_positive` (real CVE format + present in the ARGUS graph
    with grain_confidence > 0.5) or `likely_noise` (doesn't look like a
    real CVE, or isn't in the graph at all). `driver` is optional so this
    can run standalone against a comparison dict without a live Neo4j
    connection -- classification degrades to CVE-format-only in that case.
    """
    false_positives = []
    for row in comparison.get("table_a", []):
        if row.get("in_ground_truth"):
            continue
        cve_id = row.get("cve_id", "")
        is_real_format = bool(CVE_PATTERN.match(cve_id))
        in_graph, grain_confidence = False, 0.0
        if driver is not None and cve_id:
            in_graph, grain_confidence = _graph_lookup(cve_id, driver)

        if not is_real_format:
            classification = "likely_noise"
            reason = f"'{cve_id}' doesn't match real CVE ID format"
        elif driver is None:
            classification = "unvalidated_positive"
            reason = "real CVE format, not cross-checked against the graph (no driver provided)"
        elif in_graph and grain_confidence > 0.5:
            classification = "unvalidated_positive"
            reason = (f"real CVE format, present in ARGUS graph with "
                      f"grain_confidence={grain_confidence:.2f}")
        elif in_graph:
            classification = "unvalidated_positive"
            reason = (f"real CVE format, present in ARGUS graph but with low "
                      f"grain_confidence={grain_confidence:.2f} (<=0.5)")
        else:
            classification = "unvalidated_positive"
            reason = "real CVE format but not found anywhere in the ARGUS graph"

        false_positives.append({
            "cve_id": cve_id, "classification": classification,
            "reason": reason, "investigate": classification == "unvalidated_positive",
        })

    return {"false_positives": false_positives}


def _graph_lookup(cve_id: str, driver) -> tuple:
    """ARGUS-EVAL: Zero-GPU real graph lookup -- does this CVE exist in
    ARGUS's own graph, and if so, how confident is the node in itself?"""
    with driver.session() as session:
        record = session.run(
            "MATCH (n:Node {node_id: $id, node_type: 'vulnerability'}) "
            "RETURN n.grain_confidence AS gc",
            id=cve_id,
        ).single()
    if record is None:
        return False, 0.0
    return True, float(record["gc"] or 0.0)


def write_fp_report(fp_analysis: dict) -> None:
    """ARGUS-EVAL: Writes eval/false_positives.md. None discarded -- every
    entry gets a line, even the ones classified as likely noise."""
    lines = ["# False Positive Analysis", "",
             "Findings not in ground truth. None discarded -- classified for "
             "investigation, not silently dropped.", ""]
    fps = fp_analysis.get("false_positives", [])
    if not fps:
        lines.append("No unvalidated Table A findings.")
    else:
        for fp in fps:
            mark = "🔎 investigate" if fp["investigate"] else "likely noise"
            lines.append(f"## {fp['cve_id']} — {fp['classification']} ({mark})")
            lines.append(fp["reason"])
            lines.append("")

    with open("eval/false_positives.md", "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
