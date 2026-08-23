"""
ARGUS-EVAL: Builds two comparison tables + a Qwen plain-language summary.
Table A joins scanner findings to ground truth by exact CVE ID; Table B is
code-level findings with no ground truth equivalent to join against.
"""

import json
import re

import requests

from graphrange.telemetry import track, count_tokens, patch_last_tokens_out
from config import OLLAMA_CHAT_URL as OLLAMA_URL

QWEN_MODEL = "qwen3:8b"


def compare(findings: list, ground_truth: list) -> dict:
    """
    ARGUS-EVAL: Separates scanner findings into two buckets and measures
    coverage. `findings` is `run_scanner()`'s real output shape
    (`{"vuln_context", "red", "blue"}` per item).
    """
    gt_by_cve = {g["cve_id"]: g for g in ground_truth}
    found_cves = set()

    table_a, table_b = [], []
    for finding in findings:
        vc = finding["vuln_context"]
        cve_id = finding.get("red", {}).get("matched_cve_id", "")
        if cve_id:
            found_cves.add(cve_id)
            in_gt = cve_id in gt_by_cve
            table_a.append({
                "cve_id": cve_id, "found_by_scanner": True, "in_ground_truth": in_gt,
                "severity": vc.get("severity", ""),
            })
        else:
            table_b.append({
                "cwe": vc.get("cwe", ""), "file": vc.get("filepath", ""),
                "vuln_type": vc.get("vuln_type", ""), "severity": vc.get("severity", ""),
            })

    missed_cves = [g["cve_id"] for g in ground_truth if g["cve_id"] not in found_cves]
    coverage = (len(found_cves & gt_by_cve.keys()) / len(gt_by_cve)) if gt_by_cve else 0.0

    return {"table_a": table_a, "table_b": table_b,
            "missed_cves": missed_cves, "coverage": coverage}


def _summary_prompt(comparison: dict) -> str:
    return (
        "Given these vulnerability assessment results vs ground truth:\n"
        f"{json.dumps(comparison)}\n\n"
        "Write a 3-5 paragraph plain language summary:\n"
        "- What the scanner found overall\n"
        "- Where it agreed with ground truth\n"
        "- What the code-only findings (Table B) suggest\n"
        "- Notable gaps or patterns\n"
        "No headers. Just clear paragraphs a security team can read."
    )


def _qwen_summary(comparison: dict) -> str:
    """ARGUS-EVAL: The one Qwen call in this module. Not live-tested as of
    writing (2026-08-10) -- same checkpoint as the rest of this session's
    GPU-touching code."""
    prompt = _summary_prompt(comparison)
    tokens_in = count_tokens(prompt)
    with track("eval.comparator._qwen_summary", model="qwen",
               tokens_in=tokens_in, tokens_out=0):
        resp = requests.post(
            OLLAMA_URL,
            json={"model": QWEN_MODEL,
                  "messages": [{"role": "user", "content": f"/no_think\n\n{prompt}"}],
                  "stream": False},
            timeout=600,
        )
        resp.raise_for_status()
        raw = resp.json()["message"]["content"].strip()
    patch_last_tokens_out(count_tokens(raw))
    return re.sub(r"^```\s*|\s*```$", "", raw.strip())


# Column display name -> actual dict key. Kept explicit rather than
# auto-derived from the column string (e.g. "CVE".lower() -> "cve", but the
# real key is "cve_id") -- an auto-derivation silently rendered an empty
# CVE column, confirmed via a real test before this fix.
_COLUMN_KEY_MAP = {
    "CVE": "cve_id", "Found_by_scanner": "found_by_scanner",
    "In_ground_truth": "in_ground_truth", "Severity": "severity",
    "CWE": "cwe", "File": "file", "Vuln_type": "vuln_type",
}


def _md_table(rows: list, columns: list) -> list:
    if not rows:
        return ["(none)", ""]
    lines = ["| " + " | ".join(columns) + " |", "|" + "|".join(["---"] * len(columns)) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(
            str(row.get(_COLUMN_KEY_MAP.get(c, c), "")) for c in columns) + " |")
    lines.append("")
    return lines


def write_comparison_tables(comparison: dict) -> None:
    """ARGUS-EVAL: Writes eval/comparison.md with Table A, Table B, and a
    Qwen-generated plain-language summary appended after both."""
    lines = [
        "# Scanner vs Ground Truth Comparison", "",
        "> Table A matches are exact CVE ID joins.",
        "> Table B findings have no ground truth equivalent — they are code-level",
        "> findings the scanner produced independently.",
        "> Summary section is Qwen3 interpretation — review critically.", "",
        f"**Coverage:** {comparison['coverage']:.1%} of ground truth CVEs found", "",
        "## Table A — CVE-identified findings", "",
    ]
    lines.extend(_md_table(comparison["table_a"],
                            ["CVE", "Found_by_scanner", "In_ground_truth", "Severity"]))
    lines.append("## Table B — Code-level findings")
    lines.append("")
    lines.extend(_md_table(comparison["table_b"], ["CWE", "File", "Vuln_type", "Severity"]))

    if comparison["missed_cves"]:
        lines.append("## Missed CVEs")
        lines.append("")
        lines.extend(f"- {c}" for c in comparison["missed_cves"])
        lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(_qwen_summary(comparison))

    with open("eval/comparison.md", "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
