"""
ARGUS-SCANNER: Writes the scanner product report.
Contains only: vulnerabilities found + mitigation advice. No ground truth,
no comparison, no false-positive analysis -- those are eval/ concerns.
Synthesizes the base MD/PDF/HTML spec with its later revisions (multi-
container kill chain table, per-service detection table, blocked-phase
visibility, dual execution/Qwen assessment columns) into one final report.
"""

import os
from datetime import datetime

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer, Table,
                                 TableStyle, PageBreak)

# Real ARGUS dashboard palette, from dashboard/ui/src/components/GraphView.jsx
# -- not guessed, so the report actually matches the product's own visual identity.
BG_COLOR = "#080814"
TYPE_COLOR = {
    "vulnerability": "#e05252",
    "technique": "#4f9cf9",
    "tactic": "#a78bfa",
    "engagement": "#f59e0b",
    "mitigation": "#34d399",
    "memory": "#22d3ee",
    "unknown": "#6b7280",
}


def _finding_header(vc: dict) -> str:
    return (f"[{vc.get('cwe', '?')}] — {vc.get('vuln_type', '?')} — "
            f"{vc.get('severity', '?')} — priority {vc.get('priority', '?')}")


def _kill_chain_rows(execution_result: dict) -> list:
    """ARGUS-SCANNER: One row per attack phase, blocked ones included --
    a blocked phase is real information (a tool coverage gap), not
    something to hide from the report."""
    rows = [["Phase", "Service", "Tool", "Status", "Result", "Evidence", "Qwen", "Conflict"]]
    for i, phase in enumerate(execution_result.get("phases", []), start=1):
        tool_label = phase.get("tool") or "—"
        if phase.get("status") == "substituted":
            tool_label = f"{tool_label} (substituted)"
        rows.append([
            str(i), phase.get("service", ""), tool_label,
            phase.get("status", ""), phase.get("result", ""),
            "yes" if phase.get("execution_evidence") else "no",
            "yes" if phase.get("qwen_signal") else "no",
            "yes ⚠" if phase.get("conflict") else "no",
        ])
    return rows


def _detection_rows(blue: dict, execution_result: dict) -> list:
    """ARGUS-SCANNER: One row per service red was active on, showing
    exactly where blue caught the attack and where it missed."""
    rows = [["Service", "Role", "Red Active", "Blue Detected", "Miss Type"]]
    detected = set(blue.get("phases_detected", []))
    missed = set(blue.get("phases_missed", []))
    role_by_service = {p.get("service"): p.get("service", "")
                        for p in execution_result.get("phases", [])}
    for service in role_by_service:
        was_detected = service in detected
        miss_type = "—"
        if not was_detected and service in missed:
            miss_type = ("missed lateral movement" if blue.get("missed_lateral")
                         else "missed entry")
        rows.append([service, role_by_service[service], "yes",
                     "yes" if was_detected else "no", miss_type])
    return rows


def _write_markdown(findings: list, path: str) -> None:
    lines = ["# ARGUS Scanner Report", "", f"Generated: {datetime.utcnow().isoformat()}", ""]
    for finding in findings:
        vc, red, blue = finding["vuln_context"], finding["red"], finding["blue"]
        exec_result = red.get("execution_result", {})

        lines.append(f"## {_finding_header(vc)}")
        lines.append(f"**File:** {vc.get('filepath', '?')} lines "
                      f"{vc.get('line_start', '?')}-{vc.get('line_end', '?')}")
        lines.append(f"**Matched Technique:** {red.get('matched_technique_id') or 'none found in graph'}")
        lines.append(f"**Matched CVE:** {red.get('matched_cve_id') or 'none found in graph'}")
        lines.append("")

        lines.append("### Vulnerability")
        lines.append(vc.get("description", ""))
        lines.append(f"**Attack vector:** {vc.get('attack_vector', '')}")
        lines.append(f"**Impact:** {vc.get('impact', '')}")
        lines.append("")

        lines.append("### Code")
        lines.append("```")
        lines.append(vc.get("code_block", ""))
        lines.append("```")
        lines.append("")

        lines.append("### Exploitation Path (Red) — Multi-Container Kill Chain")
        attack_plan = red.get("attack_plan", {})
        lines.append(f"**Attack Plan:** {attack_plan.get('entry_rationale', '')}")
        pivots = attack_plan.get("pivot_sequence", [])
        lines.append(f"**Target sequence:** {attack_plan.get('entry_service', '')} "
                      f"→ {' → '.join(pivots) if pivots else '(none)'}")
        lines.append("")
        if exec_result.get("status") == "skipped":
            lines.append(f"**Sandbox:** skipped ({exec_result.get('reason', '')})")
        else:
            lines.extend(_md_table(_kill_chain_rows(exec_result)))
            lines.append(f"**Kill chain complete:** "
                          f"{'yes' if exec_result.get('kill_chain_complete') else 'no'}")
            blocked = [p["service"] for p in exec_result.get("phases", [])
                       if p.get("status") == "blocked"]
            if blocked:
                lines.append(f"**Blocked phases:** {', '.join(blocked)}")
                lines.append("**Note:** Blocked phases indicate tool coverage gaps — "
                              "see logs/tool_unavailable.log for details.")
        lines.append("")

        lines.append("### Mitigation (Blue)")
        lines.append(f"**Code Fix:** {blue.get('code_fix', '')}")
        lines.append(f"**Detection Rule:** {blue.get('detection_rule', '')}")
        if exec_result.get("status") == "skipped":
            lines.append("**Sandbox Detection:** skipped")
        else:
            lines.append(f"**Sandbox Detection:** "
                          f"{'yes' if blue.get('detected_overall') else 'no'}")
            lines.append("")
            lines.append("### Detection (Blue) — Per Service")
            lines.extend(_md_table(_detection_rows(blue, exec_result)))
            lines.append(f"**Missed lateral:** {'yes' if blue.get('missed_lateral') else 'no'}")
            phases_detected = blue.get("phases_detected", [])
            lines.append(f"**First detection at:** "
                          f"{phases_detected[0] if phases_detected else 'not detected'}")
        mitigation_ids = ", ".join(m.get("node_id", "") for m in blue.get("argus_mitigations", []))
        lines.append(f"**ARGUS Mitigations:** {mitigation_ids or 'none found in graph'}")
        lines.append(f"**General Advice:** {blue.get('static_advice', '')}")
        lines.append("")
        lines.append("---")
        lines.append("")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def _md_table(rows: list) -> list:
    out = ["| " + " | ".join(rows[0]) + " |", "|" + "|".join(["---"] * len(rows[0])) + "|"]
    for row in rows[1:]:
        out.append("| " + " | ".join(str(c) for c in row) + " |")
    out.append("")
    return out


def _write_pdf(findings: list, path: str) -> None:
    doc = SimpleDocTemplate(path, pagesize=letter)
    styles = getSampleStyleSheet()
    story = [Paragraph("ARGUS Scanner Report", styles["Title"]), Spacer(1, 12)]

    for finding in findings:
        vc, red, blue = finding["vuln_context"], finding["red"], finding["blue"]
        exec_result = red.get("execution_result", {})

        story.append(Paragraph(_finding_header(vc), styles["Heading2"]))
        story.append(Paragraph(
            f"File: {vc.get('filepath', '?')} lines "
            f"{vc.get('line_start', '?')}-{vc.get('line_end', '?')}", styles["Normal"]))
        story.append(Paragraph(
            f"Matched Technique: {red.get('matched_technique_id') or 'none found in graph'}",
            styles["Normal"]))
        story.append(Paragraph(
            f"Matched CVE: {red.get('matched_cve_id') or 'none found in graph'}", styles["Normal"]))
        story.append(Spacer(1, 8))
        story.append(Paragraph("Vulnerability", styles["Heading3"]))
        story.append(Paragraph(vc.get("description", "") or "(none)", styles["Normal"]))
        story.append(Spacer(1, 8))

        if exec_result.get("status") != "skipped" and exec_result.get("phases"):
            table = Table(_kill_chain_rows(exec_result))
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(TYPE_COLOR["technique"])),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
            ]))
            story.append(Paragraph("Exploitation Path (Red)", styles["Heading3"]))
            story.append(table)
            story.append(Spacer(1, 8))

        story.append(Paragraph("Mitigation (Blue)", styles["Heading3"]))
        story.append(Paragraph(f"Code Fix: {blue.get('code_fix', '') or '(none)'}", styles["Normal"]))
        story.append(Paragraph(f"Priority: {blue.get('priority', '?')}", styles["Normal"]))
        story.append(PageBreak())

    doc.build(story)


def _html_escape(text) -> str:
    return str(text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _html_table(rows: list) -> str:
    parts = ["<table>", "<tr>" + "".join(f"<th>{_html_escape(h)}</th>" for h in rows[0]) + "</tr>"]
    for row in rows[1:]:
        parts.append("<tr>" + "".join(f"<td>{_html_escape(c)}</td>" for c in row) + "</tr>")
    parts.append("</table>")
    return "\n".join(parts)


def _write_html(findings: list, path: str) -> None:
    parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        "<title>ARGUS Scanner Report</title>",
        "<style>",
        f"body {{ background: {BG_COLOR}; color: #e5e7eb; "
        f"font-family: system-ui, sans-serif; padding: 2rem; }}",
        f"h1 {{ color: {TYPE_COLOR['technique']}; }}",
        f"h2 {{ color: {TYPE_COLOR['vulnerability']}; border-bottom: 1px solid #333; "
        f"padding-bottom: 4px; }}",
        f"h3 {{ color: {TYPE_COLOR['mitigation']}; }}",
        "table { border-collapse: collapse; width: 100%; margin: 1rem 0; }",
        "th, td { border: 1px solid #333; padding: 6px 10px; text-align: left; font-size: 0.85rem; }",
        f"th {{ background: #12121f; color: {TYPE_COLOR['technique']}; }}",
        "code, pre { background: #12121f; padding: 8px; display: block; "
        "overflow-x: auto; border-radius: 4px; white-space: pre-wrap; }",
        ".finding { margin-bottom: 2.5rem; }",
        "</style></head><body>",
        "<h1>ARGUS Scanner Report</h1>",
        f"<p>Generated: {datetime.utcnow().isoformat()}</p>",
    ]

    for finding in findings:
        vc, red, blue = finding["vuln_context"], finding["red"], finding["blue"]
        exec_result = red.get("execution_result", {})

        parts.append("<div class='finding'>")
        parts.append(f"<h2>{_html_escape(_finding_header(vc))}</h2>")
        parts.append(f"<p><b>File:</b> {_html_escape(vc.get('filepath', '?'))} lines "
                      f"{_html_escape(vc.get('line_start', '?'))}-"
                      f"{_html_escape(vc.get('line_end', '?'))}</p>")
        parts.append(f"<p><b>Matched Technique:</b> "
                      f"{_html_escape(red.get('matched_technique_id') or 'none found in graph')}</p>")
        parts.append(f"<p><b>Matched CVE:</b> "
                      f"{_html_escape(red.get('matched_cve_id') or 'none found in graph')}</p>")

        parts.append("<h3>Vulnerability</h3>")
        parts.append(f"<p>{_html_escape(vc.get('description', ''))}</p>")
        parts.append(f"<p><b>Attack vector:</b> {_html_escape(vc.get('attack_vector', ''))}</p>")
        parts.append(f"<p><b>Impact:</b> {_html_escape(vc.get('impact', ''))}</p>")

        parts.append("<h3>Code</h3>")
        parts.append(f"<pre>{_html_escape(vc.get('code_block', ''))}</pre>")

        parts.append("<h3>Exploitation Path (Red) — Multi-Container Kill Chain</h3>")
        if exec_result.get("status") == "skipped":
            parts.append(f"<p>Sandbox: skipped ({_html_escape(exec_result.get('reason', ''))})</p>")
        else:
            parts.append(_html_table(_kill_chain_rows(exec_result)))
            parts.append(f"<p><b>Kill chain complete:</b> "
                          f"{'yes' if exec_result.get('kill_chain_complete') else 'no'}</p>")
            blocked = [p["service"] for p in exec_result.get("phases", [])
                       if p.get("status") == "blocked"]
            if blocked:
                parts.append(f"<p><b>Blocked phases:</b> {_html_escape(', '.join(blocked))}</p>")

        parts.append("<h3>Mitigation (Blue)</h3>")
        parts.append(f"<p><b>Code Fix:</b> {_html_escape(blue.get('code_fix', ''))}</p>")
        parts.append(f"<p><b>Detection Rule:</b> {_html_escape(blue.get('detection_rule', ''))}</p>")
        if exec_result.get("status") != "skipped":
            parts.append("<h4>Detection — Per Service</h4>")
            parts.append(_html_table(_detection_rows(blue, exec_result)))
        parts.append(f"<p><b>Priority:</b> {_html_escape(blue.get('priority', '?'))}</p>")
        parts.append(f"<p><b>General Advice:</b> {_html_escape(blue.get('static_advice', ''))}</p>")
        parts.append("</div>")

    parts.append("</body></html>")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(parts))


def write_scanner_report(findings: list, output_prefix: str = "reports/scanner") -> None:
    """ARGUS-SCANNER: Writes the report in three formats: .md, .pdf, .html."""
    out_dir = os.path.dirname(output_prefix)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    _write_markdown(findings, f"{output_prefix}.md")
    _write_pdf(findings, f"{output_prefix}.pdf")
    _write_html(findings, f"{output_prefix}.html")
