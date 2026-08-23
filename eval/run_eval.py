"""
ARGUS-EVAL: Caliber evaluation of the scanner against real ground truth.
This is a research tool -- not part of the product pipeline, not called by
the scanner itself.
"""

from eval.ground_truth import load_ground_truth, DEFAULT_OWNER, DEFAULT_REPO
from eval.comparator import compare, write_comparison_tables
from eval.false_positive_analyzer import analyze, write_fp_report
from eval.defense_plan import generate_defense_plan_prompt
from graphrange.scanner.run_scanner import run_scanner
from graph.retrieval import get_driver

# WebGoat (the original spec target) has zero ground truth available by
# either source -- checked live, documented in ground_truth.py's docstring.
# axios/axios is a real, working substitute: 30 GitHub Security Advisories,
# every one with a real assigned CVE ID, small enough to actually scan in
# reasonable time (unlike the larger platform repos also checked that have
# real advisories too -- Gitea, Grafana, Strapi).
TARGET_SOURCE = f"https://github.com/{DEFAULT_OWNER}/{DEFAULT_REPO}"


def run_eval() -> None:
    """
    ARGUS-EVAL: Full evaluation pipeline.
    1. Run scanner on the target repo -> findings
    2. Load ground truth from GitHub advisories + SECURITY.md
    3. Compare findings against ground truth -> Table A + Table B
    4. Summarizing Qwen call, written into comparison.md
    5. False positive analysis (real graph cross-check)
    6. Print defense plan prompt for Claude Code
    """
    findings = run_scanner(TARGET_SOURCE, output_prefix="eval/scanner_output")
    ground_truth = load_ground_truth()
    comparison = compare(findings, ground_truth)
    write_comparison_tables(comparison)

    driver = get_driver()
    try:
        fp_analysis = analyze(comparison, driver=driver)
    finally:
        driver.close()
    write_fp_report(fp_analysis)

    generate_defense_plan_prompt()


if __name__ == "__main__":
    run_eval()
