"""
ARGUS-EVAL: Generates the Claude Code prompt for the defense plan document.
Deliberately just prints a prompt rather than calling a model itself -- the
defense plan is meant to be written by Claude Code reading the real eval
output files, not generated blind from a template.
"""

PROMPT = """
Read these eval reports before writing (run from repo root):
  eval/comparison.md
  eval/false_positives.md
  eval/scanner_output.md  <- the scanner's full vulnerability report

Write eval/defense_plan.md with this structure:

# Defense Plan — WebGoat Evaluation

## Executive Summary
[2-3 sentences: overall risk posture]

## Critical Actions (within 24 hours)
[Critical/High confirmed findings — specific patch/mitigation per finding]

## Medium Priority Actions (within 30 days)
[Medium severity confirmed findings]

## Findings Requiring Investigation
[All unvalidated false positives marked investigate: true]
[For each: what was found, suggested validation method]

## Systematic Gaps
[Ground truth CVEs missed by scanner — what does this reveal]

## Detection Recommendations
[Based on GraphRange execution results — what controls would catch these]

Reference specific findings by CVE or CWE ID throughout. No filler.
"""


def generate_defense_plan_prompt() -> None:
    print(PROMPT)
