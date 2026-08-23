"""
ARGUS — D5 cross-check unit test (GraphRange Phase 7).

Pure-logic test for run_scenario._check_plan_matches_scenario — the check that
red actually planned for the scenario it was asked to test (added file-only
2026-08-17, otherwise unvalidated until the Phase 7 GPU run). Needs NO Neo4j or
Ollama: synthetic engagement/scenario dicts only, so it runs offline.

Usage:
    python scripts/test_scenario_match.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from graphrange.run_scenario import _check_plan_matches_scenario


def _chain(cve, tech, tactic="TA0001"):
    """A CVE->technique->tactic chain in the real hop shape from red._get_full_chains."""
    return [
        {"node_id": cve, "label": cve, "type": "vulnerability"},
        {"node_id": tech, "label": tech, "type": "technique"},
        {"node_id": tactic, "label": tactic, "type": "tactic"},
    ]


def test_full_match():
    eng = {"selected_chain": _chain("CVE-2000-0148", "T1110")}
    sc = {"cve_id": "CVE-2000-0148", "technique_id": "T1110"}
    r = _check_plan_matches_scenario(eng, sc)
    assert r["matched"] is True, r
    assert r["cve_match"] is True and r["technique_match"] is True, r
    print("[PASS] full match")


def test_technique_mismatch():
    eng = {"selected_chain": _chain("CVE-2000-0148", "T1059")}
    sc = {"cve_id": "CVE-2000-0148", "technique_id": "T1110"}
    r = _check_plan_matches_scenario(eng, sc)
    assert r["matched"] is False, r
    assert r["cve_match"] is True and r["technique_match"] is False, r
    assert r["planned_techniques"] == ["T1059"], r
    print("[PASS] technique mismatch detected")


def test_cve_mismatch():
    eng = {"selected_chain": _chain("CVE-9999-0001", "T1110")}
    sc = {"cve_id": "CVE-2000-0148", "technique_id": "T1110"}
    r = _check_plan_matches_scenario(eng, sc)
    assert r["matched"] is False and r["cve_match"] is False, r
    print("[PASS] cve mismatch detected")


def test_empty_chain_fallback():
    # run_one's fallback engagement carries selected_chain: [] — must not match.
    eng = {"selected_chain": []}
    sc = {"cve_id": "CVE-2000-0148", "technique_id": "T1110"}
    r = _check_plan_matches_scenario(eng, sc)
    assert r["matched"] is False, r
    assert r["planned_cves"] == [] and r["planned_techniques"] == [], r
    print("[PASS] empty chain -> no match")


def test_missing_technique_id():
    eng = {"selected_chain": _chain("CVE-2000-0148", "T1110")}
    sc = {"cve_id": "CVE-2000-0148"}  # no technique_id to check against
    r = _check_plan_matches_scenario(eng, sc)
    assert r["technique_match"] is None, r  # nothing to verify
    assert r["matched"] is False, r          # bool(None) is False
    print("[PASS] missing technique_id -> technique_match None, matched False")


def test_none_inputs():
    r = _check_plan_matches_scenario(None, None)
    assert r["matched"] is False, r
    assert r["planned_cves"] == [] and r["planned_techniques"] == [], r
    print("[PASS] None inputs handled gracefully")


if __name__ == "__main__":
    test_full_match()
    test_technique_mismatch()
    test_cve_mismatch()
    test_empty_chain_fallback()
    test_missing_technique_id()
    test_none_inputs()
    print("\nAll D5 cross-check tests passed.")
