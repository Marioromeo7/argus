"""
ARGUS-EVAL: Precision/recall for the dashboard's /api/chat grounding
decision -- did the model correctly decide when to ground its reply in a
real graph node vs. answer conversationally with no node cited? A separate
measurement tool from the WebGoat scanner eval in this same directory; not
part of the product, not called by the dashboard itself.

Requires the dashboard container running locally (docker compose up
argus-dashboard) with a real Ollama reachable from it -- every case here is
a live Qwen call, so this is slow on this project's hardware (see
dashboard/api/main.py's OLLAMA_URL comment). Run deliberately, not in CI.
"""

import requests

CHAT_URL = "http://localhost:3000/api/chat"

# Each case: a fresh single-turn conversation, whether grounding was
# expected, and (if so) the set of node_ids that would count as a correct
# ground -- more than one can be equally valid (several apache buffer
# overflow CVEs exist), so this isn't always a single fixed answer.
TEST_CASES = [
    {"query": "What is CVE-1999-1471?",
     "expected_grounded": True, "acceptable_nodes": {"CVE-1999-1471"}},
    {"query": "Tell me about the Lateral Movement tactic",
     "expected_grounded": True, "acceptable_nodes": {"TA0008"}},
    {"query": "apache buffer overflow",
     "expected_grounded": True,
     "acceptable_nodes": {"CVE-2002-1658", "CVE-2000-1205", "CVE-1999-0232", "CVE-1999-0235"}},
    {"query": "What tactic involves stealing account credentials?",
     "expected_grounded": True, "acceptable_nodes": {"TA0006"}},
    {"query": "hello, what can you help me with?",
     "expected_grounded": False, "acceptable_nodes": set()},
    {"query": "how does this dashboard work?",
     "expected_grounded": False, "acceptable_nodes": set()},
    {"query": "what is 2 + 2?",
     "expected_grounded": False, "acceptable_nodes": set()},
    {"query": "thanks, that's helpful",
     "expected_grounded": False, "acceptable_nodes": set()},
]


def run_case(case: dict) -> dict:
    """ARGUS-EVAL: Sends one fresh-conversation query, records what actually happened."""
    resp = requests.post(
        CHAT_URL,
        json={"messages": [{"role": "user", "content": case["query"]}]},
        timeout=320,
    )
    resp.raise_for_status()
    body = resp.json()
    grounded = body.get("grounded_node")
    return {
        **case,
        "actual_grounded": grounded is not None,
        "actual_node": grounded["id"] if grounded else None,
        "reply": body.get("reply", ""),
    }


def score(results: list[dict]) -> dict:
    """
    ARGUS-EVAL: Confusion matrix over the grounding decision.
    A grounded reply pointing at the wrong node counts as a false positive
    (the decision to ground was "right" but the outcome was still wrong --
    scoring it as a true positive would hide a real failure mode).
    """
    tp = fp = fn = tn = 0
    wrong_node = 0
    for r in results:
        expected, actual = r["expected_grounded"], r["actual_grounded"]
        if expected and actual:
            if r["acceptable_nodes"] and r["actual_node"] not in r["acceptable_nodes"]:
                wrong_node += 1
                fp += 1
            else:
                tp += 1
        elif not expected and actual:
            fp += 1
        elif expected and not actual:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else float("nan")
    recall = tp / (tp + fn) if (tp + fn) else float("nan")
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "wrong_node": wrong_node, "precision": precision, "recall": recall}


def run_eval() -> None:
    """ARGUS-EVAL: Runs every case live and prints a precision/recall report."""
    results = [run_case(c) for c in TEST_CASES]
    s = score(results)

    print(f"{'query':45s} {'expected':9s} {'actual':9s} {'node':20s}")
    for r in results:
        print(f"{r['query'][:45]:45s} {str(r['expected_grounded']):9s} "
              f"{str(r['actual_grounded']):9s} {str(r['actual_node']):20s}")

    print()
    print(f"TP={s['tp']} FP={s['fp']} FN={s['fn']} TN={s['tn']} "
          f"(of which wrong-node={s['wrong_node']})")
    print(f"Precision: {s['precision']:.2f}   Recall: {s['recall']:.2f}")


if __name__ == "__main__":
    run_eval()
