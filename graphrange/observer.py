"""
ARGUS-LAYER-7: Observation Normalizer (GraphRange Phase 5).
Normalizes raw tool output into structured observations. Schema comes from
the graph (a technique's expected_observables) -- not a generic "structure
this" prompt.
"""

import json
import re

import requests

from config import OLLAMA_CHAT_URL as OLLAMA_URL

QWEN_MODEL = "qwen3:8b"


def _get_expected_observables(technique_id: str, driver) -> list:
    """ARGUS-LAYER-7: Look up a technique's expected_observables field."""
    if not technique_id:
        return []
    cypher = "MATCH (n:Node {node_id: $tid}) RETURN n.expected_observables AS obs"
    with driver.session() as session:
        record = session.run(cypher, tid=technique_id).single()
    return record["obs"] if record and record["obs"] else []


def _slot_fill(raw_output: str, schema_fields: list) -> dict:
    """ARGUS-LAYER-7: The one model call in this module. Uses Qwen3 fast mode
    (/no_think, not /think) -- per CLAUDE.md's model usage table, slot-filling
    from raw text is a "standard (fast)" task, not one that needs deep
    reasoning."""
    prompt = (
        f"Extract these fields from the tool output: {schema_fields}\n"
        f"Output: {raw_output[:2000]}\n"
        "Return ONLY a JSON object with those keys. Use null for missing fields."
    )
    resp = requests.post(
        OLLAMA_URL,
        json={
            "model": QWEN_MODEL,
            "messages": [{"role": "user", "content": f"/no_think\n\n{prompt}"}],
            "stream": False,
        },
        timeout=600,
    )
    resp.raise_for_status()
    text = resp.json()["message"]["content"].strip()
    text = re.sub(r"^```json\s*|\s*```$", "", text.strip())
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else {f: None for f in schema_fields}
    except json.JSONDecodeError:
        return {f: None for f in schema_fields}


def normalize(raw_output: str, technique_id: str, driver) -> dict:
    """
    ARGUS-LAYER-7: Main normalizer entry point. Extracts only the fields the
    technique's expected_observables says matter.
    """
    schema_fields = _get_expected_observables(technique_id, driver)
    if not schema_fields:
        return {}

    stripped = raw_output.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, dict):
                return {f: parsed.get(f) for f in schema_fields}
        except json.JSONDecodeError:
            pass

    return _slot_fill(raw_output, schema_fields)


def determine_success(observations: dict, scenario: dict) -> bool:
    """
    ARGUS-LAYER-7: Did the technique succeed? At least 50% of the scenario's
    expected observable fields must be non-null in the extracted observations.
    """
    expected = scenario.get("expected_observables", [])
    if not expected:
        return False
    non_null = sum(1 for f in expected if observations.get(f) is not None)
    return (non_null / len(expected)) >= 0.5
