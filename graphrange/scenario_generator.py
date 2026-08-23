"""
ARGUS-LAYER-7: GraphRange scenario generator.

Generates valid scenario combinations from graph structure — the scenario
set EMERGES from graph constraints (real CVE-technique-CPE combinations that
already exist in the graph), not manually curated.

Real structure confirmed against the live graph before writing this (not
assumed): CVE->technique edges use `relation_type='enables'` between
node_type='vulnerability' and node_type='technique'; technique->tactic
edges use the same relation_type between node_type='technique' and
node_type='tactic'; vulnerability nodes carry a real `affected` list of
CPE 2.3 strings; tactic node_ids are the real `TA####` MITRE IDs.
"""

import ast
import hashlib

# ARGUS-LAYER-7: MITRE ATT&CK's own kill-chain tactic ordering — this
# doesn't change, hardcoded per GRAPHRANGE.md spec. Any tactic ID seen in
# the graph but not in this list (e.g. matrix-specific tactics outside the
# 14 Enterprise ones — TA0112 was observed in the live graph) sorts last
# rather than crashing, since order-checking should degrade gracefully on
# data this constant was never meant to model.
_TACTIC_ORDER = [
    "TA0043", "TA0042", "TA0001", "TA0002", "TA0003", "TA0004", "TA0005",
    "TA0006", "TA0007", "TA0008", "TA0009", "TA0010", "TA0011", "TA0040",
]


def _tactic_rank(tactic_id: str) -> int:
    try:
        return _TACTIC_ORDER.index(tactic_id)
    except ValueError:
        return len(_TACTIC_ORDER)  # unknown tactic — sorts last, doesn't crash


def _parse_list_field(raw) -> list:
    """ARGUS-LAYER-7: node properties are read back from Neo4j as
    str(dict)/str(list) per this project's own documented quirk — parse
    with ast.literal_eval, not json.loads."""
    if isinstance(raw, list):
        return raw
    if not raw:
        return []
    try:
        parsed = ast.literal_eval(raw)
        return parsed if isinstance(parsed, list) else []
    except (ValueError, SyntaxError):
        return []


def get_valid_scenarios(driver, limit: int = 100) -> list:
    """
    ARGUS-LAYER-7: Returns a list of valid scenario dicts, constrained by
    what the graph actually supports:

    1. Only CVE-technique pairs with a real 'enables' edge are candidates
       (no inventing combinations the graph doesn't already assert).
    2. Each technique's tactic must be resolvable via its own 'enables'
       edge to a tactic node — techniques with no tactic edge are skipped
       rather than guessed at.
    3. Each CVE's `affected` CPE list expands into one scenario per CVE-
       technique-CPE triple (a technique against one specific victim
       configuration is one scenario, not the whole CPE list at once).
    """
    cypher = """
    MATCH (v:Node {node_type: 'vulnerability'})-[r:RELATION {relation_type: 'enables'}]->(t:Node {node_type: 'technique'})
    RETURN v.node_id AS cve_id, v.properties AS v_props,
           t.node_id AS technique_id, t.label AS technique_label,
           t.expected_observables AS expected_observables
    LIMIT $lim
    """
    scenarios = []
    with driver.session() as session:
        rows = list(session.run(cypher, lim=limit * 3))  # overfetch: CPE expansion multiplies rows

        for row in rows:
            if len(scenarios) >= limit:
                break

            v_props = ast.literal_eval(row["v_props"]) if row["v_props"] else {}
            # expected_observables is a TOP-LEVEL Neo4j property (a real list,
            # not str(dict)-encoded like `properties`) -- confirmed against
            # the live graph before writing this, not assumed from the spec.
            expected_observables = row["expected_observables"] or []
            technique_id = row["technique_id"]

            tactic_result = session.run(
                """
                MATCH (t:Node {node_id: $tid})-[r:RELATION {relation_type: 'enables'}]->(ta:Node {node_type: 'tactic'})
                RETURN ta.node_id AS tactic_id LIMIT 1
                """,
                tid=technique_id,
            ).single()
            if tactic_result is None:
                continue  # no resolvable tactic — skip rather than guess
            tactic_id = tactic_result["tactic_id"]

            affected_cpes = _parse_list_field(v_props.get("affected"))

            for cpe in affected_cpes:
                if len(scenarios) >= limit:
                    break
                scenarios.append({
                    "cve_id": row["cve_id"],
                    "technique_id": technique_id,
                    "tactic_id": tactic_id,
                    "victim_cpe": cpe,
                    "expected_observables": expected_observables,
                    "win_conditions": {
                        "red": "technique_executed_successfully",
                        "blue": "technique_detected_before_completion",
                        "stalemate_turns": 20,
                    },
                })

    return scenarios


def mark_scenario_complete(driver, scenario: dict, run_id: str) -> None:
    """ARGUS-LAYER-7: Record that this scenario was run, so future calls to
    get_valid_scenarios() can filter already-covered combinations. Writes a
    lightweight edge — ScenarioRun nodes only exist once GraphRange Phase 4+
    execution actually runs one; this function is a no-op-safe write that
    will start being exercised once that exists, not before."""
    cypher = """
    MATCH (sr:Node {node_id: $run_id}), (t:Node {node_id: $technique_id})
    MERGE (sr)-[r:RELATION {relation_type: 'covered', edge_id: $edge_id}]->(t)
    SET r.cve_id = $cve_id, r.victim_cpe = $victim_cpe
    """
    edge_id = f"{run_id}_covered_{scenario['technique_id']}"
    with driver.session() as session:
        session.run(
            cypher, run_id=run_id, technique_id=scenario["technique_id"],
            edge_id=edge_id, cve_id=scenario["cve_id"], victim_cpe=scenario["victim_cpe"],
        )


def get_conflict_scenarios(driver) -> list:
    """
    ARGUS-LAYER-7: Find Outcome node pairs with the same technique+config
    but different results — open questions waiting to be investigated.
    Returns an empty list until Phase 4+ execution actually produces
    Outcome nodes; the query is real and will start returning real
    conflicts the moment that data exists, not before.
    """
    cypher = """
    MATCH (o1:Node {node_type: 'outcome'}), (o2:Node {node_type: 'outcome'})
    WHERE o1.technique_id = o2.technique_id
      AND o1.victim_config_hash = o2.victim_config_hash
      AND o1.result <> o2.result
      AND o1.node_id < o2.node_id
    RETURN o1.node_id AS a, o2.node_id AS b
    """
    with driver.session() as session:
        return [(r["a"], r["b"]) for r in session.run(cypher)]
