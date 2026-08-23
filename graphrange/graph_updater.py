"""
ARGUS-LAYER-7: Graph Updater (GraphRange Phase 6).
Writes execution results back into the ARGUS graph -- this is the learning
loop: real outcomes become graph knowledge, not just LLM reasoning.
"""

import ast
from datetime import datetime, timedelta

from graph.schema import ScenarioRun, Outcome


def _parse_properties(node: dict) -> dict:
    """ARGUS-LAYER-7: Neo4j stores properties as str(dict); parse defensively."""
    props = node.get("properties", {})
    if isinstance(props, str):
        try:
            return ast.literal_eval(props)
        except (ValueError, SyntaxError):
            return {}
    return props or {}


def write_scenario_run(driver, scenario: dict, run_id: str) -> None:
    """ARGUS-LAYER-7: Write a ScenarioRun node to Neo4j (status=running)."""
    run = ScenarioRun(
        run_id=run_id,
        status="running",
        cve_ids=[scenario["cve_id"]] if scenario.get("cve_id") else [],
        technique_ids=[scenario["technique_id"]] if scenario.get("technique_id") else [],
        tactic_ids=[scenario["tactic_id"]] if scenario.get("tactic_id") else [],
        victim_config={"cpe": scenario.get("victim_cpe", "")},
    )
    cypher = "MERGE (n:Node {node_id: $node_id}) SET n += $props SET n:ScenarioRun"
    with driver.session() as session:
        session.run(cypher, node_id=run.run_id, props=run.to_neo4j())


def update_scenario_run_status(driver, run_id: str, status: str, winner: str,
                                turn_count: int, duration_seconds: int) -> None:
    """ARGUS-LAYER-7: Called by run_one() (Phase 7) once a scenario concludes."""
    cypher = """
    MATCH (n:Node {node_id: $run_id})
    SET n.status = $status, n.winner = $winner, n.turn_count = $turn_count,
        n.duration_seconds = $duration_seconds, n.last_updated = $ts
    """
    with driver.session() as session:
        session.run(cypher, run_id=run_id, status=status, winner=winner,
                    turn_count=turn_count, duration_seconds=duration_seconds,
                    ts=datetime.utcnow().isoformat())


def _write_relation_edge(driver, source_id: str, target_id: str, relation_type: str,
                          confidence: float = 0.8) -> None:
    """ARGUS-LAYER-7: One RELATION edge, matching the shape every other
    ARGUS ingestion path already writes (see graph/ingestion/attack.py)."""
    cypher = """
    MATCH (a:Node {node_id: $src}), (b:Node {node_id: $tgt})
    MERGE (a)-[r:RELATION {edge_id: $edge_id}]->(b)
    SET r.relation_type = $rel, r.confidence = $conf,
        r.context_conditions = [], r.directionality = 'unidirectional',
        r.source = 'graphrange', r.last_updated = $ts
    """
    with driver.session() as session:
        session.run(
            cypher, src=source_id, tgt=target_id,
            edge_id=f"{source_id}_{relation_type}_{target_id}",
            rel=relation_type, conf=confidence, ts=datetime.utcnow().isoformat(),
        )


def write_outcome(driver, run_id: str, scenario: dict,
                   execution_result: dict, detection: dict) -> str:
    """
    ARGUS-LAYER-7: Write an Outcome node and its edges.
    Edges written:
    - ScenarioRun -[uses_technique]-> Technique
    - ScenarioRun -[targets_cve]-> Vulnerability
    - Outcome -[validates]-> Technique (confidence 0.8 if success, 0.2 if fail)
    Returns outcome_id.
    """
    success = bool(execution_result.get("success"))
    result = "success" if success else ("partial" if execution_result.get("observations") else "fail")
    technique_id = scenario.get("technique_id", "")
    cve_id = scenario.get("cve_id", "")
    victim_config_hash = hash_victim_config(scenario.get("victim_cpe", ""))

    outcome_id = f"OUT-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}-{technique_id}"
    outcome = Outcome(
        outcome_id=outcome_id,
        run_id=run_id,
        technique_id=technique_id,
        cve_id=cve_id,
        victim_config_hash=victim_config_hash,
        result=result,
        tools_used=[execution_result["tool_used"]] if execution_result.get("tool_used") else [],
        observations=execution_result.get("observations", {}),
        detected_by_blue=bool(detection.get("detected")),
    )
    cypher = "MERGE (n:Node {node_id: $node_id}) SET n += $props SET n:Outcome"
    with driver.session() as session:
        session.run(cypher, node_id=outcome.outcome_id, props=outcome.to_neo4j())

    if technique_id:
        _write_relation_edge(driver, run_id, technique_id, "used_technique")
        _write_relation_edge(driver, outcome_id, technique_id, "validates",
                              confidence=0.8 if success else 0.2)
    if cve_id:
        _write_relation_edge(driver, run_id, cve_id, "targeted_cve")

    return outcome_id


def hash_victim_config(victim_cpe: str) -> str:
    """ARGUS-LAYER-7: sha256 of the victim config, per GRAPHRANGE.md's spec
    (Outcome.victim_config_hash) -- used to compare outcomes across runs
    that targeted the same configuration."""
    import hashlib
    return hashlib.sha256(str({"cpe": victim_cpe}).encode()).hexdigest()


def update_technique_confidence(driver, technique_id: str,
                                 result: str, victim_config_hash: str) -> None:
    """
    ARGUS-LAYER-7: Update a technique node's grain_confidence based on a
    real execution outcome. success -> +0.05 (capped 1.0), fail -> -0.02
    (floored 0.1). victim_config_hash isn't used in the update itself
    (that's check_and_flag_conflict()'s job) -- kept in the signature to
    match the spec, since callers pass it through from the same Outcome.
    """
    delta = 0.05 if result == "success" else -0.02
    cypher = """
    MATCH (n:Node {node_id: $tid})
    SET n.grain_confidence = CASE
        WHEN coalesce(n.grain_confidence, 0.3) + $delta > 1.0 THEN 1.0
        WHEN coalesce(n.grain_confidence, 0.3) + $delta < 0.1 THEN 0.1
        ELSE coalesce(n.grain_confidence, 0.3) + $delta
    END,
    n.last_updated = $ts
    """
    with driver.session() as session:
        session.run(cypher, tid=technique_id, delta=delta, ts=datetime.utcnow().isoformat())


def check_and_flag_conflict(driver, outcome_id: str,
                             technique_id: str, victim_config_hash: str,
                             result: str) -> None:
    """
    ARGUS-LAYER-7: If a prior Outcome exists for the same technique+config
    with the opposite result (success vs fail/partial), flag it:
    1. Outcome -[conflicts_with]-> prior Outcome
    2. Add an open_question to the Technique node
    3. Reduce technique grain_confidence by 0.1 (conflict = uncertainty)
    """
    cypher = """
    MATCH (o:Node {node_type: 'outcome'})
    WHERE o.node_id <> $outcome_id
      AND o.technique_id = $tid
      AND o.victim_config_hash = $cfg_hash
      AND o.result <> $result
      AND o.result <> 'partial' AND $result <> 'partial'
    RETURN o.node_id AS prior_id
    ORDER BY o.created_at DESC
    LIMIT 1
    """
    with driver.session() as session:
        record = session.run(cypher, outcome_id=outcome_id, tid=technique_id,
                              cfg_hash=victim_config_hash, result=result).single()
    if record is None:
        return

    prior_id = record["prior_id"]
    _write_relation_edge(driver, outcome_id, prior_id, "conflicts_with", confidence=1.0)

    question = (f"Conflicting outcomes for {technique_id} on config "
                f"{victim_config_hash}. What distinguishing variable explains "
                f"the difference?")
    with driver.session() as session:
        session.run(
            """
            MATCH (n:Node {node_id: $tid})
            SET n.open_questions = CASE
                WHEN $q IN coalesce(n.open_questions, []) THEN n.open_questions
                ELSE coalesce(n.open_questions, []) + $q
            END,
            n.grain_confidence = CASE
                WHEN coalesce(n.grain_confidence, 0.3) - 0.1 < 0.1 THEN 0.1
                ELSE coalesce(n.grain_confidence, 0.3) - 0.1
            END,
            n.last_updated = $ts
            """,
            tid=technique_id, q=question, ts=datetime.utcnow().isoformat(),
        )


def decay_stale_nodes(driver, days_threshold: int = 30) -> int:
    """
    ARGUS-LAYER-7: Reduce grain_confidence by 5% on outcome nodes that
    haven't been revalidated recently and aren't already flagged as
    conflicting (a conflict is itself informative and shouldn't decay the
    same way silence does). Returns count of decayed nodes.
    """
    cutoff = (datetime.utcnow() - timedelta(days=days_threshold)).isoformat()
    cypher = """
    MATCH (n:Node {node_type: 'outcome'})
    WHERE n.created_at < $cutoff
      AND NOT (n)-[:RELATION {relation_type: 'conflicts_with'}]->()
    SET n.grain_confidence = n.grain_confidence * 0.95,
        n.last_updated = $ts
    RETURN count(n) AS decayed
    """
    with driver.session() as session:
        record = session.run(cypher, cutoff=cutoff, ts=datetime.utcnow().isoformat()).single()
    return record["decayed"] if record else 0
