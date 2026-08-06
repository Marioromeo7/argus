# GraphRange — Cyber Range Expansion for ARGUS

Autonomous cyber range built on top of ARGUS. Red and blue agents stop being
planning-only and start executing real tools in isolated Docker containers.
Outcomes feed back into the ARGUS graph. The graph grows smarter from real
execution, not just LLM reasoning.

**This file is the Claude Code spec for GraphRange. Read CLAUDE.md and
CONTEXT.md first to understand ARGUS before touching anything here.**

---

## What Changes vs What Stays

**Touch nothing in the existing 6 layers.** GraphRange is Layer 7 and beyond.
Every existing file is append-only or extended — never replaced.

| File | Action | Why |
|------|--------|-----|
| `graph/schema.py` | Add two new node types | ScenarioRun and Outcome nodes needed |
| `agents/red.py` | Add execution wrapper | `plan_attack()` stays, new `execute_attack()` wraps it |
| `agents/blue.py` | Add daemon layer | `plan_mitigation()` stays, new `monitor()` runs in parallel |
| `graph/retrieval.py` | Add 3 new query functions | Technique observables, scenario combos, conflict detection |
| `requirements.txt` | Add docker SDK + subprocess | Container management |
| `BACKLOG.md` | Add GraphRange entry | Project rule: new features must be listed |
| `docker-compose.yml` | Extend, do not replace | Add graphrange services alongside existing dashboard |
| `CLAUDE.md` | Do NOT touch | GraphRange has its own rules file (this file) |

---

## Rules for This Expansion

- All LLM calls use Qwen3 8B via Ollama — same as the rest of ARGUS
- Groq is allowed for observation interpretation only (heavy reasoning on raw
  stdout) — this is the only exception to the no-cloud rule in CLAUDE.md
- Use `think=False` HTTP API for structured tasks, `/think` for planning
- Write Cypher directly — no langchain Neo4j abstractions
- Every new function gets a `# ARGUS-LAYER-7` comment
- New files go in `graphrange/` subfolder — do not scatter into existing dirs
- Commit convention: `[L7]` prefix for all GraphRange work

---

## Phase 0 — ARGUS Preparation (do this before any Docker work)

Two things are missing from the existing graph that GraphRange requires.
Both are confirmed missing from graph dump analysis.

### Task 0.1 — Populate expected_observables on Technique nodes

**File to create:** `scripts/populate_observables.py`

**What it does:**
Every Technique node needs an `expected_observables` list. The observation
normalizer queries this to know what fields to extract from raw tool output.
Currently no Technique node has this field.

**How to write it:**
```python
# Use graph/retrieval.py get_nodes_by_type(driver, 'technique', limit=1000)
# to get all 697 technique nodes.
# For each node, extract: node_id, label, and properties (parse with
# ast.literal_eval() — properties are stored as str(dict) in Neo4j).
# Send to Qwen3 fast mode (HTTP API, think=False) with this prompt:
#
# "Given this MITRE ATT&CK technique:
#  Name: {name}
#  Description: {description}
#
#  List the observable artifacts this technique produces when executed.
#  These are the fields a tool's output would contain.
#  Return ONLY a JSON array of short snake_case strings, no explanation.
#  Example: ["open_ports", "running_services", "os_fingerprint"]"
#
# Parse the response as JSON. Strip ```json fences if present.
# Write back to Neo4j:
#   MATCH (n:Node {node_id: $node_id})
#   SET n.expected_observables = $observables,
#       n.last_updated = $ts
# Log failures to a text file — do not crash on a single bad parse.
# Run in batches of 50 with a 2-second sleep between batches (Ollama limit).
```

**Verify:** After running, spot-check 5 technique nodes with:
```cypher
MATCH (n:Node {node_type: 'technique'})
WHERE n.expected_observables IS NOT NULL
RETURN n.node_id, n.expected_observables LIMIT 5
```

---

### Task 0.2 — Create execution history schema in Neo4j

**File to create:** `scripts/create_execution_schema.py`

**What it does:**
Creates constraints and indexes for ScenarioRun and Outcome nodes.
No data — schema only. Data is written at runtime by graph_updater.

**New node types to add to `graph/schema.py`:**

Append these two dataclasses after the existing `Edge` class.
Do NOT modify Node or Edge.

```python
@dataclass
class ScenarioRun:
    """
    ARGUS-LAYER-7: Records a single GraphRange scenario execution.
    Written by graphrange/graph_updater.py after each scenario completes.
    """
    run_id:           str                        # "RUN-{timestamp}"
    node_type:        str = "scenario_run"
    status:           str = "running"            # running|completed|failed|inconclusive
    cve_ids:          list = field(default_factory=list)
    technique_ids:    list = field(default_factory=list)
    tactic_ids:       list = field(default_factory=list)
    victim_config:    dict = field(default_factory=dict)  # {cpe, os, services, ports}
    winner:           str  = ""                  # red|blue|stalemate
    turn_count:       int  = 0
    duration_seconds: int  = 0
    created_at:       datetime = field(default_factory=datetime.utcnow)
    last_updated:     datetime = field(default_factory=datetime.utcnow)

    def to_neo4j(self) -> dict:
        return {
            "node_id":          self.run_id,
            "label":            self.run_id,
            "node_type":        self.node_type,
            "status":           self.status,
            "cve_ids":          self.cve_ids,
            "technique_ids":    self.technique_ids,
            "tactic_ids":       self.tactic_ids,
            "victim_config":    str(self.victim_config),
            "winner":           self.winner,
            "turn_count":       self.turn_count,
            "duration_seconds": self.duration_seconds,
            "grain_confidence": 0.5,
            "open_questions":   [],
            "challenger_log":   "[]",
            "source":           "graphrange",
            "created_at":       self.created_at.isoformat(),
            "last_updated":     self.last_updated.isoformat(),
        }


@dataclass
class Outcome:
    """
    ARGUS-LAYER-7: Records the result of one technique execution in a scenario.
    Multiple Outcome nodes per ScenarioRun — one per technique attempted.
    """
    outcome_id:          str                     # "OUT-{timestamp}-{technique_id}"
    run_id:              str
    node_type:           str = "outcome"
    technique_id:        str = ""
    cve_id:              str = ""
    victim_config_hash:  str = ""                # sha256 of str(victim_config)
    result:              str = "fail"            # success|fail|partial
    tools_used:          list = field(default_factory=list)
    observations:        dict = field(default_factory=dict)
    detected_by_blue:    bool = False
    created_at:          datetime = field(default_factory=datetime.utcnow)

    def to_neo4j(self) -> dict:
        return {
            "node_id":             self.outcome_id,
            "label":               self.outcome_id,
            "node_type":           self.node_type,
            "run_id":              self.run_id,
            "technique_id":        self.technique_id,
            "cve_id":              self.cve_id,
            "victim_config_hash":  self.victim_config_hash,
            "result":              self.result,
            "tools_used":          self.tools_used,
            "observations":        str(self.observations),
            "detected_by_blue":    self.detected_by_blue,
            "grain_confidence":    1.0 if self.result == "success" else 0.3,
            "open_questions":      [],
            "challenger_log":      "[]",
            "source":              "graphrange",
            "created_at":          self.created_at.isoformat(),
            "last_updated":        self.created_at.isoformat(),
        }
```

**Neo4j constraints to create in the script:**
```cypher
CREATE CONSTRAINT scenario_run_id IF NOT EXISTS
FOR (n:Node) REQUIRE n.node_id IS UNIQUE;

CREATE INDEX scenario_run_type IF NOT EXISTS
FOR (n:Node) ON (n.node_type);

CREATE INDEX outcome_run_id IF NOT EXISTS
FOR (n:Node) ON (n.run_id);
```

**New edge types to add (written at runtime, not here — just document them):**
- `ScenarioRun -[RELATION {relation_type: 'used_technique'}]-> Technique`
- `ScenarioRun -[RELATION {relation_type: 'targeted_cve'}]-> Vulnerability`
- `Outcome -[RELATION {relation_type: 'validates'}]-> Technique`
- `Outcome -[RELATION {relation_type: 'conflicts_with'}]-> Outcome`

---

## Phase 1 — Docker Topology

**Files to create:**
```
graphrange/
  docker/
    supervisor/
      Dockerfile
      supervisor.py
    red/
      Dockerfile
    blue/
      Dockerfile
    victim/
      Dockerfile.template   ← parameterized, filled at runtime from CPE data
```

**Extend `docker-compose.yml` at repo root — do NOT replace it:**
Add a `graphrange` profile so existing dashboard services are unaffected.
```yaml
# Add under services: (existing dashboard service stays unchanged)
  gr-supervisor:
    profiles: ["graphrange"]
    build: graphrange/docker/supervisor
    networks:
      - gr-public
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock  # supervisor manages child containers
    environment:
      - NEO4J_URI=bolt://host.docker.internal:7400
      - NEO4J_PASSWORD=argus1234

networks:
  gr-public:
    name: graphrange-public
```

Red, blue, and victim containers are NOT defined in docker-compose — they are
spawned dynamically by supervisor.py using the Docker SDK per scenario.

### Supervisor container

**`graphrange/docker/supervisor/Dockerfile`:**
```dockerfile
FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y docker.io && rm -rf /var/lib/apt/lists/*
COPY supervisor.py .
RUN pip install docker neo4j requests python-dotenv
CMD ["python", "supervisor.py"]
```

**`graphrange/docker/supervisor/supervisor.py`** must implement:

```python
# ARGUS-LAYER-7: Supervisor — the "internet" and package broker

# Core responsibilities:
# 1. receive_tool_request(agent: str, capability: str) -> tool_name: str
#    - Query tool graph in Neo4j for nodes matching capability
#    - Return best match tool name to requesting agent
#
# 2. deliver_tool(container_name: str, tool_name: str) -> bool
#    - docker exec {container_name} apt-get install -y {tool_name}
#    - Returns True on success, False on failure
#    - NEVER rebuild the container — always exec into running container
#
# 3. spawn_scenario(scenario: dict) -> {red_id, blue_id, victim_id}
#    - docker run red container (from graphrange/docker/red/Dockerfile)
#    - docker run blue container
#    - docker run victim container (built from Dockerfile.template + scenario CPE)
#    - All on gr-public network with NAT isolation
#
# 4. collect_output(container_name: str, command: str) -> str
#    - docker exec {container_name} {command}
#    - Returns raw stdout
#
# 5. teardown_scenario(red_id, blue_id, victim_id) -> None
#    - docker stop + docker rm all three containers
#    - Called after scenario completes regardless of outcome

# Use the docker Python SDK (import docker) not subprocess for container ops.
# For Neo4j queries use the neo4j driver directly — same URI as rest of ARGUS.
```

### Red container

**`graphrange/docker/red/Dockerfile`:**
```dockerfile
FROM kalilinux/kali-rolling:latest
RUN apt-get update && apt-get install -y python3 python3-pip curl wget --no-install-recommends
# NO tools preinstalled — supervisor delivers them on demand
WORKDIR /workspace
CMD ["sleep", "infinity"]
```

### Blue container

**`graphrange/docker/blue/Dockerfile`:**
```dockerfile
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y python3 python3-pip tcpdump net-tools --no-install-recommends
WORKDIR /workspace
# monitoring daemon started by blue agent at scenario start
CMD ["sleep", "infinity"]
```

### Victim container template

**`graphrange/docker/victim/Dockerfile.template`:**
```dockerfile
FROM {base_image}
# {base_image} resolved from CPE at runtime:
# cpe:2.3:o:canonical:ubuntu:20.04 -> ubuntu:20.04
# cpe:2.3:a:apache:http_server:2.4.49 -> httpd:2.4.49 (or closest available)
RUN apt-get update 2>/dev/null || true
{install_commands}
# {install_commands} = apt-get install -y {vulnerable_software}=={version}
EXPOSE {ports}
CMD {start_command}
```

CPE → Docker image resolution logic goes in `graphrange/victim_builder.py`.
Parse CPE string: `cpe:2.3:{part}:{vendor}:{product}:{version}` and map to
available Docker Hub images. Fallback to `ubuntu:22.04` with manual package
install if no direct image match.

---

## Phase 2 — Tool Graph

**File to create:** `graphrange/tool_graph.py`

Tool graph lives in the same Neo4j instance as ARGUS, different node_type.

### Tool node schema
```python
# Node properties (stored via existing graph/schema.py Node dataclass):
# node_type: "tool"
# label: tool name e.g. "nmap"
# properties: {
#   "capability": "network_scanning",     # snake_case capability category
#   "supports_json_output": True,
#   "json_flag": "-oJ",                   # flag to get JSON output, or ""
#   "has_parser_library": True,
#   "parser_library": "python-nmap",      # or ""
#   "install_command": "apt-get install -y nmap",
#   "os_requirements": ["linux"],
#   "requires_root": False,
#   "last_crawled_at": "iso timestamp"
# }
# grain_confidence: 0.8 (crawled from structured source) or 0.5 (LLM fallback)
# source: "crawl" or "llm_derived"
```

### Tool graph queries to implement in `graphrange/tool_graph.py`
```python
def get_tools_by_capability(driver, capability: str) -> list[dict]:
    # ARGUS-LAYER-7: Return tool nodes matching a capability string
    # MATCH (n:Node {node_type: 'tool'}) WHERE n.properties CONTAINS capability
    # Return parsed tool list ordered by grain_confidence DESC

def get_tool_by_name(driver, name: str) -> dict | None:
    # ARGUS-LAYER-7: Return single tool node by name

def write_tool_node(driver, tool: dict) -> None:
    # ARGUS-LAYER-7: MERGE tool node into Neo4j
    # Use existing Node dataclass to_neo4j() for structure
```

### Tool graph crawler

**File to create:** `graphrange/crawler/tool_crawler.py`

```python
# ARGUS-LAYER-7: Crawls tool sources and populates tool graph

# Sources in priority order:
# 1. Kali tool list: https://tools.kali.org/tools-listing (scrape)
#    Fields extractable: name, description, category
# 2. Tool --help / man page via subprocess (for installed tools only)
# 3. GitHub README (use GitHub API, tool's repo)

# For each tool discovered:
# - Extract: name, category (→ capability), description
# - Determine supports_json_output: check if "--json" or "-oJ" or "--format json"
#   appears in --help output or README
# - If structured source has the info → write directly
# - If not → call Qwen3 fast mode with:
#   "Does the tool '{name}' support JSON output? Does it require root?
#    What capability category does it serve from: [network_scanning,
#    exploitation, privilege_escalation, lateral_movement, exfiltration,
#    defensive_monitoring, log_analysis, traffic_capture]?
#    Reply ONLY as JSON: {"supports_json": bool, "requires_root": bool,
#    "capability": str}"
# - Write result to tool graph via write_tool_node()

# Crawl in batches. Sleep 1s between Kali page requests.
# Log every tool written and every LLM fallback used.
```

---

## Phase 3 — Scenario Generator

**File to create:** `graphrange/scenario_generator.py`

```python
# ARGUS-LAYER-7: Generates valid scenario combinations from graph structure.
# The scenario set EMERGES from graph constraints — not manually curated.

def get_valid_scenarios(driver, limit: int = 100) -> list[dict]:
    """
    ARGUS-LAYER-7: Returns list of valid scenario dicts.

    Constraint 1 — Graph edges:
    Only CVE-technique pairs with an existing 'enables' edge are candidates.
    Query:
      MATCH (v:Node {node_type: 'vulnerability'})-[r:RELATION]->(t:Node {node_type: 'technique'})
      WHERE r.relation_type = 'enables'
      RETURN v.node_id, v.properties, t.node_id, t.label, t.expected_observables

    Constraint 2 — Tactic ordering:
    For each technique, get its tactic via enables edge.
    Tactic ordering from MITRE ATT&CK (hardcoded — this doesn't change):
      TA0043 Recon → TA0042 Resource Dev → TA0001 Initial Access →
      TA0002 Execution → TA0003 Persistence → TA0004 Privilege Escalation →
      TA0005 Defense Evasion → TA0006 Credential Access → TA0007 Discovery →
      TA0008 Lateral Movement → TA0009 Collection → TA0010 Exfiltration →
      TA0011 C2 → TA0040 Impact
    A scenario's technique sequence must respect tactic order.
    Eliminate sequences where tactic order is violated.

    Constraint 3 — Victim config:
    Each CVE node's properties['affected'] is a list of CPE strings.
    Each CPE = one possible victim configuration.
    Expand: one scenario per CVE-technique-CPE triple.

    Returns list of scenario dicts:
    {
      "cve_id": str,
      "technique_id": str,
      "tactic_id": str,
      "victim_cpe": str,           # one CPE string from affected list
      "expected_observables": list, # from technique node
      "win_conditions": {
        "red": "technique_executed_successfully",
        "blue": "technique_detected_before_completion",
        "stalemate_turns": 20
      }
    }
    """

def mark_scenario_complete(driver, scenario: dict, run_id: str) -> None:
    """ARGUS-LAYER-7: Record that this scenario was run. Prevents re-running."""
    # Write a lightweight edge: ScenarioRun -[covered]-> Technique
    # So next call to get_valid_scenarios can filter already-run combos

def get_conflict_scenarios(driver) -> list[tuple]:
    """
    ARGUS-LAYER-7: Find Outcome pairs with same technique+config but different result.
    These are open questions waiting to be investigated.
    Returns list of (outcome_id_1, outcome_id_2) tuples.
    """
```

---

## Phase 4 — Execution Layer (extends existing agents)

### Extend `agents/red.py`

**Add these functions — do NOT modify existing ones:**

```python
def execute_attack(driver, supervisor_url: str, scenario: dict,
                   engagement: dict) -> dict:
    """
    ARGUS-LAYER-7: Executes a planned attack in the Docker range.
    Called AFTER plan_attack() returns an engagement.
    supervisor_url: http address of the supervisor container API.

    Flow:
    1. Determine capability needed from scenario technique_id
       - Query technique node for expected_observables
       - Map to tool capability (e.g. observables with "port" → "network_scanning")
    2. Request tool from supervisor:
       POST supervisor_url/tool_request {"agent": "red", "capability": capability}
       → returns {"tool_name": "nmap", "install_command": "apt-get install -y nmap"}
    3. Execute tool via supervisor:
       POST supervisor_url/exec {"container": "red", "command": install_command}
       POST supervisor_url/exec {"container": "red", "command": tool_run_command}
       → returns {"stdout": raw_output}
    4. Normalize observation (see graphrange/observer.py)
    5. Return {
         "status": "executed",
         "tool_used": tool_name,
         "raw_output": stdout,
         "observations": structured_dict,
         "success": bool  # determined by observer
       }

    Use requests library. Timeout 60s per exec call.
    Fail gracefully — if supervisor unreachable, return {"status": "supervisor_error"}.
    """

def _map_observables_to_capability(observables: list[str]) -> str:
    """
    ARGUS-LAYER-7: Rough mapping from observable fields to tool capability category.
    "open_ports" / "running_services" → "network_scanning"
    "os_fingerprint" → "network_scanning"
    "credentials" / "password_hash" → "credential_access"
    "file_path" / "registry_key" → "discovery"
    "shell_access" / "command_output" → "exploitation"
    Default → "network_scanning"
    """
```

### Extend `agents/blue.py`

**Add these functions — do NOT modify existing ones:**

```python
def monitor(supervisor_url: str, container_name: str,
            scenario: dict, stop_event) -> list[dict]:
    """
    ARGUS-LAYER-7: Blue daemon that runs in a thread during red execution.
    Polls the victim container for anomalies while red is attacking.
    stop_event: threading.Event — set by caller when red is done.

    Loop until stop_event.set():
    - POST supervisor_url/exec {"container": "blue",
        "command": "tcpdump -i any -c 10 -nn 2>/dev/null"}
      → parse for anomalous connections to victim IP
    - POST supervisor_url/exec {"container": "victim",
        "command": "ss -tnp 2>/dev/null"}
      → parse for unexpected established connections
    - Sleep 3 seconds between polls
    - Append detection events to list

    Return list of detection event dicts:
    {"timestamp": iso, "type": "unexpected_connection"|"port_scan"|"auth_attempt",
     "detail": str}
    """

def assess_detection(detection_events: list[dict], scenario: dict) -> dict:
    """
    ARGUS-LAYER-7: After scenario ends, assess whether blue detected the attack.
    Returns {"detected": bool, "detection_type": str, "turn_detected": int}
    Simple heuristic — if any detection event matches scenario technique's
    expected observable pattern, detected=True.
    """
```

---

## Phase 5 — Observation Normalizer

**File to create:** `graphrange/observer.py`

```python
# ARGUS-LAYER-7: Normalizes raw tool output into structured observations.
# Schema comes from the graph — not from generic "structure this" prompts.

import ast
import json
import requests

OLLAMA_URL = "http://localhost:11434/api/chat"

def normalize(raw_output: str, technique_id: str, driver) -> dict:
    """
    ARGUS-LAYER-7: Main normalizer entry point.

    1. Query technique node for expected_observables:
       MATCH (n:Node {node_id: $tid}) RETURN n.expected_observables
    2. If tool output is already JSON (starts with '{' or '['):
       → parse directly, extract matching keys, return
    3. If raw stdout:
       → call _slot_fill(raw_output, expected_observables)
    4. Return structured dict with only the expected fields.
    """

def _slot_fill(raw_output: str, schema_fields: list[str]) -> dict:
    """
    ARGUS-LAYER-7: Qwen3 fast mode slot-filling.
    Prompt: "Extract these fields from the tool output: {schema_fields}
    Output: {raw_output[:2000]}
    Return ONLY a JSON object with those keys. Use null for missing fields."
    Parse response. Strip ```json fences. Return dict.
    """

def determine_success(observations: dict, scenario: dict) -> bool:
    """
    ARGUS-LAYER-7: Did the technique succeed?
    Simple check: if expected_observables are non-null in observations → success.
    At least 50% of fields must be non-null for success=True.
    """
```

---

## Phase 6 — Graph Updater

**File to create:** `graphrange/graph_updater.py`

```python
# ARGUS-LAYER-7: Writes execution results back into ARGUS graph.
# This is the learning loop — execution outcomes become graph knowledge.

import hashlib
import ast
from datetime import datetime
from neo4j import GraphDatabase
from graph.schema import ScenarioRun, Outcome

def write_scenario_run(driver, scenario: dict, run_id: str) -> None:
    """ARGUS-LAYER-7: Write ScenarioRun node to Neo4j."""

def write_outcome(driver, run_id: str, scenario: dict,
                  execution_result: dict, detection: dict) -> str:
    """
    ARGUS-LAYER-7: Write Outcome node and its edges.
    Edges written:
    - ScenarioRun -[RELATION {relation_type: 'used_technique'}]-> Technique
    - ScenarioRun -[RELATION {relation_type: 'targeted_cve'}]-> Vulnerability
    - Outcome -[RELATION {relation_type: 'validates'}]-> Technique
      (confidence on this edge = 0.8 if success, 0.2 if fail)
    Returns outcome_id.
    """

def update_technique_confidence(driver, technique_id: str,
                                 result: str, victim_config_hash: str) -> None:
    """
    ARGUS-LAYER-7: Update technique node grain_confidence based on outcome.
    success → grain_confidence += 0.05 (capped at 1.0)
    fail    → grain_confidence -= 0.02 (floored at 0.1)
    Also update last_updated.
    """

def check_and_flag_conflict(driver, outcome_id: str,
                              technique_id: str, victim_config_hash: str,
                              result: str) -> None:
    """
    ARGUS-LAYER-7: Check if a prior Outcome exists for same technique+config
    with opposite result. If so:
    1. Write Outcome -[RELATION {relation_type: 'conflicts_with'}]-> prior_Outcome
    2. Add open_question to Technique node:
       "Conflicting outcomes for {technique_id} on config {victim_config_hash}.
        What distinguishing variable explains the difference?"
    3. Reduce technique grain_confidence by 0.1 (conflict = uncertainty).
    """

def decay_stale_nodes(driver, days_threshold: int = 30) -> int:
    """
    ARGUS-LAYER-7: Reduce grain_confidence on nodes not validated recently.
    MATCH (n:Node {node_type: 'outcome'})
    WHERE n.created_at < (now - days_threshold)
    AND NOT (n)-[:RELATION {relation_type: 'conflicts_with'}]->()
    SET n.grain_confidence = n.grain_confidence * 0.95
    Returns count of decayed nodes.
    """
```

---

## Phase 7 — Scenario Runner (wires everything together)

**File to create:** `graphrange/run_scenario.py`

```python
# ARGUS-LAYER-7: End-to-end scenario orchestration.
# This is the main entry point for GraphRange execution.

import threading
from datetime import datetime
from graphrange.scenario_generator import get_valid_scenarios
from graphrange.observer import normalize, determine_success
from graphrange.graph_updater import (write_scenario_run, write_outcome,
    update_technique_confidence, check_and_flag_conflict)
from agents.red import plan_attack, execute_attack
from agents.blue import monitor, assess_detection
from graph.retrieval import get_driver

SUPERVISOR_URL = "http://gr-supervisor:8000"

def run_one(scenario: dict, driver) -> dict:
    """
    ARGUS-LAYER-7: Run a single scenario end to end.
    1. Write ScenarioRun node (status=running)
    2. Start blue monitor thread (threading.Event for stop signal)
    3. Red: plan_attack() → execute_attack()
    4. Stop blue monitor thread
    5. Assess detection
    6. Write Outcome node
    7. Update technique confidence
    8. Check for conflicts
    9. Update ScenarioRun status to completed/failed/stalemate
    10. Return summary dict
    """

def run_batch(limit: int = 10) -> None:
    """
    ARGUS-LAYER-7: Run up to `limit` valid scenarios sequentially.
    Call run_one() for each. Log outcome. Sleep 5s between scenarios.
    """

if __name__ == "__main__":
    run_batch(limit=10)
```

---

## Add to `requirements.txt`

Append these lines — do not remove existing ones:
```
# GraphRange additions
docker==7.1.0          # Docker SDK for Python (supervisor container management)
flask==3.0.3           # Supervisor HTTP API (lightweight, no langchain)
```

---

## Add to `BACKLOG.md`

Append this section — do not modify existing backlog items:
```markdown
## GraphRange — Cyber Range Expansion (Layer 7+)

Layer 7 that turns ARGUS's planning agents into real executors.
See GRAPHRANGE.md for full spec.

- [ ] Phase 0: populate_observables.py + create_execution_schema.py
- [ ] Phase 1: Docker topology (supervisor, red, blue, victim containers)
- [ ] Phase 2: Tool graph + crawler
- [ ] Phase 3: Scenario generator (constraint elimination from graph)
- [ ] Phase 4: execute_attack() in red.py, monitor() in blue.py
- [ ] Phase 5: Observer (observation normalizer)
- [ ] Phase 6: Graph updater (write outcomes, update confidence, flag conflicts)
- [ ] Phase 7: run_scenario.py end-to-end orchestration
```

---

## Neo4j Connection

Same as rest of ARGUS — no change needed:
```
URI:      bolt://localhost:7400   (or host.docker.internal:7400 from inside Docker)
User:     neo4j
Password: argus1234
Database: argus
```

Properties on all nodes stored as `str(dict)` — parse with `ast.literal_eval()`,
NOT `json.loads()`. This is an existing ARGUS quirk, documented in CONTEXT.md.

---

## Graph Dump Audit (confirmed before writing this file)

From actual dump of 1151 nodes, 1202 edges:

| What GraphRange needs | Status |
|-----------------------|--------|
| CVE nodes with CPE data | ✓ 73 nodes, `affected` field has CPE 2.3 strings |
| CVE → Technique edges | ✓ exists, `relation_type: enables`, e.g. `CVE-2000-0388_enables_T1059` |
| Technique → Tactic edges | ✓ exists, `relation_type: enables`, e.g. `T1053.005_enables_TA0002` |
| Tactic nodes for ordering | ✓ 15 nodes covering all ATT&CK tactics |
| expected_observables field | ✗ MISSING — Phase 0.1 adds it |
| ScenarioRun node type | ✗ MISSING — Phase 0.2 adds it |
| Outcome node type | ✗ MISSING — Phase 0.2 adds it |

---

## Build Order Summary

```
Phase 0.1  scripts/populate_observables.py
Phase 0.2  scripts/create_execution_schema.py + append to graph/schema.py
Phase 1    graphrange/docker/ + extend docker-compose.yml
Phase 2    graphrange/tool_graph.py + graphrange/crawler/tool_crawler.py
Phase 3    graphrange/scenario_generator.py
Phase 4    append execute_attack() to agents/red.py
           append monitor() + assess_detection() to agents/blue.py
Phase 5    graphrange/observer.py
Phase 6    graphrange/graph_updater.py
Phase 7    graphrange/run_scenario.py
```

Do Phase 0 before touching Docker.
Do not modify any existing file except where explicitly instructed above.
