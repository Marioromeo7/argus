# GraphRange Scanner — Vulnerability Assessment Extension

Adds vulnerability scanning with LLM-driven repo analysis, red/blue agent
reasoning, and mitigation reporting to ARGUS+GraphRange.

**Read CLAUDE.md, CONTEXT.md, and GRAPHRANGE.md before touching anything here.**
**Build order: GRAPHRANGE.md phases 0-7 must be complete before starting here.**

---

## Two Separate Systems

This file defines two things that must never be mixed:

**System — the scanner product:**
Takes any repo. Finds vulnerabilities. Advises mitigations.
Runs standalone. No ground truth. No self-evaluation.
Lives in `graphrange/scanner/`.

**Evaluation harness — caliber testing:**
Runs the system on WebGoat. Loads ground truth. Measures how good the system is.
One-time research tool. Not part of the product.
Lives in `eval/`.

The scanner report contains only: vulnerabilities found + mitigation advice.
Comparison tables, false positive analysis, and defense plans are evaluation
artifacts — they never appear in scanner output.

---

## System Architecture

```
Any GitHub repo (all files — source, tests, configs, dependencies)
    ↓
Pass 1 — File Scanner (Qwen3, bounded parallel, 3 workers)
    Flags suspicious code blocks per file
    Long methods chunked by token → merge call before Pass 2
    ↓
Pass 2 — Vulnerability Reasoner (Qwen3, block by block)
    Deep reasoning per flag → one VulnContext per finding
    ↓
Scanner Red Agent
    Queries ARGUS for matching technique/CVE
    Executes GraphRange scenario against repo Docker victim
    Outputs: exploitation path (static + execution)
    ↓
Scanner Blue Agent
    Queries ARGUS for mitigations linked to matched technique
    Runs blue daemon during red execution in sandbox
    Outputs: code fix + detection rule + execution detection
    ↓
Scanner Report (MD + PDF + HTML)
    One finding block per vulnerability
    Vulnerabilities found + mitigation advice only
    No ground truth. No false positive analysis. No comparison.
```

---

## Target Repo for Development and Testing

Use `https://github.com/WebGoat/WebGoat` as the development target.
WebGoat is a deliberately insecure Java Spring Boot app — good signal density.
Clone to `/tmp/webgoat` before running.

This is the development target only. The system works on any repo.

---

## Victim Container — WebGoat Docker

**File to create:** `graphrange/scanner/victim_builder.py`

```python
# ARGUS-SCANNER: Builds victim container from the scanned repo itself.
# Not from CPE data — this is separate from graphrange/victim_builder.py.

import os, subprocess
from graphrange.telemetry import track, count_tokens, patch_last_tokens_out

WEBGOAT_CLONE = "/tmp/webgoat"
IMAGE_TAG     = "argus-scanner-victim:webgoat"

def build_victim_image(repo_path: str = WEBGOAT_CLONE) -> str:
    """
    ARGUS-SCANNER: Builds Docker image for victim container.
    Returns image tag.

    Logic:
    1. If {repo_path}/Dockerfile exists:
       docker build -t {IMAGE_TAG} {repo_path}
       Return IMAGE_TAG.
    2. If no Dockerfile:
       Read {repo_path}/pom.xml
       Call _infer_dockerfile_from_pom(pom_xml) → Dockerfile string
       Write to {repo_path}/Dockerfile.argus
       docker build -f {repo_path}/Dockerfile.argus -t {IMAGE_TAG} {repo_path}
       Return IMAGE_TAG.
    """

def _infer_dockerfile_from_pom(pom_xml: str) -> str:
    """
    ARGUS-SCANNER: Qwen3 reasons over pom.xml to produce a Dockerfile.
    Prompt:
    'Given this Maven pom.xml, write a minimal Dockerfile that:
     1. Uses the correct Java version for this project
     2. Builds with Maven
     3. Runs the resulting JAR or WAR
     pom.xml: {pom_xml[:3000]}
     Return ONLY the Dockerfile content. No explanation.'

    tokens_in  = count_tokens(prompt)
    with track('scanner.victim_builder._infer_dockerfile_from_pom',
                model='qwen', tokens_in=tokens_in, tokens_out=0):
        raw = call_ollama(prompt)
    patch_last_tokens_out(count_tokens(raw))
    """
```

---

## Pass 1 — File Scanner

**File to create:** `graphrange/scanner/file_scanner.py`

```python
# ARGUS-SCANNER: Pass 1 — scans every file in the repo for suspicious patterns.
# All files: source, tests, configs, dependencies.
# Skips only binary files.

import os, json, threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from graphrange.telemetry import track, count_tokens, patch_last_tokens_out

SKIP_EXTENSIONS = {'.class', '.jar', '.war', '.png', '.jpg', '.gif',
                   '.ico', '.woff', '.ttf', '.eot', '.svg', '.zip'}
MAX_FILE_TOKENS = 6000   # Qwen3 8B safe context per call
CHUNK_OVERLAP   = 200    # token overlap between chunks
MAX_WORKERS     = 3      # bounded parallelism — safe for local Qwen3 8B
CALL_TIMEOUT    = 90     # seconds per Qwen call before skipping file

def scan_repo(repo_path: str) -> list[dict]:
    """
    ARGUS-SCANNER: Walks entire repo. Returns merged flag list.

    1. Walk all files, skip SKIP_EXTENSIONS.
    2. For each file: if tokens <= MAX_FILE_TOKENS → one work unit.
       If tokens > MAX_FILE_TOKENS → split by method/class boundary
       (blank lines between top-level declarations) or raw token count
       with CHUNK_OVERLAP. Each chunk = one work unit with chunk metadata.
    3. Submit all work units to ThreadPoolExecutor(max_workers=MAX_WORKERS).
       Each worker calls _scan_file() for its unit.
       Timeout per future: CALL_TIMEOUT seconds. Log warning and skip on timeout.
    4. Collect results. Log progress every 10 completed files.
    5. Call merge_chunks() on all results.
    6. Return merged flag list.
    """

def _scan_file(filepath: str, content: str,
               chunk_index: int = 0, total_chunks: int = 1) -> list[dict]:
    """
    ARGUS-SCANNER: Sends one file or chunk to Qwen3.

    Prompt:
    'You are a security scanner. File: {filepath}
     {chunk_info}  ← "Chunk {i} of {n} — hold conclusions until final chunk"
                      if total_chunks > 1, else omit

     Identify suspicious patterns that could be security vulnerabilities.
     Return a JSON array:
     [{"line_start": int, "line_end": int, "code_block": str,
       "suspected_vuln_type": str, "cwe": str, "confidence": float,
       "chunk_index": int, "total_chunks": int,
       "needs_merge": bool}]
     If nothing found, return [].
     Return ONLY the JSON array.'

    tokens_in = count_tokens(prompt)
    with track('scanner.file_scanner._scan_file', model='qwen',
                tokens_in=tokens_in, tokens_out=0):
        raw = call_ollama(prompt)
    patch_last_tokens_out(count_tokens(raw))

    Parse response. Strip ```json fences. Add filepath to each flag.
    Return list of flag dicts.
    """

def merge_chunks(flags: list[dict]) -> list[dict]:
    """
    ARGUS-SCANNER: Merges chunked findings from same file.
    Groups by filepath + suspected_vuln_type where needs_merge=True.
    Calls _merge_call() per group. Pass-through for needs_merge=False.
    """

def _merge_call(chunk_flags: list[dict]) -> dict:
    """
    ARGUS-SCANNER: Qwen3 merges partial findings from chunked method.

    Prompt:
    'These are partial findings from different chunks of the same file/method.
     Merge into a single coherent finding: {json.dumps(chunk_flags)}
     Return a single JSON object:
     {line_start, line_end, code_block (combined relevant snippets),
      suspected_vuln_type, cwe, confidence, filepath, needs_merge: false}
     If chunks describe different vulnerabilities, return the most severe.
     Return ONLY the JSON object.'

    tokens_in = count_tokens(prompt)
    with track('scanner.file_scanner._merge_call', model='qwen',
                tokens_in=tokens_in, tokens_out=0):
        raw = call_ollama(prompt)
    patch_last_tokens_out(count_tokens(raw))
    """
```

---

## Pass 2 — Vulnerability Reasoner

**File to create:** `graphrange/scanner/vuln_reasoner.py`

```python
# ARGUS-SCANNER: Pass 2 — deep reasoning per flagged block.
# Produces one VulnContext dict per finding.
# VulnContext is input to scanner red and blue agents.

from graphrange.telemetry import track, count_tokens, patch_last_tokens_out

def reason_over_flags(flags: list[dict]) -> list[dict]:
    """
    ARGUS-SCANNER: Processes each Pass 1 flag into a VulnContext.
    If flag code_block tokens > MAX_FILE_TOKENS: chunk, merge, then reason.
    Returns list of VulnContext dicts.
    """

def _reason_block(flag: dict) -> dict:
    """
    ARGUS-SCANNER: Deep Qwen3 reasoning over one suspicious block.

    Prompt:
    'You are a security researcher analyzing a specific vulnerability.
     File: {filepath} Lines: {line_start}-{line_end}
     Suspected type: {suspected_vuln_type} CWE: {cwe}
     Code: {code_block}

     Return detailed analysis as JSON:
     {"filepath": str, "line_start": int, "line_end": int,
      "vuln_type": str, "cwe": str,
      "severity": "Critical|High|Medium|Low",
      "description": str,
      "attack_vector": str,
      "impact": str,
      "argus_query_terms": [str],  ← 2-4 terms to search ARGUS graph
      "confidence": float}
     Return ONLY the JSON object.'

    tokens_in = count_tokens(prompt)
    with track('scanner.vuln_reasoner._reason_block', model='qwen',
                tokens_in=tokens_in, tokens_out=0):
        raw = call_ollama(prompt)
    patch_last_tokens_out(count_tokens(raw))
    """
```

---

## Scanner Red Agent

**File to create:** `graphrange/scanner/scanner_red.py`

```python
# ARGUS-SCANNER: Scanner Red Agent.
# Separate from agents/red.py — reasons over code vulnerability context.
# Does NOT write to ARGUS graph. Output goes to report only.

from graph.retrieval import get_driver
from graphrange.telemetry import track, count_tokens, patch_last_tokens_out
from graphrange.run_scenario import run_one

SANDBOX_AVAILABLE = False  # set by run_scanner() health check

def analyze(vuln_context: dict, driver, sandbox: bool = False) -> dict:
    """
    ARGUS-SCANNER: Full red analysis for one VulnContext.

    Step 1 — ARGUS lookup:
    MATCH (n:Node)
    WHERE any(term IN $terms WHERE toLower(n.properties) CONTAINS term
           OR toLower(n.label) CONTAINS term)
    AND n.node_type IN ['technique', 'vulnerability']
    RETURN n.node_id, n.node_type, n.label, n.grain_confidence
    ORDER BY n.grain_confidence DESC LIMIT 5

    Step 2 — Red reasoning (Qwen3):
    Prompt:
    'You are a red team researcher. Given this vulnerability and related
     MITRE ATT&CK techniques from our knowledge graph:
     Vulnerability: {description}
     Attack vector: {attack_vector}
     Matched techniques: {json.dumps(matched_techniques)}

     Describe the exploitation path:
     {"exploitation_path": str, "matched_technique_id": str,
      "matched_cve_id": str,  ← CVE from graph if found, else ""
      "attack_steps": [str], "requires_auth": bool,
      "network_accessible": bool}'

    tokens_in = count_tokens(prompt)
    with track('scanner.scanner_red.analyze', model='qwen',
                tokens_in=tokens_in, tokens_out=0):
        raw = call_ollama(prompt)
    patch_last_tokens_out(count_tokens(raw))

    Step 3 — Sandbox execution (only if sandbox=True):
    scenario = {
      "cve_id": matched_cve_id or vuln_context["cwe"],
      "technique_id": matched_technique_id,
      "victim_image": IMAGE_TAG,
      "expected_observables": ["http_response", "error_output", "shell_access"],
      "win_conditions": {"red": "vulnerability_triggered",
                         "blue": "attack_detected", "stalemate_turns": 10}
    }
    execution_result = run_one(scenario, driver)

    If sandbox=False:
    execution_result = {"status": "skipped", "reason": "sandbox_unavailable"}

    Return:
    {"vuln_context": vuln_context, "matched_technique_id": str,
     "matched_cve_id": str, "exploitation_path": str,
     "attack_steps": [str], "execution_result": execution_result,
     "source": "scanner_red"}
    """
```

---

## Scanner Blue Agent

**File to create:** `graphrange/scanner/scanner_blue.py`

```python
# ARGUS-SCANNER: Scanner Blue Agent.
# Separate from agents/blue.py — advises on code-level defenses.
# Combines static ARGUS mitigation lookup with sandbox detection.
# Does NOT write to ARGUS graph. Output goes to report only.

from graph.retrieval import get_driver
from graphrange.telemetry import track, count_tokens, patch_last_tokens_out

def analyze(vuln_context: dict, red_findings: dict, driver,
            sandbox: bool = False) -> dict:
    """
    ARGUS-SCANNER: Full blue analysis for one VulnContext.

    Step 1 — ARGUS mitigation lookup:
    MATCH (m:Node {node_type: 'mitigation'})-[r:RELATION]->(t:Node {node_id: $tid})
    RETURN m.node_id, m.label, m.properties, m.grain_confidence
    ORDER BY m.grain_confidence DESC LIMIT 5

    Also query by CWE term:
    MATCH (m:Node {node_type: 'mitigation'})
    WHERE toLower(m.properties) CONTAINS $cwe_term
    RETURN m.node_id, m.label, m.properties LIMIT 3

    Step 2 — Static defensive advice (Qwen3):
    Prompt:
    'You are a blue team security engineer. Given this vulnerability and
     the red team exploitation path, provide defensive recommendations.
     Vulnerability: {description}
     File: {filepath} lines {line_start}-{line_end}
     Exploitation path: {exploitation_path}
     ARGUS mitigations: {json.dumps(argus_mitigations)}

     Return as JSON:
     {"code_fix": str,
      "detection_rule": str,
      "argus_mitigations_applied": [str],
      "priority": "Critical|High|Medium|Low",
      "static_advice": str}'

    tokens_in = count_tokens(prompt)
    with track('scanner.scanner_blue.analyze', model='qwen',
                tokens_in=tokens_in, tokens_out=0):
        raw = call_ollama(prompt)
    patch_last_tokens_out(count_tokens(raw))

    Step 3 — Execution detection (only if sandbox=True):
    Read red_findings['execution_result']['detected_by_blue']
    and red_findings['execution_result']['detection_events'].
    If sandbox=False: execution_detected=False, detection_events=[].

    Return:
    {"vuln_context": vuln_context, "code_fix": str,
     "detection_rule": str, "static_advice": str,
     "execution_detected": bool, "detection_events": list,
     "argus_mitigations": list, "priority": str,
     "source": "scanner_blue"}
    """
```

---

## Scanner Report Generator

**File to create:** `graphrange/scanner/scanner_report.py`

```python
# ARGUS-SCANNER: Writes the scanner product report.
# Contains only: vulnerabilities found + mitigation advice.
# No ground truth. No comparison. No false positive analysis.
# Those are eval/ concerns.

def write_scanner_report(findings: list[dict],
                         output_prefix: str = "reports/scanner") -> None:
    """
    ARGUS-SCANNER: Writes report in three formats.
    {output_prefix}.md, {output_prefix}.pdf, {output_prefix}.html

    MD structure per finding:
    ## [CWE] — [vuln_type] — [severity] — [priority]
    **File:** [filepath] lines [start]-[end]
    **Matched Technique:** [T-ID] — [label] (or 'none found in graph')
    **Matched CVE:** [CVE-ID] (or 'none found in graph')

    ### Vulnerability
    [description]
    **Attack vector:** [attack_vector]
    **Impact:** [impact]

    ### Code
    ```java
    [code_block]
    ```

    ### Exploitation Path (Red)
    [exploitation_path]
    **Steps:** 1. ... 2. ...
    **Sandbox:** [success|fail|skipped]

    ### Mitigation (Blue)
    **Code Fix:** [code_fix]
    **Detection Rule:** [detection_rule]
    **Sandbox Detection:** [yes|no|skipped]
    **ARGUS Mitigations:** [list]
    **General Advice:** [static_advice]

    ---

    PDF: use reportlab.
    HTML: self-contained, dark theme matching ARGUS dashboard (#080814 bg,
          TYPE_COLOR accent palette from GraphView.jsx).
    """
```

---

## Scanner Orchestrator

**File to create:** `graphrange/scanner/run_scanner.py`

```python
# ARGUS-SCANNER: Full scanner pipeline. Entry point for the product.
# Takes a repo path. Produces a vulnerability + mitigation report.

import os, subprocess
from graphrange.scanner.victim_builder import build_victim_image
from graphrange.scanner.file_scanner import scan_repo, merge_chunks
from graphrange.scanner.vuln_reasoner import reason_over_flags
from graphrange.scanner.scanner_red import analyze as red_analyze
from graphrange.scanner.scanner_blue import analyze as blue_analyze
from graphrange.scanner.scanner_report import write_scanner_report
from graphrange.telemetry import print_summary
from graph.retrieval import get_driver

def _check_range_health() -> bool:
    """ARGUS-SCANNER: Verifies GraphRange supervisor is reachable."""
    import requests
    try:
        return requests.get("http://gr-supervisor:8000/health",
                            timeout=5).status_code == 200
    except Exception:
        return False

def run_scanner(repo_path: str, output_prefix: str = "reports/scanner") -> list[dict]:
    """
    ARGUS-SCANNER: Full pipeline.

    1. Check sandbox health → set sandbox flag
    2. Clone repo if not present (subprocess git clone --depth=1)
    3. Build victim container from repo
    4. Pass 1: scan_repo() → merge_chunks() → flags
    5. Pass 2: reason_over_flags() → vuln_contexts
    6. For each vuln_context:
       a. red_analyze(vc, driver, sandbox=sandbox_available)
       b. blue_analyze(vc, red, driver, sandbox=sandbox_available)
       c. Combine into finding dict
    7. write_scanner_report(findings, output_prefix)
    8. print_summary() — telemetry
    9. Return findings

    Log: repo path, file count, flag count, vuln count, sandbox status.
    """
    os.makedirs("reports", exist_ok=True)
    driver = get_driver()

    sandbox = _check_range_health()
    if not sandbox:
        print("[Scanner] Sandbox unavailable — static analysis only.")
        print("          Start range: docker compose --profile graphrange up -d")

    print(f"[Scanner] Building victim container from {repo_path}...")
    build_victim_image(repo_path)

    print("[Scanner] Pass 1 — scanning all files...")
    flags = merge_chunks(scan_repo(repo_path))
    print(f"[Scanner] {len(flags)} flags found")

    print("[Scanner] Pass 2 — deep reasoning...")
    vuln_contexts = reason_over_flags(flags)
    print(f"[Scanner] {len(vuln_contexts)} vulnerabilities identified")

    findings = []
    for i, vc in enumerate(vuln_contexts):
        print(f"[Scanner] {i+1}/{len(vuln_contexts)} "
              f"{vc.get('vuln_type','?')} in {vc.get('filepath','?')}")
        red  = red_analyze(vc, driver, sandbox=sandbox)
        blue = blue_analyze(vc, red, driver, sandbox=sandbox)
        findings.append({"vuln_context": vc, "red": red, "blue": blue})

    write_scanner_report(findings, output_prefix)
    print_summary()
    driver.close()
    return findings

if __name__ == "__main__":
    import sys
    repo = sys.argv[1] if len(sys.argv) > 1 else "/tmp/webgoat"
    run_scanner(repo)
```

---

## Telemetry Tracker

**File to create:** `graphrange/telemetry.py`

```python
# ARGUS-LAYER-7: Tracks all LLM calls — tokens, cost estimates, system load.
# Written to logs/telemetry.jsonl (one JSON line per call).

import time, json, os, psutil
from datetime import datetime
from contextlib import contextmanager
from threading import Lock

PRICING = {
    "gpt4o":  {"input": 2.50 / 1_000_000, "output": 10.00 / 1_000_000},
    "claude": {"input": 3.00 / 1_000_000, "output": 15.00 / 1_000_000},
    "qwen":   {"input": 0.0,               "output": 0.0},
}

LOG_PATH     = "logs/telemetry.jsonl"
_lock        = Lock()
_session_log: list[dict] = []

import tiktoken
_enc = tiktoken.get_encoding("cl100k_base")

def count_tokens(text: str) -> int:
    """ARGUS-LAYER-7: Approximate token count."""
    return len(_enc.encode(text))

@contextmanager
def track(caller: str, model: str = "qwen",
          tokens_in: int = 0, tokens_out: int = 0):
    """
    ARGUS-LAYER-7: Context manager for any LLM call.
    caller: function name e.g. 'scanner.file_scanner._scan_file'
    Always pass tokens_in before call. Call patch_last_tokens_out() after.

    Logs: caller, model, tokens_in, tokens_out, inference_time_s,
          cpu_percent, ram_used_gb, est_cost_gpt4o, est_cost_claude, timestamp
    """
    os.makedirs("logs", exist_ok=True)
    t0  = time.time()
    cpu = psutil.cpu_percent(interval=None)
    ram = psutil.virtual_memory().used / 1e9
    yield
    elapsed = round(time.time() - t0, 2)
    entry = {
        "timestamp":        datetime.utcnow().isoformat(),
        "caller":           caller,
        "model":            model,
        "tokens_in":        tokens_in,
        "tokens_out":       tokens_out,
        "inference_time_s": elapsed,
        "cpu_percent":      cpu,
        "ram_used_gb":      round(ram, 2),
        "est_cost_gpt4o":   round(tokens_in  * PRICING["gpt4o"]["input"] +
                                  tokens_out * PRICING["gpt4o"]["output"], 6),
        "est_cost_claude":  round(tokens_in  * PRICING["claude"]["input"] +
                                  tokens_out * PRICING["claude"]["output"], 6),
    }
    with _lock:
        _session_log.append(entry)
        with open(LOG_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")

def patch_last_tokens_out(tokens_out: int) -> None:
    """
    ARGUS-LAYER-7: Updates tokens_out and recalculates costs on last entry.
    Call immediately after parsing LLM response.
    """
    with _lock:
        if not _session_log:
            return
        e = _session_log[-1]
        e["tokens_out"]      = tokens_out
        e["est_cost_gpt4o"]  = round(e["tokens_in"] * PRICING["gpt4o"]["input"] +
                                     tokens_out      * PRICING["gpt4o"]["output"], 6)
        e["est_cost_claude"] = round(e["tokens_in"] * PRICING["claude"]["input"] +
                                     tokens_out      * PRICING["claude"]["output"], 6)
        if os.path.exists(LOG_PATH):
            with open(LOG_PATH, "r") as f:
                lines = f.readlines()
            if lines:
                lines[-1] = json.dumps(e) + "\n"
                with open(LOG_PATH, "w") as f:
                    f.writelines(lines)

def print_summary() -> None:
    """ARGUS-LAYER-7: Prints session totals."""
    if not _session_log:
        print("No telemetry recorded.")
        return
    print(f"Telemetry: {len(_session_log)} calls | "
          f"{sum(e['tokens_in'] for e in _session_log)} in / "
          f"{sum(e['tokens_out'] for e in _session_log)} out tokens | "
          f"{round(sum(e['inference_time_s'] for e in _session_log), 1)}s | "
          f"est GPT-4o: ${sum(e['est_cost_gpt4o'] for e in _session_log):.4f} | "
          f"est Claude: ${sum(e['est_cost_claude'] for e in _session_log):.4f}")

def get_session_log() -> list[dict]:
    """ARGUS-LAYER-7: Returns full session log for dashboard API."""
    return list(_session_log)
```

---

## Dashboard Extensions

### Extend `dashboard/api/main.py` — append only

```python
# ARGUS-SCANNER: Telemetry endpoint
import json as _json

@app.get("/api/telemetry")
def telemetry():
    """Returns last 200 telemetry entries from logs/telemetry.jsonl."""
    path = "logs/telemetry.jsonl"
    if not os.path.exists(path):
        return {"entries": [], "summary": {}}
    entries = []
    with open(path) as f:
        for line in f:
            try: entries.append(_json.loads(line.strip()))
            except: continue
    entries = entries[-200:]
    if not entries:
        return {"entries": [], "summary": {}}
    return {
        "entries": entries,
        "summary": {
            "total_calls":      len(entries),
            "total_tokens_in":  sum(e.get("tokens_in", 0)        for e in entries),
            "total_tokens_out": sum(e.get("tokens_out", 0)       for e in entries),
            "total_time_s":     round(sum(e.get("inference_time_s", 0) for e in entries), 2),
            "est_cost_gpt4o":   round(sum(e.get("est_cost_gpt4o", 0)  for e in entries), 4),
            "est_cost_claude":  round(sum(e.get("est_cost_claude", 0)  for e in entries), 4),
        }
    }

@app.get("/api/llm/navigate")
def llm_navigate(query: str):
    """
    ARGUS-SCANNER: LLM graph navigation.
    Returns node_id LLM identifies for the query.
    UI uses this to pan/zoom to the node.

    1. Fetch all nodes (id + label + type, limit 1200)
    2. Qwen3 prompt:
       'Given these graph nodes: {node_list[:800]}
        User is looking for: {query}
        Return ONLY the node_id of the best match. Nothing else.'
    3. Validate node_id exists. Return {node_id, label, type}.
    Log with telemetry.track('dashboard.llm_navigate', model='qwen').
    """
    from graphrange.telemetry import track as tel, count_tokens, patch_last_tokens_out
    import requests as _req

    d = _driver()
    try:
        with d.session() as s:
            rows = list(s.run(
                "MATCH (n:Node) RETURN n.node_id AS id, n.label AS label, "
                "n.node_type AS type LIMIT 1200"
            ))
    finally:
        d.close()

    node_list = [{"id": r["id"], "label": r["label"], "type": r["type"]}
                 for r in rows if r["id"]]
    node_map  = {n["id"]: n for n in node_list}

    prompt = (f"Given these graph nodes:\n{json.dumps(node_list[:800])}\n\n"
              f"User is looking for: {query}\n\n"
              f"Return ONLY the node_id of the best match. Nothing else.")

    tokens_in = count_tokens(prompt)
    node_id   = ""
    with tel("dashboard.llm_navigate", model="qwen",
              tokens_in=tokens_in, tokens_out=0):
        resp = _req.post(
            "http://localhost:11434/api/chat",
            json={"model": "qwen3:8b", "think": False,
                  "messages": [{"role": "user", "content": prompt}],
                  "stream": False},
            timeout=30
        ).json()
        node_id = resp.get("message", {}).get("content", "").strip().strip('"')
    patch_last_tokens_out(count_tokens(node_id))

    if node_id not in node_map:
        raise HTTPException(status_code=404, detail=f"Node not found: {node_id}")
    return node_map[node_id]
```

### New file: `dashboard/ui/src/components/LLMSearch.jsx`

```jsx
// ARGUS-SCANNER: LLM graph navigation — user types query, graph pans to node.
import React, { useState } from 'react'

export default function LLMSearch({ onNavigate }) {
  const [query,   setQuery]   = useState('')
  const [loading, setLoading] = useState(false)
  const [error,   setError]   = useState(null)

  async function handleSearch(e) {
    e.preventDefault()
    if (!query.trim()) return
    setLoading(true); setError(null)
    try {
      const res = await fetch(`/api/llm/navigate?query=${encodeURIComponent(query)}`)
      if (!res.ok) throw new Error('Node not found')
      onNavigate(await res.json())
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <form className="llm-search" onSubmit={handleSearch}>
      <input className="llm-search-input" type="text"
        placeholder="Navigate graph… e.g. 'log4shell' or 'lateral movement'"
        value={query} onChange={e => setQuery(e.target.value)} disabled={loading} />
      <button className="llm-search-btn" type="submit" disabled={loading}>
        {loading ? '…' : '↵'}
      </button>
      {error && <span className="llm-search-error">{error}</span>}
    </form>
  )
}
```

### Extend `dashboard/ui/src/components/GraphView.jsx`

```jsx
// ARGUS-SCANNER: Add navigateTo via forwardRef. Append to existing file.
// Change import line:
import React, { useRef, useCallback, useImperativeHandle, forwardRef } from 'react'

// Change export signature:
// FROM: export default function GraphView({ graphData, selected, onSelect })
// TO:   const GraphView = forwardRef(function GraphView(
//         { graphData, selected, onSelect, onNavigated }, ref) {

// Add after fgRef declaration:
useImperativeHandle(ref, () => ({
  navigateTo(node) {
    if (!fgRef.current || !node) return
    fgRef.current.centerAt(node.x, node.y, 800)  // smooth pan 800ms
    fgRef.current.zoom(6, 800)                     // zoom to level 6
    onNavigated && onNavigated(node)
  }
}))

// Change end of file:
// FROM: export default function GraphView
// TO:   export default GraphView
```

### Extend `dashboard/ui/src/App.jsx`

```jsx
// ARGUS-SCANNER: Wire LLMSearch + TelemetryPanel. Append to existing.
// Add imports:
import LLMSearch      from './components/LLMSearch'
import TelemetryPanel from './components/TelemetryPanel'

// Add ref:
const graphRef = useRef()

// Add handler:
function handleNavigate(node) {
  const live = graphData.nodes.find(n => n.id === node.node_id)
  if (live && graphRef.current) {
    graphRef.current.navigateTo(live)
    setSelected(live)
  }
}

// Update GraphView JSX:
// <GraphView ref={graphRef} ... onNavigated={node => setSelected(node)} />

// Add LLMSearch inside <header> after header-brand div:
// <LLMSearch onNavigate={handleNavigate} />

// Add TelemetryPanel inside workspace div after NodeSidebar:
// <TelemetryPanel />
```

### New file: `dashboard/ui/src/components/TelemetryPanel.jsx`

```jsx
// ARGUS-SCANNER: Telemetry panel. Polls /api/telemetry every 10s.
import React, { useState, useEffect } from 'react'

export default function TelemetryPanel() {
  const [data, setData] = useState(null)
  const [open, setOpen] = useState(false)

  useEffect(() => {
    async function poll() {
      try {
        const res = await fetch('/api/telemetry')
        if (res.ok) setData(await res.json())
      } catch {}
    }
    poll()
    const id = setInterval(poll, 10_000)
    return () => clearInterval(id)
  }, [])

  if (!data) return null
  const { summary, entries } = data

  return (
    <div className={`telemetry-panel ${open ? 'open' : ''}`}>
      <div className="telemetry-header" onClick={() => setOpen(o => !o)}>
        <span>⬡ Telemetry</span>
        <span className="telemetry-costs">
          GPT-4o equiv: ${summary.est_cost_gpt4o?.toFixed(4)}
          &nbsp;·&nbsp;Claude equiv: ${summary.est_cost_claude?.toFixed(4)}
          &nbsp;·&nbsp;{summary.total_calls} calls
          &nbsp;·&nbsp;{summary.total_time_s}s
        </span>
        <span>{open ? '▲' : '▼'}</span>
      </div>
      {open && (
        <div className="telemetry-log">
          {[...entries].reverse().map((e, i) => (
            <div key={i} className="telemetry-entry">
              <span className="tel-caller">{e.caller}</span>
              <span className="tel-model">{e.model}</span>
              <span className="tel-tokens">{e.tokens_in}→{e.tokens_out} tok</span>
              <span className="tel-time">{e.inference_time_s}s</span>
              <span className="tel-cost">${e.est_cost_gpt4o?.toFixed(5)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
```

---

## Evaluation Harness (separate from the product)

Lives in `eval/`. Runs the scanner on WebGoat, loads ground truth,
measures caliber. Not part of the product. Not called by the scanner.

**File to create:** `eval/run_eval.py`

```python
# ARGUS-EVAL: Caliber evaluation of the scanner against WebGoat ground truth.
# Run this AFTER the scanner has produced reports/scanner.md.
# This is a research tool — not part of the product pipeline.

from eval.ground_truth import load_ground_truth
from eval.comparator import compare, write_comparison_tables
from eval.false_positive_analyzer import analyze, write_fp_report
from eval.defense_plan import generate_defense_plan_prompt
from graphrange.scanner.run_scanner import run_scanner

WEBGOAT_CLONE = "/tmp/webgoat"

def run_eval():
    """
    ARGUS-EVAL: Full evaluation pipeline.

    1. Run scanner on WebGoat → findings
    2. Load ground truth from GitHub advisories + SECURITY.md
    3. Compare findings against ground truth → two separate tables:
       Table A: CVE-identified findings (exact join on CVE ID)
       Table B: Code-level findings (CWE/SCAN IDs, no join to ground truth)
    4. Summarizing Qwen call: reads both tables, writes plain language
       interpretation of what the system found, where it agreed with
       ground truth, what the code-only findings suggest
    5. False positive analysis (CVEs found but not in ground truth)
    6. Print defense plan prompt for Claude Code
    """
    findings     = run_scanner(WEBGOAT_CLONE, output_prefix="eval/scanner_output")
    ground_truth = load_ground_truth()
    comparison   = compare(findings, ground_truth)
    write_comparison_tables(comparison)        # Table A + Table B + Qwen summary
    write_fp_report(analyze(comparison))
    generate_defense_plan_prompt()

if __name__ == "__main__":
    run_eval()
```

**File to create:** `eval/ground_truth.py`

```python
# ARGUS-EVAL: Loads WebGoat known vulnerabilities as ground truth.

def load_ground_truth() -> list[dict]:
    """
    ARGUS-EVAL: Two sources merged and deduplicated by CVE ID.

    Source 1 — GitHub Security Advisories API:
    GET https://api.github.com/repos/WebGoat/WebGoat/security-advisories
    Headers: Accept: application/vnd.github+json
    Parse: ghsa_id, cve_id, severity, summary, vulnerable_versions

    Source 2 — SECURITY.md raw:
    GET https://raw.githubusercontent.com/WebGoat/WebGoat/main/SECURITY.md
    Parse for CVE IDs and descriptions.

    Return list of:
    {"cve_id": str, "severity": str, "summary": str, "source": str}
    Write to eval/ground_truth.md.
    """
```

**File to create:** `eval/comparator.py`

```python
# ARGUS-EVAL: Builds two comparison tables + Qwen summary.

def compare(findings: list[dict], ground_truth: list[dict]) -> dict:
    """
    ARGUS-EVAL: Separates findings into two buckets.

    Table A — CVE-identified findings:
    Scanner findings with a matched_cve_id joined exactly to ground truth CVE IDs.
    Columns: CVE | Found by Scanner | In Ground Truth | Severity

    Table B — Code-level findings:
    Scanner findings with only CWE/SCAN IDs — no ground truth join attempted.
    Columns: CWE | File | Vuln Type | Severity

    Returns:
    {"table_a": [...], "table_b": [...],
     "missed_cves": [...],   ← ground truth CVEs scanner didn't find
     "coverage": float}      ← % of ground truth CVEs found (Table A only)
    """

def write_comparison_tables(comparison: dict) -> None:
    """
    ARGUS-EVAL: Writes eval/comparison.md with Table A, Table B, and summary.

    After both tables, one Qwen3 call reads the full comparison dict and writes
    a plain language summary section:
    Prompt:
    'Given these vulnerability assessment results vs ground truth:
     {json.dumps(comparison)}
     Write a 3-5 paragraph plain language summary:
     - What the scanner found overall
     - Where it agreed with ground truth
     - What the code-only findings (Table B) suggest
     - Notable gaps or patterns
     No headers. Just clear paragraphs a security team can read.'

    Append Qwen summary to eval/comparison.md after both tables.
    Note at top of file:
    > Table A matches are exact CVE ID joins.
    > Table B findings have no ground truth equivalent — they are code-level
    > findings the scanner produced independently.
    > Summary section is Qwen3 interpretation — review critically.
    """
```

**File to create:** `eval/false_positive_analyzer.py`

```python
# ARGUS-EVAL: Analyzes Table A findings not in ground truth.
# These are CVEs the scanner found that ground truth doesn't list.
# Not discarded — reported as unvalidated findings needing investigation.

def analyze(comparison: dict) -> dict:
    """
    ARGUS-EVAL: For each Table A finding not in ground truth:
    Classify as unvalidated_positive or likely_noise based on:
    - Is the CVE ID a real CVE format? (CVE-XXXX-XXXX)
    - Does it exist in the ARGUS graph with grain_confidence > 0.5?
    - Is the cvss_score > 0?
    Returns {"false_positives": [{"cve_id", "classification", "reason", "investigate"}]}
    """

def write_fp_report(fp_analysis: dict) -> None:
    """ARGUS-EVAL: Writes eval/false_positives.md. None discarded."""
```

**File to create:** `eval/defense_plan.py`

```python
# ARGUS-EVAL: Generates Claude Code prompt for defense plan document.

PROMPT = """
Read these eval reports before writing (run from repo root):
  eval/comparison.md
  eval/false_positives.md
  eval/scanner_output.md  ← the scanner's full vulnerability report

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
```

---

## File Structure

```
graphrange/
  telemetry.py                    ← token counting, cost tracking, system load
  scanner/
    victim_builder.py             ← Docker image from repo Dockerfile or pom.xml
    file_scanner.py               ← Pass 1, parallel Qwen, chunk/merge
    vuln_reasoner.py              ← Pass 2, VulnContext per finding
    scanner_red.py                ← ARGUS lookup + exploitation + sandbox
    scanner_blue.py               ← ARGUS mitigations + advice + sandbox
    scanner_report.py             ← MD + PDF + HTML report (product output)
    run_scanner.py                ← pipeline entry point, takes any repo path

eval/
  run_eval.py                     ← evaluation orchestrator
  ground_truth.py                 ← WebGoat GitHub advisories loader
  comparator.py                   ← Table A + Table B + Qwen summary
  false_positive_analyzer.py      ← classify unvalidated findings
  defense_plan.py                 ← Claude Code prompt generator

reports/
  scanner.md                      ← product output: vulns + mitigations
  scanner.pdf
  scanner.html

eval/
  scanner_output.md               ← scanner run used for evaluation
  ground_truth.md
  comparison.md                   ← Table A + Table B + Qwen summary
  false_positives.md
  defense_plan.md                 ← Claude Code writes this
```

---

## Add to `requirements.txt`

```
# Scanner additions
reportlab==4.1.0     # PDF generation
psutil==5.9.8        # system load metrics
tiktoken==0.7.0      # token counting
```

---

## Add to `BACKLOG.md`

```markdown
## GraphRange Scanner (Layer 8)

See GRAPHRANGE_SCANNER.md for full spec.

### Product (graphrange/scanner/)
- [ ] telemetry.py
- [ ] victim_builder.py
- [ ] file_scanner.py (Pass 1, parallel, chunk/merge)
- [ ] vuln_reasoner.py (Pass 2)
- [ ] scanner_red.py
- [ ] scanner_blue.py
- [ ] scanner_report.py (MD + PDF + HTML)
- [ ] run_scanner.py

### Dashboard extensions
- [ ] LLMSearch.jsx + pan/zoom navigation
- [ ] TelemetryPanel.jsx
- [ ] Extend GraphView.jsx (forwardRef + navigateTo)
- [ ] Extend App.jsx
- [ ] Extend dashboard/api/main.py (/api/telemetry + /api/llm/navigate)

### Evaluation harness (eval/)
- [ ] ground_truth.py
- [ ] comparator.py (Table A + Table B + Qwen summary)
- [ ] false_positive_analyzer.py
- [ ] defense_plan.py
- [ ] run_eval.py
```

---

## Repo Intake & Safety Layer

**File to create:** `graphrange/scanner/repo_intake.py`

This is the mandatory first step in `run_scanner.py` before any file is read.
No file reaches the scanner without passing through this layer.

```python
# ARGUS-SCANNER: Repo intake and safety validation.
# Accepts GitHub URL or local path.
# Validates, sanitizes, and stages into an isolated directory.
# File contents are wrapped in XML tags before leaving this module —
# this neutralizes prompt injection attempts in file content.

import os, re, shutil, subprocess, pathlib
from urllib.parse import urlparse

STAGING_ROOT  = "/tmp/argus_scanner_staging"
MAX_FILE_SIZE = 10 * 1024 * 1024   # 10MB per file — skip larger files
GITHUB_REGEX  = re.compile(
    r'^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(\.git)?$'
)

def intake(source: str) -> str:
    """
    ARGUS-SCANNER: Main entry point for repo intake.
    Accepts either a GitHub URL or a local directory path.
    Returns path to staged, validated, safe copy of the repo.

    Flow:
    1. Detect source type (URL or local path)
    2. Validate source
    3. Acquire into staging directory
    4. Validate staged content
    5. Return staging path
    """
    source = source.strip()
    if source.startswith("http://") or source.startswith("https://"):
        return _intake_url(source)
    else:
        return _intake_local(source)


def _intake_url(url: str) -> str:
    """
    ARGUS-SCANNER: Validates and clones a GitHub URL.

    Validation steps:
    1. Regex match against GITHUB_REGEX — must be github.com domain exactly.
       Reject anything else including github.io, raw.githubusercontent.com,
       URL-encoded variants, and redirects.
    2. HEAD request to verify repo exists and returns 200.
       Use requests with allow_redirects=False — reject any redirect.
       Timeout 10 seconds.
    3. If valid: git clone --depth=1 into fresh staging directory.
       Staging dir: {STAGING_ROOT}/{repo_name}_{timestamp}
       If staging dir already exists from prior run, delete and reclone.
    4. Run _validate_staged_content() on cloned dir.
    5. Return staging path.

    Raise ValueError with clear message on any validation failure.
    Never follow redirects. Never accept non-github.com URLs.
    """


def _intake_local(path: str) -> str:
    """
    ARGUS-SCANNER: Validates and copies a local repo path.

    Validation steps:
    1. Resolve to absolute path with pathlib.Path.resolve().
    2. Verify it exists and is a directory (not a file, not a symlink to outside).
    3. If it is a symlink: resolve the real path and verify it still exists
       and is under a sane root (not / or /etc or /home or anywhere sensitive).
       Reject if symlink points outside /tmp, /home, or user's working directory.
    4. Check for path traversal: reject if resolved path contains '..' segments
       after resolution (should be impossible after resolve() but verify anyway).
    5. Copy entire directory to fresh staging dir:
       {STAGING_ROOT}/{dirname}_{timestamp}
       Use shutil.copytree() with symlinks=False (resolve all symlinks on copy).
    6. Run _validate_staged_content() on copied dir.
    7. Return staging path.

    Raise ValueError with clear message on any validation failure.
    """


def _validate_staged_content(staged_path: str) -> None:
    """
    ARGUS-SCANNER: Validates content of staged repo before scanner touches it.

    Checks performed on every file in the staged directory:
    1. Symlink check: walk directory, reject any symlink that resolves
       to a path outside staged_path. Use os.path.realpath() to resolve.
       Delete offending symlink and log warning — do not raise, just remove it.

    2. File size check: any file over MAX_FILE_SIZE gets flagged in a skip list.
       Log warning per skipped file. Do not delete — scanner will skip them.
       Write skip list to {staged_path}/.argus_skip (one path per line).

    3. Path traversal check: verify no filename contains '..' or starts with '/'.
       Delete offending files and log warning.

    4. No execution: this function never runs any file. Ever.
       If a file appears to be an executable (check +x bit on unix):
       remove execute permission with os.chmod() — do not delete the file,
       just strip the bit. Scanner reads files as text, never executes them.

    Returns None. Logs all actions taken.
    """


def read_file_safe(filepath: str, staging_root: str) -> str | None:
    """
    ARGUS-SCANNER: Reads a single file and wraps content in XML tags.
    Returns None if file is in .argus_skip list or over size limit.

    This is the ONLY way file contents enter the scanner pipeline.
    All Qwen prompts that include file content must use this function.

    Returns:
    '<file path="{relative_path}">\n{file_content}\n</file>'

    The XML wrapper neutralizes prompt injection — any instructions
    inside the file are treated as data content by Qwen, not directives.

    relative_path is the path relative to staging_root (never absolute).
    Encoding: read as UTF-8, replace errors (latin-1 fallback for binary-ish files).
    If file cannot be decoded at all: return None and log warning.
    """
    # Check skip list
    skip_file = os.path.join(staging_root, ".argus_skip")
    if os.path.exists(skip_file):
        with open(skip_file) as f:
            skips = set(f.read().splitlines())
        if filepath in skips:
            return None

    # Read with encoding fallback
    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception as e:
        print(f"[Intake] Cannot read {filepath}: {e}")
        return None

    rel_path = os.path.relpath(filepath, staging_root)
    return f'<file path="{rel_path}">\n{content}\n</file>'
```

---

## Update `file_scanner.py` to use `read_file_safe()`

**In `_scan_file()` and all file reading in `file_scanner.py`:**

Replace any direct `open()` calls with `read_file_safe()` from `repo_intake`.
The wrapped XML content goes directly into the Qwen prompt — no unwrapping needed.

Prompt structure becomes:
```
You are a security scanner analyzing code for vulnerabilities.

<file path="src/main/java/Login.java">
[file content here — including any text that was in the file]
</file>

Analyze the code inside the <file> tags for security vulnerabilities.
[rest of prompt...]
```

Qwen reads the file content as data inside the tags.
Any injection attempts inside the file are inert.

---

## Update `run_scanner.py` entry point

**Replace the repo path handling at the top of `run_scanner()`:**

```python
from graphrange.scanner.repo_intake import intake

def run_scanner(source: str, output_prefix: str = "reports/scanner") -> list[dict]:
    """
    ARGUS-SCANNER: source is either a GitHub URL or a local directory path.
    """
    os.makedirs("reports", exist_ok=True)
    driver = get_driver()

    print(f"[Scanner] Validating and staging repo from: {source}")
    try:
        repo_path = intake(source)
    except ValueError as e:
        print(f"[Scanner] Intake failed: {e}")
        return []
    print(f"[Scanner] Staged to: {repo_path}")

    # rest of run_scanner() continues unchanged from here
    # passing repo_path to scan_repo(), build_victim_image() etc.
```

---

## Add to `BACKLOG.md` scanner section

```markdown
- [ ] repo_intake.py — URL/path validation, staging, symlink/traversal checks,
                       XML wrapping of all file content (prompt injection defense)
- [ ] Update file_scanner.py to use read_file_safe() exclusively
- [ ] Update run_scanner.py entry point to call intake() before anything else
```

---

## Generalized Multi-Container Victim Builder

**Replaces the WebGoat-specific victim_builder.py spec above.**
The old spec is superseded by this one. Claude Code implements this version.

**File to create:** `graphrange/scanner/victim_builder.py`

```python
# ARGUS-SCANNER: Generalized multi-container victim builder.
# Supports any repo regardless of framework or language.
# One container per application layer detected in the repo.
# Red agent gets the full topology and reasons its own attack path.

import os, re, json, subprocess
from pathlib import Path
from graphrange.telemetry import track, count_tokens, patch_last_tokens_out

STAGING_ROOT = "/tmp/argus_scanner_staging"

# Manifest files by ecosystem — checked in priority order per directory
MANIFEST_PRIORITY = [
    ("docker-compose.yml",  "compose"),
    ("docker-compose.yaml", "compose"),
    ("pom.xml",             "java_maven"),
    ("build.gradle",        "java_gradle"),
    ("composer.json",       "php_laravel"),
    ("package.json",        "node"),
    ("requirements.txt",    "python"),
    ("pyproject.toml",      "python"),
    ("Gemfile",             "ruby_rails"),
    ("go.mod",              "go"),
    ("Cargo.toml",          "rust"),
    ("*.csproj",            "dotnet"),
    ("*.sln",               "dotnet"),
]

def build_victim_topology(repo_path: str) -> dict:
    """
    ARGUS-SCANNER: Detects all application layers in the repo and builds
    a multi-container topology. Returns topology dict used by the supervisor
    to spawn victim containers and by red agent for attack planning.

    Step 1 — Check for docker-compose.yml at repo root:
    If found → use it directly.
    subprocess: docker compose -f {path} up -d
    Parse the compose file to extract service names, ports, networks.
    Return topology dict (see format below) derived from compose file.
    Tag each service with its role (see _infer_role()).

    Step 2 — If no compose file: scan for manifests.
    Walk repo root and one level of subdirectories.
    Collect all matching manifest files from MANIFEST_PRIORITY.
    For glob patterns (*.csproj, *.sln): use pathlib.Path.glob().
    Group by ecosystem type.

    Step 3 — Build docker-compose.yml from manifests via Qwen:
    Call _infer_compose_from_manifests(manifest_map) → compose file string.
    Write to {repo_path}/docker-compose.argus.yml.
    subprocess: docker compose -f docker-compose.argus.yml up -d
    Parse to extract topology.

    Step 4 — Return topology dict:
    {
      "compose_file": str,           # path used
      "services": [
        {
          "name": str,               # service name from compose
          "role": str,               # "web_frontend"|"api_backend"|"database"|
                                     # "cache"|"queue"|"worker"|"unknown"
          "image": str,              # docker image or build path
          "ports": [str],            # exposed port mappings
          "networks": [str],         # networks this service is on
          "container_id": str,       # filled after docker compose up
          "ecosystem": str,          # java_maven|php_laravel|node|python|etc
          "entry_point": bool        # True for the internet-facing service
        }
      ],
      "network_map": {               # which services can reach which
        "service_a": ["service_b", "service_c"],
      }
    }
    """

def _infer_role(service_name: str, ports: list, image: str) -> str:
    """
    ARGUS-SCANNER: Infers service role from name, ports, and image.
    web_frontend: ports 80/443/8080, names containing web/nginx/apache/front
    api_backend:  ports 8000-9000, names containing api/backend/app/server
    database:     ports 3306/5432/27017/6379, names containing db/mysql/postgres/mongo
    cache:        port 6379, names containing redis/cache/memcache
    queue:        names containing queue/rabbit/kafka/worker
    worker:       names containing worker/celery/sidekiq/consumer
    unknown:      anything else
    Entry point: the service with the lowest-numbered public port
    """

def _infer_compose_from_manifests(manifest_map: dict) -> str:
    """
    ARGUS-SCANNER: Qwen3 reasons over all detected manifests to produce
    a docker-compose.yml that correctly wires all application layers.

    manifest_map format:
    {"php_laravel": "content of composer.json",
     "node": "content of package.json",
     "python": "content of requirements.txt", ...}

    Prompt:
    'Given these project manifest files from a single repository:
     {json.dumps(manifest_map)}

     Write a docker-compose.yml that:
     1. Creates one service per application layer detected
     2. Uses the correct base image and version for each
     3. Wires services together correctly (e.g. app connects to db)
     4. Exposes the internet-facing service on a public port
     5. Keeps all other services on an internal network only
     6. Includes realistic environment variables for service connectivity

     Return ONLY the docker-compose.yml content. No explanation.'

    tokens_in = count_tokens(prompt)
    with track('scanner.victim_builder._infer_compose_from_manifests',
                model='qwen', tokens_in=tokens_in, tokens_out=0):
        raw = call_ollama(prompt)
    patch_last_tokens_out(count_tokens(raw))
    Return raw compose string.
    """

def teardown_victim_topology(topology: dict) -> None:
    """
    ARGUS-SCANNER: Tears down all victim containers after scenario completes.
    docker compose -f {topology['compose_file']} down --remove-orphans
    """
```

---

## Red Agent Topology Reasoning

**Update `graphrange/scanner/scanner_red.py`:**

Red receives the full topology dict and reasons about it before planning.
Add this before the existing ARGUS lookup step:

```python
def _plan_attack_path(topology: dict, driver) -> dict:
    """
    ARGUS-SCANNER: Red reasons over the full victim topology to plan
    its attack path across containers before execution begins.

    Prompt:
    'You are a red team attacker. You have identified the following
     target infrastructure:
     {json.dumps(topology["services"])}

     Network connectivity:
     {json.dumps(topology["network_map"])}

     Plan your attack path:
     1. Which service do you attack first and why?
     2. What is your objective on that service?
     3. If you gain access, which service do you pivot to next?
     4. What is the end goal of the full attack chain?

     Return as JSON:
     {
       "entry_service": str,         ← service name to attack first
       "entry_rationale": str,
       "pivot_sequence": [str],      ← ordered list of services to pivot through
       "end_goal": str,
       "attack_phases": [
         {
           "service": str,
           "objective": str,
           "capability_needed": str  ← tool capability for this phase
         }
       ]
     }'

    tokens_in = count_tokens(prompt)
    with track('scanner.scanner_red._plan_attack_path', model='qwen',
                tokens_in=tokens_in, tokens_out=0):
        raw = call_ollama(prompt)
    patch_last_tokens_out(count_tokens(raw))
    Return attack plan dict.
    """

def _request_tool_for_phase(phase: dict, supervisor_url: str,
                             container_name: str) -> str:
    """
    ARGUS-SCANNER: Requests a tool from supervisor for the current attack phase.
    Enforces two-cycle maximum on tool request loop.

    Cycle 1: POST supervisor_url/tool_request
             {"agent": "red", "capability": phase["capability_needed"],
              "container": container_name}
             → {"tool_name": str, "install_command": str} or {"error": str}

    If success on cycle 1: install and return tool_name.

    If error on cycle 1:
    Cycle 2: Broaden capability term and retry once.
             e.g. "sql_injection_scanner" → "web_scanner"
             Broaden by taking first word of capability_needed.

    If error on cycle 2: log to logs/tool_unavailable.log:
             "TOOL_UNAVAILABLE | phase: {phase} | container: {container_name} |
              cycles: 2 | timestamp: {iso}"
             Return None — caller proceeds with whatever tools are already
             installed in the container.

    Never attempt a third cycle.
    """
```

**Update `analyze()` in `scanner_red.py` to use topology:**

```python
def analyze(vuln_context: dict, topology: dict, driver,
            sandbox: bool = False) -> dict:
    """
    ARGUS-SCANNER: Updated signature — takes topology dict.

    Step 0 — Plan attack path across topology:
    attack_plan = _plan_attack_path(topology, driver)

    Step 1 — ARGUS lookup (unchanged)

    Step 2 — Red reasoning now includes attack plan context:
    Add attack_plan to the reasoning prompt so exploitation path
    reflects the real multi-container kill chain, not just one service.

    Step 3 — Sandbox execution per attack phase:
    For each phase in attack_plan["attack_phases"]:
      a. Get target container from topology by service name
      b. _request_tool_for_phase(phase, supervisor_url, container_name)
         (enforces 2-cycle max, logs unavailable tools)
      c. Execute tool in container via supervisor
      d. Normalize observation
      e. If phase objective met → proceed to next phase
      f. If stalemate_turns exceeded → stop, log as incomplete chain

    execution_result now contains per-phase outcomes:
    {"phases": [{"service": str, "tool": str, "result": str,
                 "observations": dict, "pivoted": bool}],
     "kill_chain_complete": bool,
     "final_service_reached": str}
    """
```

---

## Update `run_scanner.py` for multi-container topology

```python
# Replace the build_victim_image() call in run_scanner() with:

from graphrange.scanner.victim_builder import build_victim_topology, teardown_victim_topology

print(f"[Scanner] Building victim topology from {repo_path}...")
topology = build_victim_topology(repo_path)
print(f"[Scanner] {len(topology['services'])} services: "
      f"{[s['name'] for s in topology['services']]}")

# Pass topology into red_analyze() instead of IMAGE_TAG:
# red = red_analyze(vc, topology, driver, sandbox=sandbox)

# After all findings complete, teardown:
teardown_victim_topology(topology)
```

---

## Update scanner_report.py for multi-container findings

**Add per-phase execution section to each finding in the report:**

```
### Exploitation Path (Red) — Multi-Container Kill Chain
**Attack Plan:** [entry_rationale]
**Target sequence:** [entry_service] → [pivot_sequence]

| Phase | Service | Tool | Result | Pivoted |
|-------|---------|------|--------|---------|
| 1 | web_frontend | sqlmap | success | yes |
| 2 | database | mysqldump | partial | no |

**Kill chain complete:** yes/no
**End goal achieved:** [end_goal or "incomplete — see phases above"]
```

---

## Add to `BACKLOG.md` scanner section

```markdown
- [ ] victim_builder.py — generalized multi-container topology builder
      (docker-compose first, manifest fallback, Qwen infers compose from manifests)
- [ ] scanner_red.py — topology reasoning, attack path planning across containers,
      dynamic tool requests with 2-cycle max + tool_unavailable.log
- [ ] logs/tool_unavailable.log — created automatically on first unavailable tool
- [ ] scanner_report.py — multi-container kill chain section per finding
- [ ] run_scanner.py — topology build/teardown replacing single image build
```

---

## Blue Agent Multi-Container Monitoring

**Update `graphrange/scanner/scanner_blue.py`:**

Blue monitors all victim services simultaneously during red execution.
One thread per service, all feeding a single detection assessment.
Detection events labeled by service so report shows exactly where blue
caught the attack and where it missed.

```python
import threading
from graphrange.telemetry import track, count_tokens, patch_last_tokens_out

def monitor_topology(topology: dict, supervisor_url: str,
                     stop_event: threading.Event) -> list[dict]:
    """
    ARGUS-SCANNER: Spawns one monitoring thread per victim service.
    All threads feed into a shared event list.
    Runs until stop_event is set by caller (red finished).

    For each service in topology["services"]:
      Thread target: _monitor_service(service, supervisor_url,
                                      stop_event, shared_events, lock)

    shared_events: list shared across all threads (append with lock)
    lock: threading.Lock()

    Returns shared_events after all threads join.
    Each event dict includes "service" field identifying which container
    the event came from.
    """

def _monitor_service(service: dict, supervisor_url: str,
                     stop_event: threading.Event,
                     shared_events: list, lock: threading.Lock) -> None:
    """
    ARGUS-SCANNER: Monitors one victim service container.
    Polls every 3 seconds until stop_event is set.

    Per poll:
    1. POST supervisor_url/exec
       {"container": service["container_id"],
        "command": "ss -tnp 2>/dev/null"}
       → parse for unexpected established connections

    2. POST supervisor_url/exec
       {"container": service["container_id"],
        "command": "tcpdump -i any -c 10 -nn 2>/dev/null"}
       → parse for anomalous traffic patterns

    On detection:
    with lock:
        shared_events.append({
          "timestamp": iso,
          "service": service["name"],
          "service_role": service["role"],
          "type": "unexpected_connection"|"port_scan"|"auth_attempt"|"data_exfil",
          "detail": str
        })
    """

def assess_detection(detection_events: list[dict],
                     attack_plan: dict) -> dict:
    """
    ARGUS-SCANNER: Assesses blue detection across the full kill chain.

    For each phase in attack_plan["attack_phases"]:
      Check if any detection_event["service"] matches phase["service"]
      and event timestamp falls within phase execution window.

    Returns:
    {
      "detected_overall": bool,
      "phases_detected": [str],    ← service names where blue caught red
      "phases_missed":   [str],    ← service names where blue missed red
      "first_detection": str,      ← service name of first detection or None
      "missed_lateral":  bool,     ← True if pivot was missed even if entry caught
      "detection_events": list     ← full event list with service labels
    }
    """
```

**Update `analyze()` in `scanner_blue.py`:**

```python
def analyze(vuln_context: dict, red_findings: dict, topology: dict,
            driver, sandbox: bool = False) -> dict:
    """
    ARGUS-SCANNER: Updated signature — takes topology dict.

    Step 1 — ARGUS mitigation lookup (unchanged)

    Step 2 — Static defensive advice (unchanged)

    Step 3 — Sandbox monitoring (only if sandbox=True):
    stop_event = threading.Event()
    monitor_thread = threading.Thread(
        target=monitor_topology,
        args=(topology, supervisor_url, stop_event, shared_events, lock)
    )
    monitor_thread.start()

    # Red execution runs in parallel (already started by scanner_red)
    # Blue waits for stop_event set by run_scanner orchestrator

    stop_event.set()
    monitor_thread.join(timeout=30)

    detection = assess_detection(shared_events, red_findings["attack_plan"])

    Return adds per-service detection breakdown:
    {
      ...existing fields...,
      "detected_overall":  bool,
      "phases_detected":   [str],
      "phases_missed":     [str],
      "missed_lateral":    bool,
      "detection_events":  list
    }
    """
```

**Update `run_scanner.py` orchestration for parallel red/blue:**

```python
# Red and blue must run in parallel during sandbox execution.
# run_scanner() coordinates the stop_event:

stop_event = threading.Event()
shared_events = []
lock = threading.Lock()

# Start blue monitoring before red executes
blue_thread = threading.Thread(
    target=monitor_topology,
    args=(topology, SUPERVISOR_URL, stop_event, shared_events, lock)
)
blue_thread.start()

# Red executes (blocking per phase)
red = red_analyze(vc, topology, driver, sandbox=sandbox)

# Signal blue to stop after red finishes
stop_event.set()
blue_thread.join(timeout=30)

# Blue assesses what it caught
blue = blue_analyze(vc, red, topology, driver,
                    sandbox=sandbox,
                    shared_events=shared_events)
```

**Update scanner report for per-service detection:**

```
### Detection (Blue) — Per Service
| Service | Role | Red Active | Blue Detected | Miss Type |
|---------|------|------------|---------------|-----------|
| web_frontend | api_backend | yes | yes | — |
| database | database | yes | no | missed lateral movement |

**Missed lateral:** yes/no
**First detection at:** [service name or "not detected"]
```

---

## Compose File Validation Before Execution

**Add to `victim_builder.py` — call before any `docker compose up`:**

```python
UNSAFE_FLAGS = [
    "privileged: true",
    "network_mode: host",
    "pid: host",
    "ipc: host",
    "cap_add:",           # any capability add is suspicious
    "security_opt: []",   # disabling seccomp
]

def _validate_compose(compose_path: str) -> None:
    """
    ARGUS-SCANNER: Validates a compose file before running it.
    Raises ValueError with clear message on any failure.
    Called before every docker compose up — no exceptions.

    Step 1 — Dry run (syntax + image resolution):
    subprocess.run(
        ["docker", "compose", "-f", compose_path, "config"],
        capture_output=True, check=True, timeout=30
    )
    If returncode != 0: raise ValueError(f"Compose validation failed: {stderr}")

    Step 2 — Safety flag checks:
    Read compose file as text.
    For each flag in UNSAFE_FLAGS:
      If flag found in compose text:
        raise ValueError(
          f"Unsafe flag '{flag}' in compose file — isolation breach risk. "
          f"Remove it and retry."
        )

    Step 3 — Image reference check:
    Parse compose YAML (import yaml).
    For each service with an 'image' key (not 'build'):
      Verify image string matches pattern: [registry/]name[:tag]
      Reject images with digest pinning to unknown registries.
      Allow: docker.io, ghcr.io, gcr.io, public.ecr.aws only.
      Reject: any private registry URL or IP-based registry.

    If all checks pass: return None. Ready to run.
    """

# In build_victim_topology(), replace every docker compose up call with:
# _validate_compose(compose_path)   ← raises on failure, never silently proceeds
# subprocess.run(["docker", "compose", "-f", compose_path, "up", "-d"], ...)
```

---

## Add to `BACKLOG.md` scanner section

```markdown
- [ ] scanner_blue.py — multi-container monitoring (one thread per service,
      shared event list with lock, per-service detection assessment,
      missed_lateral flag)
- [ ] victim_builder.py — compose validation before every docker compose up
      (dry-run + unsafe flag check + image registry allowlist)
- [ ] run_scanner.py — parallel red/blue orchestration with stop_event
- [ ] scanner_report.py — per-service detection table + missed_lateral field
```

---

## Revised Tool Request Logic — Phase-Aware with Substitution Reasoning

**Replaces the two-cycle cap spec in `scanner_red.py` above.**
Claude Code implements this version.

```python
def _request_tool_for_phase(phase: dict, installed_tools: list[str],
                             supervisor_url: str,
                             container_name: str,
                             max_cycles: int = 3) -> dict:
    """
    ARGUS-SCANNER: Requests a tool from supervisor for the current attack phase.
    Falls back to substitution reasoning if tool unavailable after max_cycles.
    Never stops the scenario — either gets a tool, substitutes, or marks blocked.

    Returns:
    {
      "tool": str | None,         ← tool name acquired or None
      "status": "acquired"        ← tool delivered successfully
              | "substituted"     ← using installed tool instead
              | "blocked",        ← phase cannot proceed, skip it
      "installed_tool_used": str, ← if substituted, which installed tool
      "log_entry": str | None     ← written to logs/tool_unavailable.log if blocked
    }

    Flow:

    Cycles 1 to max_cycles:
      POST supervisor_url/tool_request
           {"agent": "red", "capability": phase["capability_needed"],
            "container": container_name}
      → {"tool_name": str, "install_command": str} = success → return acquired
      → {"error": str} = failure → broaden capability term and retry

      Broadening strategy per cycle:
        Cycle 1: exact capability_needed as-is
        Cycle 2: first word of capability_needed only
        Cycle 3: category of capability (map via _broaden_to_category())
      After cycle max_cycles with no success → proceed to substitution check.

    Substitution check (Qwen3, fast mode):
    Prompt:
    'You are a red team attacker. Your objective for this phase is:
     {phase["objective"]}
     Capability you wanted: {phase["capability_needed"]}
     Tools currently installed in your container: {installed_tools}

     Can you achieve this phase objective using any of the installed tools?
     Return ONLY a JSON object:
     {"can_substitute": bool,
      "tool_to_use": str,    ← installed tool name or ""
      "reasoning": str}'

    If can_substitute=True:
      Return {"tool": None, "status": "substituted",
              "installed_tool_used": tool_to_use, "log_entry": None}

    If can_substitute=False:
      Write to logs/tool_unavailable.log:
      "PHASE_BLOCKED | run_id: {run_id} | service: {container_name} |
       phase_objective: {phase['objective']} | capability: {phase['capability_needed']} |
       cycles: {max_cycles} | installed_tools: {installed_tools} |
       timestamp: {iso}"
      Return {"tool": None, "status": "blocked",
              "installed_tool_used": None,
              "log_entry": "logged to tool_unavailable.log"}
    """

def _broaden_to_category(capability: str) -> str:
    """
    ARGUS-SCANNER: Maps a specific capability to a broader category.
    Used for cycle 3 broadening.

    Mapping:
    anything with "scan"|"discover"|"enum"  → "scanner"
    anything with "exploit"|"inject"|"exec" → "exploitation"
    anything with "privesc"|"escalat"       → "privilege_escalation"
    anything with "lateral"|"pivot"|"move"  → "lateral_movement"
    anything with "exfil"|"dump"|"extract"  → "exfiltration"
    anything with "crack"|"brute"|"auth"    → "credential_access"
    default                                 → "network_tool"
    """
```

**Update phase execution loop in `analyze()` of `scanner_red.py`:**

```python
# Phase execution loop — replaces previous per-phase tool request logic

installed_tools = []   # tracks what's been delivered to this container
phase_results   = []
all_blocked     = True  # flips to False if any phase executes

for phase in attack_plan["attack_phases"]:
    tool_result = _request_tool_for_phase(
        phase, installed_tools, supervisor_url,
        container_name=phase["service"],
        max_cycles=3
    )

    if tool_result["status"] == "blocked":
        phase_results.append({
            "service":  phase["service"],
            "tool":     None,
            "status":   "blocked",
            "result":   "skipped",
            "observations": {},
            "pivoted":  False
        })
        continue   # move to next phase — never stop scenario

    # Determine which tool to actually run
    active_tool = (tool_result["tool"]
                   if tool_result["status"] == "acquired"
                   else tool_result["installed_tool_used"])

    if tool_result["status"] == "acquired":
        installed_tools.append(active_tool)

    # Execute tool in container
    stdout = _exec_in_container(supervisor_url, phase["service"], active_tool, phase)

    # Normalize observation
    obs = normalize(stdout, phase.get("technique_id", ""), driver)

    # Assess phase objective met
    objective_met = _assess_objective(phase["objective"], obs, driver)

    all_blocked = False
    phase_results.append({
        "service":      phase["service"],
        "tool":         active_tool,
        "status":       tool_result["status"],
        "result":       "success" if objective_met else "partial",
        "observations": obs,
        "pivoted":      objective_met and phase != attack_plan["attack_phases"][-1]
    })

# Scenario stops only when all phases blocked or stalemate turns exceeded
kill_chain_complete = (
    not all_blocked and
    phase_results[-1]["result"] in ("success", "partial") and
    phase_results[-1]["service"] == attack_plan["attack_phases"][-1]["service"]
)

def _assess_objective(objective: str, observations: dict, driver) -> bool:
    """
    ARGUS-SCANNER: Qwen3 fast mode — did red achieve this phase objective?

    Prompt:
    'Phase objective: {objective}
     Observations from tool execution: {json.dumps(observations)}
     Did the attacker achieve the objective based on these observations?
     Return ONLY: {"achieved": true} or {"achieved": false}'

    tokens_in = count_tokens(prompt)
    with track('scanner.scanner_red._assess_objective', model='qwen',
                tokens_in=tokens_in, tokens_out=0):
        raw = call_ollama(prompt)
    patch_last_tokens_out(count_tokens(raw))
    Parse and return bool.
    """
```

---

## Update scanner_report.py — blocked phases visible in report

```
### Exploitation Path (Red) — Multi-Container Kill Chain

| Phase | Service | Tool | Status | Result | Pivoted |
|-------|---------|------|--------|--------|---------|
| 1 | web_frontend | sqlmap | acquired | success | yes |
| 2 | database | mysqldump | substituted (mysql-client) | partial | no |
| 3 | cache | redis-cli | blocked | skipped | — |

**Kill chain complete:** yes/no
**Blocked phases:** [list of service names where no tool could execute]
**Note:** Blocked phases indicate tool coverage gaps —
          see logs/tool_unavailable.log for details.
```

---

## Add to `BACKLOG.md` scanner section

```markdown
- [ ] scanner_red.py — revised tool request logic: max_cycles=3 broadening,
      substitution reasoning call, phase blocked vs scenario stopped,
      _assess_objective() per phase, installed_tools tracking across phases
- [ ] scanner_report.py — blocked phase visibility in kill chain table,
      substituted tool labeling, tool_unavailable.log reference in report
```

---

## Final Gap Closures

### Gap — installed_tools tracks by purpose not by container

**Replaces the flat list spec in the phase execution loop above.**

Tools are known by purpose, not by container. When red acquires a capability
in phase 1 on web_frontend, that same capability can be delivered to database
in phase 3 without a new tool request cycle — supervisor just installs the
same tool in the new container.

**Update phase execution loop in `scanner_red.py`:**

```python
# Replace: installed_tools = []  (flat list)
# With:
acquired_capabilities = {}  # {capability_str: tool_name}
# Tracks which capabilities have already been resolved this scenario.
# Tool delivery to a new container is just re-install of known tool.

# In _request_tool_for_phase() — add capability cache check as first step:
# Before cycle 1:
if phase["capability_needed"] in acquired_capabilities:
    known_tool = acquired_capabilities[phase["capability_needed"]]
    # Deliver to current container without a new supervisor request cycle
    _deliver_tool(supervisor_url, container_name,
                  known_tool, install_from_cache=True)
    return {"tool": known_tool, "status": "acquired",
            "installed_tool_used": None, "log_entry": None}
# Otherwise proceed with normal cycle 1-3 logic.
# On successful acquisition: acquired_capabilities[capability_needed] = tool_name

# For substitution check — pass acquired_capabilities.values() as installed_tools:
# Qwen sees tool names by purpose, not container location.
```

**Add to supervisor.py:**

```python
def _deliver_tool(supervisor_url: str, container_name: str,
                  tool_name: str, install_from_cache: bool = False) -> bool:
    """
    ARGUS-SCANNER: Delivers a tool to a specific container.
    install_from_cache=True skips tool graph lookup — tool name already known.
    POST supervisor_url/deliver
         {"container": container_name, "tool_name": tool_name}
    Returns True on success.
    Logs delivery: "TOOL_DELIVERED | {tool_name} → {container_name} | cached: {bool}"
    """
```

---

### Objection — execution result is primary, Qwen assessment is secondary

**Update `_assess_objective()` spec:**

```python
def _assess_objective(objective: str, observations: dict,
                      execution_stdout: str, driver) -> dict:
    """
    ARGUS-SCANNER: Assesses phase objective from two sources.
    Execution stdout is ground truth. Qwen assessment is a secondary signal.
    Never let Qwen assessment override execution evidence.

    Step 1 — Execution-based assessment (primary):
    Check execution_stdout for hard evidence:
    - Non-empty stdout with meaningful content → execution_success = True
    - Empty stdout, error strings, timeout markers → execution_success = False
    Hard evidence markers (execution_success = False regardless of Qwen):
      "Connection refused", "Permission denied", "command not found",
      "No route to host", "timed out", empty string

    Step 2 — Qwen assessment (secondary signal only):
    Prompt:
    'Phase objective: {objective}
     Observations: {json.dumps(observations)}
     Did the attacker achieve the objective?
     Return ONLY: {"achieved": true} or {"achieved": false}'

    tokens_in = count_tokens(prompt)
    with track('scanner.scanner_red._assess_objective', model='qwen',
                tokens_in=tokens_in, tokens_out=0):
        raw = call_ollama(prompt)
    patch_last_tokens_out(count_tokens(raw))
    qwen_achieved = parse bool from raw

    Step 3 — Resolve:
    if execution_success is False: achieved = False  (execution wins)
    elif execution_success is True and qwen_achieved: achieved = True
    elif execution_success is True and not qwen_achieved:
        achieved = True   (execution wins — stdout had content, Qwen missed it)
        log warning: "OBJECTIVE_SIGNAL_CONFLICT | Qwen said not achieved
                      but execution produced output | phase: {objective}"

    Return:
    {
      "achieved":           bool,   ← final verdict
      "execution_evidence": bool,   ← raw execution assessment
      "qwen_signal":        bool,   ← Qwen's read
      "conflict":           bool    ← True if they disagreed
    }
    """
```

**Update phase_results in execution loop:**

```python
phase_results.append({
    "service":            phase["service"],
    "tool":               active_tool,
    "status":             tool_result["status"],
    "result":             "success" if assessment["achieved"] else "partial",
    "execution_evidence": assessment["execution_evidence"],  # primary
    "qwen_signal":        assessment["qwen_signal"],         # secondary
    "conflict":           assessment["conflict"],            # flag for report
    "observations":       obs,
    "pivoted":            assessment["achieved"] and phase != attack_plan["attack_phases"][-1]
})
```

**Update scanner_report.py — show assessment source in kill chain table:**

```
| Phase | Service | Tool | Status | Result | Evidence | Qwen | Conflict |
|-------|---------|------|--------|--------|----------|------|----------|
| 1 | web_frontend | sqlmap | acquired | success | yes | yes | no |
| 2 | database | mysql-client | substituted | partial | yes | no | yes⚠ |

**Note:** Result is always determined by execution evidence.
Qwen signal is a secondary indicator. Conflicts flagged with ⚠
indicate observation interpretation may have been imprecise —
review raw logs for phase detail.
```

---

## Add to `BACKLOG.md` scanner section

```markdown
- [ ] scanner_red.py — acquired_capabilities dict replacing installed_tools list,
      capability cache check before tool request cycles,
      _deliver_tool() for cache hits to new containers,
      _assess_objective() with execution-primary dual assessment,
      conflict logging for Qwen vs execution disagreements
- [ ] supervisor.py — _deliver_tool() with install_from_cache flag
- [ ] scanner_report.py — dual assessment columns in kill chain table,
      conflict flag ⚠ with explanatory note
```
