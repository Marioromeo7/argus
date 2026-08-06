"""
ARGUS-LAYER-7 — GraphRange Phase 0.1: Populate expected_observables
========================================================================
Every Technique node needs an expected_observables list — the fields a
tool's output would contain when the technique executes. GraphRange's
observation normalizer (graphrange/observer.py) queries this to know
what to extract from raw tool stdout.

Uses Qwen3 fast mode (HTTP API, think=False) — same pattern as
agents/crawler.py's _extract_entities().

Usage:
    conda activate argus
    python -u scripts/populate_observables.py
"""

import sys, os, ast, json, re, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests as _http
from dotenv import load_dotenv
load_dotenv()

MODEL       = "qwen3:8b"
OLLAMA_URL  = "http://localhost:11434/api/chat"
BATCH_SIZE  = 50
BATCH_SLEEP = 2  # seconds between batches
FAIL_LOG    = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "logs", "populate_observables_failures.log")


def _p(msg):
    print(msg, flush=True)


def _log_failure(node_id: str, reason: str, raw: str = "") -> None:
    os.makedirs(os.path.dirname(FAIL_LOG), exist_ok=True)
    with open(FAIL_LOG, "a", encoding="utf-8") as f:
        f.write(f"{node_id} | {reason} | {raw[:300]!r}\n")


def _strip_json_fence(text: str) -> str:
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    return text.strip()


def _build_prompt(name: str, description: str) -> str:
    return (
        f"Given this MITRE ATT&CK technique:\n"
        f"Name: {name}\n"
        f"Description: {description}\n\n"
        "List the observable artifacts this technique produces when executed.\n"
        "These are the fields a tool's output would contain.\n"
        "Return ONLY a JSON array of short snake_case strings, no explanation.\n"
        'Example: ["open_ports", "running_services", "os_fingerprint"]'
    )


def _fast_call(prompt: str) -> str:
    """ARGUS-LAYER-7: Qwen3 HTTP API, think=False."""
    r = _http.post(
        OLLAMA_URL,
        json={
            "model": MODEL,
            "messages": [{"role": "user", "content": prompt}],
            "think": False,
            "stream": False,
        },
        timeout=120,
    )
    r.raise_for_status()
    return r.json().get("message", {}).get("content", "")


def get_observables(name: str, description: str) -> list[str] | None:
    """ARGUS-LAYER-7: Call Qwen3 fast mode, parse JSON array. Returns None on failure."""
    raw = _fast_call(_build_prompt(name, description))
    cleaned = _strip_json_fence(raw)
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, list):
        return None
    return [str(x) for x in parsed if isinstance(x, (str, int, float))]


def run():
    from graph.retrieval import get_driver, get_nodes_by_type

    t0 = time.time()
    driver = get_driver()

    _p("Fetching technique nodes...")
    nodes = get_nodes_by_type(driver, "technique", limit=1000)
    total = len(nodes)
    _p(f"Technique nodes found: {total}")

    parsed = []
    parse_failures = 0
    for n in nodes:
        raw_props = n.get("properties", {})
        try:
            props = ast.literal_eval(raw_props) if isinstance(raw_props, str) else (raw_props or {})
        except (ValueError, SyntaxError, TypeError):
            props = {}
            parse_failures += 1
        parsed.append({
            "node_id":     n["node_id"],
            "label":       n.get("label", n["node_id"]),
            "description": props.get("description", ""),
        })
    _p(f"Property parse failures: {parse_failures}")

    written = 0
    llm_failures = 0
    call_times = []

    with driver.session() as session:
        for batch_start in range(0, total, BATCH_SIZE):
            batch = parsed[batch_start: batch_start + BATCH_SIZE]
            for i, item in enumerate(batch):
                idx = batch_start + i + 1
                t_call = time.time()
                try:
                    observables = get_observables(item["label"], item["description"])
                except Exception as e:
                    observables = None
                    _log_failure(item["node_id"], f"call_error: {e}")
                elapsed = time.time() - t_call
                call_times.append(elapsed)
                avg_sec = sum(call_times) / len(call_times)
                eta_min = avg_sec * (total - idx) / 60

                if observables is None:
                    llm_failures += 1
                    _log_failure(item["node_id"], "unparseable_response")
                    _p(f"  [{idx:>4}/{total}] {item['node_id']}  {elapsed:.1f}s  "
                       f"→ FAILED  (avg {avg_sec:.1f}s, ETA ~{eta_min:.1f} min)")
                    continue

                session.run(
                    "MATCH (n:Node {node_id: $node_id}) "
                    "SET n.expected_observables = $observables, "
                    "    n.last_updated = $ts",
                    node_id=item["node_id"],
                    observables=observables,
                    ts=__import__("datetime").datetime.utcnow().isoformat(),
                )
                written += 1
                _p(f"  [{idx:>4}/{total}] {item['node_id']}  {elapsed:.1f}s  "
                   f"→ {observables}  (avg {avg_sec:.1f}s, ETA ~{eta_min:.1f} min)")

            if batch_start + BATCH_SIZE < total:
                time.sleep(BATCH_SLEEP)

    driver.close()
    total_elapsed = time.time() - t0

    _p(f"\n{'='*60}")
    _p("POPULATE OBSERVABLES SUMMARY")
    _p(f"  Total elapsed:            {total_elapsed/60:.1f} min")
    _p(f"  Technique nodes:          {total}")
    _p(f"  Written:                  {written}")
    _p(f"  LLM/parse failures:       {llm_failures}  (see {FAIL_LOG})")
    _p(f"{'='*60}")


if __name__ == "__main__":
    _p("=" * 60)
    _p("ARGUS-LAYER-7 — populate_observables")
    _p("=" * 60)
    run()
