"""
ARGUS — Reflexion Diversity Analyzer
=====================================
Reads all MEM-RED and MEM-BLUE nodes from Neo4j, embeds each lesson
with nomic-embed-text, and measures whether reflexion memories are
converging to repetitive patterns or remaining genuinely diverse.

Metrics:
  - Consecutive similarity: cosine(lesson_i, lesson_{i+1})
  - Mean / std of consecutive similarities
  - Diversity score: 1 - mean_consecutive_similarity
  - Convergence trend: early-third vs late-third mean similarity
  - Repetition flag: triggered if mean similarity > 0.90 or
    late-third is significantly higher than early-third

Usage:
    conda activate argus
    python scripts/analyze_reflexion.py
"""

import sys, os, ast, json, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

import numpy as np
import ollama
from graph.retrieval import get_driver

SKIP_LOG = os.path.join("results", "reflexion_skips.jsonl")


CONVERGENCE_THRESHOLD = 0.90   # flag if mean similarity exceeds this
TREND_DELTA_THRESHOLD = 0.05   # flag if late-third mean exceeds early-third by this
DUPLICATE_THRESHOLD   = 0.93   # any consecutive pair above this = wasted cycle


def _p(msg=""):
    try:
        print(msg, flush=True)
    except UnicodeEncodeError:
        print(msg.encode("ascii", errors="replace").decode("ascii"), flush=True)


def _embed(text: str) -> np.ndarray:
    resp = ollama.embeddings(
        model="nomic-embed-text",
        prompt=text[:512],
        options={"num_gpu": 0},
    )
    return np.array(resp["embedding"], dtype=np.float32)


def _cosine(a: np.ndarray, b: np.ndarray) -> float:
    denom = np.linalg.norm(a) * np.linalg.norm(b)
    return float(np.dot(a, b) / denom) if denom > 1e-9 else 0.0


def _extract_lesson(props_raw) -> str:
    if isinstance(props_raw, str):
        try:
            props = ast.literal_eval(props_raw)
        except Exception:
            return ""
    else:
        props = props_raw or {}
    return props.get("lesson", "").strip()


def _extract_fields(props_raw) -> dict:
    if isinstance(props_raw, str):
        try:
            props = ast.literal_eval(props_raw)
        except Exception:
            return {}
    else:
        props = props_raw or {}
    return {
        "lesson":        props.get("lesson", "").strip(),
        "gap":           props.get("coverage_gap", props.get("blind_spot", "")).strip(),
        "next_strategy": props.get("next_strategy", "").strip(),
        "delta":         props.get("delta", 0.0),
        "timestamp":     props.get("timestamp", ""),
    }


def _load_skips() -> dict[str, list[dict]]:
    """Read reflexion_skips.jsonl; return {"red": [...], "blue": [...]}."""
    skips: dict[str, list[dict]] = {"red": [], "blue": []}
    if not os.path.exists(SKIP_LOG):
        return skips
    with open(SKIP_LOG, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            agent = entry.get("agent", "")
            if agent in skips:
                skips[agent].append(entry)
    return skips


def _load_memories(driver) -> tuple[list[dict], list[dict]]:
    with driver.session() as s:
        rows = list(s.run(
            "MATCH (n:Node {node_type: 'memory'}) "
            "RETURN n.node_id AS nid, n.properties AS props "
            "ORDER BY n.node_id"
        ))
    red  = [{"nid": r["nid"], **_extract_fields(r["props"])}
            for r in rows if "MEM-RED"  in r["nid"]]
    blue = [{"nid": r["nid"], **_extract_fields(r["props"])}
            for r in rows if "MEM-BLUE" in r["nid"]]
    return red, blue


def _analyze(memories: list[dict], label: str) -> dict:
    lessons = [m["lesson"] for m in memories if m["lesson"]]
    n = len(lessons)

    if n < 2:
        _p(f"  [{label}] Only {n} lessons — skipping similarity analysis")
        return {"n": n, "error": "insufficient data"}

    _p(f"  Embedding {n} lessons for {label}…")
    t0 = time.time()
    embeddings = []
    for i, lesson in enumerate(lessons):
        emb = _embed(lesson)
        embeddings.append(emb)
        if (i + 1) % 10 == 0:
            elapsed = time.time() - t0
            eta = elapsed / (i + 1) * (n - i - 1)
            _p(f"    {i+1}/{n}  ({elapsed:.0f}s elapsed, ~{eta:.0f}s remaining)")

    # Consecutive similarities
    consec = [_cosine(embeddings[i], embeddings[i + 1]) for i in range(n - 1)]

    # All-pairs mean (sampled if large)
    if n <= 30:
        pairs = [_cosine(embeddings[i], embeddings[j])
                 for i in range(n) for j in range(i + 1, n)]
    else:
        rng = np.random.default_rng(42)
        idxs = [(int(a), int(b))
                for a, b in rng.choice(n, size=(200, 2), replace=True)
                if a != b]
        pairs = [_cosine(embeddings[a], embeddings[b]) for a, b in idxs]

    mean_consec = float(np.mean(consec))
    std_consec  = float(np.std(consec))
    mean_pairs  = float(np.mean(pairs))
    diversity   = 1.0 - mean_consec

    # Trend: compare early third vs late third
    third = max(1, n // 3)
    early_sims = consec[:third]
    late_sims  = consec[-third:]
    early_mean = float(np.mean(early_sims)) if early_sims else 0.0
    late_mean  = float(np.mean(late_sims))  if late_sims  else 0.0
    trend_delta = late_mean - early_mean

    # Linear regression on consecutive similarities
    x = np.arange(len(consec), dtype=float)
    if len(x) >= 3:
        slope = float(np.polyfit(x, consec, 1)[0])
    else:
        slope = 0.0

    # Duplicate pairs: consecutive lessons above the duplication threshold
    duplicates = [
        (i, lessons[i], lessons[i + 1], consec[i])
        for i in range(len(consec))
        if consec[i] >= DUPLICATE_THRESHOLD
    ]
    duplication_rate = len(duplicates) / len(consec)

    # Convergence flags
    flag_high_sim  = mean_consec > CONVERGENCE_THRESHOLD
    flag_trend     = trend_delta > TREND_DELTA_THRESHOLD
    flag_duplicates = len(duplicates) > 0
    converging     = flag_high_sim or flag_trend or flag_duplicates

    # Most similar and most diverse consecutive pairs
    sorted_pairs = sorted(enumerate(consec), key=lambda x: x[1])
    most_diverse_idx  = sorted_pairs[0][0]
    most_similar_idx  = sorted_pairs[-1][0]

    return {
        "label":            label,
        "n":                n,
        "mean_consec":      mean_consec,
        "std_consec":       std_consec,
        "mean_all_pairs":   mean_pairs,
        "diversity_score":  diversity,
        "early_mean":       early_mean,
        "late_mean":        late_mean,
        "trend_delta":      trend_delta,
        "slope":            slope,
        "converging":       converging,
        "flag_high_sim":    flag_high_sim,
        "flag_trend":       flag_trend,
        "flag_duplicates":  flag_duplicates,
        "duplicates":       duplicates,
        "duplication_rate": duplication_rate,
        "consec_sims":      consec,
        "most_diverse":     (most_diverse_idx, lessons[most_diverse_idx], lessons[most_diverse_idx + 1], sorted_pairs[0][1]),
        "most_similar":     (most_similar_idx, lessons[most_similar_idx], lessons[most_similar_idx + 1], sorted_pairs[-1][1]),
        "delta_values":     [m.get("delta", 0) for m in memories if m["lesson"]],
    }


def _sparkline(values: list[float], width: int = 40) -> str:
    chars = " ▁▂▃▄▅▆▇█"
    if not values:
        return ""
    lo, hi = min(values), max(values)
    rng = hi - lo if hi > lo else 1.0
    return "".join(chars[min(8, int((v - lo) / rng * 8))] for v in values)


def _report(result: dict, out_lines: list, skips: list[dict] | None = None) -> None:
    def w(line=""):
        out_lines.append(line)
        _p(line)

    label = result["label"]
    n     = result["n"]

    w(f"\n{'─' * 60}")
    w(f"  {label.upper()} AGENT  ({n} lessons)")
    w(f"{'─' * 60}")

    if "error" in result:
        w(f"  ERROR: {result['error']}")
        return

    w(f"  Consecutive similarity  mean={result['mean_consec']:.4f}  "
      f"std={result['std_consec']:.4f}")
    w(f"  All-pairs mean          {result['mean_all_pairs']:.4f}")
    w(f"  Diversity score         {result['diversity_score']:.4f}  "
      f"(1 - mean_consec)")
    w(f"  Slope (consec vs cycle) {result['slope']:+.6f}/cycle")
    w()
    w(f"  Early-third mean: {result['early_mean']:.4f}  "
      f"Late-third mean: {result['late_mean']:.4f}  "
      f"Δ={result['trend_delta']:+.4f}")
    w()
    w(f"  Consecutive similarity trend:")
    w(f"  [{_sparkline(result['consec_sims'])}]")
    w()

    # Duplicate pairs — listed first because they're the clearest failure signal
    dups = result["duplicates"]
    dup_rate = result["duplication_rate"]
    if dups:
        w(f"  [DUPLICATE LESSONS — {len(dups)}/{len(result['consec_sims'])} pairs "
          f"≥ {DUPLICATE_THRESHOLD} sim, {dup_rate:.1%} waste rate]")
        for idx, a, b, sim in dups:
            w(f"    cycle {idx}→{idx+1}  sim={sim:.4f}")
            w(f"      A: \"{a[:110]}\"")
            w(f"      B: \"{b[:110]}\"")
        w()

    if result["converging"]:
        reasons = []
        if result["flag_duplicates"]:
            reasons.append(f"{len(dups)} near-duplicate lesson pair(s) — wasted reflexion cycles")
        if result["flag_high_sim"]:
            reasons.append(f"mean similarity {result['mean_consec']:.3f} > threshold {CONVERGENCE_THRESHOLD}")
        if result["flag_trend"]:
            reasons.append(f"late-third ({result['late_mean']:.3f}) > early-third ({result['early_mean']:.3f}) by {result['trend_delta']:+.3f}")
        w(f"  [FAILURE] {'; '.join(reasons)}")
    else:
        w(f"  [OK] No convergence detected")

    w()
    md_idx, l1, l2, sim = result["most_diverse"]
    w(f"  Most diverse consecutive pair (sim={sim:.4f}, cycles {md_idx}→{md_idx+1}):")
    w(f"    A: \"{l1[:100]}\"")
    w(f"    B: \"{l2[:100]}\"")

    w()
    ms_idx, l1, l2, sim = result["most_similar"]
    w(f"  Most repetitive consecutive pair (sim={sim:.4f}, cycles {ms_idx}→{ms_idx+1}):")
    w(f"    A: \"{l1[:100]}\"")
    w(f"    B: \"{l2[:100]}\"")

    # Delta trend
    deltas = result["delta_values"]
    if deltas:
        w()
        w(f"  Confidence delta (lesson quality signal):")
        w(f"    mean={np.mean(deltas):.3f}  "
          f"positive={sum(1 for d in deltas if d > 0)}/{len(deltas)}")

    # Fix 3 skip stats
    if skips is not None:
        w()
        written   = n
        n_skipped = len(skips)
        attempted = written + n_skipped
        skip_rate = n_skipped / attempted if attempted else 0.0
        w(f"  Fix-3 dedup (skip log):")
        w(f"    written={written}  skipped={n_skipped}  attempted={attempted}  "
          f"skip rate={skip_rate:.1%}")


def run(txt_out: str | None = None, json_out: str | None = None):
    _p("=" * 60)
    _p("ARGUS — Reflexion Diversity Analysis")
    _p("=" * 60)

    driver = get_driver()
    red_mems, blue_mems = _load_memories(driver)
    driver.close()

    skips_by_agent = _load_skips()

    total = len(red_mems) + len(blue_mems)
    _p(f"\nLoaded {total} memory nodes  ({len(red_mems)} red, {len(blue_mems)} blue)")
    _p(f"Embedding model: nomic-embed-text (CPU)\n")

    red_result  = _analyze(red_mems,  "red")
    blue_result = _analyze(blue_mems, "blue")

    out_lines = []
    def w(line=""):
        out_lines.append(line)
        _p(line)

    w("=" * 60)
    w("ARGUS — Reflexion Diversity Analysis")
    w("=" * 60)
    w(f"Total memories: {total}  ({len(red_mems)} red, {len(blue_mems)} blue)")

    _report(red_result,  out_lines, skips=skips_by_agent.get("red"))
    _report(blue_result, out_lines, skips=skips_by_agent.get("blue"))

    # Combined summary
    w()
    w("=" * 60)
    w("COMBINED SUMMARY")
    w("=" * 60)

    # Skip stats are independent of the diversity results
    red_skipped     = len(skips_by_agent.get("red",  []))
    blue_skipped    = len(skips_by_agent.get("blue", []))
    total_skipped   = red_skipped + blue_skipped
    total_attempted = total + total_skipped
    overall_skip    = total_skipped / total_attempted if total_attempted else 0.0

    results = [r for r in [red_result, blue_result] if "error" not in r]
    if results:
        overall_div   = np.mean([r["diversity_score"] for r in results])
        overall_slope = np.mean([r["slope"] for r in results])
        any_converging = any(r["converging"] for r in results)

        w(f"  Mean diversity score:  {overall_div:.4f}")
        w(f"  Mean similarity slope: {overall_slope:+.6f}/cycle")
        w()

        total_dups = sum(len(r.get("duplicates", [])) for r in results)
        total_pairs = sum(len(r.get("consec_sims", [])) for r in results)
        overall_waste = total_dups / total_pairs if total_pairs else 0.0

        w(f"  Duplicate pairs (sim ≥ {DUPLICATE_THRESHOLD}): {total_dups} / {total_pairs} "
          f"({overall_waste:.1%} waste rate)")
        w()

        # Fix 3 skip stats (combined)
        w(f"  Fix-3 dedup skips: {total_skipped} total "
          f"(red={red_skipped}, blue={blue_skipped})  "
          f"skip rate={overall_skip:.1%} of all attempted writes")
        w()

        if any_converging:
            w("  [FAILURE] Reflexion is producing near-duplicate lessons.")
            w(f"  {total_dups} wasted cycle(s) out of {total_pairs} — the agent learned nothing new.")
            w()
            w("  Root cause: limited CVE/technique corpus forces agents to revisit")
            w("  the same attack chains, producing structurally identical lessons.")
            w()
            w("  Fixes:")
            w("    1. Expand corpus (more CVE types, more technique nodes)")
            w("    2. Add a diversity penalty to the reflexion prompt: inject the")
            w("       last N lesson summaries and instruct the LLM not to repeat them")
            w("    3. Track lesson hashes and skip writing duplicates above 0.93 sim")
        else:
            w("  [OK] Both agents maintain diverse lessons across cycles.")
            w("  Reflexion memory is generating genuinely varied strategic insights.")

    os.makedirs("results", exist_ok=True)
    path = txt_out or os.path.join("results", "reflexion_diversity.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(out_lines))

    # Also save raw data as JSON
    json_path = json_out or os.path.join("results", "reflexion_diversity.json")
    SKIP_KEYS = ("consec_sims", "most_diverse", "most_similar", "delta_values")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "red":  {
                **{k: v for k, v in red_result.items()  if k not in SKIP_KEYS},
                "skips_written": red_skipped,
            },
            "blue": {
                **{k: v for k, v in blue_result.items() if k not in SKIP_KEYS},
                "skips_written": blue_skipped,
            },
            "combined": {
                "total_skipped":  total_skipped,
                "total_attempted": total_attempted,
                "skip_rate":      round(overall_skip, 4),
            },
        }, f, indent=2)

    _p(f"\nSaved: {path}")
    _p(f"Saved: {json_path}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--txt",  type=str, default=None, help="Override output .txt path")
    parser.add_argument("--json", type=str, default=None, help="Override output .json path")
    args = parser.parse_args()
    run(txt_out=args.txt, json_out=args.json)
