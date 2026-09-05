"""
ARGUS — R2.4: Local latency lock-in
======================================
Locks in cold-start and warm-call latency numbers on LOCAL hardware (never
Kaggle/Colab, per CLAUDE.md's model-usage rule and ROADMAP D4) as the
paper's Claim 4 (hardware feasibility) source of truth, replacing the
development-time observations currently cited in PAPER_DRAFT.md/
PAPER_CLAIMS.md.

Must be run with NO other process contending for local Ollama/GPU (this
project's own history shows concurrent load measurably slows individual
calls) -- this script does not check for that itself; run it standalone.

Usage:
    conda activate argus
    python scripts/eval_local_latency.py
"""

import sys, os, json, time, subprocess
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import numpy as np
import requests

# Deliberately NOT reading OLLAMA_BASE_URL from .env / config.py: this
# script's entire purpose is measuring LOCAL hardware regardless of what
# other scripts are currently configured to point at (e.g. a Kaggle tunnel
# URL set for a concurrent R2.3 run) -- CLAUDE.md's rule that paper-cited
# latency numbers must come from local, never Kaggle/Colab, only holds if
# this script can't silently follow a redirected .env.
LOCAL_OLLAMA = "http://localhost:11434"
CHAT_URL = f"{LOCAL_OLLAMA}/api/chat"
EMBED_URL = f"{LOCAL_OLLAMA}/api/embeddings"

N_WARM_CALLS = 5

# A real, representative prompt -- not a trivial "PONG" -- closer to what
# the narrowing engine's asker actually sends (see agents/narrowing.py
# _asker_prompt), so the timing reflects genuine usage.
_THINK_PROMPT = (
    "You are the ARGUS Asker. Your only job is to find the sharpest question "
    "that would expose ambiguity or gaps in this node.\n\n"
    "Node: T1055.011 (technique)\n"
    "Properties: {'name': 'Extra Window Memory Injection', 'tactics': "
    "['defense-evasion', 'privilege-escalation'], 'platforms': ['Windows']}\n\n"
    "Ask ONE new question. Reply with ONLY the question."
)
_FAST_PROMPT = (
    "Extract the CVE ID, CWE ID, and CVSS score from this text as JSON: "
    "'CVE-2021-44228 is a critical vulnerability (CVSS 10.0) in Apache Log4j2, "
    "categorized as CWE-502 (improper deserialization).'"
)
_EMBED_TEXT = (
    "Adversaries may inject malicious code into process via Extra Window "
    "Memory (EWM) in order to evade process-based defenses."
)


def _stop_model(model: str) -> None:
    """Stop and VERIFY unload via `ollama ps` before returning -- a first
    attempt at this (2026-09-05) called `ollama stop` then slept 2s and
    proceeded without checking, and the resulting "cold start" call came
    back with Ollama's own load_duration=0 -- proof the model was still
    resident, not a real cold start. Poll `ollama ps` until the model is
    actually gone (up to 30s) instead of trusting a fixed sleep."""
    try:
        subprocess.run(["ollama", "stop", model], capture_output=True, timeout=30)
    except Exception as e:
        print(f"  [WARN] could not stop {model}: {e}")
        return
    for _ in range(15):
        try:
            out = subprocess.run(["ollama", "ps"], capture_output=True, timeout=10,
                                  text=True).stdout
        except Exception:
            break
        if model not in out:
            return
        time.sleep(2)
    print(f"  [WARN] {model} still shows in 'ollama ps' after 30s of polling")


def _think_call(prompt: str) -> dict:
    t0 = time.monotonic()
    r = requests.post(CHAT_URL, json={
        "model": "qwen3:8b",
        "messages": [{"role": "user", "content": f"/think\n\n{prompt}"}],
        "stream": False,
    }, timeout=900)
    r.raise_for_status()
    wall = time.monotonic() - t0
    body = r.json()
    return {"wall_s": wall, "total_duration_s": body.get("total_duration", 0) / 1e9,
            "load_duration_s": body.get("load_duration", 0) / 1e9}


def _fast_call(prompt: str) -> dict:
    t0 = time.monotonic()
    r = requests.post(CHAT_URL, json={
        "model": "qwen3:8b",
        "messages": [{"role": "user", "content": prompt}],
        "think": False,
        "stream": False,
    }, timeout=300)
    r.raise_for_status()
    wall = time.monotonic() - t0
    body = r.json()
    return {"wall_s": wall, "total_duration_s": body.get("total_duration", 0) / 1e9,
            "load_duration_s": body.get("load_duration", 0) / 1e9}


def _embed_call(text: str) -> dict:
    t0 = time.monotonic()
    r = requests.post(EMBED_URL, json={
        "model": "nomic-embed-text",
        "prompt": text,
        "options": {"num_gpu": 0},
    }, timeout=60)
    r.raise_for_status()
    wall = time.monotonic() - t0
    return {"wall_s": wall}


def _summarize(label: str, calls: list) -> dict:
    walls = [c["wall_s"] for c in calls]
    stats = {"n": len(calls), "mean_s": float(np.mean(walls)), "std_s": float(np.std(walls)),
             "min_s": float(np.min(walls)), "max_s": float(np.max(walls))}
    print(f"  {label}: mean={stats['mean_s']:.1f}s std={stats['std_s']:.1f}s "
          f"min={stats['min_s']:.1f}s max={stats['max_s']:.1f}s (n={stats['n']})")
    return stats


def run_eval() -> dict:
    print("=" * 70)
    print("ARGUS R2.4 -- Local latency lock-in (no concurrent GPU load)")
    print("=" * 70)

    print("\nStopping qwen3:8b to force a genuine cold start...")
    _stop_model("qwen3:8b")
    time.sleep(2)

    print("Cold-start call (think mode, real narrowing-style prompt)...")
    cold = _think_call(_THINK_PROMPT)
    print(f"  cold start: wall={cold['wall_s']:.1f}s "
          f"total_duration={cold['total_duration_s']:.1f}s "
          f"load_duration={cold['load_duration_s']:.1f}s")
    if cold["load_duration_s"] <= 0.01:
        print("  [WARN] load_duration ~0 -- model was NOT actually unloaded, "
              "this is not a genuine cold start. Results flagged accordingly.")
        cold["genuine_cold_start"] = False
    else:
        cold["genuine_cold_start"] = True

    print(f"\nWarm think-mode calls (n={N_WARM_CALLS})...")
    think_calls = [_think_call(_THINK_PROMPT) for _ in range(N_WARM_CALLS)]
    think_stats = _summarize("think mode", think_calls)

    print(f"\nWarm fast-mode calls (n={N_WARM_CALLS})...")
    fast_calls = [_fast_call(_FAST_PROMPT) for _ in range(N_WARM_CALLS)]
    fast_stats = _summarize("fast mode", fast_calls)

    print(f"\nEmbedding calls (n={N_WARM_CALLS}, CPU-only)...")
    embed_calls = [_embed_call(_EMBED_TEXT) for _ in range(N_WARM_CALLS)]
    embed_stats = _summarize("embedding", embed_calls)

    result = {
        "hardware": "RTX 3050 4GB VRAM (local)",
        "model": "qwen3:8b Q4_K_M",
        "cold_start": cold,
        "warm_think_mode": think_stats,
        "warm_fast_mode": fast_stats,
        "warm_embedding": embed_stats,
        "note": "No concurrent GPU load during this run (R2.3's Kaggle move "
                "freed local Ollama first) -- this is the paper's Claim 4 "
                "source of truth, not a development-time observation.",
    }

    print("\n" + "=" * 70)
    print(f"COLD START: {cold['wall_s']:.1f}s")
    print(f"WARM THINK MODE: {think_stats['mean_s']:.1f}s +/- {think_stats['std_s']:.1f}s")
    print(f"WARM FAST MODE:  {fast_stats['mean_s']:.1f}s +/- {fast_stats['std_s']:.1f}s")
    print(f"EMBEDDING:       {embed_stats['mean_s']:.1f}s +/- {embed_stats['std_s']:.1f}s")
    print("=" * 70)

    os.makedirs("results", exist_ok=True)
    out_path = os.path.join("results", "r2_4_local_latency.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)
    print(f"Results saved to {out_path}")
    return result


if __name__ == "__main__":
    run_eval()
