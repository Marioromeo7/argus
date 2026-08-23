"""
ARGUS-LAYER-7: Tracks all LLM calls -- tokens, cost estimates, system load.
Written to logs/telemetry.jsonl (one JSON line per call).
"""

import time
import json
import os
from datetime import datetime
from contextlib import contextmanager
from threading import Lock

import psutil
import tiktoken

PRICING = {
    "gpt4o":  {"input": 2.50 / 1_000_000, "output": 10.00 / 1_000_000},
    "claude": {"input": 3.00 / 1_000_000, "output": 15.00 / 1_000_000},
    "qwen":   {"input": 0.0, "output": 0.0},
}

LOG_PATH = "logs/telemetry.jsonl"
_lock = Lock()
_session_log: list = []
_enc = tiktoken.get_encoding("cl100k_base")


def count_tokens(text: str) -> int:
    """ARGUS-LAYER-7: Approximate token count."""
    return len(_enc.encode(text))


def _costs(tokens_in: int, tokens_out: int) -> dict:
    return {
        "est_cost_gpt4o": round(tokens_in * PRICING["gpt4o"]["input"] +
                                 tokens_out * PRICING["gpt4o"]["output"], 6),
        "est_cost_claude": round(tokens_in * PRICING["claude"]["input"] +
                                  tokens_out * PRICING["claude"]["output"], 6),
    }


@contextmanager
def track(caller: str, model: str = "qwen",
          tokens_in: int = 0, tokens_out: int = 0):
    """
    ARGUS-LAYER-7: Context manager for any LLM call.
    caller: function name, e.g. 'scanner.file_scanner._scan_file'.
    Pass tokens_in before the call; call patch_last_tokens_out() after
    parsing the response, once tokens_out is actually known.
    """
    os.makedirs("logs", exist_ok=True)
    t0 = time.time()
    cpu = psutil.cpu_percent(interval=None)
    ram = psutil.virtual_memory().used / 1e9
    yield
    elapsed = round(time.time() - t0, 2)
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "caller": caller,
        "model": model,
        "tokens_in": tokens_in,
        "tokens_out": tokens_out,
        "inference_time_s": elapsed,
        "cpu_percent": cpu,
        "ram_used_gb": round(ram, 2),
        **_costs(tokens_in, tokens_out),
    }
    with _lock:
        _session_log.append(entry)
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")


def patch_last_tokens_out(tokens_out: int) -> None:
    """
    ARGUS-LAYER-7: Updates tokens_out and recalculates costs on the last
    entry. Call immediately after parsing the LLM response.
    """
    with _lock:
        if not _session_log:
            return
        e = _session_log[-1]
        e["tokens_out"] = tokens_out
        e.update(_costs(e["tokens_in"], tokens_out))
        if os.path.exists(LOG_PATH):
            with open(LOG_PATH, encoding="utf-8") as f:
                lines = f.readlines()
            if lines:
                lines[-1] = json.dumps(e) + "\n"
                with open(LOG_PATH, "w", encoding="utf-8") as f:
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


def get_session_log() -> list:
    """ARGUS-LAYER-7: Returns the full session log, for the dashboard API."""
    return list(_session_log)
