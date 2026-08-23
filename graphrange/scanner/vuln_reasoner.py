"""
ARGUS-SCANNER: Pass 2 -- deep reasoning per flagged block. Produces one
VulnContext dict per finding. VulnContext is input to the scanner red and
blue agents.
"""

import json
import re

import requests

from graphrange.telemetry import track, count_tokens, patch_last_tokens_out
from graphrange.scanner.file_scanner import _chunk_content, merge_chunks, MAX_FILE_TOKENS
from config import OLLAMA_CHAT_URL as OLLAMA_URL

QWEN_MODEL = "qwen3:8b"
CALL_TIMEOUT = 600  # was 90s -- too tight given this hardware's real observed latency


def _log(msg: str) -> None:
    print(f"[VulnReasoner] {msg}", flush=True)


def _call_qwen(prompt: str, caller: str) -> str:
    """ARGUS-SCANNER: the one Ollama call helper this module uses, wired
    through telemetry per spec. Not live-tested as of writing (2026-08-10)
    -- holding at the same live-GPU-call checkpoint as GraphRange Phase 7."""
    tokens_in = count_tokens(prompt)
    with track(caller, model="qwen", tokens_in=tokens_in, tokens_out=0):
        resp = requests.post(
            OLLAMA_URL,
            json={"model": QWEN_MODEL,
                  "messages": [{"role": "user", "content": f"/no_think\n\n{prompt}"}],
                  "stream": False},
            timeout=CALL_TIMEOUT,
        )
        resp.raise_for_status()
        raw = resp.json()["message"]["content"].strip()
    patch_last_tokens_out(count_tokens(raw))
    return raw


def reason_over_flags(flags: list) -> list:
    """
    ARGUS-SCANNER: Processes each Pass 1 flag into a VulnContext. If a
    flag's code_block exceeds MAX_FILE_TOKENS, chunk it (reusing
    file_scanner's own chunker -- no reason to duplicate that logic),
    merge, then reason over the merged result.
    """
    contexts = []
    for flag in flags:
        code_block = flag.get("code_block", "")
        if count_tokens(code_block) > MAX_FILE_TOKENS:
            chunk_flags = [
                {**flag, "code_block": c, "chunk_index": i,
                 "total_chunks": total, "needs_merge": True}
                for c, i, total in _chunk_content(code_block)
            ]
            merged = merge_chunks(chunk_flags)
            flag_to_reason = merged[0] if merged else flag
        else:
            flag_to_reason = flag
        # Same graceful-skip discipline as file_scanner.py's scan_repo():
        # one flag's Ollama call failing (a dead tunnel, a timeout) shouldn't
        # crash the whole pass and lose every context already reasoned over
        # -- confirmed live 2026-08-12, a Kaggle tunnel dying mid-eval-run
        # took down the entire run_eval.py process with an uncaught
        # ConnectionError from exactly this call site.
        try:
            contexts.append(_reason_block(flag_to_reason))
        except Exception as e:
            _log(f"skipping {flag_to_reason.get('filepath', '?')}: {e}")
    return contexts


def _reason_block(flag: dict) -> dict:
    """ARGUS-SCANNER: Deep Qwen3 reasoning over one suspicious block."""
    prompt = (
        "You are a security researcher analyzing a specific vulnerability.\n"
        f"File: {flag.get('filepath', '')} "
        f"Lines: {flag.get('line_start', '')}-{flag.get('line_end', '')}\n"
        f"Suspected type: {flag.get('suspected_vuln_type', '')} "
        f"CWE: {flag.get('cwe', '')}\n"
        f"Code: {flag.get('code_block', '')}\n\n"
        "Return detailed analysis as JSON:\n"
        '{"filepath": str, "line_start": int, "line_end": int, '
        '"vuln_type": str, "cwe": str, '
        '"severity": "Critical|High|Medium|Low", '
        '"description": str, "attack_vector": str, "impact": str, '
        '"argus_query_terms": [str], "confidence": float}\n'
        "Return ONLY the JSON object."
    )
    raw = _call_qwen(prompt, "scanner.vuln_reasoner._reason_block")
    raw = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw.strip())
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        _log(f"unparseable response for {flag.get('filepath', '?')}, "
             f"returning a degraded fallback context")
        return {
            "filepath": flag.get("filepath", ""),
            "line_start": flag.get("line_start", 0),
            "line_end": flag.get("line_end", 0),
            "vuln_type": flag.get("suspected_vuln_type", ""),
            "cwe": flag.get("cwe", ""),
            "severity": "Low",
            "description": "",
            "attack_vector": "",
            "impact": "",
            "argus_query_terms": [],
            "confidence": 0.0,
        }
