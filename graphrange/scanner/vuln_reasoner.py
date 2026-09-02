"""
ARGUS-SCANNER: Pass 2 -- deep reasoning per flagged block. Produces one
VulnContext dict per finding. VulnContext is input to the scanner red and
blue agents.
"""

import json
import os
import re

import requests

from graphrange.telemetry import track, count_tokens, patch_last_tokens_out
from graphrange.scanner.file_scanner import _chunk_content, merge_chunks, MAX_FILE_TOKENS
from config import OLLAMA_CHAT_URL as OLLAMA_URL

QWEN_MODEL = "qwen3:8b"
CALL_TIMEOUT = 1800  # was 600s -- still too tight, found live 2026-08-25: a
                      # comparable-scale Qwen call on local hardware (RTX
                      # 3050, ~8 tok/s, the only compute left after Colab's
                      # quota ran out on all 3 accounts) exceeded 600s
                      # without finishing


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


_CHECKPOINT_SAVE_EVERY = 10  # flags between checkpoint writes


def _reason_checkpoint_path(repo_path: str) -> str:
    return os.path.join(repo_path, ".argus_reason_checkpoint.json")


def _flag_key(flag: dict) -> str:
    """ARGUS-SCANNER: filepath+lines+type is a stable enough composite key
    -- two genuinely different findings at the exact same location and
    type would be real duplicates anyway."""
    return (f"{flag.get('filepath', '')}::{flag.get('line_start', '')}-"
            f"{flag.get('line_end', '')}::{flag.get('suspected_vuln_type', '')}")


def _load_reason_checkpoint(repo_path: str) -> dict:
    path = _reason_checkpoint_path(repo_path)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_reason_checkpoint(repo_path: str, checkpoint: dict) -> None:
    """Atomic write (temp file + os.replace), same as file_scanner.py's
    checkpoint -- a crash mid-write must never corrupt it."""
    path = _reason_checkpoint_path(repo_path)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(checkpoint, f)
    os.replace(tmp, path)


def reason_over_flags(flags: list, repo_path: str | None = None) -> list:
    """
    ARGUS-SCANNER: Processes each Pass 1 flag into a VulnContext. If a
    flag's code_block exceeds MAX_FILE_TOKENS, chunk it (reusing
    file_scanner's own chunker -- no reason to duplicate that logic),
    merge, then reason over the merged result.

    Triages out non-genuine findings (see _reason_block's is_genuine_finding
    field) -- found live 2026-08-25 on a real WebGoat run: this function had
    ZERO filtering, appending every single flag (even the unparseable-
    response fallback) as a "confirmed vulnerability" needing full red/blue
    dynamic analysis. 385 flags in -> 385 vulnerabilities out, a 100%
    conversion rate that isn't real triage, just relabeling -- and each one
    downstream costs 5-9x more compute than this reasoning step alone. A
    real scanner product has to triage before spending expensive dynamic-
    analysis compute on every static-analysis guess.

    Checkpointed to .argus_reason_checkpoint.json inside repo_path (same
    pattern as file_scanner.py's scan_repo(), added 2026-08-26) -- this
    pass runs one real Qwen call per flag and took ~21hr for 385 flags on
    local hardware; re-running it unprotected after the SECOND consecutive
    real crash mid-pipeline that day (three total Colab session deaths)
    would be repeating a mistake already paid for twice. repo_path is
    optional -- omitting it keeps the old, unprotected behavior for any
    other caller.
    """
    checkpoint = _load_reason_checkpoint(repo_path) if repo_path else {}
    contexts = []
    triaged_out = 0
    newly_completed = 0
    already_done = 0
    for flag in flags:
        key = _flag_key(flag) if repo_path else None
        if key and key in checkpoint:
            already_done += 1
            cached = checkpoint[key]
            # _reason_block()'s own JSON schema never asks the model to echo
            # the code back, so it was never in the context at all -- found
            # live 2026-08-29 on the finished WebGoat report: every single
            # finding's "### Code" section was empty. The real snippet is
            # already sitting on the Pass 1 flag being iterated right now
            # (same key => same source location), so copy it in directly
            # rather than asking the LLM to reproduce code verbatim (slower,
            # and risks it paraphrasing/mangling the snippet).
            cached["code_block"] = flag.get("code_block", "")
            if cached.get("is_genuine_finding", True):
                contexts.append(cached)
            else:
                triaged_out += 1
            continue

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
        # ConnectionError from exactly this call site. Deliberately NOT
        # checkpointed as a "done" entry -- a transient failure should be
        # retried on the next call, not permanently remembered as skipped.
        try:
            context = _reason_block(flag_to_reason)
        except Exception as e:
            _log(f"skipping {flag_to_reason.get('filepath', '?')}: {e}")
            continue

        context["code_block"] = flag.get("code_block", "")
        if key:
            checkpoint[key] = context
            newly_completed += 1
            if newly_completed % _CHECKPOINT_SAVE_EVERY == 0:
                _save_reason_checkpoint(repo_path, checkpoint)
                _log(f"{newly_completed} new + {already_done} resumed "
                     f"complete (checkpoint saved)")

        if not context.get("is_genuine_finding", True):
            triaged_out += 1
            continue
        contexts.append(context)

    if repo_path:
        _save_reason_checkpoint(repo_path, checkpoint)
    _log(f"{len(contexts)} genuine vulnerabilities, {triaged_out} triaged "
         f"out as false positives / not worth pursuing, out of {len(flags)} flags"
         + (f" ({already_done} resumed from checkpoint)" if already_done else ""))
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
        '"argus_query_terms": [str], "confidence": float, '
        '"is_genuine_finding": bool}\n'
        "Set is_genuine_finding=false if this is a false positive, "
        "defensive/safe code that only looks suspicious, test or example "
        "code not reachable by a real attacker, or too speculative to "
        "pursue further -- true only for a real, worth-investigating issue.\n"
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
