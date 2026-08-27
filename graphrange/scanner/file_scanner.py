"""
ARGUS-SCANNER: Pass 1 -- scans every file in the repo for suspicious
patterns. Source, configs, dependencies -- not documentation or test
directories (see SKIP_EXTENSIONS/SKIP_DIRS below) and not binary files.
"""

import os
import re
import json
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from graphrange.telemetry import track, count_tokens, patch_last_tokens_out
from graphrange.scanner.repo_intake import read_file_safe
from config import OLLAMA_CHAT_URL as OLLAMA_URL

QWEN_MODEL = "qwen3:8b"

SKIP_EXTENSIONS = {'.class', '.jar', '.war', '.png', '.jpg', '.gif',
                   '.ico', '.woff', '.ttf', '.eot', '.svg', '.zip',
                   # Documentation formats, added 2026-08-25 -- found live
                   # scanning WebGoat: 274 of its 1355 real work units were
                   # .adoc lesson write-ups (prose describing a vuln, not
                   # code that could contain one), each still costing a
                   # full Qwen call for a guaranteed empty result. General,
                   # not WebGoat-specific: no ecosystem's real
                   # vulnerabilities live in prose documentation.
                   '.adoc', '.md', '.rst'}

# Directory names skipped anywhere in the tree, added 2026-08-25 for the
# same reason as SKIP_EXTENSIONS -- found live scanning WebGoat: its
# src/it/ integration-test tree (playwright page objects, test fixtures)
# and *.txt sample files added real Qwen-call cost for code that isn't the
# shipped product surface. This is a real, common SAST convention (most
# scanners default to skipping test trees), not a WebGoat-specific
# workaround -- these directory names are near-universal across ecosystems.
SKIP_DIRS = {'.git', 'test', 'tests', '__tests__', 'spec', 'specs',
             'it', 'integration-test', 'integration-tests'}
MAX_FILE_TOKENS = 6000   # Qwen3 8B safe context per call
CHUNK_OVERLAP = 200      # token overlap between chunks
# 2, found via a real live sweep 2026-08-24 against a Colab T4 -- the
# initial theory (remote Ollama was OLLAMA_NUM_PARALLEL=1, so raise it and
# MAX_WORKERS together) was only half right: after fixing that, N=1/2/4
# concurrent real calls measured 13.1s/8.6s/8.5s effective-per-file --
# throughput improves 1->2, then genuinely flatlines 2->4. The T4's compute
# is saturated at ~2 concurrent qwen3:8b streams; more client-side workers
# beyond that buys nothing (a compute-bound ceiling, not a queuing one).
# Revisit if the tunnel ever points at a bigger GPU (L4/A100/H100).
MAX_WORKERS = 2
CALL_TIMEOUT = 1800      # seconds per Qwen call before skipping the file -- 90s
                         # was silently skipping files (no error, just fewer
                         # findings) given this hardware's observed real
                         # latency (minutes, not seconds, even in /no_think
                         # mode with small prompts); bumped again from 600s
                         # 2026-08-25 after a comparable-scale local call
                         # (victim_builder's compose inference) exceeded
                         # 600s outright on the only compute left (local
                         # RTX 3050) once Colab's quota ran out


def _log(msg: str) -> None:
    print(f"[FileScanner] {msg}", flush=True)


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


def _chunk_content(content: str) -> list:
    """
    ARGUS-SCANNER: Splits content into (chunk_text, index, total) tuples
    if it exceeds MAX_FILE_TOKENS -- prefers splitting on blank lines
    between top-level declarations (a rough, language-agnostic proxy for
    method/class boundaries), falling back to raw character-count slicing
    with CHUNK_OVERLAP when boundary splitting doesn't produce usable
    pieces (e.g. one long unbroken blob with no blank lines at all).
    Factored out of scan_repo() specifically so it's independently
    testable without a live Qwen call -- everything else in this module
    needs one.
    """
    if count_tokens(content) <= MAX_FILE_TOKENS:
        return [(content, 0, 1)]

    boundaries = [m.start() for m in re.finditer(r"\n[ \t]*\n", content)]
    chunks = []
    if boundaries:
        start = 0
        current = ""
        for b in boundaries + [len(content)]:
            piece = content[start:b]
            if current and count_tokens(current + piece) > MAX_FILE_TOKENS:
                chunks.append(current)
                current = piece
            else:
                current += piece
            start = b
        if current:
            chunks.append(current)

    if not chunks or any(count_tokens(c) > MAX_FILE_TOKENS * 1.5 for c in chunks):
        # Boundary splitting didn't produce usable chunks -- fall back to
        # raw slicing by character count (~4 chars/token approximation),
        # with overlap so a vulnerability spanning a cut point isn't lost.
        chars_per_chunk = MAX_FILE_TOKENS * 4
        overlap_chars = CHUNK_OVERLAP * 4
        chunks = []
        pos = 0
        while pos < len(content):
            chunks.append(content[pos:pos + chars_per_chunk])
            pos += max(1, chars_per_chunk - overlap_chars)

    total = len(chunks)
    return [(c, i, total) for i, c in enumerate(chunks)]


_CHECKPOINT_SAVE_EVERY = 10  # work units between checkpoint writes


def _checkpoint_path(repo_path: str) -> str:
    return os.path.join(repo_path, ".argus_scan_checkpoint.json")


def _work_unit_key(filepath: str, idx: int, total: int) -> str:
    return f"{filepath}::{idx}/{total}"


def _load_checkpoint(repo_path: str) -> dict:
    """ARGUS-SCANNER: {work_unit_key: [flags]} for already-completed units,
    {} if no checkpoint exists or it's unreadable. Found live 2026-08-25:
    a real multi-hour WebGoat scan completed its ENTIRE 1355-work-unit pass
    and then lost all of it to an unhandled connection error in the final
    merge step (results only lived in an in-memory list, never persisted) --
    this and _save_checkpoint make scan_repo() resumable against the exact
    same repo_path instead of re-paying for every already-done call."""
    path = _checkpoint_path(repo_path)
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_checkpoint(repo_path: str, checkpoint: dict) -> None:
    """ARGUS-SCANNER: Atomic write (temp file + os.replace) so a crash
    mid-write never corrupts the checkpoint -- os.replace is atomic on both
    POSIX and Windows, a plain open(path, "w") is not."""
    path = _checkpoint_path(repo_path)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(checkpoint, f)
    os.replace(tmp, path)


def scan_repo(repo_path: str) -> list:
    """
    ARGUS-SCANNER: Walks the entire staged repo (already validated by
    repo_intake). Returns a merged flag list. Resumable: checkpoints
    completed work units to .argus_scan_checkpoint.json inside repo_path
    every _CHECKPOINT_SAVE_EVERY completions (thread-safe) and a final save
    before merging -- a second call with the SAME repo_path (e.g. after a
    crash) skips every already-checkpointed unit rather than re-scanning.
    """
    work_units = []
    for root, dirs, files in os.walk(repo_path):
        # .git internals aren't source content -- sending them to Qwen just
        # burns real GPU time for a guaranteed "unparseable response,
        # skipping" (found live 2026-08-24 scanning WebGoat's own real
        # .git directory). Test/spec/integration-test directories excluded
        # 2026-08-25 for the same cost reason -- see SKIP_DIRS's own
        # comment above.
        dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
        for name in files:
            if name in (".argus_skip",) or name.startswith(".argus"):
                continue
            ext = os.path.splitext(name)[1].lower()
            if ext in SKIP_EXTENSIONS:
                continue
            filepath = os.path.join(root, name)
            wrapped = read_file_safe(filepath, repo_path)
            if wrapped is None:
                continue
            for chunk_text, idx, total in _chunk_content(wrapped):
                work_units.append((filepath, chunk_text, idx, total))

    checkpoint = _load_checkpoint(repo_path)
    pending = [
        (filepath, chunk_text, idx, total)
        for filepath, chunk_text, idx, total in work_units
        if _work_unit_key(filepath, idx, total) not in checkpoint
    ]
    already_done = len(work_units) - len(pending)
    _log(f"{len(work_units)} work units across the repo"
         + (f" ({already_done} already checkpointed, resuming)" if already_done else ""))

    results = []
    for flags in checkpoint.values():
        results.extend(flags)

    completed = 0
    checkpoint_lock = threading.Lock()
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(_scan_file, filepath, chunk_text, idx, total): (filepath, idx, total)
            for filepath, chunk_text, idx, total in pending
        }
        for future in as_completed(futures):
            filepath, idx, total = futures[future]
            try:
                flags = future.result(timeout=CALL_TIMEOUT)
            except Exception as e:
                _log(f"skipping {filepath}: {e}")
                flags = []
            results.extend(flags)
            with checkpoint_lock:
                checkpoint[_work_unit_key(filepath, idx, total)] = flags
                completed += 1
                if completed % _CHECKPOINT_SAVE_EVERY == 0:
                    _save_checkpoint(repo_path, checkpoint)
                    _log(f"{completed}/{len(pending)} pending complete (checkpoint saved)")

    _save_checkpoint(repo_path, checkpoint)
    return merge_chunks(results)


def _scan_file(filepath: str, content: str,
                chunk_index: int = 0, total_chunks: int = 1) -> list:
    """ARGUS-SCANNER: Sends one file or chunk to Qwen3."""
    chunk_info = (
        f"Chunk {chunk_index + 1} of {total_chunks} -- hold conclusions "
        f"until final chunk\n"
    ) if total_chunks > 1 else ""
    prompt = (
        f"You are a security scanner. File: {filepath}\n"
        f"{chunk_info}"
        "Identify suspicious patterns that could be security vulnerabilities.\n"
        f"{content}\n\n"
        "Return a JSON array:\n"
        '[{"line_start": int, "line_end": int, "code_block": str, '
        '"suspected_vuln_type": str, "cwe": str, "confidence": float, '
        '"chunk_index": int, "total_chunks": int, "needs_merge": bool}]\n'
        "If nothing found, return [].\n"
        "Return ONLY the JSON array."
    )
    raw = _call_qwen(prompt, "scanner.file_scanner._scan_file")
    raw = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw.strip())
    try:
        flags = json.loads(raw)
    except json.JSONDecodeError:
        _log(f"unparseable response for {filepath}, skipping")
        return []
    if not isinstance(flags, list):
        return []
    for flag in flags:
        flag["filepath"] = filepath
    return flags


def merge_chunks(flags: list) -> list:
    """
    ARGUS-SCANNER: Merges chunked findings from the same file. Groups by
    filepath + suspected_vuln_type where needs_merge=True; pass-through
    for everything else.
    """
    groups = {}
    passthrough = []
    for flag in flags:
        if flag.get("needs_merge") and flag.get("total_chunks", 1) > 1:
            key = (flag.get("filepath"), flag.get("suspected_vuln_type"))
            groups.setdefault(key, []).append(flag)
        else:
            passthrough.append(flag)

    merged = list(passthrough)
    for group in groups.values():
        merged.append(group[0] if len(group) == 1 else _merge_call(group))
    return merged


def _merge_call(chunk_flags: list) -> dict:
    """ARGUS-SCANNER: Qwen3 merges partial findings from a chunked file.
    Degrades to the first chunk's own flag on ANY failure (bad JSON OR a
    real request/connection error), not just a parse failure -- found live
    2026-08-25: an uncaught requests.ConnectionError here (the Ollama
    tunnel died between the scan pass finishing and this running) crashed
    the entire scan_repo() call, losing a completed 1355-work-unit pass
    that was never persisted. A degraded (unmerged) finding is still a
    real, useful finding; a crash here has no upside over falling back."""
    prompt = (
        "These are partial findings from different chunks of the same "
        f"file/method. Merge into a single coherent finding: "
        f"{json.dumps(chunk_flags)}\n"
        "Return a single JSON object:\n"
        '{"line_start": int, "line_end": int, "code_block": str, '
        '"suspected_vuln_type": str, "cwe": str, "confidence": float, '
        '"filepath": str, "needs_merge": false}\n'
        "If chunks describe different vulnerabilities, return the most severe.\n"
        "Return ONLY the JSON object."
    )
    try:
        raw = _call_qwen(prompt, "scanner.file_scanner._merge_call")
    except requests.RequestException as e:
        _log(f"merge call failed ({e}), falling back to unmerged first chunk")
        return chunk_flags[0]
    raw = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw.strip())
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return chunk_flags[0]
