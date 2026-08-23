"""
ARGUS-SCANNER: Pass 1 -- scans every file in the repo for suspicious
patterns. All files: source, tests, configs, dependencies. Skips only
binary files.
"""

import os
import re
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from graphrange.telemetry import track, count_tokens, patch_last_tokens_out
from graphrange.scanner.repo_intake import read_file_safe
from config import OLLAMA_CHAT_URL as OLLAMA_URL

QWEN_MODEL = "qwen3:8b"

SKIP_EXTENSIONS = {'.class', '.jar', '.war', '.png', '.jpg', '.gif',
                   '.ico', '.woff', '.ttf', '.eot', '.svg', '.zip'}
MAX_FILE_TOKENS = 6000   # Qwen3 8B safe context per call
CHUNK_OVERLAP = 200      # token overlap between chunks
MAX_WORKERS = 3          # bounded parallelism -- safe for local Qwen3 8B
CALL_TIMEOUT = 600       # seconds per Qwen call before skipping the file -- 90s
                         # was silently skipping files (no error, just fewer
                         # findings) given this hardware's observed real
                         # latency (minutes, not seconds, even in /no_think
                         # mode with small prompts)


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


def scan_repo(repo_path: str) -> list:
    """
    ARGUS-SCANNER: Walks the entire staged repo (already validated by
    repo_intake). Returns a merged flag list.
    """
    work_units = []
    for root, _, files in os.walk(repo_path):
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

    _log(f"{len(work_units)} work units across the repo")
    results = []
    completed = 0
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(_scan_file, filepath, chunk_text, idx, total): filepath
            for filepath, chunk_text, idx, total in work_units
        }
        for future in as_completed(futures):
            filepath = futures[future]
            try:
                results.extend(future.result(timeout=CALL_TIMEOUT))
            except Exception as e:
                _log(f"skipping {filepath}: {e}")
            completed += 1
            if completed % 10 == 0:
                _log(f"{completed}/{len(work_units)} complete")

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
    """ARGUS-SCANNER: Qwen3 merges partial findings from a chunked file."""
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
    raw = _call_qwen(prompt, "scanner.file_scanner._merge_call")
    raw = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw.strip())
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return chunk_flags[0]
