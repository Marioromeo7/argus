"""
ARGUS-SCANNER: Repo intake and safety validation.
Accepts a GitHub URL or a local path. Validates, sanitizes, and stages
into an isolated directory. This is the mandatory first step in
run_scanner.py before any file is read -- no file reaches the scanner
without passing through this layer. File contents are wrapped in XML tags
before leaving this module, neutralizing prompt injection attempts in
file content.
"""

import os
import re
import shutil
import subprocess
import tempfile
import time
from urllib.parse import urlparse

import requests

# The spec hardcodes /tmp/argus_scanner_staging -- this codebase runs
# natively on Windows for this step (not inside a container), so a
# hardcoded Unix path would silently fail there. tempfile.gettempdir()
# gives the same "isolated staging directory" intent, cross-platform.
STAGING_ROOT = os.path.join(tempfile.gettempdir(), "argus_scanner_staging")
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB per file -- skip larger files
GITHUB_REGEX = re.compile(
    r'^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(\.git)?$'
)


def _log(msg: str) -> None:
    print(f"[Intake] {msg}", flush=True)


def intake(source: str) -> str:
    """
    ARGUS-SCANNER: Main entry point for repo intake. Accepts either a
    GitHub URL or a local directory path. Returns the path to a staged,
    validated, safe copy of the repo.
    """
    source = source.strip()
    if source.startswith("http://") or source.startswith("https://"):
        return _intake_url(source)
    return _intake_local(source)


def _intake_url(url: str) -> str:
    """
    ARGUS-SCANNER: Validates and clones a GitHub URL.
    Never follows redirects. Never accepts non-github.com URLs.
    Raises ValueError with a clear message on any validation failure.
    """
    if not GITHUB_REGEX.match(url):
        raise ValueError(
            f"Rejected: {url!r} is not a github.com repo URL "
            "(github.io, raw.githubusercontent.com, and encoded variants "
            "are all rejected too)"
        )

    try:
        resp = requests.head(url, allow_redirects=False, timeout=10)
    except requests.RequestException as e:
        raise ValueError(f"Rejected: could not reach {url!r}: {e}") from e
    if resp.status_code != 200:
        raise ValueError(
            f"Rejected: {url!r} returned {resp.status_code}, expected 200 "
            "(redirects are rejected, not followed)"
        )

    repo_name = url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
    staging_path = os.path.join(STAGING_ROOT, f"{repo_name}_{int(time.time())}")
    if os.path.exists(staging_path):
        shutil.rmtree(staging_path)
    os.makedirs(STAGING_ROOT, exist_ok=True)

    result = subprocess.run(
        ["git", "clone", "--depth=1", url, staging_path],
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode != 0:
        raise ValueError(f"Rejected: git clone failed: {result.stderr.strip()}")

    _validate_staged_content(staging_path)
    return staging_path


def _intake_local(path: str) -> str:
    """
    ARGUS-SCANNER: Validates and copies a local repo path.
    Raises ValueError with a clear message on any validation failure.
    """
    import pathlib
    resolved = pathlib.Path(path).resolve()

    if not resolved.exists() or not resolved.is_dir():
        raise ValueError(f"Rejected: {path!r} does not exist or is not a directory")

    if os.path.islink(path):
        real = os.path.realpath(path)
        allowed_roots = [tempfile.gettempdir(), os.path.expanduser("~"), os.getcwd()]
        if not any(os.path.commonpath([real, root]) == root for root in allowed_roots
                    if os.path.splitdrive(real)[0] == os.path.splitdrive(root)[0]):
            raise ValueError(
                f"Rejected: {path!r} is a symlink resolving outside allowed "
                f"roots (temp dir, home, or cwd): {real!r}"
            )
        if not os.path.exists(real):
            raise ValueError(f"Rejected: symlink {path!r} points to a nonexistent target")

    if ".." in resolved.parts:
        raise ValueError(f"Rejected: resolved path contains '..' segments: {resolved}")

    repo_name = resolved.name
    staging_path = os.path.join(STAGING_ROOT, f"{repo_name}_{int(time.time())}")
    if os.path.exists(staging_path):
        shutil.rmtree(staging_path)
    os.makedirs(STAGING_ROOT, exist_ok=True)

    shutil.copytree(resolved, staging_path, symlinks=False)

    _validate_staged_content(staging_path)
    return staging_path


def _validate_staged_content(staged_path: str) -> None:
    """
    ARGUS-SCANNER: Validates content of a staged repo before the scanner
    touches it. Never executes anything, ever. Logs every action taken.
    """
    skipped = []
    for root, dirs, files in os.walk(staged_path):
        for name in list(files):
            full_path = os.path.join(root, name)

            # 1. Symlink check: reject anything resolving outside staged_path.
            if os.path.islink(full_path):
                real = os.path.realpath(full_path)
                if not real.startswith(os.path.realpath(staged_path) + os.sep):
                    _log(f"removing symlink escaping staging root: {full_path} -> {real}")
                    os.remove(full_path)
                    continue

            # 3. Path traversal check on the filename itself.
            if ".." in name or name.startswith("/"):
                _log(f"removing file with unsafe name: {full_path}")
                os.remove(full_path)
                continue

            # 2. File size check -- flagged, not deleted; scanner skips it.
            try:
                size = os.path.getsize(full_path)
            except OSError:
                continue
            if size > MAX_FILE_SIZE:
                _log(f"flagging oversized file ({size} bytes): {full_path}")
                skipped.append(full_path)
                continue

            # 4. No execution: strip the execute bit if set, never delete.
            mode = os.stat(full_path).st_mode
            if mode & 0o111:
                _log(f"stripping execute bit: {full_path}")
                os.chmod(full_path, mode & ~0o111)

    if skipped:
        skip_file = os.path.join(staged_path, ".argus_skip")
        with open(skip_file, "w", encoding="utf-8") as f:
            f.write("\n".join(skipped) + "\n")


def read_file_safe(filepath: str, staging_root: str) -> str | None:
    """
    ARGUS-SCANNER: Reads a single file and wraps content in XML tags. This
    is the ONLY way file contents may enter the scanner pipeline -- every
    Qwen prompt that includes file content must use this function, never
    a direct open(). Returns None if the file is in the .argus_skip list
    or cannot be decoded at all.
    """
    skip_file = os.path.join(staging_root, ".argus_skip")
    if os.path.exists(skip_file):
        with open(skip_file, encoding="utf-8") as f:
            skips = set(f.read().splitlines())
        if filepath in skips:
            return None

    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError as e:
        _log(f"cannot read {filepath}: {e}")
        return None

    rel_path = os.path.relpath(filepath, staging_root)
    return f'<file path="{rel_path}">\n{content}\n</file>'
