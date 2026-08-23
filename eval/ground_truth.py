"""
ARGUS-EVAL: Loads a target repo's known vulnerabilities as ground truth,
from GitHub Security Advisories + SECURITY.md.

Originally hardcoded to WebGoat per spec. Real finding, checked live
(2026-08-10): WebGoat has zero ground truth available by either source --
`GET /repos/WebGoat/WebGoat/security-advisories` returns `[]`, and
SECURITY.md 404s everywhere tried. Not a bug in this module: WebGoat is an
intentionally vulnerable teaching app, so its "vulnerabilities" are
deliberate lesson content, never disclosed/CVE'd against the project
itself. The approach here is correct; that specific target just can't
supply ground truth.

Generalized 2026-08-12 to take a target repo instead of assuming WebGoat --
checked several real candidates live via the same API this module calls
(not guessed): axios/axios has 30 advisories, every one with a real
assigned CVE ID (prototype pollution, ReDoS, proxy-bypass, request-
smuggling-adjacent bugs -- genuinely the class of thing a code-level
scanner should be able to find patterns for), and it's a small, focused
library, unlike the large platform repos also checked (Gitea, Grafana,
Strapi all have real advisories too, but scanning their full codebases
would take far longer than the time this is worth). Kept as the default.
"""

import re

import requests

GITHUB_HEADERS = {"Accept": "application/vnd.github+json"}
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")

DEFAULT_OWNER = "axios"
DEFAULT_REPO = "axios"


def _log(msg: str) -> None:
    print(f"[GroundTruth] {msg}", flush=True)


def _get_default_branch(owner: str, repo: str) -> str:
    """ARGUS-EVAL: Resolves the real default branch rather than assuming
    "main" -- axios's is "v1.x", not "main", confirmed live."""
    try:
        resp = requests.get(f"https://api.github.com/repos/{owner}/{repo}",
                             headers=GITHUB_HEADERS, timeout=15)
        resp.raise_for_status()
        return resp.json().get("default_branch", "main")
    except requests.RequestException as e:
        _log(f"could not resolve default branch, assuming 'main': {e}")
        return "main"


def _load_advisories(owner: str, repo: str) -> list:
    """ARGUS-EVAL: Source 1 -- GitHub Security Advisories API."""
    url = f"https://api.github.com/repos/{owner}/{repo}/security-advisories"
    try:
        resp = requests.get(url, headers=GITHUB_HEADERS, timeout=15)
        resp.raise_for_status()
        advisories = resp.json()
    except requests.RequestException as e:
        _log(f"advisories API request failed: {e}")
        return []

    if not isinstance(advisories, list):
        _log(f"unexpected advisories response shape: {type(advisories)}")
        return []

    entries = []
    for adv in advisories:
        cve_id = adv.get("cve_id")
        if not cve_id:
            continue
        vulnerabilities = adv.get("vulnerabilities", []) or []
        vulnerable_versions = [
            v.get("vulnerable_version_range", "") for v in vulnerabilities
        ]
        entries.append({
            "cve_id": cve_id,
            "severity": adv.get("severity", ""),
            "summary": adv.get("summary", ""),
            "vulnerable_versions": vulnerable_versions,
            "source": "github_security_advisories",
        })
    _log(f"{len(entries)} entries from Security Advisories API")
    return entries


def _load_security_md(owner: str, repo: str, default_branch: str) -> list:
    """ARGUS-EVAL: Source 2 -- SECURITY.md, tried at every real candidate
    location on the repo's real default branch."""
    candidates = [
        f"https://raw.githubusercontent.com/{owner}/{repo}/{default_branch}/SECURITY.md",
        f"https://raw.githubusercontent.com/{owner}/{repo}/{default_branch}/.github/SECURITY.md",
    ]
    text = None
    for url in candidates:
        try:
            resp = requests.get(url, timeout=15)
        except requests.RequestException:
            continue
        if resp.status_code == 200:
            text = resp.text
            _log(f"found SECURITY.md at {url}")
            break
    if text is None:
        _log("no SECURITY.md found at any candidate location")
        return []

    entries = []
    for cve_id in sorted(set(CVE_PATTERN.findall(text))):
        idx = text.find(cve_id)
        snippet = text[max(0, idx - 50):idx + 200].strip()
        entries.append({
            "cve_id": cve_id, "severity": "", "summary": snippet,
            "vulnerable_versions": [], "source": "security_md",
        })
    _log(f"{len(entries)} entries from SECURITY.md")
    return entries


def load_ground_truth(owner: str = DEFAULT_OWNER, repo: str = DEFAULT_REPO) -> list:
    """
    ARGUS-EVAL: Merges both sources for the given repo, deduplicated by CVE
    ID. Writes eval/ground_truth.md regardless of how many entries were
    found -- an empty ground truth is real, useful information about the
    target, not something to hide by skipping the file.
    """
    default_branch = _get_default_branch(owner, repo)
    merged = {}
    for entry in (_load_advisories(owner, repo)
                  + _load_security_md(owner, repo, default_branch)):
        cve_id = entry["cve_id"]
        if cve_id not in merged:
            merged[cve_id] = entry

    entries = list(merged.values())
    _write_ground_truth_md(owner, repo, entries)
    return entries


def _write_ground_truth_md(owner: str, repo: str, entries: list) -> None:
    lines = [f"# {owner}/{repo} Ground Truth", ""]
    if not entries:
        lines.append(
            f"No ground truth entries found for {owner}/{repo}. Zero published "
            "GitHub Security Advisories and no discoverable SECURITY.md as of "
            "this run. Comparison against this ground truth will show 0% "
            "coverage by construction, not because the scanner missed real, "
            "documented CVEs."
        )
    else:
        for e in entries:
            lines.append(f"## {e['cve_id']}")
            lines.append(f"**Severity:** {e['severity'] or 'unknown'}")
            lines.append(f"**Source:** {e['source']}")
            lines.append(e.get("summary", ""))
            lines.append("")

    with open("eval/ground_truth.md", "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
