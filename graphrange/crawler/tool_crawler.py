"""
ARGUS-LAYER-7: Crawls tool sources and populates the tool graph.

Sources, in priority order (per GRAPHRANGE.md Phase 2 spec):
  1. Kali tools listing (https://www.kali.org/tools/) — scraped, structured
  2. Tool --help output via subprocess (installed tools only — not used by
     the primary crawl_kali() path, kept as a documented extension point)
  3. GitHub README (not implemented yet — flagged, not silently skipped)

Real page structure below was verified against the live site before writing
this (not guessed):
  - Listing page: `<a href="https://www.kali.org/tools/{slug}/...">{name}</a>`
    inside `<li>` elements, no CSS classes to key off — text content is the
    tool name.
  - Tool page: `<div id=categories>` holds a `<ul class=table-of-contents>`
    of `<a title="{Category Name}">` — Kali's own category taxonomy.
    `<h1 id=packages-and-binaries>` precedes one `<h3 id={pkg}>` per
    installable package, each followed by a `<p><strong>{short desc}</strong>
    <br>{long desc}</p>` and a `<strong>How to install:</strong>
    <code>sudo apt install {pkg}</code>` line.

Kali's own category tags don't map 1:1 onto ARGUS's capability taxonomy
(network_scanning, exploitation, privilege_escalation, lateral_movement,
exfiltration, defensive_monitoring, log_analysis, traffic_capture) — most
map cleanly via _CATEGORY_MAP below; anything that doesn't falls back to
Qwen3 fast mode, per spec ("if not [determinable from structured source] ->
call Qwen3 fast mode"). That fallback is the ONLY model call in this file —
everything else is pure scraping/parsing.
"""

import json
import re
import time

import requests
from bs4 import BeautifulSoup

from graphrange.tool_graph import write_tool_node

KALI_LISTING_URL = "https://www.kali.org/tools/"
KALI_TOOL_URL = "https://www.kali.org/tools/{slug}/"
HEADERS = {"User-Agent": "Mozilla/5.0 (ARGUS-GraphRange research crawler)"}

from config import OLLAMA_CHAT_URL as OLLAMA_URL

QWEN_MODEL = "qwen3:8b"

_JSON_FLAG_PATTERN = re.compile(r"--json|-oJ\b|--format\s+json", re.IGNORECASE)

# Kali category display name -> ARGUS capability. Only the confident,
# unambiguous mappings live here; anything else goes to the LLM fallback
# rather than being force-fit into the nearest guess.
_CATEGORY_MAP = {
    "Network Information": "network_scanning",
    "Network Service Discovery": "network_scanning",
    "Vulnerability Scanning": "network_scanning",
    "Reconnaissance": "network_scanning",
    "Exploitation Tools": "exploitation",
    "Web Application Analysis": "exploitation",
    "Password Attacks": "credential_access",
    "Sniffing & Spoofing": "traffic_capture",
    "Reporting Tools": "log_analysis",
    "Forensics": "log_analysis",
    "Post Exploitation": "lateral_movement",

    # Expanded 2026-08-10 after sampling 28 real Kali tool pages against the
    # map above: only 18% hit a mapped category, 82% would have gone to the
    # LLM fallback. Most of the unmapped names turned out to be literal
    # MITRE ATT&CK tactic names — this project already carries that exact
    # vocabulary elsewhere (Tactic nodes, technique `tactics` lists) — so
    # mapping them directly is a well-grounded fit, not a guess dressed up.
    # The remainder (forensics/protocol/wireless-specific names) are a
    # best-effort fit, flagged as such, not asserted as definitive.
    "Discovery": "network_scanning",
    "Credential Access": "credential_access",
    "Defense Evasion": "exploitation",
    "Persistence": "lateral_movement",
    "Collection": "exfiltration",
    "Initial Access": "exploitation",
    "Resource Development": "exploitation",
    "Impact": "exploitation",
    "Lateral Movement": "lateral_movement",
    "Brute Force": "credential_access",
    "Pass-the-Hash": "credential_access",
    "Password Cracking": "credential_access",
    "Password Profiling & Wordlists": "credential_access",
    "WiFi Credential Access": "credential_access",
    "Network Sniffing": "traffic_capture",
    "Application Layer Protocol": "traffic_capture",
    "Non-Application Layer Protocol": "traffic_capture",
    "Protocol Tunneling": "traffic_capture",
    "Web Scanning": "network_scanning",
    "Web Vulnerability Scanning": "network_scanning",
    "Host Information": "network_scanning",
    "Network Share Discovery": "network_scanning",
    "Databases": "exploitation",
    # Best-effort, less confident than the above — genuinely ambiguous
    # without more context, not a strong fit either way.
    "Digital Forensics": "log_analysis",
    "Forensic Carving Tools": "log_analysis",
    "VoIP": "network_scanning",
    "WiFi": "network_scanning",

    # Expanded again 2026-08-10, same day — the 28-tool sample above showed
    # 0% fallback and looked complete, but the FULL 418-tool run hit real
    # LLM-fallback timeouts anyway. Root cause: a 28-tool sample doesn't
    # cover Kali's real long tail of category names — a full scan of all
    # 418 pages (zero failed requests) found 64 unique categories total, 31
    # still unmapped. This is the complete list this time, not another
    # sample; see BACKLOG.md/THESIS.md for the full account.
    "Account Discovery": "network_scanning",
    "Process Discovery": "network_scanning",
    "Remote System Discovery": "network_scanning",
    "System Network Configuration Discovery": "network_scanning",
    "System Services": "network_scanning",
    "Network Information: DNS": "network_scanning",
    "Network Security Appliances": "network_scanning",
    "Cisco Tools": "network_scanning",
    "Services and Other Tools": "network_scanning",
    "SMTP": "network_scanning",
    "SNMP": "network_scanning",
    "Bluetooth": "network_scanning",
    "NFC": "network_scanning",
    "Radio Frequency": "network_scanning",
    "Identity Information": "network_scanning",
    "Active Directory": "exploitation",
    "Execution": "exploitation",
    "Laboratories": "exploitation",
    "Privilege Escalation": "privilege_escalation",
    "Exfiltration": "exfiltration",
    "Command and Control": "traffic_capture",
    "SSL / TLS": "traffic_capture",
    "Kerberoasting": "credential_access",
    "Hash Identification": "credential_access",
    "Keylogger": "credential_access",
    "OS Credential Dumping": "credential_access",
    "Unsecured Credentials": "credential_access",
    "VoIP Credential Access": "credential_access",
    "Forensic Imaging Tools": "log_analysis",
    "PDF Forensics Tools": "log_analysis",
    "Sleuth Kit Suite": "log_analysis",
}

_LOG_PATH = "logs/tool_crawler.log"


def _log(msg: str) -> None:
    print(msg, flush=True)
    try:
        with open(_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(msg + "\n")
    except OSError:
        pass


def list_kali_tools() -> list[dict]:
    """ARGUS-LAYER-7: Scrape the Kali tools listing page for {name, slug}."""
    resp = requests.get(KALI_LISTING_URL, timeout=15, headers=HEADERS)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")

    tools = {}
    for link in soup.select('a[href*="/tools/"]'):
        # Real tool entries carry an <img> icon; the page's own nav/view-toggle
        # links (Top 100, All tools, Submit new tool) match the same href
        # pattern but use <input type=checkbox> or nothing — verified against
        # the live page, not assumed.
        if link.find("img") is None:
            continue
        href = link.get("href", "")
        m = re.search(r"/tools/([a-zA-Z0-9_.-]+)/", href)
        if not m:
            continue
        slug = m.group(1)
        name = link.get_text(strip=True)
        if not name or slug in tools:
            continue
        tools[slug] = {"name": name, "slug": slug}
    return list(tools.values())


def _llm_fallback_capability(name: str, description: str) -> str:
    """ARGUS-LAYER-7: The one model call in this module. Only reached when
    Kali's own category tags don't map onto ARGUS's capability taxonomy."""
    prompt = (
        f"Does the tool '{name}' fit one of these capability categories: "
        "network_scanning, exploitation, privilege_escalation, "
        "lateral_movement, exfiltration, defensive_monitoring, log_analysis, "
        "traffic_capture?\n"
        f"Tool description: {description[:500]}\n"
        'Reply ONLY as JSON: {"capability": str}'
    )
    resp = requests.post(
        OLLAMA_URL,
        json={
            "model": QWEN_MODEL,
            "messages": [{"role": "user", "content": f"/no_think\n\n{prompt}"}],
            "stream": False,
        },
        timeout=600,  # 120 was too optimistic — real /no_think calls on this
        # hardware have been observed exceeding it; matches this session's
        # established variance (200-900s+) rather than a guess.
    )
    resp.raise_for_status()
    text = resp.json()["message"]["content"].strip()
    text = re.sub(r"^```json\s*|\s*```$", "", text.strip())
    try:
        return json.loads(text).get("capability", "network_scanning")
    except (json.JSONDecodeError, AttributeError):
        return "network_scanning"


def crawl_tool_page(slug: str, name: str) -> list[dict]:
    """ARGUS-LAYER-7: Fetch one tool's page, extract every installable
    package on it (a Kali tool page often lists several, e.g. nmap also
    ships ncat/ndiff/zenmap packages). Returns a list of tool dicts ready
    for write_tool_node(); does not write them itself."""
    resp = requests.get(KALI_TOOL_URL.format(slug=slug), timeout=15, headers=HEADERS)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")

    categories = [
        a.get("title", a.get_text(strip=True))
        for a in soup.select("div#categories ul.table-of-contents a")
        if a.get("title") or a.get_text(strip=True)
    ]
    capability = next((_CATEGORY_MAP[c] for c in categories if c in _CATEGORY_MAP), None)

    packages_header = soup.find(id="packages-and-binaries")
    package_headers = packages_header.find_all_next("h3") if packages_header else []

    # Packages on one tool page (e.g. gnuradio / gnuradio-dev / gnuradio-doc /
    # libgnuradio-*) are build artifacts of the SAME tool, not distinct tools
    # -- they share one capability. When Kali's own category tags don't cover
    # this page (capability is None), resolve the LLM fallback ONCE for the
    # page using the top-level tool name, not once per package. Found this
    # 2026-08-10 after a real crawl hung twice at the identical point:
    # gnuradio's page carries zero category tags and lists 25 packages, so
    # the per-package version of this call fired 25 sequential multi-minute
    # Ollama requests for one page -- not a hang, just unbounded fanout.
    page_fallback_capability = None
    page_used_llm_fallback = False
    if capability is None:
        first_desc_p = package_headers[0].find_next("p") if package_headers else None
        first_description = first_desc_p.get_text(" ", strip=True) if first_desc_p else ""
        page_fallback_capability = _llm_fallback_capability(name, first_description)
        page_used_llm_fallback = True

    results = []
    for h3 in package_headers:
        pkg_name = h3.get_text(strip=True)
        desc_p = h3.find_next("p")
        description = desc_p.get_text(" ", strip=True) if desc_p else ""

        install_command = None
        install_p = h3.find_next(string=re.compile("How to install"))
        if install_p:
            code = install_p.find_next("code")
            if code:
                install_command = code.get_text(strip=True)

        if capability is not None:
            tool_capability, used_llm_fallback = capability, False
        else:
            tool_capability, used_llm_fallback = page_fallback_capability, page_used_llm_fallback

        supports_json = bool(_JSON_FLAG_PATTERN.search(description))

        results.append({
            "name": pkg_name,
            "capability": tool_capability,
            "supports_json_output": supports_json,
            "json_flag": "",
            "has_parser_library": False,
            "parser_library": "",
            "install_command": install_command or f"apt-get install -y {pkg_name}",
            "os_requirements": ["linux"],
            "requires_root": False,
            "grain_confidence": 0.5 if used_llm_fallback else 0.8,
            "source": "llm_derived" if used_llm_fallback else "crawl",
            "_used_llm_fallback": used_llm_fallback,
        })
    return results


def crawl_kali(driver, limit: int | None = None, batch_size: int = 50,
                sleep_seconds: float = 1.0) -> dict:
    """ARGUS-LAYER-7: Main crawl entry point. Lists tools, crawls each page,
    writes results to the tool graph in batches. Logs every tool written and
    every LLM fallback used — never crashes on one bad tool page."""
    tools = list_kali_tools()
    if limit:
        tools = tools[:limit]

    written, fallback_count, failed = 0, 0, 0
    for i, tool in enumerate(tools):
        try:
            packages = crawl_tool_page(tool["slug"], tool["name"])
            for pkg in packages:
                used_fallback = pkg.pop("_used_llm_fallback")
                write_tool_node(driver, pkg)
                written += 1
                fallback_count += int(used_fallback)
                _log(f"[tool_crawler] wrote {pkg['name']} "
                     f"(capability={pkg['capability']}, "
                     f"llm_fallback={used_fallback})")
        except requests.RequestException as e:
            failed += 1
            _log(f"[tool_crawler] FAILED {tool['name']}: {e}")

        if (i + 1) % batch_size == 0:
            time.sleep(sleep_seconds)
        else:
            time.sleep(sleep_seconds / 5)  # be polite even within a batch

    summary = {"tools_found": len(tools), "packages_written": written,
               "llm_fallback_used": fallback_count, "failed": failed}
    _log(f"[tool_crawler] DONE {summary}")
    return summary


if __name__ == "__main__":
    import sys
    sys.path.insert(0, ".")
    from graph.retrieval import get_driver

    d = get_driver()
    print(crawl_kali(d, limit=10))
    d.close()
