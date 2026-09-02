"""
ARGUS-SCANNER: Generalized multi-container victim builder.
Supports any repo regardless of framework or language -- one container per
detected application layer. Red agent gets the full topology and reasons
its own attack path across it.
"""

import os
import re
import json
import subprocess
from pathlib import Path

import yaml
import requests

from graphrange.telemetry import track, count_tokens, patch_last_tokens_out
from config import OLLAMA_CHAT_URL as OLLAMA_URL

QWEN_MODEL = "qwen3:8b"

# Manifest files by ecosystem -- checked in priority order per directory.
MANIFEST_PRIORITY = [
    ("pom.xml", "java_maven"),
    ("build.gradle", "java_gradle"),
    ("composer.json", "php_laravel"),
    ("package.json", "node"),
    ("requirements.txt", "python"),
    ("pyproject.toml", "python"),
    ("Gemfile", "ruby_rails"),
    ("go.mod", "go"),
    ("Cargo.toml", "rust"),
    ("*.csproj", "dotnet"),
    ("*.sln", "dotnet"),
]

UNSAFE_FLAGS = [
    "privileged: true",
    "network_mode: host",
    "pid: host",
    "ipc: host",
    "cap_add:",
    "security_opt: []",
]
ALLOWED_REGISTRIES = {"docker.io", "ghcr.io", "gcr.io", "public.ecr.aws"}

# ARGUS-SCANNER: per-ecosystem pre-build step, used only as a *retry* after
# a plain `docker build .` from the repo's own Dockerfile fails -- see
# _try_build_from_dockerfile()'s docstring for why this exists at all.
# Builder image + command only; the repo is bind-mounted read-write so
# build output (target/, dist/, build/) lands where the Dockerfile's own
# COPY expects it. Ecosystems whose Dockerfiles are typically already
# self-contained (python, ruby_rails, php_laravel, dotnet) are absent on
# purpose -- they get exactly one `docker build .` attempt and then the
# existing manifest+Qwen-inference fallback, not a guessed build step that
# would just as likely be wrong.
_SOURCE_BUILD_MAP = {
    "java_maven": ("maven:3.9-eclipse-temurin-21", "mvn package -DskipTests -q"),
    "java_gradle": ("gradle:8-jdk21", "gradle build -x test"),
    "node": ("node:22", "sh -c 'npm install && npm run build --if-present'"),
    "go": ("golang:1.22", "go build -o /repo/app ./..."),
    "rust": ("rust:1.79", "cargo build --release"),
}

# ARGUS-SCANNER: persistent named volumes for each ecosystem's dependency
# cache -- without this, every _prebuild_from_source() call (including a
# retry after a transient network blip, or a re-run against the same repo
# later) re-downloads the entire dependency tree from zero. Named volumes
# survive across containers/runs (unlike a bind mount to a temp dir this
# process would have to manage and clean up itself).
_CACHE_MOUNT_MAP = {
    "java_maven": ("argus-maven-cache", "/root/.m2"),
    "java_gradle": ("argus-gradle-cache", "/root/.gradle"),
    "node": ("argus-npm-cache", "/root/.npm"),
    "go": ("argus-go-cache", "/root/go/pkg/mod"),
    "rust": ("argus-cargo-cache", "/usr/local/cargo/registry"),
}


def _log(msg: str) -> None:
    print(f"[VictimBuilder] {msg}", flush=True)


def _infer_role(service_name: str, ports: list, image: str) -> str:
    """ARGUS-SCANNER: Infers a service's role from its name, ports, and
    image. Name keywords are checked before port ranges: port 8080 is
    listed under both web_frontend and api_backend in spec (the ranges
    genuinely overlap), so a clearly-named service like "api-server" on
    :8080 should resolve by its name, not lose to an ambiguous port match
    -- confirmed as a real mismatch via a live test before this ordering
    was added (api-server on :8080 was resolving to web_frontend)."""
    name = service_name.lower()
    img = (image or "").lower()
    port_nums = set()
    for p in ports:
        for m in re.finditer(r"(\d+)(?:/(?:tcp|udp))?", str(p)):
            port_nums.add(int(m.group(1)))

    name_matches = [
        ("cache", ("redis", "cache", "memcache")),
        ("database", ("db", "mysql", "postgres", "mongo")),
        ("queue", ("queue", "rabbit", "kafka")),
        ("worker", ("worker", "celery", "sidekiq", "consumer")),
        ("api_backend", ("api", "backend", "app", "server")),
        ("web_frontend", ("web", "nginx", "apache", "front")),
    ]
    for role, keywords in name_matches:
        if any(k in name for k in keywords):
            return role

    if port_nums & {6379}:
        return "cache"
    if port_nums & {3306, 5432, 27017} or any(k in img for k in
                                               ("mysql", "postgres", "mongo")):
        return "database"
    if any(8000 <= p <= 9000 for p in port_nums):
        return "api_backend"
    if port_nums & {80, 443, 8080}:
        return "web_frontend"
    return "unknown"


def _extract_docker_hints(repo_path: str, max_chars: int = 3000) -> str:
    """ARGUS-SCANNER: Looks for real, documented `docker run`/`docker
    compose` examples in the repo's own README before Qwen ever has to
    guess blind from manifest files. Found live 2026-08-25: across 5
    separate real WebGoat attempts, Qwen guessed at the right Docker setup
    from `pom.xml` alone and got it wrong 5 different ways (a deprecated
    image, a raw Maven property copied into an image tag, YAML syntax
    errors, a plausible-but-wrong `owasp/webgoat` org guess, and trying to
    `docker build` from the repo's own Dockerfile without ever running the
    Maven build it needs) -- meanwhile WebGoat's actual README documents
    the correct, official, pre-built image directly:
    `docker run ... webgoat/webgoat`. Most public-facing repos, especially
    training/vulnerable apps meant for outside users, document the real
    way to run them precisely because they can't assume local build
    tooling -- this is general, not WebGoat-specific: any repo with real
    Docker docs in its README benefits, and it costs nothing when a repo
    has no such docs (returns "")."""
    for name in ("README.md", "README.rst", "README"):
        path = os.path.join(repo_path, name)
        if not os.path.exists(path):
            continue
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        blocks = [
            block.strip() for block in re.findall(r"```[a-zA-Z]*\n([\s\S]*?)```", text)
            if re.search(r"\bdocker\b", block, re.IGNORECASE)
        ]
        return "\n---\n".join(blocks)[:max_chars]
    return ""


def _infer_compose_from_manifests(manifest_map: dict, docker_hints: str = "") -> str:
    """ARGUS-SCANNER: Qwen reasons over detected manifests to produce a
    docker-compose.yml wiring all application layers together. The one
    model call in this module -- everything else is pure detection/parsing.
    Live-tested 2026-08-24 against a real WebGoat scan (Colab T4 tunnel):
    correctly identified the java_maven ecosystem and wrote a structurally
    valid compose file, but picked `openjdk:17` -- a real, deprecated/
    removed Docker Hub image (confirmed via a live 404 against Docker
    Hub's own API), since Qwen3 8B's training data predates the
    deprecation. Deliberately NOT steering this prompt toward a specific
    known-good image: the reconcile mechanism in _compose_up() (asks Qwen
    for a replacement given the real failure, bounded retries) is the
    actual general fix for stale image knowledge across any ecosystem --
    hardcoding "for Java use eclipse-temurin" here would just be praying
    the model resolves this ONE case, and would silently hide whether the
    reconcile path itself actually works, since it'd never fire."""
    hints_section = (
        f"\nThe repository's own README documents real, working Docker "
        f"commands for running it -- use these as your PRIMARY source of "
        f"truth (the real image name/tag, real ports, real env vars) "
        f"instead of guessing:\n{docker_hints}\n"
        if docker_hints else ""
    )
    prompt = (
        "Given these project manifest files from a single repository:\n"
        f"{json.dumps(manifest_map)}\n"
        f"{hints_section}\n"
        "Write a docker-compose.yml that:\n"
        "1. Creates one service per application layer detected\n"
        "2. Uses the correct base image and version for each\n"
        "3. Wires services together correctly (e.g. app connects to db)\n"
        "4. Exposes the internet-facing service on a public port\n"
        "5. Keeps all other services on an internal network only\n"
        "6. Includes realistic environment variables for service connectivity\n\n"
        "Return ONLY the docker-compose.yml content. No explanation."
    )
    tokens_in = count_tokens(prompt)
    with track("scanner.victim_builder._infer_compose_from_manifests",
               model="qwen", tokens_in=tokens_in, tokens_out=0):
        resp = requests.post(
            OLLAMA_URL,
            json={"model": QWEN_MODEL,
                  "messages": [{"role": "user", "content": f"/no_think\n\n{prompt}"}],
                  "stream": False},
            # 1800s, not 600s -- found live 2026-08-25: this exact call
            # (compose-file generation, a larger output than most Qwen
            # calls in this project) genuinely exceeded 600s on local
            # hardware (RTX 3050, ~8 tok/s) without finishing, timing out
            # the whole build_victim_topology() call. Real margin now that
            # local is the only compute available.
            timeout=1800,
        )
        resp.raise_for_status()
        raw = resp.json()["message"]["content"].strip()
    patch_last_tokens_out(count_tokens(raw))
    return re.sub(r"^```(?:ya?ml)?\s*|\s*```$", "", raw.strip())


class _UnsafeComposeError(ValueError):
    """ARGUS-SCANNER: Raised only for safety-boundary violations (unsafe
    Docker flags, disallowed registries) -- these NEVER get reconciled/
    retried, unlike syntax or image-resolution failures. A hard stop is
    the correct behavior for a security boundary; looping an LLM against
    it risks it just generating a different-but-still-bad workaround
    rather than genuinely respecting the constraint."""


def _validate_compose(compose_path: str) -> None:
    """ARGUS-SCANNER: Validates a compose file before it's ever run. Raises
    _UnsafeComposeError for safety-boundary violations (never retried) or
    plain ValueError for a syntax/config failure (reconcilable by
    _compose_up's retry loop) -- called before every `docker compose up`,
    no exceptions."""
    result = subprocess.run(
        ["docker", "compose", "-f", compose_path, "config"],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise ValueError(f"Compose validation failed: {result.stderr.strip()}")

    with open(compose_path, encoding="utf-8") as f:
        text = f.read()
    for flag in UNSAFE_FLAGS:
        if flag in text:
            raise _UnsafeComposeError(
                f"Unsafe flag '{flag}' in compose file -- isolation breach "
                f"risk. Remove it and retry."
            )

    parsed = yaml.safe_load(text) or {}
    for name, svc in (parsed.get("services") or {}).items():
        image = svc.get("image")
        if not image:
            continue
        first_segment = image.split("/")[0]
        registry = first_segment if ("/" in image and "." in first_segment) else "docker.io"
        if registry not in ALLOWED_REGISTRIES:
            raise _UnsafeComposeError(
                f"Rejected: service {name!r} uses image {image!r} from "
                f"disallowed registry {registry!r} (allowed: "
                f"{', '.join(sorted(ALLOWED_REGISTRIES))})"
            )


_MAX_COMPOSE_RECONCILE_ATTEMPTS = 6


def _reconcile_compose(compose_text: str, error: str) -> str | None:
    """ARGUS-SCANNER: General repair -- given a REAL compose
    validation/up failure of any kind, asks Qwen to produce a corrected
    version of the whole file. Same "try, fail, ask for a fix given the
    real error" shape as scanner_red._request_tool_for_phase's
    substitution fallback, but general rather than narrowly matched to one
    failure class. Deliberately NOT pattern-matched to specific error
    text: a live 2026-08-24 WebGoat run hit three genuinely different
    failure modes across three separate attempts (a deprecated
    `openjdk:17` image, an unescaped `${project.version}` Maven property
    copied verbatim into the image tag, and a raw YAML syntax error) --
    hardcoding a fix for each one discovered would only ever cover cases
    already seen, never generalize to the next one."""
    prompt = (
        "This docker-compose.yml failed validation or failed to start:\n\n"
        f"{compose_text}\n\n"
        f"Real error:\n{error[:1500]}\n\n"
        "Fix the file so it is valid and will actually run. Keep the same "
        "overall structure and services where possible; change only what "
        "the error requires.\n\n"
        "Return ONLY the corrected docker-compose.yml content. No explanation."
    )
    tokens_in = count_tokens(prompt)
    with track("scanner.victim_builder._reconcile_compose",
               model="qwen", tokens_in=tokens_in, tokens_out=0):
        resp = requests.post(
            OLLAMA_URL,
            json={"model": QWEN_MODEL,
                  "messages": [{"role": "user", "content": f"/no_think\n\n{prompt}"}],
                  "stream": False},
            # 1800s, not 600s -- found live 2026-08-25: this exact call
            # (compose-file generation, a larger output than most Qwen
            # calls in this project) genuinely exceeded 600s on local
            # hardware (RTX 3050, ~8 tok/s) without finishing, timing out
            # the whole build_victim_topology() call. Real margin now that
            # local is the only compute available.
            timeout=1800,
        )
        resp.raise_for_status()
        raw = resp.json()["message"]["content"].strip()
    patch_last_tokens_out(count_tokens(raw))
    fixed = re.sub(r"^```(?:ya?ml)?\s*|\s*```$", "", raw.strip())
    return fixed or None


def _compose_up(compose_path: str) -> None:
    """ARGUS-SCANNER: Validates then brings up a compose file -- the only
    path anything in this module uses to actually run containers. Retries
    up to _MAX_COMPOSE_RECONCILE_ATTEMPTS times on ANY real validation or
    startup failure (syntax, image resolution, interpolation, etc.),
    feeding the real error back to Qwen for a whole-file fix each time.
    _UnsafeComposeError (a safety-boundary violation, not a generation
    bug) is the one exception -- it always propagates immediately, never
    retried."""
    for attempt in range(_MAX_COMPOSE_RECONCILE_ATTEMPTS + 1):
        try:
            _validate_compose(compose_path)
        except _UnsafeComposeError:
            raise
        except ValueError as e:
            error = str(e)
        else:
            result = subprocess.run(
                ["docker", "compose", "-f", compose_path, "up", "-d"],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode == 0:
                return
            error = f"docker compose up failed: {result.stderr.strip()}"

        if attempt == _MAX_COMPOSE_RECONCILE_ATTEMPTS:
            raise ValueError(error)

        _log(f"compose failure (attempt {attempt + 1}/{_MAX_COMPOSE_RECONCILE_ATTEMPTS}): "
             f"{error[:200]} -- asking Qwen to fix its own compose file")
        with open(compose_path, encoding="utf-8") as f:
            content = f.read()
        fixed = _reconcile_compose(content, error)
        if not fixed:
            raise ValueError(error)
        with open(compose_path, "w", encoding="utf-8") as f:
            f.write(fixed)


def _service_image(svc: dict) -> str:
    """ARGUS-SCANNER: A service can specify `image:` or `build:` (a path
    string or a dict with a `context` key) -- normalize to one string."""
    if svc.get("image"):
        return str(svc["image"])
    build = svc.get("build")
    if isinstance(build, dict):
        return str(build.get("context", ""))
    return str(build or "")


def _parse_topology(compose_path: str) -> dict:
    """ARGUS-SCANNER: Parses a (validated, already-up) compose file into
    the topology dict shape, including real container IDs from
    `docker compose ps`."""
    with open(compose_path, encoding="utf-8") as f:
        parsed = yaml.safe_load(f.read()) or {}

    ps_result = subprocess.run(
        ["docker", "compose", "-f", compose_path, "ps", "--format", "json"],
        capture_output=True, text=True, timeout=30,
    )
    container_ids = {}
    if ps_result.returncode == 0 and ps_result.stdout.strip():
        # `docker compose ps --format json` emits either a JSON array or
        # JSON-lines depending on Compose version -- handle both rather
        # than assuming one.
        raw = ps_result.stdout.strip()
        try:
            entries = json.loads(raw)
            if isinstance(entries, dict):
                entries = [entries]
        except json.JSONDecodeError:
            entries = []
            for line in raw.splitlines():
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        for entry in entries:
            container_ids[entry.get("Service")] = entry.get("ID", "")

    services = []
    for name, svc in (parsed.get("services") or {}).items():
        ports = svc.get("ports", []) or []
        networks = svc.get("networks", []) or []
        if isinstance(networks, dict):
            networks = list(networks.keys())
        image = _service_image(svc)
        services.append({
            "name": name,
            "role": _infer_role(name, ports, image),
            "image": image,
            "ports": [str(p) for p in ports],
            "networks": [str(n) for n in networks],
            "container_id": container_ids.get(name, ""),
            "ecosystem": "",
            "entry_point": False,
        })

    public_ports = []
    for svc in services:
        for p in svc["ports"]:
            m = re.match(r"^(\d+):", p)
            if m:
                public_ports.append((int(m.group(1)), svc["name"]))
    if public_ports:
        entry_name = min(public_ports)[1]
        for svc in services:
            svc["entry_point"] = (svc["name"] == entry_name)

    network_map = {}
    for svc in services:
        peers = [s["name"] for s in services
                 if s["name"] != svc["name"]
                 and set(s["networks"]) & set(svc["networks"])]
        network_map[svc["name"]] = peers

    # The staging directory's basename preserves the repo's real, correctly-
    # cased name (repo_intake.py names it "{repo_name}_{timestamp}" straight
    # from the clone URL/path, before anything downstream lowercases it for
    # Docker-safe service naming) -- a strong, nearly-free signal for
    # self-branded apps that mount themselves under their own project name
    # as a context path (WebGoat -> /WebGoat being the exact real-world
    # case this was added for, 2026-09-01). Stripped of the trailing
    # "_<timestamp>" repo_intake.py always appends.
    repo_dir_name = os.path.basename(os.path.dirname(os.path.abspath(compose_path)))
    repo_name = re.sub(r"_\d+$", "", repo_dir_name)

    return {"compose_file": compose_path, "services": services,
            "network_map": network_map, "repo_name": repo_name}


def _scan_manifests(repo_path: str) -> dict:
    """ARGUS-SCANNER: Walks repo root and one level of subdirectories,
    collecting manifest files by ecosystem. Returns {ecosystem: file_content},
    first match per ecosystem wins."""
    manifest_map = {}
    search_dirs = [repo_path] + [
        os.path.join(repo_path, d) for d in os.listdir(repo_path)
        if os.path.isdir(os.path.join(repo_path, d)) and not d.startswith(".")
    ]
    for directory in search_dirs:
        for pattern, ecosystem in MANIFEST_PRIORITY:
            if ecosystem in manifest_map:
                continue
            if "*" in pattern:
                matches = list(Path(directory).glob(pattern))
            else:
                candidate = Path(directory) / pattern
                matches = [candidate] if candidate.exists() else []
            for match in matches:
                try:
                    manifest_map[ecosystem] = match.read_text(
                        encoding="utf-8", errors="replace")
                    break
                except OSError:
                    continue
    return manifest_map


def _dockerfile_exposed_ports(dockerfile_path: str) -> list[str]:
    """ARGUS-SCANNER: Pure regex extraction of EXPOSE directives -- zero-GPU,
    deterministic, used to wire up the minimal compose file that wraps an
    image built from the repo's own Dockerfile (see
    _try_build_from_dockerfile)."""
    try:
        text = Path(dockerfile_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    ports = []
    for m in re.finditer(r"^\s*EXPOSE\s+(.+)$", text, re.IGNORECASE | re.MULTILINE):
        for tok in m.group(1).split():
            port = re.match(r"^(\d+)", tok)
            if port:
                ports.append(port.group(1))
    return ports


_JAVA_VERSION_PATTERNS = (
    r"<java\.version>\s*(\d+)\s*</java\.version>",
    r"<maven\.compiler\.release>\s*(\d+)\s*</maven\.compiler\.release>",
    r"<maven\.compiler\.target>\s*(\d+)\s*</maven\.compiler\.target>",
    r"sourceCompatibility\s*=?\s*['\"]?(?:JavaVersion\.VERSION_)?(\d+)",
    r"languageVersion\s*=\s*JavaLanguageVersion\.of\((\d+)\)",
)


def _detect_java_version(manifest_content: str) -> str:
    """ARGUS-SCANNER: Extracts the JDK version a Maven/Gradle project
    actually requires straight from its own manifest (pom.xml's
    <java.version>/<maven.compiler.release>, or Gradle's
    sourceCompatibility/toolchain) -- zero-GPU, deterministic.

    Found live 2026-09-01: a fixed builder tag (`maven:3.9-eclipse-
    temurin-21`) is not general -- it broke on the very first real repo
    tried (WebGoat's pom.xml declares <java.version>25</java.version>,
    Maven's compiler plugin then fails outright with "release version 25
    not supported" against a JDK 21 builder). Any project pinned to a
    different JDK than whatever this project happened to hardcode would
    hit the exact same failure -- detecting the real requirement per-repo
    is the only way this generalizes. Defaults to "21" (a current, widely
    available LTS) only when no version marker is found at all."""
    for pattern in _JAVA_VERSION_PATTERNS:
        m = re.search(pattern, manifest_content)
        if m:
            return m.group(1)
    return "21"


def _prebuild_from_source(repo_path: str, ecosystem: str, manifest_content: str = "") -> bool:
    """ARGUS-SCANNER: Runs the detected ecosystem's standard build command
    in a throwaway builder container with the repo bind-mounted, so a
    Dockerfile that expects a pre-built artifact (a jar under target/, a
    dist/ folder, a compiled binary) has one to COPY when the real `docker
    build` is retried. Only called as a retry after a first `docker build
    .` attempt fails -- see _try_build_from_dockerfile().

    For the two Java ecosystems, the builder image's JDK version is
    resolved from the project's own manifest (_detect_java_version)
    rather than fixed -- see that function's docstring for why a fixed
    tag isn't general enough."""
    if ecosystem not in _SOURCE_BUILD_MAP:
        return False
    builder_image, build_command = _SOURCE_BUILD_MAP[ecosystem]
    if ecosystem in ("java_maven", "java_gradle") and manifest_content:
        java_version = _detect_java_version(manifest_content)
        base_tool = "maven:3.9" if ecosystem == "java_maven" else "gradle:8"
        builder_image = f"{base_tool}-eclipse-temurin-{java_version}"
    try:
        pull = subprocess.run(["docker", "pull", builder_image],
                               capture_output=True, text=True, timeout=300)
        if pull.returncode != 0 and ecosystem in ("java_maven", "java_gradle"):
            # The version-specific tag doesn't exist on Docker Hub for
            # this particular JDK release -- fall back to the map's
            # original fixed tag rather than failing outright on a pull
            # miss alone (a real compile failure against it still falls
            # through to the existing manifest+Qwen-inference path).
            _log(f"builder image {builder_image} not found -- "
                 f"falling back to {_SOURCE_BUILD_MAP[ecosystem][0]}")
            builder_image = _SOURCE_BUILD_MAP[ecosystem][0]
            subprocess.run(["docker", "pull", builder_image],
                            capture_output=True, text=True, timeout=300)
        run_args = ["docker", "run", "--rm", "-v", f"{repo_path}:/repo", "-w", "/repo"]
        if ecosystem in _CACHE_MOUNT_MAP:
            volume_name, cache_path = _CACHE_MOUNT_MAP[ecosystem]
            run_args += ["-v", f"{volume_name}:{cache_path}"]
        run_args += [builder_image, "sh", "-c", build_command]
        result = subprocess.run(
            run_args, capture_output=True, text=True, timeout=900,
        )
        if result.returncode != 0:
            # Maven/Gradle write almost everything, including the actual
            # failure reason, to stdout -- stderr alone (the original
            # version of this log line) came back empty on a real compile
            # failure, hiding the real error entirely.
            _log(f"source pre-build failed ({ecosystem}, {builder_image}): "
                 f"{(result.stdout + result.stderr)[-800:]}")
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError) as e:
        _log(f"source pre-build error ({ecosystem}): {e}")
        return False


def _try_build_from_dockerfile(repo_path: str) -> str | None:
    """
    ARGUS-SCANNER: Builds an image straight from the repo's own Dockerfile
    -- the only path in this module that guarantees the dynamic-analysis
    container matches the exact commit Pass 1/2 statically analyzed,
    rather than whatever released version a public image tag happens to
    be pinned to.

    Found live 2026-09-01 on a real WebGoat run: the existing manifest+
    Qwen-inference fallback picked the README's documented `webgoat/webgoat`
    image (a reasonable inference -- see _extract_docker_hints), but that
    image was version 24.04 (built 2025-03-11) while the statically
    analyzed checkout was a commit from 2026-08-14 -- over a year newer.
    Every dynamic-verification result for that scan was checked against
    code that didn't necessarily match what was flagged. This isn't
    WebGoat-specific: any repo without its own docker-compose.yml (most
    repos) falls into the same manifest-inference path and the same risk.

    Tries a direct `docker build .` first -- many Dockerfiles (especially
    for interpreted languages) are fully self-contained and this just
    works. Only on failure does it detect the ecosystem and run a real
    pre-build step (_prebuild_from_source) before retrying once -- this
    mirrors the exact gap _extract_docker_hints's own docstring already
    named ("trying to docker build from the repo's own Dockerfile without
    ever running the Maven build it needs") rather than guessing a fix
    for it. Returns the built image tag, or None if both attempts fail --
    the caller falls back to the existing manifest+Qwen-inference path
    unchanged, so a source build failure never blocks a scan."""
    dockerfile_path = os.path.join(repo_path, "Dockerfile")
    if not os.path.exists(dockerfile_path):
        return None

    tag = f"argus-victim-{re.sub(r'[^a-z0-9]+', '-', os.path.basename(repo_path).lower())}"

    def _build() -> bool:
        result = subprocess.run(
            ["docker", "build", "-t", tag, repo_path],
            capture_output=True, text=True, timeout=1200,
        )
        if result.returncode != 0:
            _log(f"docker build . failed: {(result.stdout + result.stderr)[-800:]}")
        return result.returncode == 0

    _log("repo has its own Dockerfile -- trying to build from source directly")
    if _build():
        _log(f"built {tag} from source on the first attempt (no pre-build needed)")
        return tag

    manifest_map = _scan_manifests(repo_path)
    ecosystem = next((eco for eco in manifest_map if eco in _SOURCE_BUILD_MAP), None)
    if not ecosystem:
        _log("docker build . failed and no known pre-build step applies -- "
             "falling back to manifest+Qwen inference")
        return None

    _log(f"docker build . failed -- running a real {ecosystem} pre-build "
         f"(the repo's Dockerfile expects a pre-built artifact) then retrying")
    if not _prebuild_from_source(repo_path, ecosystem, manifest_map[ecosystem]):
        return None
    if _build():
        _log(f"built {tag} from source after the {ecosystem} pre-build step")
        return tag
    return None


def _write_prebuilt_compose(repo_path: str, image_tag: str) -> str:
    """ARGUS-SCANNER: Minimal single-service compose file wrapping an
    already-built image (from _try_build_from_dockerfile) -- no Qwen call
    needed, ports come straight from the Dockerfile's own EXPOSE
    directives (deterministic, zero-GPU)."""
    ports = _dockerfile_exposed_ports(os.path.join(repo_path, "Dockerfile"))
    service_name = re.sub(r'[^a-z0-9]+', '-', os.path.basename(repo_path).lower()) or "app"
    compose = {
        "services": {
            service_name: {
                "image": image_tag,
                "ports": [f"{p}:{p}" for p in ports] if ports else [],
            }
        }
    }
    compose_path = os.path.join(repo_path, "docker-compose.argus.yml")
    with open(compose_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(compose, f)
    return compose_path


def build_victim_topology(repo_path: str) -> dict:
    """
    ARGUS-SCANNER: Detects all application layers in the repo and builds
    a multi-container topology. Returns the topology dict used by the
    supervisor to spawn victim containers and by the red agent for attack
    planning.

    Step 1: use a real docker-compose.yml at the repo root if present.
    Step 2: if the repo has its own Dockerfile, build from source --
    guarantees the running container matches the exact analyzed commit
    (see _try_build_from_dockerfile's docstring for why this matters and
    when it was added).
    Step 3: otherwise (or if the source build fails) scan for manifests
    and have Qwen infer a compose file from them (the one GPU-touching
    path in this module) -- unpinned to any specific commit, but the
    long-standing fallback that always works.
    """
    for filename in ("docker-compose.yml", "docker-compose.yaml"):
        compose_path = os.path.join(repo_path, filename)
        if os.path.exists(compose_path):
            _log(f"found {filename}, using it directly")
            _compose_up(compose_path)
            return _parse_topology(compose_path)

    image_tag = _try_build_from_dockerfile(repo_path)
    if image_tag:
        compose_path = _write_prebuilt_compose(repo_path, image_tag)
        _compose_up(compose_path)
        return _parse_topology(compose_path)

    _log("no compose file and no buildable Dockerfile -- scanning manifests")
    manifest_map = _scan_manifests(repo_path)
    if not manifest_map:
        raise ValueError(
            f"No docker-compose.yml and no recognized manifests found in {repo_path}"
        )

    docker_hints = _extract_docker_hints(repo_path)
    _log(f"found manifests: {list(manifest_map.keys())}, "
         f"inferring compose via Qwen"
         + (" (with real README Docker hints)" if docker_hints else ""))
    compose_content = _infer_compose_from_manifests(manifest_map, docker_hints)
    compose_path = os.path.join(repo_path, "docker-compose.argus.yml")
    with open(compose_path, "w", encoding="utf-8") as f:
        f.write(compose_content)

    _compose_up(compose_path)
    return _parse_topology(compose_path)


def teardown_victim_topology(topology: dict) -> None:
    """ARGUS-SCANNER: Tears down all victim containers after a scenario
    completes."""
    subprocess.run(
        ["docker", "compose", "-f", topology["compose_file"], "down", "--remove-orphans"],
        capture_output=True, text=True, timeout=60,
    )
