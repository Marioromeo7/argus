#!/usr/bin/env python3
"""
P1.1 Test: Cyrus IMAP + Squid end-to-end validation.

Validates that both services (Cyrus and Squid) can be built, deployed, and
demonstrate their documented vulnerability behavior end-to-end.

Test sequence:
1. Spawn Cyrus IMAP 2.2.5 container (CVE-2004-1012/1013: RCE)
2. Spawn Squid 2.2.STABLE5 container (CVE-1999-1481: ACL bypass)
3. Wait for services to be reachable
4. Run validation exploits on each
5. Report overall status

Status: Ready for execution. Both services have validated build recipes.
"""

import sys
import os
import subprocess
import time
import socket
import uuid
import docker

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from graphrange.docker.supervisor.supervisor import spawn_scenario, teardown_scenario, NETWORK_NAME

# 2026-08-24 fix: this whole file was written against an API spawn_scenario()
# doesn't have. Real signature: spawn_scenario(scenario: dict) -> dict
# (no `init` kwarg -- it already hardcodes init=True on all three containers
# unconditionally since the 2026-08-13 zombie-process fix). Real scenario
# shape: a flat scenario["victim_cpe"] CPE string, not scenario["victims"] =
# [{"cpe": (vendor, product, version) tuple, ...}] -- confirmed by reading
# supervisor.py's spawn_scenario() directly, which reads
# scenario.get("victim_cpe", "") verbatim. Under the old (wrong) shape that
# key was always absent, so victim_cpe was always "", is_generic_base and
# victim_cpe was always False, and _resolve_victim_service() never fired at
# all -- the victim would just sit at ubuntu:22.04 running "sleep infinity"
# forever, meaning even a "successful" run never actually tested anything.
# Real return shape: {"red_id", "blue_id", "victim_id",
# "victim_service_status", "install_exit_code", "start_exit_code"} -- plain
# ID strings and status text, not a docker container object (no
# .network_settings, no .stop()). Nothing in the codebase resolved a
# victim's IP from its container ID before this fix -- verified live against
# a real container on the graphrange-public network.
_docker_client = docker.from_env()


def _victim_ip(victim_id: str) -> str | None:
    """Resolve a spawned victim container's IP on the graphrange-public network."""
    try:
        c = _docker_client.containers.get(victim_id)
        return c.attrs["NetworkSettings"]["Networks"][NETWORK_NAME]["IPAddress"]
    except Exception:
        return None


def wait_for_port(host: str, port: int, timeout: int = 30, service_name: str = "service") -> bool:
    """Poll a port until it accepts connections."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                print(f"[+] {service_name} is reachable on {host}:{port}")
                return True
        except:
            pass
        time.sleep(1)

    print(f"[-] {service_name} did not become reachable on {host}:{port}")
    return False


# 2026-08-24 fix, found live: wait_for_port() above connects from the plain
# Windows-host Python process. Confirmed directly, not assumed -- spun up a
# throwaway http.server on graphrange-public and tried reaching it both ways:
# a raw host socket connect to the container's bridge-network IP fails
# outright (Docker Desktop on this Windows setup does not route the custom
# bridge network to the host), while the identical connect from inside
# another container on the same network succeeds immediately. This is
# exactly what caused Squid to report "did not become reachable" earlier
# despite genuinely running -- confirmed via a live docker-exec into that
# exact victim: real squid processes in `ps aux`, cache.log showing
# "Accepting HTTP connections on port 3128... Ready to serve requests.",
# and a manual second squid start attempt failing with "Address already in
# use" -- conclusive proof the first instance really was bound and
# listening the whole time. Same reasoning applies to the exploit scripts
# below, which were also being run as plain host subprocesses. Both are
# fixed here by executing inside the already-spawned `red` container
# instead, which sits on graphrange-public and can reach the victim exactly
# the way this project's own prior validated tests always did ("nmap-
# scanned the victim from the red container", per BACKLOG.md).

def _wait_for_port_via_red(red_container, host: str, port: int, timeout: int = 30,
                            service_name: str = "service") -> bool:
    """Poll a port from inside the red container (which shares the victim's
    network), not from the host."""
    probe = (f"import socket,sys; s=socket.socket(); s.settimeout(2); "
             f"sys.exit(0 if s.connect_ex(('{host}',{port}))==0 else 1)")
    start = time.time()
    while time.time() - start < timeout:
        exit_code, _ = red_container.exec_run(["python3", "-c", probe])
        if exit_code == 0:
            print(f"[+] {service_name} is reachable on {host}:{port} (checked from red container)")
            return True
        time.sleep(1)
    print(f"[-] {service_name} did not become reachable on {host}:{port} (checked from red container)")
    return False


def _run_exploit_in_container(container, script_path: str, args: list[str]) -> tuple[bool, str]:
    """Copy a (stdlib-only) exploit script into `container` and run it there
    via python3, instead of as a host subprocess that can't reach the
    victim's Docker-internal IP at all. Returns (success, combined_output).
    No timeout here (docker-py's exec_run has none built in) -- unnecessary
    anyway since all three exploit scripts already bound every socket op to
    ~5s internally, so this can't hang."""
    import io, tarfile
    basename = os.path.basename(script_path)
    remote_path = f"/tmp/{basename}"

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        tar.add(script_path, arcname=basename)
    buf.seek(0)
    container.put_archive("/tmp", buf.read())

    try:
        exit_code, output = container.exec_run(
            ["python3", remote_path, *args], demux=False
        )
        text = output.decode(errors="replace") if isinstance(output, bytes) else str(output)
        return exit_code == 0, text
    except Exception as e:
        return False, f"[-] Error running exploit in container: {e}"


def test_cyrus():
    """Spawn and test Cyrus IMAP 2.2.5."""
    print("\n" + "=" * 70)
    print("PART 1: CYRUS IMAP 2.2.5 VALIDATION")
    print("=" * 70)
    print("[*] CVE-2004-1012 & CVE-2004-1013: PARTIAL/FETCH RCE (CVSS 10.0)")
    print()

    scenario = {
        "name": "cyrus-2.2.5-cve-2004",
        # run_id gives spawn_scenario() a unique container-name suffix
        # (gr-red-{run_id} etc). Without it, run_suffix defaults to "adhoc"
        # -- every scenario that omits run_id collides on the exact same
        # container names, both across separate runs (409 Conflict against a
        # leftover from an earlier session) and even between Cyrus and Squid
        # within this same script (both would've raced for "gr-red-adhoc").
        "run_id": f"cyrus-{uuid.uuid4().hex[:8]}",
        "cves": ["CVE-2004-1012", "CVE-2004-1013"],
        "victim_cpe": "cpe:2.3:a:carnegie_mellon_university:cyrus_imap_server:2.2.5:*:*:*:*:*:*:*",
    }

    print("[1] Spawning Cyrus IMAP 2.2.5 scenario...")
    try:
        result = spawn_scenario(scenario)
    except Exception as e:
        print(f"[-] Failed to spawn scenario: {e}")
        return False

    red_id, blue_id, victim_id = result["red_id"], result["blue_id"], result["victim_id"]
    status = result["victim_service_status"]
    print(f"[+] Scenario spawned (victim {victim_id[:12]}, service_status={status})")

    if status != "mapped":
        print(f"[-] Victim CPE did not resolve to a known recipe (status={status})")
        teardown_scenario(red_id, blue_id, victim_id)
        return False
    if result.get("install_exit_code") not in (0, None):
        print(f"[-] Install failed (exit code {result['install_exit_code']})")
        teardown_scenario(red_id, blue_id, victim_id)
        return False
    if result.get("start_exit_code") not in (0, None):
        print(f"[-] Start failed (exit code {result['start_exit_code']})")
        teardown_scenario(red_id, blue_id, victim_id)
        return False

    host = _victim_ip(victim_id)
    if not host:
        print("[-] Could not resolve victim container IP")
        teardown_scenario(red_id, blue_id, victim_id)
        return False
    print(f"[+] Container running at {host}:143")

    red_container = _docker_client.containers.get(red_id)
    if not _wait_for_port_via_red(red_container, host, 143, timeout=60, service_name="Cyrus IMAP"):
        teardown_scenario(red_id, blue_id, victim_id)
        return False

    print("[2] Running Cyrus validation test (from red container)...")
    exploit_path = os.path.join(os.path.dirname(__file__), "exploit_cyrus_cve_2004_rce.py")
    success, output = _run_exploit_in_container(red_container, exploit_path, [host, "143"])
    print(output)

    teardown_scenario(red_id, blue_id, victim_id)
    return success


def test_squid():
    """Spawn and test Squid 2.2.STABLE5."""
    print("\n" + "=" * 70)
    print("PART 2: SQUID 2.2.STABLE5 VALIDATION")
    print("=" * 70)
    print("[*] CVE-1999-1481: External-auth ACL bypass (CVSS 5.8)")
    print()

    scenario = {
        "name": "squid-2.2.stable5-cve-1999",
        "run_id": f"squid-{uuid.uuid4().hex[:8]}",
        "cves": ["CVE-1999-1481"],
        "victim_cpe": "cpe:2.3:a:national_science_foundation:squid_web_proxy:2.2.STABLE5:*:*:*:*:*:*:*",
    }

    print("[1] Spawning Squid 2.2.STABLE5 scenario...")
    try:
        result = spawn_scenario(scenario)
    except Exception as e:
        print(f"[-] Failed to spawn scenario: {e}")
        return False

    red_id, blue_id, victim_id = result["red_id"], result["blue_id"], result["victim_id"]
    status = result["victim_service_status"]
    print(f"[+] Scenario spawned (victim {victim_id[:12]}, service_status={status})")

    if status != "mapped":
        print(f"[-] Victim CPE did not resolve to a known recipe (status={status})")
        teardown_scenario(red_id, blue_id, victim_id)
        return False
    if result.get("install_exit_code") not in (0, None):
        print(f"[-] Install failed (exit code {result['install_exit_code']})")
        teardown_scenario(red_id, blue_id, victim_id)
        return False
    if result.get("start_exit_code") not in (0, None):
        print(f"[-] Start failed (exit code {result['start_exit_code']})")
        teardown_scenario(red_id, blue_id, victim_id)
        return False

    host = _victim_ip(victim_id)
    if not host:
        print("[-] Could not resolve victim container IP")
        teardown_scenario(red_id, blue_id, victim_id)
        return False
    print(f"[+] Container running at {host}:3128")

    red_container = _docker_client.containers.get(red_id)
    if not _wait_for_port_via_red(red_container, host, 3128, timeout=60, service_name="Squid"):
        teardown_scenario(red_id, blue_id, victim_id)
        return False

    print("[2] Running Squid validation test (from red container)...")
    exploit_path = os.path.join(os.path.dirname(__file__), "exploit_squid_cve_1999_1481.py")
    success, output = _run_exploit_in_container(red_container, exploit_path, [host, "3128"])
    print(output)

    teardown_scenario(red_id, blue_id, victim_id)
    return success


def main():
    print("P1.1 TEST: Cyrus IMAP + Squid End-to-End Validation")
    print()
    print("Validates that:")
    print("  1. Cyrus IMAP 2.2.5 builds and runs (CVE-2004-1012/1013)")
    print("  2. Squid 2.2.STABLE5 builds and runs (CVE-1999-1481)")
    print("  3. Both services are reachable and functional")
    print("  4. Authentication and ACL handling work as expected")
    print()

    cyrus_ok = test_cyrus()
    squid_ok = test_squid()

    print("\n" + "=" * 70)
    print("FINAL RESULTS")
    print("=" * 70)
    print(f"Cyrus IMAP 2.2.5:     {'✓ PASS' if cyrus_ok else '✗ FAIL'}")
    print(f"Squid 2.2.STABLE5:    {'✓ PASS' if squid_ok else '✗ FAIL'}")
    print()

    if cyrus_ok and squid_ok:
        print("[+] P1.1 VALIDATION COMPLETE: Both services verified")
        return 0
    else:
        print("[-] P1.1 VALIDATION INCOMPLETE: One or more services failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
