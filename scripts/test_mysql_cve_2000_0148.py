#!/usr/bin/env python3
"""
P1.2 Test: MySQL CVE-2000-0148 end-to-end validation.

This script:
1. Spawns a GraphRange victim container with vulnerable MySQL 3.22.30
2. Waits for the service to be reachable
3. Runs the short-scramble exploit (exploit_short_scramble.py)
4. Verifies successful authentication bypass
"""

import sys
import os
import subprocess
import time
import socket
import uuid
import docker

# Add parent to path so we can import graphrange modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from graphrange.docker.supervisor.supervisor import spawn_scenario, teardown_scenario, NETWORK_NAME

# 2026-08-24 fix -- same broken pattern as test_p1_1_validation.py, fixed the
# same way (see that file's comment for the full account): spawn_scenario()
# takes no `init` kwarg and returns a plain dict of IDs/status, not a
# container object with .network_settings/.stop(). Target version went
# through two corrections the same day: first "3.21.33" (a version that was
# never actually on NVD's CVE-2000-0148 CPE list, and whose sourced URL
# turned out to 404 anyway), then "3.21.33b" was tried and found to mismatch
# victim_builder.py's real _MYSQL_SOURCES key, and finally "3.22.30" -- a
# real NVD-listed vulnerable version, with a real working source tarball the
# user found and verified (real gzip, real check_scramble() present).
_docker_client = docker.from_env()


def _victim_ip(victim_id: str) -> str | None:
    """Resolve a spawned victim container's IP on the graphrange-public network."""
    try:
        c = _docker_client.containers.get(victim_id)
        return c.attrs["NetworkSettings"]["Networks"][NETWORK_NAME]["IPAddress"]
    except Exception:
        return None


def wait_for_port(host: str, port: int, timeout: int = 30) -> bool:
    """Poll a port until it's accepting connections."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                return True
        except:
            pass
        time.sleep(1)
    return False


# 2026-08-24 fix -- confirmed live (see test_p1_1_validation.py's comment for
# the full reproduction): a raw host socket connect to a graphrange-public
# container IP fails outright on this Docker Desktop/Windows setup, even
# when the service is genuinely up. wait_for_port() above is now dead code
# for this reason, kept only in case a future non-Docker-Desktop environment
# needs it; both actual checks below run inside the `red` container instead,
# same as GraphRange's own prior validated tests always did.

def _wait_for_port_via_red(red_container, host: str, port: int, timeout: int = 30) -> bool:
    """Poll a port from inside the red container (shares the victim's network)."""
    probe = (f"import socket,sys; s=socket.socket(); s.settimeout(2); "
             f"sys.exit(0 if s.connect_ex(('{host}',{port}))==0 else 1)")
    start = time.time()
    while time.time() - start < timeout:
        exit_code, _ = red_container.exec_run(["python3", "-c", probe])
        if exit_code == 0:
            return True
        time.sleep(1)
    return False


def _run_exploit_in_container(container, script_path: str, args: list[str]) -> tuple[bool, str]:
    """Copy a (stdlib-only) exploit script into `container` and run it there
    via python3 -- a host subprocess can't reach the victim's Docker-internal
    IP at all (see comment above). No timeout here (docker-py's exec_run has
    none built in) -- unnecessary anyway since exploit_short_scramble.py
    already bounds every socket op to ~5s internally."""
    import io, tarfile
    basename = os.path.basename(script_path)
    remote_path = f"/tmp/{basename}"

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        tar.add(script_path, arcname=basename)
    buf.seek(0)
    container.put_archive("/tmp", buf.read())

    try:
        exit_code, output = container.exec_run(["python3", remote_path, *args])
        text = output.decode(errors="replace") if isinstance(output, bytes) else str(output)
        return exit_code == 0, text
    except Exception as e:
        return False, f"[-] Error running exploit in container: {e}"


def test_mysql_cve_2000_0148():
    """
    End-to-end test: spawn vulnerable MySQL, run exploit, verify bypass.

    Returns True if exploit succeeds (CVE reproduced), False otherwise.
    """
    print("[*] P1.2: MySQL CVE-2000-0148 (short-scramble auth bypass) test")
    print("[*] Target: MySQL 3.22.30, a real NVD-listed vulnerable version")
    print()

    scenario = {
        "name": "mysql-3.22.30-cve-2000-0148",
        # See test_p1_1_validation.py's comment: without a unique run_id,
        # spawn_scenario() defaults every container name to "...-adhoc",
        # colliding with any other scenario (or leftover from a prior run)
        # that also omitted one.
        "run_id": f"mysql-{uuid.uuid4().hex[:8]}",
        "cves": ["CVE-2000-0148"],
        "victim_cpe": "cpe:2.3:a:oracle:mysql:3.22.30:*:*:*:*:*:*:*",
    }

    print("[1] Spawning vulnerable MySQL 3.22.30 scenario...")
    try:
        result = spawn_scenario(scenario)
    except Exception as e:
        print(f"[-] Failed to spawn scenario: {e}")
        return False

    red_id, blue_id, victim_id = result["red_id"], result["blue_id"], result["victim_id"]
    status = result["victim_service_status"]
    print(f"[+] Scenario spawned (victim {victim_id[:12]}, service_status={status})")

    if status in ("no_install_mapping", "not_application_cpe", "windows_only",
                  "client_side_not_executable", "not_attempted"):
        print(f"[-] Victim CPE did not resolve to a known recipe (status={status})")
        print()
        print("SETUP INSTRUCTIONS:")
        print("=" * 70)
        print("To complete P1.2, confirm graphrange/victim_builder.py's _MYSQL_SOURCES")
        print("has a real URL for '3.22.30' and that _VERSION_MAP is populated")
        print("from it under ('oracle', 'mysql', '3.22.30') in BOTH victim_builder.py")
        print("and supervisor.py's hand-synced duplicate.")
        print("=" * 70)
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

    victim_ip = _victim_ip(victim_id)
    if not victim_ip:
        print("[-] Could not resolve victim container IP")
        teardown_scenario(red_id, blue_id, victim_id)
        return False
    print(f"[+] Container running at {victim_ip}:3306")

    red_container = _docker_client.containers.get(red_id)
    print("[2] Waiting for MySQL to start (checked from red container)...")
    if not _wait_for_port_via_red(red_container, victim_ip, 3306, timeout=60):
        print(f"[-] MySQL did not become reachable on {victim_ip}:3306")
        teardown_scenario(red_id, blue_id, victim_id)
        return False
    print(f"[+] MySQL is reachable")

    print("[3] Running CVE-2000-0148 short-scramble exploit (from red container)...")
    exploit_path = os.path.join(os.path.dirname(__file__), "exploit_short_scramble.py")
    exploit_success, output = _run_exploit_in_container(red_container, exploit_path, [victim_ip, "3306"])
    print(output)
    success = exploit_success and "VULNERABLE" in output
    if success:
        print("[+] SUCCESS: CVE-2000-0148 reproduced on vulnerable MySQL 3.22.30")
    else:
        print("[-] Exploit did not succeed (mysql may not be vulnerable, or services not ready)")

    teardown_scenario(red_id, blue_id, victim_id)
    return success


def main():
    success = test_mysql_cve_2000_0148()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
