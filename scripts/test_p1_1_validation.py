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

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from graphrange.docker.supervisor.supervisor import spawn_scenario


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


def test_cyrus():
    """Spawn and test Cyrus IMAP 2.2.5."""
    print("\n" + "=" * 70)
    print("PART 1: CYRUS IMAP 2.2.5 VALIDATION")
    print("=" * 70)
    print("[*] CVE-2004-1012 & CVE-2004-1013: PARTIAL/FETCH RCE (CVSS 10.0)")
    print()

    scenario = {
        "name": "cyrus-2.2.5-cve-2004",
        "cves": ["CVE-2004-1012", "CVE-2004-1013"],
        "victims": [
            {
                "name": "cyrus-victim",
                "cpe": ("carnegie_mellon_university", "cyrus_imap_server", "2.2.5"),
                "port": 143,
            }
        ],
    }

    print("[1] Spawning Cyrus IMAP 2.2.5 container...")
    try:
        result = spawn_scenario(scenario)
        host = result.get("victim_ip", result.get("victim", {}).get("ip"))
        print(f"[+] Container running at {host}:143")
    except Exception as e:
        print(f"[-] Failed to spawn container: {e}")
        return False

    if not wait_for_port(host, 143, timeout=60, service_name="Cyrus IMAP"):
        container.stop()
        return False

    print("[2] Running Cyrus validation test...")
    try:
        result = subprocess.run(
            [sys.executable, os.path.join(os.path.dirname(__file__), "exploit_cyrus_cve_2004_rce.py"),
             host, "143"],
            capture_output=True,
            timeout=10,
            text=True,
        )
        print(result.stdout)
        if result.stderr:
            print("[stderr]:", result.stderr)

        success = result.returncode == 0
        container.stop()
        return success

    except subprocess.TimeoutExpired:
        print("[-] Test timed out")
        container.stop()
        return False
    except Exception as e:
        print(f"[-] Error running test: {e}")
        container.stop()
        return False


def test_squid():
    """Spawn and test Squid 2.2.STABLE5."""
    print("\n" + "=" * 70)
    print("PART 2: SQUID 2.2.STABLE5 VALIDATION")
    print("=" * 70)
    print("[*] CVE-1999-1481: External-auth ACL bypass (CVSS 5.8)")
    print()

    scenario = {
        "name": "squid-2.2.stable5-cve-1999",
        "cves": ["CVE-1999-1481"],
        "victims": [
            {
                "name": "squid-victim",
                "cpe": ("national_science_foundation", "squid_web_proxy", "2.2.STABLE5"),
                "port": 3128,
            }
        ],
    }

    print("[1] Spawning Squid 2.2.STABLE5 container...")
    try:
        container = spawn_scenario(scenario, init=True)
        host = container.network_settings["IPAddress"]
        print(f"[+] Container running at {host}:3128")
    except Exception as e:
        print(f"[-] Failed to spawn container: {e}")
        return False

    if not wait_for_port(host, 3128, timeout=60, service_name="Squid"):
        container.stop()
        return False

    print("[2] Running Squid validation test...")
    try:
        result = subprocess.run(
            [sys.executable, os.path.join(os.path.dirname(__file__), "exploit_squid_cve_1999_1481.py"),
             host, "3128"],
            capture_output=True,
            timeout=10,
            text=True,
        )
        print(result.stdout)
        if result.stderr:
            print("[stderr]:", result.stderr)

        success = result.returncode == 0
        container.stop()
        return success

    except subprocess.TimeoutExpired:
        print("[-] Test timed out")
        container.stop()
        return False
    except Exception as e:
        print(f"[-] Error running test: {e}")
        container.stop()
        return False


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
