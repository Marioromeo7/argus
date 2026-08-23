#!/usr/bin/env python3
"""
P1.2 Test: MySQL CVE-2000-0148 end-to-end validation.

This script:
1. Spawns a GraphRange victim container with vulnerable MySQL 3.21.33b
2. Waits for the service to be reachable
3. Runs the short-scramble exploit (exploit_short_scramble.py)
4. Verifies successful authentication bypass

Status: Awaiting vulnerable MySQL source URL (see setup instructions below).
"""

import sys
import os
import subprocess
import time
import socket

# Add parent to path so we can import graphrange modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from graphrange.docker.supervisor.supervisor import spawn_scenario


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


def test_mysql_cve_2000_0148():
    """
    End-to-end test: spawn vulnerable MySQL, run exploit, verify bypass.

    Returns True if exploit succeeds (CVE reproduced), False otherwise.
    """
    print("[*] P1.2: MySQL CVE-2000-0148 (short-scramble auth bypass) test")
    print("[*] Target: MySQL 3.21.33b vulnerable to remote auth bypass")
    print()

    # Define the vulnerable scenario
    scenario = {
        "name": "mysql-3.21.33b-cve-2000-0148",
        "cves": ["CVE-2000-0148"],
        "victims": [
            {
                "name": "mysql-victim",
                "cpe": ("oracle", "mysql", "3.21.33b"),
                "port": 3306,
            }
        ],
    }

    print("[1] Spawning vulnerable MySQL 3.21.33b container...")
    try:
        container = spawn_scenario(scenario, init=True)
        victim_ip = container.network_settings["IPAddress"]
        print(f"[+] Container running at {victim_ip}:3306")
    except Exception as e:
        print(f"[-] Failed to spawn container: {e}")
        print()
        print("SETUP INSTRUCTIONS:")
        print("=" * 70)
        print("To complete P1.2, you need to source a vulnerable MySQL 3.21.33b:")
        print()
        print("1. Find the source tarball from one of:")
        print("   - Internet Archive Wayback Machine: https://web.archive.org/web/2000/mysql.com/")
        print("   - Software Heritage: https://archive.softwareheritage.org/")
        print("   - TUNA/university mirrors of MySQL-3.21/ directory")
        print()
        print("2. Update graphrange/victim_builder.py:")
        print("   In _MYSQL_SOURCES, replace the placeholder URL for '3.21.33b' with the")
        print("   actual download URL and the extracted directory name (usually 'mysql-3.21.33')")
        print()
        print("3. Re-run this test to build and exploit the vulnerable version")
        print("=" * 70)
        return False

    print("[2] Waiting for MySQL to start...")
    if not wait_for_port(victim_ip, 3306, timeout=60):
        print(f"[-] MySQL did not become reachable on {victim_ip}:3306")
        container.stop()
        return False
    print(f"[+] MySQL is reachable")

    print("[3] Running CVE-2000-0148 short-scramble exploit...")
    try:
        result = subprocess.run(
            [sys.executable, os.path.join(os.path.dirname(__file__), "exploit_short_scramble.py"),
             victim_ip, "3306"],
            capture_output=True,
            timeout=10,
            text=True,
        )
        print(result.stdout)
        if result.stderr:
            print("[stderr]:", result.stderr)

        # Check if exploit succeeded
        if result.returncode == 0 and "VULNERABLE" in result.stdout:
            print("[+] SUCCESS: CVE-2000-0148 reproduced on vulnerable MySQL 3.21.33b")
            container.stop()
            return True
        else:
            print("[-] Exploit did not succeed (mysql may not be vulnerable, or services not ready)")
            container.stop()
            return False

    except subprocess.TimeoutExpired:
        print("[-] Exploit timed out")
        container.stop()
        return False
    except Exception as e:
        print(f"[-] Error running exploit: {e}")
        container.stop()
        return False


def main():
    success = test_mysql_cve_2000_0148()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
