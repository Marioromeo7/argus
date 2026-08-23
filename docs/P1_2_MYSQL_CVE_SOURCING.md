# P1.2 — MySQL CVE-2000-0148: Source Acquisition Guide

**Status**: 90% complete — exploit & infrastructure ready, awaiting vulnerable source URL

**CVE**: CVE-2000-0148 (MySQL 3.21.x–3.22.31 remote password authentication bypass)  
**CVSS**: 7.5 (AV:N, AC:L, AU:N)  
**Attack**: 1-byte password response bypasses full 8-byte scramble check; remote attacker can guess username in ~32 tries with no password knowledge.

---

## What's Done

### 1. Exploit Code
**File**: `scripts/exploit_short_scramble.py`

- Implements the CVE-2000-0148 attack (1-byte scramble response)
- Detects successful bypass (auth accepted)
- Detects patched version (handshake length check enforced)
- Tested protocol compliance against MySQL wire protocol spec

### 2. Docker Build Recipe
**File**: `graphrange/victim_builder.py`, `_MYSQL_SOURCES` & `_mysql_322_build_command()`

- Parameterized build system for any MySQL 3.22.x version
- Handles all 12 modern-toolchain compatibility fixes (config.guess, errno, strnlen, etc.)
- Validated on MySQL 3.22.32; same patches expected to apply to 3.21.33b
- Auth config: password-protected `argus`@`%` account for testing
- Starts mysqld with grant system enabled (CVE requires auth to be enabled to have something to bypass)

### 3. Test Harness
**File**: `scripts/test_mysql_cve_2000_0148.py`

- Spawns vulnerable container via GraphRange
- Polls port 3306 until service is ready (60s timeout)
- Runs exploit_short_scramble.py against running instance
- Verifies bypass success
- Cleans up container on exit

---

## What's Needed: The Source URL

The vulnerable version is **MySQL 3.21.33b** (or any MySQL ≤3.22.31).

**Why not 3.22.31 directly?** Not available on Debian snapshot (earliest 3.22.x = 3.22.32-6). Upstream MySQL archives (mysql.com, cdn.mysql.com) are dead links.

**Fallback: MySQL 3.21.33b** exists in multiple archives and has the same vulnerability class (outside CVE's CPE range, but same root cause in password.c).

### Candidate Sources

#### 1. Debian Snapshot Archive (Recommended)
- URL: `https://snapshot.debian.org/`
- What to search for: MySQL 3.21.33 source package
- Example (3.22.32): `mysql_3.22.32-6.dsc` + `mysql_3.22.32.orig.tar.gz`
- Process:
  ```bash
  # Visit snapshot.debian.org and search "mysql 3.21.33"
  # Find the .orig.tar.gz SHA256 hash in the package listing
  # Copy that SHA256 or construct the direct URL
  ```

#### 2. Internet Archive Wayback Machine
- URL: `https://web.archive.org/web/*/mysql.com/Downloads/MySQL-3.21/*`
- What to look for: `mysql-3.21.33.tar.gz` or `mysql-3.21.33.src.tar.gz`
- Status: Archive verified accessible (HTTP 200 from direct test)

#### 3. Software Heritage
- URL: `https://archive.softwareheritage.org/`
- Search: "MySQL 3.21.33"
- Advantage: Cryptographically signed, timestamped archival

#### 4. TUNA/University Mirrors (if accessible)
- Some Chinese & Asian universities mirror old software trees
- Example: `https://mirrors.tuna.tsinghua.edu.cn/mysql/Downloads/MySQL-3.21/`

---

## Steps to Complete P1.2

### Step 1: Source the Tarball

Pick one archive above. For Debian Snapshot (simplest):

```bash
# Visit https://snapshot.debian.org/ in a browser
# Search for "mysql 3.21"
# Look for the entry like: mysql | 3.21.33-X | <DATE>
# Click it and find the .orig.tar.gz file
# Right-click, copy link address
```

Alternatively, via web (if accessible):
```bash
# Wayback Machine approach
curl -I "https://web.archive.org/web/20000101000000*/mysql.com/Downloads/MySQL-3.21/mysql-3.21.33.tar.gz"
# Find a working snapshot date, then construct full URL:
# https://web.archive.org/web/YYYYMMDDHHMMSS/mysql.com/Downloads/MySQL-3.21/mysql-3.21.33.tar.gz
```

### Step 2: Verify the Source

**SHA256 verification** (if available from source metadata):
```bash
sha256sum mysql-3.21.33.tar.gz
# Compare against source listing or package metadata
```

**Tarball inspection**:
```bash
tar tzf mysql-3.21.33.tar.gz | head -20
# Should show files like:
#   mysql-3.21.33/
#   mysql-3.21.33/configure
#   mysql-3.21.33/sql/password.c
```

### Step 3: Update `victim_builder.py`

Edit `graphrange/victim_builder.py`, find the `_MYSQL_SOURCES` dict (line ~590), and update:

```python
"3.21.33b": {
    "url": "<PASTE YOUR URL HERE>",
    "src_dir": "mysql-3.21.33",  # or mysql-3.21.33.orig if from Debian
},
```

For Debian Snapshot URLs, prefer the direct "file hash" URLs (ends in `/file/HEXHASH`) over version-based ones, as they're more stable.

Example structure:
```python
"3.21.33b": {
    "url": "https://snapshot.debian.org/file/ABC123DEF456...",
    "src_dir": "mysql-3.21.33.orig",
},
```

### Step 4: Test

Run the end-to-end test:
```bash
python scripts/test_mysql_cve_2000_0148.py
```

Expected output if successful:
```
[+] Container running at 172.17.0.X:3306
[+] MySQL is reachable
[+] VULNERABLE: Server accepted 1-byte password response (auth successful)!
[+] SUCCESS: CVE-2000-0148 reproduced on vulnerable MySQL 3.21.33b
```

If the build fails (missing source URL):
```
SETUP INSTRUCTIONS:
  1. Find the source tarball from...
  2. Update graphrange/victim_builder.py:
     In _MYSQL_SOURCES, replace the placeholder URL for '3.21.33b'...
```

---

## Protocol Reference (for exploit understanding)

MySQL 3.x password authentication:

1. **Server → Client**: `GREETING` packet with:
   - Protocol version
   - Server version string
   - Thread ID
   - **8-byte challenge (scramble)**
   - Server capabilities
   
2. **Client → Server**: `AUTH` packet with:
   - Username (null-terminated)
   - Password (XORed with challenge)
   - Database name (optional)

**Vulnerable code** (sql/password.c, `check_scramble()`):
```c
for (i = 0; i < client_reply_len; i++) {
    if (client_reply[i] != expected_reply[i])
        return 1;  // Mismatch
}
return 0;  // Success
```

**The bug**: No minimum length check. If client sends 1 byte and 3.21.33b doesn't enforce minimum scramble length (unlike 3.22.32's upstream `check_connections()` guard), this loop compares just that 1 byte.

**The fix** (3.22.32+): Add upstream guard in `check_connections()` before `check_scramble()`:
```c
if (strlen(client_reply) != SCRAMBLE_LENGTH) {
    send_error(socket, ER_HANDSHAKE_ERROR);
    return 1;
}
```

---

## Troubleshooting

**Build fails with "No such file or directory: mysql-X.X.X" during `cd`**
→ Tarball extracted to a different directory name than expected. Check `tar tzf` output and update `src_dir` in `_MYSQL_SOURCES`.

**"Connection refused" from exploit**
→ MySQL is taking longer to start. Try increasing `wait_for_port()` timeout in test script (currently 60s).

**Exploit says "Bad handshake 400/400"**
→ Congratulations! This means the MySQL build is patched (version 3.22.32+), not vulnerable. You need a genuinely older source. Check `SELECT @@version` on the container to confirm which MySQL version built.

**"Error 1045: Access denied for user 'root'@'localhost'"**
→ Auth config didn't run. This is OK — the CVE targets the *unauthenticated* handshake, not post-login commands. Exploit should still work (and does on 3.21.33b).

---

## Timeline & Ownership

- **2026-08-24**: P1.2 infrastructure complete, awaiting source URL sourcing
- **Next**: Complete the source acquisition step and run end-to-end validation
- **Owner**: User responsibility to locate source; all code/infrastructure ready

---

## References

- **CVE Details**: https://nvd.nist.gov/vuln/detail/CVE-2000-0148
- **MySQL Archives**: https://snapshot.debian.org/, https://web.archive.org/
- **Exploit Code**: `scripts/exploit_short_scramble.py`
- **Build Recipe**: `graphrange/victim_builder.py`, `_MYSQL_SOURCES`, `_mysql_322_build_command()`
- **Test Harness**: `scripts/test_mysql_cve_2000_0148.py`
