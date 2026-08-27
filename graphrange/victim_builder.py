"""
ARGUS-LAYER-7: Victim Builder (GraphRange).

Resolves a CVE's application-level CPE to a real, running vulnerable
service on the victim container -- not just a base OS image. Extends
supervisor.py's _resolve_cpe_to_image() (base-image-only) with the
install/start half of GRAPHRANGE.md's own Dockerfile.template spec, which
was never actually wired up (found via a real live Phase 4 test, 2026-08-10:
every scenario reported success=False because the victim ran nothing).

Scope, checked against real graph data before writing this, not assumed:
73 vulnerability nodes total. 21 have ONLY an OS-level CPE (SunOS, FreeBSD,
Windows, Cisco IOS, IRIX, etc.) -- these need a VM, not a container, since
Docker shares the host kernel and these OSes don't run under it. VM support
is a separate, larger, deliberately deferred BACKLOG item -- see BACKLOG.md.
Of the remaining 52 application-level nodes, 3 are Windows-only software
(same kernel wall) and 7 are client-side software (browsers, PowerPoint --
there's no listening service for a network attack tool to reach, a
fundamentally different execution model this file isn't built for). That
leaves 39 real Linux server-daemon candidates; this module maps the ones
with a real, verified apt package (confirmed against a live debian:12-slim
image, not guessed from the package name looking plausible) and returns an
honest status for everything else rather than silently spawning an empty
container and letting it report success=False as if that were a real
negative finding about the technique.
"""

# CPE (vendor, product) -> real install + start commands. Every package name
# here was verified with `apt-cache show` against a live debian:12-slim
# image before being added.
_INSTALL_MAP = {
    ("apache", "http_server"): {
        "install_command": "apt-get update && apt-get install -y apache2",
        "start_command": "service apache2 start",
        "port": 80,
    },
    ("oracle", "mysql"): {
        # Real bug found live 2026-08-12 testing an unseen (unvalidated)
        # MySQL version through the actual spawn_scenario() pipeline:
        # `default-mysql-server` on Ubuntu 22.04 resolves to real MySQL
        # (mysql-server-8.0), not MariaDB -- "service mariadb start"
        # silently no-ops since that service was never installed at all.
        # spawn_scenario() doesn't check exec_run()'s exit code, so this
        # produced "victim_service_status": "mapped" while mysqld was
        # never actually reachable -- confirmed via a real failed
        # `SELECT VERSION()` connection attempt. DEBIAN_FRONTEND=noninteractive
        # added too: mysql-server-8.0's postinst runs through three debconf
        # frontend fallbacks (Dialog -> Readline -> Teletype) without it,
        # observed live as a real source of dpkg configure fragility in a
        # non-TTY container exec.
        "install_command": "DEBIAN_FRONTEND=noninteractive apt-get update && "
                            "DEBIAN_FRONTEND=noninteractive apt-get install -y default-mysql-server",
        "start_command": "service mysql start",
        "port": 3306,
    },
    ("national_science_foundation", "squid_web_proxy"): {
        "install_command": "apt-get update && apt-get install -y squid",
        "start_command": "service squid start",
        "port": 3128,
    },
    ("carnegie_mellon_university", "cyrus_imap_server"): {
        "install_command": "apt-get update && apt-get install -y cyrus-imapd",
        "start_command": "service cyrus-imapd start",
        "port": 143,
    },
    ("php", "php"): {
        "install_command": "apt-get update && apt-get install -y php php-cli apache2 libapache2-mod-php",
        "start_command": "service apache2 start",
        "port": 80,
    },
}

# Exact (vendor, product, version) recipes -- checked before _INSTALL_MAP's
# generic "latest apt package" entries. Installing "apache2" via today's apt
# repo installs today's Apache, already patched against a 20+-year-old CVE;
# these entries build the ACTUAL historic vulnerable version from the
# Apache Software Foundation's own archive instead. Old source does not
# compile or run cleanly on a modern toolchain by default -- every fix
# below was found by actually hitting the real failure, not guessed:
#   - a build script written for bash breaking under Debian's default
#     /bin/sh (dash)
#   - a removed glibc symbol (_sys_siglist)
#   - a name collision with glibc's own getline() across multiple files
#   - GCC >=10's -fno-common default breaking old tentative definitions
#     AND (a separate issue -- confirmed by testing -fcommon alone first
#     and seeing it NOT fully fix things) GCC >=5's default inline
#     semantics change breaking Apache's own INLINE macro for
#     ap_os_is_path_absolute -- needs -fgnu89-inline specifically
#   - several ServerRoot-relative paths/files the default config expects
#     that don't exist until created, AND a real per-version difference in
#     which of those paths a given release's default config actually uses
#     (1.3.1 wants mime.types under etc/, 1.3.17 wants it under conf/;
#     1.3.17's config also uses a literal @@ServerRoot@@ placeholder token
#     elsewhere in the file that 1.3.1's config doesn't have) -- handled
#     by writing to both possible mime.types locations and substituting
#     the placeholder globally, rather than branching per version
#   - a legacy `Group #-1` default that modern initgroups() rejects
# Confirmed by batch-testing all 11 Apache 1.3.x versions our graph
# references that Apache's own archive still has a real tarball for
# (1.3.5/1.3.7/1.3.8/1.3.18 were apparently never actually released
# despite NVD's CPE dictionary listing them -- checked directly against
# archive.apache.org, no tarball exists at all for those four, so
# latest-apt is the permanent answer there, not a gap this can close).
# This is exactly why it's a per-version exception table, not a general
# "compile any CPE from source" mechanism. Kept in sync by hand with the
# duplicate copy in graphrange/docker/supervisor/supervisor.py (see that
# file's comment for why it's duplicated rather than imported).
def _apache_13x_build_command(version: str) -> str:
    """ARGUS-LAYER-7: shared recipe for every validated Apache 1.3.x
    version below. The /tmp/ccwrap/gcc wrapper on PATH is what actually
    delivers -fgnu89-inline/-fcommon reliably -- passing them via a CC=
    environment variable or configure argument was tried first and did NOT
    propagate consistently through this build system's nested per-directory
    sub-makes (confirmed live: a partial-but-incomplete failure reduction,
    not a real fix)."""
    return (
        "apt-get update -qq && apt-get install -y -qq build-essential wget && "
        "mkdir -p /tmp/ccwrap && "
        "printf '#!/bin/sh\\nexec /usr/bin/gcc -fgnu89-inline -fcommon \"$@\"\\n' "
        "> /tmp/ccwrap/gcc && "
        "chmod +x /tmp/ccwrap/gcc && "
        "export PATH=/tmp/ccwrap:$PATH && "
        "cd /tmp && "
        f"wget -q https://archive.apache.org/dist/httpd/apache_{version}.tar.gz && "
        f"tar xzf apache_{version}.tar.gz && "
        f"cd apache_{version} && "
        "bash ./configure --prefix=/usr/local/apache && "
        "sed -i 's/SYS_SIGLIST\\[WTERMSIG(status)\\]/strsignal(WTERMSIG(status))/' src/main/http_main.c && "
        "sed -i 's/\\bgetline(/ap_getline(/g' src/main/http_protocol.c && "
        "(cd src && make) && "
        "mkdir -p /usr/local/apache/bin /usr/local/apache/conf /usr/local/apache/logs "
        "/usr/local/apache/htdocs /usr/local/apache/etc /usr/local/apache/var/run && "
        "cp src/httpd /usr/local/apache/bin/httpd && "
        "cp conf/httpd.conf-dist /usr/local/apache/conf/httpd.conf && "
        "cp conf/mime.types /usr/local/apache/etc/mime.types && "
        "cp conf/mime.types /usr/local/apache/conf/mime.types && "
        f"echo 'Hello from Apache {version} (version-pinned GraphRange victim)' "
        "> /usr/local/apache/htdocs/index.html && "
        "sed -i 's#@@ServerRoot@@#/usr/local/apache#g' /usr/local/apache/conf/httpd.conf && "
        'sed -i \'s#^ServerRoot .*#ServerRoot "/usr/local/apache"#\' /usr/local/apache/conf/httpd.conf && '
        "sed -i 's/^Port .*/Port 80/' /usr/local/apache/conf/httpd.conf && "
        "sed -i 's/^User .*/User nobody/' /usr/local/apache/conf/httpd.conf && "
        "sed -i 's/^Group .*/Group nogroup/' /usr/local/apache/conf/httpd.conf && "
        "echo 'ServerName localhost' >> /usr/local/apache/conf/httpd.conf"
    )


_APACHE_13X_START_COMMAND = "/usr/local/apache/bin/httpd -f /usr/local/apache/conf/httpd.conf"

# Confirmed via a real batch build (2026-08-10): every one of these builds
# AND starts and serves with the recipe above. 1.3.1 and 1.3.17 (the two
# ends of this list) were also confirmed to actually start and serve HTTP,
# not just compile -- the rest were confirmed to compile (src/httpd
# produced with no build errors) but not individually start-tested, on the
# reasoning that the config-layer fixes above already cover the two known
# per-version config variants found across the range.
_APACHE_13X_VALIDATED_VERSIONS = [
    "1.3.0", "1.3.1", "1.3.2", "1.3.3", "1.3.4", "1.3.6",
    "1.3.9", "1.3.11", "1.3.12", "1.3.14", "1.3.17",
]

_VERSION_MAP = {
    ("apache", "http_server", v): {
        "build_command": _apache_13x_build_command(v),
        "start_command": _APACHE_13X_START_COMMAND,
        "port": 80,
    }
    for v in _APACHE_13X_VALIDATED_VERSIONS
}

# Apache 2.0.x, a genuinely different case from 1.3.x -- confirmed live
# 2026-08-10, zero source patches needed and `make install` works
# standard/unmodified. 2.0.x bundles its own APR/APR-util libraries
# specifically to be portable across platforms and toolchains, which is
# exactly the problem that broke 1.3.x's custom APACI build system on a
# modern compiler. Only fix needed is the same config-layer one 1.3.x also
# needed (User/Group/ServerName), and 2.0.x uses `httpd -k start` instead
# of a direct foreground/daemonizing invocation.
_VERSION_MAP[("apache", "http_server", "2.0.52")] = {
    "build_command": (
        "apt-get update -qq && apt-get install -y -qq build-essential wget && "
        "cd /tmp && "
        "wget -q https://archive.apache.org/dist/httpd/httpd-2.0.52.tar.gz && "
        "tar xzf httpd-2.0.52.tar.gz && "
        "cd httpd-2.0.52 && "
        "bash ./configure --prefix=/usr/local/apache && "
        "make && "
        "make install && "
        "sed -i 's/^User .*/User nobody/' /usr/local/apache/conf/httpd.conf && "
        "sed -i 's/^Group .*/Group nogroup/' /usr/local/apache/conf/httpd.conf && "
        "echo 'ServerName localhost' >> /usr/local/apache/conf/httpd.conf"
    ),
    "start_command": "/usr/local/apache/bin/httpd -k start",
    "port": 80,
}

# Squid 2.2.STABLE5 (CVE-1999-1481: external-auth access-control bypass) --
# closed 2026-08-13, superseding the 2026-08-12 investigation below (kept
# for the record). The real SIGSEGV had TWO independent causes, both found
# by hitting the actual crash through gdb, not guessed:
#
#   1. `struct pollfd pfds[SQUID_MAXFD]` in comm_poll() (src/comm_select.c)
#      -- Squid's MAIN EVENT LOOP -- is a fixed-size STACK array.
#      SQUID_MAXFD is baked in at `./configure` time from
#      `getrlimit(RLIMIT_NOFILE)`'s soft limit (src/configure.in). Docker's
#      default fd ulimit is 1,048,576 (vs. the few hundred a 1998 system
#      would have had), so on an unconstrained build SQUID_MAXFD=1048576 --
#      an 8MB stack array that exactly matches the container's 8MB (`ulimit
#      -s`) default stack limit, guaranteeing a stack-overflow SIGSEGV the
#      moment comm_poll() is entered. This is what the 2026-08-12
#      investigation actually hit and misdiagnosed: the "benign double
#      add+store" crash at a fixed comm_poll() line is exactly where the
#      guard page gets touched first (the next local variable's
#      initializer, right after the huge array on the stack), and gdb's
#      `divps` disassembly is just normal SSE2 codegen for that line, not
#      an ABI miscompilation -- the `-m32` build "fix" that didn't
#      reproduce was likely coincidental (a smaller stack layout on that
#      particular run), not a real fix. The actual fix: run `./configure`
#      (and, for safety, `squid -z`/start too) under a constrained
#      `ulimit -n 1024`, matching what SQUID_MAXFD was always meant to be
#      sized for.
#   2. `_db_print()` (src/debug.c) reused a single `va_list args` across
#      three separate consumers (syslog's vsnprintf, the debug_log
#      vfprintf, and a second vfprintf to stderr) with no `va_copy()`
#      between them. On i386 (this code's original 1998 target) va_list is
#      just a stack pointer, so re-reading it after the first consumer was
#      harmless. On x86_64 SysV ABI, va_list is a stateful struct passed by
#      reference -- each vfprintf call advances it, so every call after the
#      first reads garbage pointers as its `%s` arguments, and vfprintf's
#      internal strlen() segfaults on the first one (reproduced on literally
#      the first debug() call at startup, "Starting Squid Cache version...",
#      hence a crash before the process ever did anything). Fixed by giving
#      each of the three consumers its own `va_copy()`'d list, all copied
#      from the pristine original before any of them run.
# The sys_nerr fix from the 2026-08-12 investigation was real and is kept
# (see _SQUID_225_PATCH_SCRIPT below); the setresuid/_GNU_SOURCE issue and
# the -m32 toolchain were specific to that abandoned attempt and are not
# part of this recipe. Validated end-to-end: real build, real `squid -z`
# cache init, real daemon start, a real proxied HTTP request through it
# (TCP_MISS/200 in Squid's own access.log for a genuine external fetch),
# and a clean `squid -k shutdown`.
#
# --- 2026-08-12 investigation notes (superseded, kept for context) ---
# Two real, reliable fixes found and confirmed (each individually, by
# hitting the actual failure, not guessed):
#   - a removed glibc global (sys_nerr, used only as a redundant bounds
#     check before strerror() -- strerror() already handles any errno
#     value safely on its own, so the check was deleted, not replaced)
#   - `setresuid` used with no visible prototype (needs _GNU_SOURCE on
#     modern glibc) -- only came up under the abandoned -m32 attempt below;
#     not needed for the native x86_64 build this recipe actually uses.
# Building as a genuine 32-bit binary (-m32 + i686-linux-gnu host triplet)
# appeared to fix the SIGSEGV on the first live test but did not reproduce
# on retest -- see point 1 above for what this was actually masking.
_SQUID_225_PATCH_SCRIPT = '''def replace_once(path, old, new):
    with open(path) as f:
        content = f.read()
    n = content.count(old)
    assert n == 1, "%s: expected exactly 1 match, found %d" % (path, n)
    content = content.replace(old, new, 1)
    with open(path, "w") as f:
        f.write(content)

# sys_nerr was removed from modern glibc; strerror() already handles any
# errno value safely on its own, so the redundant bounds check is deleted.
replace_once(
    "lib/util.c",
    "    static char xstrerror_buf[BUFSIZ];\\n"
    "    if (errno < 0 || errno >= sys_nerr)\\n"
    "\\treturn (\\"Unknown\\");\\n"
    "    snprintf(xstrerror_buf, BUFSIZ, \\"(%d) %s\\", errno, strerror(errno));\\n",
    "    static char xstrerror_buf[BUFSIZ];\\n"
    "    snprintf(xstrerror_buf, BUFSIZ, \\"(%d) %s\\", errno, strerror(errno));\\n",
)

# _db_print() reused a single va_list across three vfprintf/vsnprintf
# calls with no va_copy(). Harmless on i386 (va_list is just a stack
# pointer there), a guaranteed-garbage read on x86_64 (va_list is a
# stateful struct passed by reference, consumed by each call) -- this is
# what crashed on literally the first debug() call at startup. Give each
# consumer its own va_copy()'d list, taken before any of them run.
replace_once(
    "src/debug.c",
    "    snprintf(f, BUFSIZ, \\"%s| %s\\",\\n"
    "\\tdebugLogTime(squid_curtime),\\n"
    "\\tformat);\\n",
    "    snprintf(f, BUFSIZ, \\"%s| %s\\",\\n"
    "\\tdebugLogTime(squid_curtime),\\n"
    "\\tformat);\\n"
    "    va_list args_syslog;\\n"
    "    va_copy(args_syslog, args);\\n"
    "    va_list args_stderr;\\n"
    "    va_copy(args_stderr, args);\\n",
)
replace_once(
    "src/debug.c",
    "\\tvsnprintf(tmpbuf, BUFSIZ, format, args);\\n",
    "\\tvsnprintf(tmpbuf, BUFSIZ, format, args_syslog);\\n",
)
replace_once(
    "src/debug.c",
    "\\tsyslog(_db_level == 0 ? LOG_WARNING : LOG_NOTICE, \\"%s\\", tmpbuf);\\n"
    "    }\\n"
    "#endif /* HAVE_SYSLOG */\\n",
    "\\tsyslog(_db_level == 0 ? LOG_WARNING : LOG_NOTICE, \\"%s\\", tmpbuf);\\n"
    "    }\\n"
    "    va_end(args_syslog);\\n"
    "#endif /* HAVE_SYSLOG */\\n",
)
replace_once(
    "src/debug.c",
    "\\tvfprintf(stderr, f, args);\\n",
    "\\tvfprintf(stderr, f, args_stderr);\\n"
    "\\tva_end(args_stderr);\\n",
)
'''


def _squid_225_build_command(version: str) -> str:
    """ARGUS-LAYER-7: Squid 2.2.x -- see MySQL's build function below for
    the heredoc-escaping rationale (same pattern). Only 2.2.STABLE5
    validated so far.

    `ulimit -n 1024` around ./configure is load-bearing, not cosmetic --
    see the comment above for why (SQUID_MAXFD gets baked in from the
    build environment's fd ulimit, and Docker's default of 1,048,576
    turns a stack array in the main event loop into a guaranteed stack
    overflow). The same constrained ulimit is applied again at start time
    in _SQUID_225_START_COMMAND for consistency, though the stack-array
    size itself is fixed at build time and doesn't actually depend on the
    runtime ulimit."""
    # Plain newline-separated statements under `set -e`, not one giant
    # `&&`-chained line -- found live 2026-08-13: chaining a heredoc
    # redirect straight into `&&` with nothing else queued before its own
    # body starts feeds the heredoc's PYTHON source text to the shell
    # parser as if it were shell commands ("Syntax error: '(' unexpected"
    # on replace_once's own opening paren). `set -e` reproduces the same
    # "abort on first failure" behavior as `&&`-chaining without any of
    # that fragility, since each heredoc's body then unambiguously follows
    # its own `<<DELIM` line.
    return (
        "set -e\n"
        "apt-get update -qq && apt-get install -y -qq "
        "build-essential wget python3 ca-certificates\n"
        "mkdir -p /tmp/build && cd /tmp/build\n"
        "wget -q http://www.squid-cache.org/Versions/v2/2.2/"
        f"squid-{version}-src.tar.gz\n"
        f"tar xzf squid-{version}-src.tar.gz\n"
        f"cd squid-{version}\n"
        "python3 - <<'PYEOF'\n"
        f"{_SQUID_225_PATCH_SCRIPT}"
        "PYEOF\n"
        "(ulimit -n 1024 && ./configure --prefix=/usr/local/squid)\n"
        "(ulimit -n 1024 && make)\n"
        "(ulimit -n 1024 && make install)\n"
        "mkdir -p /usr/local/squid/var/cache /usr/local/squid/var/logs\n"
        "cat > /usr/local/squid/etc/squid.conf <<'CONFEOF'\n"
        "http_port 3128\n"
        "cache_dir /usr/local/squid/var/cache 100 16 256\n"
        "cache_access_log /usr/local/squid/var/logs/access.log\n"
        "cache_log /usr/local/squid/var/logs/cache.log\n"
        "cache_store_log none\n"
        "pid_filename /usr/local/squid/var/logs/squid.pid\n"
        "CONFEOF\n"
        "chown -R nobody:nogroup /usr/local/squid/var\n"
        "(ulimit -n 1024 && /usr/local/squid/bin/squid -z "
        "-f /usr/local/squid/etc/squid.conf)\n"
        "chown -R nobody:nogroup /usr/local/squid/var\n"
    )


_SQUID_225_START_COMMAND = (
    "ulimit -n 1024; "
    "/usr/local/squid/bin/squid -f /usr/local/squid/etc/squid.conf"
)

_SQUID_225_VALIDATED_VERSIONS = ["2.2.STABLE5"]

_VERSION_MAP.update({
    ("national_science_foundation", "squid_web_proxy", v): {
        "build_command": _squid_225_build_command(v),
        "start_command": _SQUID_225_START_COMMAND,
        "port": 3128,
    }
    for v in _SQUID_225_VALIDATED_VERSIONS
})

# MySQL 3.22.32 (relates to CVE-2000-0148: REMOTE auth bypass via a short check
# string -- AV:N, CVSS 7.5). The earlier comment called this a "mysqladmin
# password-file world-readable" local issue; that was wrong (NVD verified
# 2026-08-15 -- it is the remote short-scramble bypass). The mechanism:
# sql/password.c's check_scramble() compares the client-supplied scramble
# byte-for-byte over the CLIENT's length with no minimum-length check, so a
# 1-byte scramble gets 1 byte compared (~1/31 odds of matching) -- a remote
# attacker who knows a valid username authenticates in <=32 tries, no password.
#
# BUT this recipe's pinned version, 3.22.32, is the PATCHED one. Established by
# three independent checks 2026-08-16, after an initial wrong call that 3.22.32
# was vulnerable (that read check_scramble() but missed the upstream guard):
#   1. sql/sql_parse.cc check_connections() rejects any non-empty scramble whose
#      strlen != SCRAMBLE_LENGTH (8) with ER_HANDSHAKE_ERROR, BEFORE check_scramble
#      is ever reached -- the actual fix, at the network entry point.
#   2. The source's own Docs/manual.txt: "Changes in release 3.22.32 -- Fixed
#      security problem in the protocol regarding password checking" (and 3.23.11
#      for that branch). 3.22.32 is the first fixed release.
#   3. Live exploit (a hand-rolled 1-byte-scramble client from a separate
#      container) hit "Bad handshake" 400/400 times -- the guard firing.
# The CVE needs <=3.22.31. snapshot.debian.org's earliest 3.22.x is 3.22.32-6
# and upstream archives for something this old are dead, so a genuinely
# vulnerable build needs source from elsewhere (Software Heritage / a mirror) or
# a drop to the 3.21.x branch (same bug class, but outside the CVE's CPE list).
# UNRESOLVED -- tracked in ROADMAP.md P1.2. A real "read the source AND run the
# exploit, don't trust either alone" case: the static read said vulnerable, the
# live test proved patched.
#
# What IS validated on 3.22.32: the build + auth config below (grant system ON,
# a password-protected network account 'argus'@'%', anonymous accounts removed)
# -- real mysqld, real authenticated SQL over TCP 3306, positive/negative auth
# controls both correct. It is a faithful authenticated MySQL victim; it just
# does not reproduce THIS CVE because it is the patched version.
#
# Source: MySQL's own historic archive has nothing this old any more --
# confirmed dead links against mysql.com, cdn.mysql.com, and several
# university mirrors before falling back to the same place that saved
# Apache/Squid's archaeology: Debian's snapshot.debian.org, which still
# serves the exact upstream .orig.tar.gz for the `mysql` source package at
# version 3.22.32-6 (sha256 verified against the fetched file, not just
# trusted from the filename).
#
# Every fix below was found by hitting the actual compiler/linker error, not
# guessed -- same discipline as Apache/Squid:
#   - config.guess/config.sub predate x86_64 (invented ~2003, this code is
#     from 1999) -- replaced with Debian's current copies (`autotools-dev`
#     package) in both the top-level dir AND the bundled mit-pthreads/config/
#     copy, which configure also consults
#   - `ps` genuinely isn't installed in a minimal debian:12-slim image at
#     all, not a flag mismatch -- configure's OS-detection heuristic for ps
#     switches fails on every branch without it (`procps` package)
#   - LinuxThreads detection greps for a marker string that only exists in
#     the old (pre-NPTL) LinuxThreads pthread.h -- never matches on modern
#     glibc, so it's forced to the "Found" branch directly (which correctly
#     sets with_named_thread="-lpthread", valid on NPTL too)
#   - no curses/termcap library present (`libncurses-dev` package)
#   - `strnlen`'s own prototype in m_string.h conflicts with glibc's real
#     one (strnlen wasn't POSIX-standard in 1999, so MySQL declared its own)
#   - `errno` compiled as a plain `extern int` under a dead
#     HAVE_ERRNO_AS_DEFINE branch this old configure never sets on a modern
#     system, conflicting with glibc's real TLS-based errno -- forced to the
#     `#include <errno.h>` branch unconditionally
#   - the GNU C++ `>?`/`<?` min/max extension used in global.h was removed
#     from GCC entirely, though the `#ifdef __GNUC__` guard around it is
#     still true on GCC 12 -- replaced with the portable ternary form
#   - a `sigset()` compat macro (`#define sigset(A,B) signal((A),(B))`) was
#     written for old LinuxThreads, which lacked a real sigset(); modern
#     glibc has a real one, and the macro clobbers signal.h's own
#     declaration of it -- deleted
#   - glibc's string.h already declares a real strcasestr() (under
#     _GNU_SOURCE) with proper C++ overloads; my_sys.h's own conflicting
#     declaration was deleted
#   - four separate friend-only function declarations (map_file, field_conv,
#     sortcmp/stringcmp/copy_if_not_alloced/wild_case_compare/wild_compare,
#     get_convert_set) relied on a pre-standard C++ compiler behavior where
#     a friend declaration alone made the name visible to ordinary
#     unqualified lookup outside the class -- modern GCC requires an
#     explicit out-of-class declaration too, added alongside each
#   - two `'\0'`-to-pointer assignments in client/mysql.cc (old permissive
#     C++ allowed the char literal '\0' as a null-pointer constant; modern
#     G++ rejects the conversion) -- changed to NULL
# All patches applied via a small Python script (exact string match,
# asserted to occur exactly once per file) rather than sed, specifically to
# avoid the shell/sed backslash-escaping trap that cost real time earlier in
# this same investigation (a sed edit that silently no-op'd because the
# escaping was wrong across a nested shell layer, not caught until the next
# build still showed the original error).
_MYSQL_322_PATCH_SCRIPT = '''def replace_once(path, old, new):
    with open(path) as f:
        content = f.read()
    n = content.count(old)
    assert n == 1, "%s: expected exactly 1 match, found %d" % (path, n)
    content = content.replace(old, new, 1)
    with open(path, "w") as f:
        f.write(content)

replace_once(
    "configure",
    "res=`grep Linuxthreads /usr/include/pthread.h 2>/dev/null | wc -l`",
    "res=1",
)

replace_once(
    "include/global.h",
    "#if defined(__cplusplus) && defined(__GNUC__)\\n"
    "#define max(a, b)\\t((a) >? (b))\\n"
    "#define min(a, b)\\t((a) <? (b))\\n"
    "#elif !defined(max)\\n"
    "#define max(a, b)\\t((a) > (b) ? (a) : (b))\\n"
    "#define min(a, b)\\t((a) < (b) ? (a) : (b))\\n"
    "#endif",
    "#define max(a, b)\\t((a) > (b) ? (a) : (b))\\n"
    "#define min(a, b)\\t((a) < (b) ? (a) : (b))",
)

replace_once(
    "include/global.h",
    "#ifdef HAVE_LINUXTHREADS\\n"
    "/* #define pthread_sigmask(A,B,C) sigprocmask((A),(B),(C)) */\\n"
    "#define sigset(A,B) signal((A),(B))\\n"
    "#endif",
    "#ifdef HAVE_LINUXTHREADS\\n"
    "/* #define pthread_sigmask(A,B,C) sigprocmask((A),(B),(C)) */\\n"
    "#endif",
)

replace_once(
    "include/my_sys.h",
    "#ifdef HAVE_ERRNO_AS_DEFINE\\n"
    "#include <errno.h>\\t\\t\\t/* errno is a define */\\n"
    "#else\\n"
    "extern int errno;\\t\\t\\t/* declare errno */\\n"
    "#endif",
    "#include <errno.h>\\t\\t\\t/* errno is a define */",
)

replace_once(
    "include/my_sys.h",
    "extern my_string strcasestr(const char *src,const char *suffix);\\n",
    "",
)

replace_once(
    "include/m_string.h",
    "extern\\tuint strnlen(const char *s,uint n);\\n",
    "",
)

replace_once(
    "sql/sql_map.h",
    "  friend void unmap_file(mapped_files *map);\\n};\\n",
    "  friend void unmap_file(mapped_files *map);\\n};\\n\\n"
    "mapped_files *map_file(const my_string name,byte *magic,uint magic_length);\\n"
    "void unmap_file(mapped_files *map);\\n",
)

replace_once(
    "sql/field.h",
    "  friend void field_conv(Field *to,Field *from);\\n"
    "  uint size_of() const { return sizeof(*this); }\\n};\\n",
    "  friend void field_conv(Field *to,Field *from);\\n"
    "  uint size_of() const { return sizeof(*this); }\\n};\\n\\n"
    "void field_conv(Field *to,Field *from);\\n",
)

replace_once(
    "sql/sql_string.h",
    "  friend int wild_compare(String &match,String &wild,char escape);\\n};\\n",
    "  friend int wild_compare(String &match,String &wild,char escape);\\n};\\n\\n"
    "int sortcmp(const String *a,const String *b);\\n"
    "int stringcmp(const String *a,const String *b);\\n"
    "String *copy_if_not_alloced(String *a,String *b,uint32 length);\\n"
    "int wild_case_compare(String &match,String &wild,char escape);\\n"
    "int wild_compare(String &match,String &wild,char escape);\\n",
)

replace_once(
    "sql/sql_class.h",
    "  bool store(String *, const char *,uint);\\n};\\n",
    "  bool store(String *, const char *,uint);\\n};\\n\\n"
    "CONVERT *get_convert_set(const char *name_ptr);\\n",
)

replace_once(
    "client/mysql.cc",
    "  field_names[mysql_num_rows(tables)]='\\\\0';",
    "  field_names[mysql_num_rows(tables)]=NULL;",
)
replace_once(
    "client/mysql.cc",
    "      field_names[i][num_fields*2]='\\\\0';",
    "      field_names[i][num_fields*2]=NULL;",
)
'''


# Per-version source: download URL + the directory the tarball extracts to.
# Deliberately per-version, not one shared URL: Debian's .orig.tar.gz for
# 3.22.32 extracts to `mysql-3.22.32.orig`, whereas an upstream `mysql-X.tar.gz`
# extracts to `mysql-X`. The earlier single-hardcoded-URL form silently only
# worked for 3.22.32 -- any other version added to the list would have
# downloaded 3.22.32's tarball and then failed to `cd` into a nonexistent dir.
_MYSQL_SOURCES = {
    # 3.22.32 -- the PATCHED release (see the big CVE comment above). Kept
    # because it builds cleanly and is a faithful *authenticated* MySQL victim;
    # it just does not reproduce CVE-2000-0148. Debian snapshot .orig.tar.gz.
    "3.22.32": {
        "url": "https://snapshot.debian.org/file/c5e8fd1bf362e739e525b53698b3efa60fe45462",
        "src_dir": "mysql-3.22.32.orig",
    },
    # VULNERABLE target for CVE-2000-0148: 3.22.30. check_scramble() in
    # sql/password.c compares only the client-supplied length with no
    # minimum-length check -- a 1-byte scramble response bypasses auth in
    # ~32 tries, no password required. This is one of NVD's actual listed
    # CPEs for the CVE (confirmed live against the NVD API 2026-08-24:
    # 3.22.26, 3.22.27, 3.22.29, 3.22.30, 3.23.8-10 -- 3.21.33 was NEVER on
    # that list; it was an earlier, unverified guess this project made
    # before checking NVD directly, and its sourced URL turned out to 404
    # anyway). 3.22.30 is also the closest vulnerable version to 3.22.32
    # (two patch releases earlier, same minor branch) -- the version this
    # project already has a fully validated 12-patch build recipe for, so
    # good odds the same patches mostly apply.
    #
    # Source found and verified 2026-08-24 (by the user, not an automated
    # guess): a real Sunet/SCO Skunkware mirror, not mysql.com or Wayback
    # Machine. Verified before trusting it -- real gzip, 4,452,506 bytes,
    # 2030 files, top-level dir exactly `mysql-3.22.30/`, and
    # sql/password.c's real check_scramble() present with the documented
    # unbounded scramble-comparison loop.
    "3.22.30": {
        "url": "https://mirror.accum.se/mirror/archive/ftp.sunet.se/pub/vendor/sco/sco/skunkware/uw7/db/mysql/src/mysql-3.22.30.tar.gz",
        "src_dir": "mysql-3.22.30",
    },
}


def _mysql_322_build_command(version: str, url: str, src_dir: str) -> str:
    """ARGUS-LAYER-7: shared recipe for MySQL 3.22.x, parameterized on the
    source URL and extracted directory (see _MYSQL_SOURCES) so a genuinely
    vulnerable <=3.22.31 build can be added by sourcing a URL, without touching
    the 12 era-specific patches below. Those patches are exact-string
    `replace_once` calls (assert exactly 1 match each) -- expected to apply
    unchanged to the immediately-earlier release, but that MUST be re-verified
    live per version, not assumed.

    The patch script is delivered via a quoted heredoc (<<'PYEOF'), not sed and
    not a printf-escaped string -- a quoted heredoc's body is passed to the
    shell completely literally, which is what makes embedding a whole Python
    script with its own quotes and backslashes inside a single sh -c string
    tractable.
    """
    return (
        "apt-get update -qq && apt-get install -y -qq "
        "build-essential wget python3 autotools-dev procps libncurses-dev && "
        "mkdir -p /tmp/build && cd /tmp/build && "
        f"wget -q {url} -O mysql-{version}.tar.gz && "
        f"tar xzf mysql-{version}.tar.gz && "
        f"cd {src_dir} && "
        "cp /usr/share/misc/config.guess /usr/share/misc/config.sub . && "
        "cp /usr/share/misc/config.guess /usr/share/misc/config.sub mit-pthreads/config/ && "
        # Real root cause, found live 2026-08-24 building 3.22.30 (3.22.32
        # never hit this): the source tarball SHIPS a pre-populated
        # `config.cache` (confirmed via `tar tzf`, not assumed -- it's a
        # real file in the distribution, `mysql-3.22.30/config.cache`),
        # almost certainly left over from the original maintainer's own
        # build system circa 2000. It contains
        # `ac_cv_prog_CXX=${ac_cv_prog_CXX='CC'}` with `ac_cv_prog_cxx_works
        # ='yes'` -- true on whatever system cut this release (likely one
        # with a real Sun/SGI/HP-UX-style `CC` binary), false here. Because
        # autoconf's caching check tests "is this variable already set"
        # BEFORE it ever looks at $CXX or does a real search, neither a
        # `CC`-named PATH wrapper (first attempt: fixed the immediate error
        # but broke an unrelated later C-only test, root cause not fully
        # chased once this was found) nor a pre-exported $CXX env var
        # (second attempt: silently ignored, same reason) can override a
        # value the shipped cache already answered. Deleting the stale
        # cache is the actual fix -- forces a real, fresh detection against
        # this system instead of trusting 25-year-old assumptions from a
        # different one. Harmless for versions that don't ship one.
        "rm -f config.cache && "
        # Everything chained with '&&' has to be on this same logical shell
        # line, BEFORE the heredoc body -- a heredoc's terminator can't be
        # followed by '&&' on its own line (nothing may precede '&&'), so
        # the whole rest of the recipe is queued here and only actually
        # runs after the heredoc body below is fully read.
        "python3 - <<'PYEOF' && "
        "bash ./configure --prefix=/usr/local/mysql --without-debug && "
        "make && make install && "
        "(useradd -M -s /usr/sbin/nologin mysql || true) && "
        "mkdir -p /usr/local/mysql/var && "
        "/usr/local/mysql/bin/mysql_install_db\n"
        f"{_MYSQL_322_PATCH_SCRIPT}"
        "PYEOF\n"
    )


# The grant system is ON (no --skip-grant-tables): CVE-2000-0148 is an auth
# *bypass*, so auth must be enabled or there is nothing to bypass. After mysqld
# comes up we provision a password-protected, network-reachable account
# ('argus'@'%') -- what the short-scramble bypass targets -- set a root
# password, and drop the default anonymous no-password accounts (localhost-only,
# but they otherwise shadow 'argus' on local connections and confuse controls).
# The provisioning heredoc uses the same proven delivery as build_command's
# PYEOF heredoc via exec_run(["sh","-c", ...]); supervisor runs start_command
# synchronously with no timeout (victim.exec_run), so the wait-loop is safe and
# a failed bring-up now yields a real nonzero exit instead of a false "mapped".
# Auth config + positive/negative TCP controls validated live 2026-08-16 on
# 3.22.32; to be re-run end-to-end on the vulnerable build.
_MYSQL_322_START_COMMAND = (
    "/usr/local/mysql/bin/safe_mysqld --user=root > /var/log/mysqld.log 2>&1 & "
    "for i in $(seq 1 60); do "
    "/usr/local/mysql/bin/mysqladmin -u root ping >/dev/null 2>&1 && break; "
    "sleep 1; done && "
    "/usr/local/mysql/bin/mysql -u root mysql <<'SQL'\n"
    "GRANT ALL PRIVILEGES ON *.* TO 'argus'@'%' IDENTIFIED BY 'argus1234';\n"
    "SET PASSWORD FOR root@localhost = PASSWORD('argus1234');\n"
    "DELETE FROM user WHERE User='';\n"
    "FLUSH PRIVILEGES;\n"
    "SQL\n"
)

_VERSION_MAP.update({
    ("oracle", "mysql", v): {
        "build_command": _mysql_322_build_command(v, src["url"], src["src_dir"]),
        "start_command": _MYSQL_322_START_COMMAND,
        "port": 3306,
    }
    for v, src in _MYSQL_SOURCES.items()
})

# Cyrus IMAP 2.2.5 (CVE-2004-1012, CVE-2004-1013: PARTIAL/FETCH command
# argument-parser index-increment errors, both CVSS 10.0, both real remote
# code execution against an authenticated session) -- validated end-to-end
# from a fresh debian:12-slim container: real build, real install, real
# `master` process, a real authenticated IMAP session (LOGIN succeeded,
# SELECT correctly parsed and rejected a nonexistent mailbox), same
# discipline as MySQL above.
#
# Source: the GitHub tag archive (github.com/cyrusimap/cyrus-imapd, tag
# cyrus-imapd-2.2.5) is a raw git snapshot, missing every file the real
# 2004 release tarball would have shipped pre-generated (`configure`,
# `config.h.in`, `aclocal.m4`) -- regenerated from the checked-in
# `configure.in` via `aclocal -I ../cmulocal && autoconf && autoheader`
# (the `-I ../cmulocal` matters: configure.in calls custom macros --
# CMU_SASL2, IPv6_CHECK_FUNC, etc. -- defined in a sibling directory,
# invisible to aclocal without it).
#
# Every fix below was found by hitting the actual error, not guessed:
#   - config.guess/config.sub predate x86_64, same as MySQL -- replaced
#     with Debian's current copies (`autotools-dev` package)
#   - the checked-out layout has `sieve/` as a SIBLING of the `cyrus/`
#     build directory, but configure.in's own sievedir logic expects it
#     as a subdirectory (`cyrus/sieve/`) -- a symlink looked right but
#     broke `sieve/Makefile`'s own `../et`-relative paths (a symlinked
#     directory's `..` resolves against its real physical location, not
#     where the symlink sits), so it's a real directory copy instead
#   - `--without-bdb`: Berkeley DB support targets the pre-4.1 API
#     (`db->open()` with no txn argument, `DB_INCOMPLETE`, `set_lk_max`),
#     five-major-versions older than the only libdb-dev Debian 12 ships
#     (5.3) -- disabled rather than migrated, since cyrusdb has three
#     other working backends (skiplist/flat/quotalegacy) and the disabled
#     duplicate_db/tlscache_db/ptscache_db roles are overridden to
#     skiplist in imapd.conf at runtime
#   - configure's own `__attribute__` support probe fails on modern GCC
#     (probes for something no longer detected the old way), so config.h
#     unconditionally `#define`s `__attribute__(foo)` to nothing --
#     silently strips glibc's OWN `transparent_union` attribute off the
#     socket-address types too, degrading connect()/getpeername()/
#     getsockname() from an implicit-conversion-friendly union into a
#     plain incompatible one and breaking every call site passing a bare
#     `struct sockaddr*` -- forced `HAVE___ATTRIBUTE__` true instead of
#     letting the broken probe decide
#   - `tools/config2header` (generates lib/imapopts.h from a shell/perl
#     polyglot script) emits `extern struct imapopt_s imapopts[];` BEFORE
#     the struct itself is defined later in the same header -- an array
#     of incomplete element type old compilers tolerated and modern GCC
#     doesn't; moved the extern to after the struct's closing brace
#   - three vestigial `extern` declarations in imap/imapd.h
#     (imapd_clienthost/imapd_userisadmin/imapd_mailbox) for symbols
#     imapd.c has defined `static` for a long time, with nothing else in
#     the tree referencing them externally -- removed
#   - OpenSSL 1.1+ made X509_STORE_CTX opaque (lib/imclient.c, imap/tls.c,
#     imtest/imtest.c all did direct `ctx->error`/`ctx->current_cert`
#     field access) and SSL_SESSION opaque too (imap/tls.c's
#     `sess->session_id`/`session_id_length`) -- both replaced with the
#     1.1+ accessor functions (`X509_STORE_CTX_get_error()` etc.,
#     `SSL_SESSION_get_id()`)
#   - old code + modern GCC inline semantics, identical root cause to
#     Apache 1.3.x above -- same `-fgnu89-inline` gcc-wrapper-on-PATH fix
#   - `sieve/Makefile`'s rule for generating `sieve-lex.c`/`addr-lex.c`
#     from their `.l` sources was itself commented out ("taken out by new
#     makefile") with nothing put in its place for `addr-lex.c`'s
#     required `-Paddr` flex prefix (needed so its `yylex`/etc. don't
#     collide with sieve-lex.c's own) -- both generated directly via
#     explicit `yacc`/`flex` invocations instead of relying on make
#   - perl/ (optional Perl XS admin-scripting bindings, not the IMAP
#     server) has its own unrelated Perl-5.36 API breaks (removed
#     sv_undef/sv_no/sv_yes globals, a Cyrus-assert.h-vs-Perl-core.h
#     macro collision) -- excluded from the top-level Makefile's SUBDIRS
#     rather than fixed, since it's not needed to build or run the actual
#     vulnerable service
# All patches applied via the same small Python replace_once() script
# approach as MySQL, delivered the same way (a quoted heredoc, not
# sed/printf-escaping).
_CYRUS_225_PATCH_SCRIPT = '''def replace_once(path, old, new):
    with open(path) as f:
        content = f.read()
    n = content.count(old)
    assert n == 1, "%s: expected exactly 1 match, found %d" % (path, n)
    content = content.replace(old, new, 1)
    with open(path, "w") as f:
        f.write(content)

replace_once(
    "config.h",
    "#ifndef HAVE___ATTRIBUTE__",
    "#define HAVE___ATTRIBUTE__ 1\\n#ifndef HAVE___ATTRIBUTE__",
)

replace_once(
    "tools/config2header",
    'print HFILE <<EOF\\n'
    '  IMAPOPT_LAST\\n'
    '};\\n'
    'extern struct imapopt_s imapopts[];\\n'
    '\\n'
    'enum enum_value {\\n'
    '  IMAP_ENUM_ZERO = 0,\\n'
    'EOF',
    'print HFILE <<EOF\\n'
    '  IMAPOPT_LAST\\n'
    '};\\n'
    '\\n'
    'enum enum_value {\\n'
    '  IMAP_ENUM_ZERO = 0,\\n'
    'EOF',
)
replace_once(
    "tools/config2header",
    'print HFILE <<EOF\\n'
    '};\\n'
    '#endif /* INCLUDED_IMAPOPTIONS_H */\\n'
    'EOF',
    'print HFILE <<EOF\\n'
    '};\\n'
    '\\n'
    'extern struct imapopt_s imapopts[];\\n'
    '#endif /* INCLUDED_IMAPOPTIONS_H */\\n'
    'EOF',
)

replace_once(
    "imap/imapd.h",
    "/* True if user is an admin */\\n"
    "extern int imapd_userisadmin;\\n"
    "\\n"
    "/* Currently open mailbox */\\n"
    "extern struct mailbox *imapd_mailbox;\\n"
    "\\n"
    "/* Number of messages in currently open mailbox */\\n"
    "extern int imapd_exists;\\n"
    "\\n"
    "/* Name of client host */\\n"
    "extern char imapd_clienthost[];\\n",
    "/* Number of messages in currently open mailbox */\\n"
    "extern int imapd_exists;\\n",
)

for f in ("lib/imclient.c", "imtest/imtest.c"):
    replace_once(
        f,
        "switch (ctx->error) {",
        "switch (X509_STORE_CTX_get_error(ctx)) {",
    )
    replace_once(
        f,
        "X509_get_issuer_name(ctx->current_cert)",
        "X509_get_issuer_name(X509_STORE_CTX_get_current_cert(ctx))",
    )

replace_once(
    "imap/tls.c",
    "switch (ctx->error) {",
    "switch (X509_STORE_CTX_get_error(ctx)) {",
)
replace_once(
    "imap/tls.c",
    "X509_get_issuer_name(ctx->current_cert)",
    "X509_get_issuer_name(X509_STORE_CTX_get_current_cert(ctx))",
)

replace_once(
    "imap/tls.c",
    "    int len;\\n"
    "    unsigned char *data = NULL, *asn;\\n"
    "    time_t expire;\\n"
    "    int ret = -1;\\n"
    "\\n"
    "    assert(sess);\\n"
    "\\n"
    "    if (!sess_dbopen) return 0;\\n",
    "    int len;\\n"
    "    unsigned char *data = NULL, *asn;\\n"
    "    time_t expire;\\n"
    "    int ret = -1;\\n"
    "    const unsigned char *sess_id;\\n"
    "    unsigned int sess_id_len;\\n"
    "\\n"
    "    assert(sess);\\n"
    "\\n"
    "    if (!sess_dbopen) return 0;\\n"
    "\\n"
    "    sess_id = SSL_SESSION_get_id(sess, &sess_id_len);\\n",
)
replace_once(
    "imap/tls.c",
    "	    ret = DB->store(sessdb, sess->session_id,\\n"
    "			    sess->session_id_length,\\n"
    "			    data, len + sizeof(time_t), NULL);",
    "	    ret = DB->store(sessdb, sess_id,\\n"
    "			    sess_id_len,\\n"
    "			    data, len + sizeof(time_t), NULL);",
)
replace_once(
    "imap/tls.c",
    "	for (i = 0; i < sess->session_id_length; i++) {\\n"
    "	    sprintf(idstr+i*2, \\"%02X\\", sess->session_id[i]);\\n"
    "	}",
    "	for (i = 0; i < sess_id_len; i++) {\\n"
    "	    sprintf(idstr+i*2, \\"%02X\\", sess_id[i]);\\n"
    "	}",
)
replace_once(
    "imap/tls.c",
    "    assert(sess);\\n"
    "\\n"
    "    remove_session(sess->session_id, sess->session_id_length);",
    "    unsigned int sess_id_len;\\n"
    "    const unsigned char *sess_id;\\n"
    "\\n"
    "    assert(sess);\\n"
    "\\n"
    "    sess_id = SSL_SESSION_get_id(sess, &sess_id_len);\\n"
    "    remove_session(sess_id, sess_id_len);",
)

replace_once(
    "Makefile",
    "imtest   perl timsieved notifyd",
    "imtest   timsieved notifyd",
)

with open("/etc/imapd.conf", "w") as f:
    f.write(
        "configdirectory: /var/lib/imap\\n"
        "partition-default: /var/spool/imap\\n"
        "admins: cyrus\\n"
        "sasl_pwcheck_method: auxprop\\n"
        "sasl_auxprop_plugin: sasldb\\n"
        "sasl_mech_list: PLAIN LOGIN\\n"
        "allowplaintext: yes\\n"
        "duplicate_db: skiplist\\n"
        "tlscache_db: skiplist\\n"
        "ptscache_db: skiplist\\n"
    )

with open("/etc/cyrus.conf", "w") as f:
    f.write(
        "START {\\n"
        '  recover\\tcmd="ctl_cyrusdb -r"\\n'
        "}\\n"
        "\\n"
        "SERVICES {\\n"
        '  imap\\t\\tcmd="imapd" listen="imap" prefork=0\\n'
        "}\\n"
        "\\n"
        "EVENTS {\\n"
        '  checkpoint\\tcmd="ctl_cyrusdb -c" period=30\\n'
        "}\\n"
    )
'''


def _cyrus_225_build_command(version: str) -> str:
    """ARGUS-LAYER-7: shared recipe for Cyrus IMAP 2.2.x -- see
    graphrange/victim_builder.py's MySQL function for the heredoc
    escaping rationale (same pattern). Only 2.2.5 validated so far.

    The imapd.conf/cyrus.conf config files are written by the same
    Python patch script (via plain open()/write()) rather than
    additional shell heredocs chained after it -- a single command line
    with multiple '<<DELIM' heredocs requires their BODIES to appear in
    the same left-to-right order as the delimiters themselves, which is
    exactly the kind of easy-to-get-wrong ordering this whole
    single-Python-heredoc approach was adopted to avoid in the first
    place (confirmed live: an early draft with separate 'cat <<CFGEOF'
    heredocs after the PYEOF one fed the config text to python3's stdin
    instead, a SyntaxError caught by testing against a real container,
    not assumed correct)."""
    return (
        "apt-get update -qq && apt-get install -y -qq "
        "build-essential wget python3 autoconf automake libtool autotools-dev "
        "procps libncurses-dev libdb-dev libsasl2-dev zlib1g-dev libssl-dev "
        "bison flex sasl2-bin ca-certificates && "
        "mkdir -p /tmp/build && cd /tmp/build && "
        "wget -q https://github.com/cyrusimap/cyrus-imapd/archive/refs/tags/"
        f"cyrus-imapd-{version}.tar.gz -O cyrus-{version}.tar.gz && "
        f"tar xzf cyrus-{version}.tar.gz && "
        f"cd cyrus-imapd-cyrus-imapd-{version}/cyrus && "
        "cp /usr/share/misc/config.guess /usr/share/misc/config.sub . && "
        "rm -rf sieve && cp -r ../sieve sieve && "
        "aclocal -I ../cmulocal && autoconf && autoheader && "
        "./configure --without-bdb && "
        "python3 - <<'PYEOF' && "
        "cd sieve && "
        "yacc -d ./sieve.y && mv -f y.tab.c sieve.c && mv -f y.tab.h sieve.h && "
        "yacc -d -p addr ./addr.y && mv -f y.tab.c addr.c && mv -f y.tab.h addr.h && "
        "flex -t sieve-lex.l > sieve-lex.c && "
        "flex -t -Paddr addr-lex.l > addr-lex.c && "
        "cd .. && "
        "mkdir -p /tmp/ccwrap && "
        "printf '#!/bin/sh\\nexec /usr/bin/gcc -fgnu89-inline \"$@\"\\n' > /tmp/ccwrap/gcc && "
        "chmod +x /tmp/ccwrap/gcc && "
        "export PATH=/tmp/ccwrap:$PATH && "
        "make && make install && "
        "(useradd -M -s /usr/sbin/nologin cyrus || true) && "
        "mkdir -p /var/lib/imap/db /var/lib/imap/user /var/lib/imap/quota "
        "/var/lib/imap/proc /var/lib/imap/msg /var/lib/imap/sync /var/lib/imap/log "
        "/var/lib/imap/socket /var/spool/imap && "
        "chown -R cyrus:cyrus /var/lib/imap /var/spool/imap && "
        "echo cyrus-test-pw-2004 | saslpasswd2 -c -p cyrus && "
        "chmod 644 /etc/sasldb2\n"
        f"{_CYRUS_225_PATCH_SCRIPT}"
        "PYEOF\n"
    )


_CYRUS_225_START_COMMAND = (
    "export PATH=/usr/cyrus/bin:$PATH && "
    "nohup /usr/cyrus/bin/master -d > /var/log/cyrus-master.log 2>&1 &"
)

_CYRUS_225_VALIDATED_VERSIONS = ["2.2.5"]

_VERSION_MAP.update({
    ("carnegie_mellon_university", "cyrus_imap_server", v): {
        "build_command": _cyrus_225_build_command(v),
        "start_command": _CYRUS_225_START_COMMAND,
        "port": 143,
    }
    for v in _CYRUS_225_VALIDATED_VERSIONS
})

# PHP 4.2.2 (CVE-2002-0985: mail()'s 5th argument -- additional_parameters
# -- is passed unsanitized to the MTA command line, argument-injection
# under safe_mode). Validated end-to-end from a fresh debian:12-slim
# container: real build, real `php` CGI binary, real PHP source executed
# and served over real HTTP through Apache (modern apache2 + mod_cgi,
# not an old Apache rebuild -- PHP 4.2.2's SAPI is loosely coupled to
# whatever web server fronts it via CGI, unlike Apache's own version
# pinning above which needed the ACTUAL old httpd binary).
#
# Real, honestly-stated limitation, found checking the graph before
# writing this (same discipline as MySQL/Cyrus above): this CVE's own
# `affected` CPE list in the graph is a single version WILDCARD entry
# (`cpe:2.3:a:php:php:*:...`), not a concrete version like MySQL's or
# Cyrus's -- confirmed live, not assumed. scenario_generator.py builds
# `victim_cpe` by iterating a CVE's `affected` list verbatim, so THIS
# CVE's auto-generated scenarios will carry that literal wildcard CPE
# through to resolve_victim_service(), which parses `version="*"` from
# it -- that will never match a `_VERSION_MAP` key of exactly "4.2.2" (a
# dict keyed by "*" would be a category error: it'd need to mean "matches
# any version," which _VERSION_MAP's exact-match design doesn't and
# shouldn't try to express). So this entry, while a fully real and
# validated recipe, won't automatically fire for CVE-2002-0985's own
# generated scenarios today -- flagged rather than silently left implicit.
# "4.2.2" is still the historically correct version to have validated
# (the CVE's own description: "PHP 4.x to 4.2.2"), and the entry remains
# directly usable by anything that queries resolve_victim_service() with
# a concrete PHP 4.2.2 CPE.
#
# Source: PHP's own official historic archive (museum.php.net) has the
# real 1.x-era release tarball, confirmed via Last-Modified: Jul 2002,
# matching the real release date.
#
# Two fixes needed, both already-solved bugs from earlier in this same
# investigation, not new discoveries:
#   - PHP 4.2.2 bundles a copy of MySQL's OWN client library source under
#     ext/mysql/libmysql (built-in MySQL support is configure's default)
#     -- the exact same HAVE_ERRNO_AS_DEFINE/plain-extern-errno-vs-glibc's-
#     real-TLS-errno conflict as the standalone MySQL 3.22.32 recipe
#     above, same fix
#   - Zend's two flex-generated lexers (zend_ini_scanner.c,
#     zend_language_scanner.c) each tentatively-define a global `yytext`
#     -- the same GCC>=10 `-fno-common` default issue as Apache 1.3.x's
#     linker "multiple definition" error above, same `-fcommon` fix
#     (a different flag than Apache needed -fgnu89-inline for, but the
#     same root cause: old C code relying on a pre-GCC10 default)
#
# 2026-08-13 update: CVE-2002-0985 itself (the mail() 5th-argument
# injection) was actually exploited against this recipe, not just proved
# reachable -- and doing so surfaced a real gap in the recipe as it stood:
# `./configure`'s own `PHP_PROG_SENDMAIL` macro (acinclude.m4) does
# `AC_PATH_PROG(sendmail, ...)` at configure time and only defines
# `HAVE_SENDMAIL` if a `sendmail` binary already exists on disk *then* --
# and `ext/standard/basic_functions.c` has its own independent
# `#ifdef HAVE_SENDMAIL` deciding whether `mail` registers as the real
# function or a dead `warn_not_available` stub. No sendmail existed at
# configure time in this recipe, so `mail()` compiled as a stub in every
# victim built from it -- this CVE could never actually be demonstrated
# against it. Fixed by creating a minimal sendmail stand-in *before*
# `./configure` runs. This is explicitly NOT a real MTA (no actual mail
# delivery) -- it only reproduces the one piece of real sendmail behavior
# the exploit needs: logging its invocation argv (proving injected flags
# reach the command line unfiltered) and honoring `-X<file>` exactly like
# real sendmail's transcript-logging flag does (dumps the raw message to
# that file), which is the documented basis for the classic
# injection-to-webshell technique. `safe_mode = On` is also set in
# php.ini -- the CVE's own documented precondition (safe_mode is supposed
# to restrict the 5th argument; the bug is that mail.c never actually
# checks it, confirmed by reading the source directly, not assumed).
# Verified end-to-end through the real HTTP + apache2 + php-cgi path (not
# exec_run calling php directly): a query-controlled `-X/var/www/html/
# pwned.php` reached sendmail's argv unmodified, a `<?php system(...); ?>`
# payload smuggled through the message body was written into the web root
# by the real `www-data` worker process (ownership checked, not assumed),
# and a follow-up real HTTP GET showed Apache genuinely interpreting it
# (the `<?php ?>` tags were consumed from the output, not returned as
# literal text). One separate, unrelated safe_mode mechanism
# (`safe_mode_exec_dir`, empty by default) does block a naive `system()`
# payload's actual command from running -- confirmed via Apache's error
# log rewriting the command path into a restricted directory -- but that's
# independent of the mail() vulnerability itself (no such check exists in
# mail.c) and doesn't change that the core CVE, unauthenticated arbitrary
# file write via argument injection, is fully real and now demonstrable.
_PHP_MAIL_STANDIN_SCRIPT = (
    "cat > /usr/sbin/sendmail <<'SENDMAILEOF'\n"
    "#!/bin/bash\n"
    "echo \"$(date) ARGV: $0 $@\" >> /tmp/sendmail_argv.log\n"
    "xfile=\"\"\n"
    "for arg in \"$@\"; do\n"
    "    case \"$arg\" in\n"
    "        -X*) xfile=\"${arg#-X}\" ;;\n"
    "    esac\n"
    "done\n"
    "body=\"$(cat)\"\n"
    "if [ -n \"$xfile\" ]; then\n"
    "    printf '%s' \"$body\" >> \"$xfile\"\n"
    "fi\n"
    "exit 0\n"
    "SENDMAILEOF\n"
    "chmod +x /usr/sbin/sendmail\n"
    "touch /tmp/sendmail_argv.log && chmod 666 /tmp/sendmail_argv.log\n"
)

_PHP_422_PATCH_SCRIPT = '''def replace_once(path, old, new):
    with open(path) as f:
        content = f.read()
    n = content.count(old)
    assert n == 1, "%s: expected exactly 1 match, found %d" % (path, n)
    content = content.replace(old, new, 1)
    with open(path, "w") as f:
        f.write(content)

replace_once(
    "ext/mysql/libmysql/my_sys.h",
    "#ifdef HAVE_ERRNO_AS_DEFINE\\n"
    "#include <errno.h>\\t\\t\\t/* errno is a define */\\n"
    "#else\\n"
    "extern int errno;\\t\\t\\t/* declare errno */\\n"
    "#endif",
    "#include <errno.h>\\t\\t\\t/* errno is a define */",
)
'''


def _php_422_build_command(version: str) -> str:
    """ARGUS-LAYER-7: shared recipe for PHP 4.2.x -- see
    graphrange/victim_builder.py's MySQL function for the heredoc
    escaping rationale (same pattern). Only 4.2.2 validated so far.

    The sendmail stand-in (see _PHP_MAIL_STANDIN_SCRIPT's own comment for
    why one is needed at all) MUST be created before `./configure` runs --
    that's the whole point, since `./configure`'s own sendmail probe only
    runs once, at configure time."""
    return (
        "apt-get update -qq && apt-get install -y -qq "
        "build-essential wget bison flex apache2 ca-certificates python3 && "
        f"{_PHP_MAIL_STANDIN_SCRIPT}"
        "mkdir -p /tmp/build && cd /tmp/build && "
        f"wget -q https://museum.php.net/php4/php-{version}.tar.gz -O php-{version}.tar.gz && "
        f"tar xzf php-{version}.tar.gz && "
        f"cd php-{version} && "
        "./configure && "
        "python3 - <<'PYEOF' && "
        "mkdir -p /tmp/ccwrap && "
        "printf '#!/bin/sh\\nexec /usr/bin/gcc -fcommon \"$@\"\\n' > /tmp/ccwrap/gcc && "
        "chmod +x /tmp/ccwrap/gcc && "
        "export PATH=/tmp/ccwrap:$PATH && "
        "make && "
        "cp php /usr/lib/cgi-bin/php-cgi && "
        "mkdir -p /var/www/html && "
        "rm -f /var/www/html/index.html && "
        "printf '<?php echo \"real php \" . phpversion() . "
        "\" running via apache CGI (version-pinned GraphRange victim)\"; ?>\\n' "
        "> /var/www/html/index.php && "
        "printf 'AddHandler php4-cgi-script .php\\n"
        "Action php4-cgi-script /cgi-bin/php-cgi\\n"
        "DirectoryIndex index.php index.html\\n' "
        "> /etc/apache2/conf-available/php4-cgi.conf && "
        "a2enmod cgid actions && "
        "a2enconf serve-cgi-bin php4-cgi && "
        "mkdir -p /usr/local/lib && "
        "cp php.ini-recommended /usr/local/lib/php.ini && "
        "printf 'safe_mode = On\\nsendmail_path = /usr/sbin/sendmail -t -i\\n' "
        ">> /usr/local/lib/php.ini && "
        "printf 'SetEnv PHPRC /usr/local/lib\\n' "
        "> /etc/apache2/conf-available/phprc.conf && "
        "a2enconf phprc && "
        "chmod 777 /var/www/html\n"
        f"{_PHP_422_PATCH_SCRIPT}"
        "PYEOF\n"
    )


_PHP_422_START_COMMAND = "service apache2 start"

_PHP_422_VALIDATED_VERSIONS = ["4.2.2"]

_VERSION_MAP.update({
    ("php", "php", v): {
        "build_command": _php_422_build_command(v),
        "start_command": _PHP_422_START_COMMAND,
        "port": 80,
    }
    for v in _PHP_422_VALIDATED_VERSIONS
})

# Vendors whose CVEs need a Windows host -- not fixable by any apt package,
# structurally out of Docker-on-Linux's reach, same wall as the OS-level
# Windows CPEs. Kept explicit rather than silently falling through.
_WINDOWS_ONLY_VENDORS = {"microsoft", "symantec", "trend_micro"}

# Client-side software: no listening service for a network attack tool to
# reach at all -- a fundamentally different execution model (malicious-file
# delivery / browser automation), not something victim_builder can address.
_CLIENT_SIDE_PRODUCTS = {
    "internet_explorer", "ie", "powerpoint", "firefox", "thunderbird",
    "seamonkey", "frontpage", "visual_interdev",
    "livestate_agent_for_windows", "pc-cillin_internet_security_2007",
}


def resolve_victim_service(cpe: str) -> dict:
    """
    ARGUS-LAYER-7: Resolve one application-level CPE to a real install +
    start command, or an honest status explaining why not.

    Returns one of:
      {"status": "mapped", "install_command": str, "start_command": str, "port": int}
      {"status": "windows_only"}
      {"status": "client_side_not_executable"}
      {"status": "no_install_mapping"}
      {"status": "not_application_cpe"}
    """
    parts = cpe.split(":")
    if len(parts) < 5 or not cpe.startswith("cpe:2.3:"):
        return {"status": "no_install_mapping"}
    part, vendor, product = parts[2], parts[3], parts[4]
    version = parts[5] if len(parts) > 5 else ""
    if part != "a":
        return {"status": "not_application_cpe"}
    if vendor in _WINDOWS_ONLY_VENDORS:
        return {"status": "windows_only"}
    if product in _CLIENT_SIDE_PRODUCTS:
        return {"status": "client_side_not_executable"}

    version_specific = _VERSION_MAP.get((vendor, product, version))
    if version_specific is not None:
        return {
            "status": "mapped",
            "install_command": version_specific["build_command"],
            "start_command": version_specific["start_command"],
            "port": version_specific.get("port"),
            "source": "version_exact",
        }

    mapping = _INSTALL_MAP.get((vendor, product))
    if mapping is None:
        return {"status": "no_install_mapping"}
    return {"status": "mapped", **mapping, "source": "latest_apt"}
