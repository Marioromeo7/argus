"""
ARGUS-LAYER-7: Supervisor — the "internet" and package broker for GraphRange.

Runs inside the gr-supervisor container (docker.sock mounted) and exposes an
HTTP API that red/blue agents (running outside Docker, in the host Python
process, per agents/red.py + agents/blue.py) call to control the range.
"""

import os
import re
import ast

import docker
from flask import Flask, request, jsonify
from neo4j import GraphDatabase

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://host.docker.internal:7400")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "argus1234")
NETWORK_NAME = os.getenv("GR_NETWORK", "graphrange-public")

app = Flask(__name__)
docker_client = docker.from_env()
neo4j_driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

RED_IMAGE = "graphrange-red"
BLUE_IMAGE = "graphrange-blue"

# ARGUS-LAYER-7: minimal CPE -> Docker Hub image fallback map. Extended as
# GraphRange scenarios exercise more CPEs — not exhaustive by design, falls
# back to a bare ubuntu image (spec's own documented fallback) rather than
# failing when a CPE isn't recognized.
_CPE_IMAGE_MAP = {
    ("canonical", "ubuntu"): "ubuntu",
    ("apache", "http_server"): "httpd",
    ("debian", "debian_linux"): "debian",
}

# ARGUS-LAYER-7: duplicated from graphrange/victim_builder.py rather than
# imported -- this container's build context is graphrange/docker/supervisor
# only (see docker-compose.yml), which can't reach a file living at
# graphrange/victim_builder.py without restructuring the whole build.
# victim_builder.py stays as the canonical, host-side-testable copy of this
# same table; keep both in sync by hand if either changes. Every package
# name here was verified with `apt-cache show` against a live debian:12-slim
# image before being added -- not guessed.
_VICTIM_INSTALL_MAP = {
    ("apache", "http_server"): {
        "install_command": "apt-get update && apt-get install -y apache2",
        "start_command": "service apache2 start",
    },
    ("oracle", "mysql"): {
        # Real bug found live 2026-08-12/13 (see victim_builder.py's own
        # comment for the full story): "service mariadb start" was wrong
        # -- default-mysql-server resolves to real MySQL on Ubuntu 22.04,
        # mariadb is never installed. spawn_scenario() doesn't check
        # exec_run()'s exit code, so this silently reported "mapped" while
        # mysqld was never actually reachable.
        "install_command": "DEBIAN_FRONTEND=noninteractive apt-get update && "
                            "DEBIAN_FRONTEND=noninteractive apt-get install -y default-mysql-server",
        "start_command": "service mysql start",
    },
    ("national_science_foundation", "squid_web_proxy"): {
        "install_command": "apt-get update && apt-get install -y squid",
        "start_command": "service squid start",
    },
    ("carnegie_mellon_university", "cyrus_imap_server"): {
        "install_command": "apt-get update && apt-get install -y cyrus-imapd",
        "start_command": "service cyrus-imapd start",
    },
    ("php", "php"): {
        "install_command": "apt-get update && apt-get install -y php php-cli apache2 libapache2-mod-php",
        "start_command": "service apache2 start",
    },
}
_VICTIM_WINDOWS_ONLY_VENDORS = {"microsoft", "symantec", "trend_micro"}
_VICTIM_CLIENT_SIDE_PRODUCTS = {
    "internet_explorer", "ie", "powerpoint", "firefox", "thunderbird",
    "seamonkey", "frontpage", "visual_interdev",
    "livestate_agent_for_windows", "pc-cillin_internet_security_2007",
}

# ARGUS-LAYER-7: exact (vendor, product, version) recipes -- checked before
# _VICTIM_INSTALL_MAP's generic "latest apt package" entries. Installing
# "apache2" via today's apt repo installs today's Apache, already patched
# against a 20+-year-old CVE; these entries build the ACTUAL historic
# vulnerable version from the Apache Software Foundation's own archive
# instead. Old source does not compile or run cleanly on a modern toolchain
# by default -- every fix below was found by actually hitting the real
# failure, not guessed:
#   - a build script written for bash breaking under Debian's default
#     /bin/sh (dash)
#   - a removed glibc symbol (_sys_siglist)
#   - a name collision with glibc's own getline() across multiple files
#   - GCC >=10's -fno-common default breaking old tentative definitions
#     AND (a separate issue, confirmed by testing -fcommon alone first and
#     seeing it NOT fully fix things) GCC >=5's default inline semantics
#     change breaking Apache's own INLINE macro for ap_os_is_path_absolute
#     -- needs -fgnu89-inline specifically, confirmed via the linker's
#     "multiple definition" error pointing at an inline-declared function,
#     not a data symbol
#   - several ServerRoot-relative paths/files the default config expects
#     that don't exist until created, AND a real per-version difference in
#     which of those paths a given release's default config actually uses
#     (1.3.1 wants mime.types under etc/, 1.3.17 wants it under conf/;
#     1.3.17's config also uses a literal @@ServerRoot@@ placeholder token
#     elsewhere in the file that 1.3.1's config doesn't have at all) --
#     handled by writing to both possible mime.types locations and
#     substituting the placeholder globally, rather than branching per
#     version, since doing both is harmless when the other doesn't apply
#   - a legacy `Group #-1` default that modern initgroups() rejects
# None of this is 1.3.1-specific; confirmed by batch-testing all 11 Apache
# 1.3.x versions our graph references that Apache's own archive still has
# a real tarball for (1.3.5/1.3.7/1.3.8/1.3.18 were apparently never
# actually released despite NVD's CPE dictionary listing them -- checked
# directly against archive.apache.org, not assumed, no tarball exists at
# all for those four, so latest-apt is the permanent answer there, not a
# gap this recipe can close). This is exactly why it's a per-version
# exception table, not a general "compile any CPE from source" mechanism:
# a different old CVE's source would hit its own, different, unpredictable
# set of era-specific breakages.
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
# ends of this list) were also confirmed to actually start and serve
# HTTP, not just compile -- the rest were confirmed to compile
# (src/httpd produced with no build errors) but not individually
# start-tested, on the reasoning that the config-layer fixes above already
# cover the two known per-version config variants found across the range.
_APACHE_13X_VALIDATED_VERSIONS = [
    "1.3.0", "1.3.1", "1.3.2", "1.3.3", "1.3.4", "1.3.6",
    "1.3.9", "1.3.11", "1.3.12", "1.3.14", "1.3.17",
]

_VICTIM_VERSION_MAP = {
    ("apache", "http_server", v): {
        "build_command": _apache_13x_build_command(v),
        "start_command": _APACHE_13X_START_COMMAND,
    }
    for v in _APACHE_13X_VALIDATED_VERSIONS
}

# ARGUS-LAYER-7: Apache 2.0.x, a genuinely different case from 1.3.x --
# confirmed live 2026-08-10, zero source patches needed and `make install`
# works standard/unmodified. 2.0.x bundles its own APR/APR-util libraries
# specifically to be portable across platforms and toolchains, which is
# exactly the problem that broke 1.3.x's custom APACI build system on a
# modern compiler. Only fix needed is the same config-layer one 1.3.x also
# needed (User/Group/ServerName), and 2.0.x uses `httpd -k start` instead
# of a direct foreground/daemonizing invocation.
_VICTIM_VERSION_MAP[("apache", "http_server", "2.0.52")] = {
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
}

# ARGUS-LAYER-7: MySQL 3.22.32 (CVE-2000-0148) -- duplicated from
# graphrange/victim_builder.py's validated recipe (see that file's own
# comment for the full archaeology: config.guess/config.sub, procps,
# LinuxThreads detection, libncurses-dev, strnlen/errno/min-max/sigset/
# strcasestr conflicts with modern glibc, four friend-only-declaration
# fixes, two '\0'-to-pointer fixes in client/mysql.cc). Verified
# end-to-end from a fresh debian:12-slim container via the real
# production exec_run() path: real mysqld, real SELECT VERSION() over
# TCP 3306. Keep in sync by hand with victim_builder.py per this file's
# own top-of-map comment.
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


# Per-version source: download URL + extracted dir. See victim_builder.py's
# copy for the full rationale (Debian .orig extracts to mysql-X.orig, upstream
# to mysql-X; the old single-hardcoded-URL form only ever worked for 3.22.32).
_MYSQL_SOURCES = {
    "3.22.32": {
        "url": "https://snapshot.debian.org/file/c5e8fd1bf362e739e525b53698b3efa60fe45462",
        "src_dir": "mysql-3.22.32.orig",
    },
    # VULNERABLE target for CVE-2000-0148 (<=3.22.31) -- source URL TBD (not on
    # Debian snapshot). See victim_builder.py / ROADMAP P1.2.
    # "3.22.30": {"url": "<FILL WHEN SOURCED>", "src_dir": "mysql-3.22.30"},
}


def _mysql_322_build_command(version: str, url: str, src_dir: str) -> str:
    """ARGUS-LAYER-7: shared recipe for MySQL 3.22.x -- see
    graphrange/victim_builder.py's copy of this function for the heredoc
    escaping rationale and the _MYSQL_SOURCES parameterization."""
    return (
        "apt-get update -qq && apt-get install -y -qq "
        "build-essential wget python3 autotools-dev procps libncurses-dev && "
        "mkdir -p /tmp/build && cd /tmp/build && "
        f"wget -q {url} -O mysql-{version}.tar.gz && "
        f"tar xzf mysql-{version}.tar.gz && "
        f"cd {src_dir} && "
        "cp /usr/share/misc/config.guess /usr/share/misc/config.sub . && "
        "cp /usr/share/misc/config.guess /usr/share/misc/config.sub mit-pthreads/config/ && "
        "python3 - <<'PYEOF' && "
        "bash ./configure --prefix=/usr/local/mysql --without-debug && "
        "make && make install && "
        "(useradd -M -s /usr/sbin/nologin mysql || true) && "
        "mkdir -p /usr/local/mysql/var && "
        "/usr/local/mysql/bin/mysql_install_db\n"
        f"{_MYSQL_322_PATCH_SCRIPT}"
        "PYEOF\n"
    )


# Grant system ON (no --skip-grant-tables) + provision a password-protected
# network account 'argus'@'%', set root password, drop anonymous accounts. See
# victim_builder.py's copy for the full rationale: CVE-2000-0148 is an auth
# bypass, so auth must be enabled or there is nothing to bypass. Validated live
# 2026-08-16 on 3.22.32 (the patched build); to be re-run on the vulnerable one.
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

_VICTIM_VERSION_MAP.update({
    ("oracle", "mysql", v): {
        "build_command": _mysql_322_build_command(v, src["url"], src["src_dir"]),
        "start_command": _MYSQL_322_START_COMMAND,
    }
    for v, src in _MYSQL_SOURCES.items()
})

# ARGUS-LAYER-7: Cyrus IMAP 2.2.5 (CVE-2004-1012/1013) -- duplicated from
# graphrange/victim_builder.py's validated recipe (see that file's own
# comment for the full archaeology). Verified end-to-end from a fresh
# debian:12-slim container via the real exec_run() path: real master
# process, a real authenticated IMAP session (LOGIN succeeded, SELECT
# correctly parsed). Keep in sync by hand, same as MySQL above.
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
    graphrange/victim_builder.py's copy of this function for the heredoc
    escaping rationale. Only 2.2.5 validated so far."""
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

_VICTIM_VERSION_MAP.update({
    ("carnegie_mellon_university", "cyrus_imap_server", v): {
        "build_command": _cyrus_225_build_command(v),
        "start_command": _CYRUS_225_START_COMMAND,
    }
    for v in _CYRUS_225_VALIDATED_VERSIONS
})

# ARGUS-LAYER-7: PHP 4.2.2 (CVE-2002-0985) -- duplicated from
# graphrange/victim_builder.py's validated recipe (see that file's own
# comment for the full archaeology, including the honest note that this
# CVE's own graph CPE is a version wildcard so this exact-version entry
# won't auto-fire for ITS scenarios, but remains a real validated recipe).
# Verified end-to-end from a fresh debian:12-slim container: real `php`
# CGI binary, real PHP source executed and served over real HTTP through
# apache2 + mod_cgi.
#
# 2026-08-13 update: CVE-2002-0985 itself was actually exploited, not just
# proved reachable, which surfaced a real gap -- `./configure`'s own
# sendmail probe (PHP_PROG_SENDMAIL in acinclude.m4) only defines
# HAVE_SENDMAIL if a sendmail binary exists on disk at configure time, and
# basic_functions.c has its own independent #ifdef HAVE_SENDMAIL deciding
# whether `mail` registers as the real function or a dead stub. No
# sendmail existed in this recipe, so mail() could never actually be
# demonstrated. Fixed with a minimal sendmail stand-in created *before*
# ./configure runs (see victim_builder.py's _PHP_MAIL_STANDIN_SCRIPT
# comment for why this is explicitly not a real MTA, just enough of real
# sendmail's -X transcript-logging behavior for the exploit) plus
# safe_mode = On in php.ini (the CVE's own documented precondition).
# Verified end-to-end through the real HTTP + apache2 + php-cgi path: a
# query-controlled -X/var/www/html/pwned.php reached sendmail's argv
# unmodified, a smuggled <?php system(...); ?> payload was written into
# the web root by the real www-data worker process, and Apache genuinely
# interpreted it on a follow-up real HTTP GET.
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
    graphrange/victim_builder.py's copy of this function for the heredoc
    escaping rationale. Only 4.2.2 validated so far.

    The sendmail stand-in must be created before ./configure runs -- see
    _PHP_MAIL_STANDIN_SCRIPT's own comment."""
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

_VICTIM_VERSION_MAP.update({
    ("php", "php", v): {
        "build_command": _php_422_build_command(v),
        "start_command": _PHP_422_START_COMMAND,
    }
    for v in _PHP_422_VALIDATED_VERSIONS
})

# ARGUS-LAYER-7: Squid 2.2.STABLE5 (CVE-1999-1481) -- duplicated from
# graphrange/victim_builder.py's validated recipe (see that file's own
# comment for the full archaeology: two independent real SIGSEGV causes,
# both found by hitting the actual crash through gdb, not guessed -- an
# 8MB stack-array overflow in the main event loop from SQUID_MAXFD baking
# in Docker's default 1,048,576 fd ulimit at ./configure time, and a
# va_list reused across three vfprintf/vsnprintf calls with no va_copy(),
# undefined on x86_64 though harmless on this code's original i386
# target). Verified end-to-end from a fresh ubuntu:22.04 container: real
# build, real `squid -z` cache init, real daemon start, a real proxied
# HTTP request through it (TCP_MISS/200 in Squid's own access.log), clean
# shutdown.
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
    """ARGUS-LAYER-7: shared recipe for Squid 2.2.x -- see
    graphrange/victim_builder.py's copy of this function for the full
    heredoc-structure rationale. Only 2.2.STABLE5 validated so far.

    `ulimit -n 1024` around ./configure is load-bearing, not cosmetic:
    SQUID_MAXFD gets baked in from the build environment's fd ulimit, and
    Docker's default of 1,048,576 turns a stack array in the main event
    loop into a guaranteed stack overflow.

    Plain newline-separated statements under `set -e`, not one giant
    `&&`-chained line -- chaining a heredoc redirect straight into `&&`
    with nothing else queued before its own body starts feeds the
    heredoc's Python source text to the shell parser as if it were shell
    commands. `set -e` reproduces the same "abort on first failure"
    behavior as `&&`-chaining without that fragility."""
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

_VICTIM_VERSION_MAP.update({
    ("national_science_foundation", "squid_web_proxy", v): {
        "build_command": _squid_225_build_command(v),
        "start_command": _SQUID_225_START_COMMAND,
    }
    for v in _SQUID_225_VALIDATED_VERSIONS
})


def _resolve_victim_service(cpe: str) -> dict:
    """ARGUS-LAYER-7: see graphrange/victim_builder.py's resolve_victim_service()
    docstring for the full reasoning -- this is the same logic, duplicated
    for the build-context reason above. Checks _VICTIM_VERSION_MAP (an exact
    version match -- a validated, real build recipe) before falling back to
    _VICTIM_INSTALL_MAP (whatever apt currently ships); the caller doesn't
    need to know which path fired, both return the same {install_command,
    start_command} shape via the "build_command"/"install_command" keys."""
    parts = cpe.split(":")
    if len(parts) < 5 or not cpe.startswith("cpe:2.3:"):
        return {"status": "no_install_mapping"}
    part, vendor, product = parts[2], parts[3], parts[4]
    version = parts[5] if len(parts) > 5 else ""
    if part != "a":
        return {"status": "not_application_cpe"}
    if vendor in _VICTIM_WINDOWS_ONLY_VENDORS:
        return {"status": "windows_only"}
    if product in _VICTIM_CLIENT_SIDE_PRODUCTS:
        return {"status": "client_side_not_executable"}

    version_specific = _VICTIM_VERSION_MAP.get((vendor, product, version))
    if version_specific is not None:
        return {
            "status": "mapped",
            "install_command": version_specific["build_command"],
            "start_command": version_specific["start_command"],
            "source": "version_exact",
        }

    mapping = _VICTIM_INSTALL_MAP.get((vendor, product))
    if mapping is None:
        return {"status": "no_install_mapping"}
    return {"status": "mapped", **mapping, "source": "latest_apt"}


def _resolve_cpe_to_image(cpe: str) -> str:
    """ARGUS-LAYER-7: cpe:2.3:{part}:{vendor}:{product}:{version}:... -> docker image[:tag]."""
    parts = cpe.split(":")
    if len(parts) < 6 or not cpe.startswith("cpe:2.3:"):
        return "ubuntu:22.04"
    vendor, product, version = parts[3], parts[4], parts[5]
    image = _CPE_IMAGE_MAP.get((vendor, product))
    if not image:
        return "ubuntu:22.04"
    version = version if version and version != "*" else "latest"
    return f"{image}:{version}"


# ---------------------------------------------------------------------------
# 1. receive_tool_request
# ---------------------------------------------------------------------------
def receive_tool_request(agent: str, capability: str) -> dict:
    """ARGUS-LAYER-7: Query tool graph for a capability match.

    Tool graph (Phase 2, graphrange/tool_graph.py) may not be populated yet —
    this queries the same node_type='tool' shape it will write, so it starts
    working the moment Phase 2 lands with zero changes here.
    """
    cypher = """
    MATCH (n:Node {node_type: 'tool'})
    WHERE n.properties CONTAINS $capability
    RETURN n.node_id AS node_id, n.properties AS properties
    ORDER BY n.grain_confidence DESC
    LIMIT 1
    """
    with neo4j_driver.session() as session:
        record = session.run(cypher, capability=capability).single()
    if record is None:
        return {"tool_name": None, "install_command": None}
    try:
        props = ast.literal_eval(record["properties"])
    except (ValueError, SyntaxError):
        props = {}
    return {
        "tool_name": record["node_id"],
        "install_command": props.get("install_command"),
    }


# ---------------------------------------------------------------------------
# 2. deliver_tool
# ---------------------------------------------------------------------------
def _normalize_install_command(command: str) -> str:
    """ARGUS-LAYER-7: install_command values come from Kali's own human-facing
    "How to install" text (crawled verbatim by tool_crawler.py) -- correct to
    show a person, wrong to exec directly. Confirmed via a real live test
    (2026-08-10): "sudo apt install nmap" fails with "sh: 1: sudo: not found"
    because exec already runs as root inside these containers and the
    minimal Kali image doesn't ship a sudo binary at all -- it's not that
    sudo needs a password, it isn't there. Also force non-interactive apt
    (-y) since exec has no TTY to answer a confirmation prompt; without it
    an unconfirmed `apt install` returns immediately without installing
    anything (no TTY means no prompt to hang on, it just aborts)."""
    cmd = re.sub(r"^\s*sudo\s+", "", command.strip())
    if re.match(r"^apt(-get)?\s+install\b", cmd) and not re.search(r"\s-y\b", cmd):
        cmd = re.sub(r"^(apt(?:-get)?\s+install)\b", r"\1 -y", cmd)
    return cmd


def deliver_tool(container_name: str, install_command: str) -> bool:
    """ARGUS-LAYER-7: exec into a running container to install a tool.
    Never rebuilds the container image."""
    command = _normalize_install_command(install_command)
    try:
        container = docker_client.containers.get(container_name)
        # List form, not an f-string wrapped in its own quotes -- a command
        # containing a single quote (e.g. a sed pattern) would silently
        # break the f-string version by terminating it early. Confirmed
        # this matters live 2026-08-10 building the version-pinned Apache
        # recipe in _VICTIM_VERSION_MAP, which is full of sed '...' calls.
        exit_code, _ = container.exec_run(["sh", "-c", command])
        return exit_code == 0
    except docker.errors.NotFound:
        return False


# ---------------------------------------------------------------------------
# 3. spawn_scenario
# ---------------------------------------------------------------------------
def spawn_scenario(scenario: dict) -> dict:
    """ARGUS-LAYER-7: docker-run red, blue, and victim containers on the
    isolated gr-public network. All-or-nothing: if anything fails partway
    through, whatever was already created gets torn down before the error
    propagates -- found via a real orphaned red+blue pair left behind by a
    mid-spawn crash, 2026-08-10 (the NotFound-exception bug above crashed
    the request after red/blue existed but before victim did, and nothing
    ever cleaned them up since the caller never got IDs to tear down)."""
    run_suffix = scenario.get("run_id", "adhoc")
    red = blue = victim = None
    try:
        # init=True (Docker's --init, tini as PID 1) on all three -- found
        # live 2026-08-13 diagnosing the MySQL fallback's "Error: Unable to
        # shut down server" postinst failure: mysqld --daemonize forks and
        # its immediate parent exits, re-parenting the real daemon to
        # whatever this container's PID 1 is. Without a real init process,
        # nothing ever calls wait() on it when it dies, so it becomes a
        # permanent zombie (confirmed via `ps` showing `[mysqld] <defunct>`
        # for a process the postinst script's own liveness check -- `ps
        # $pid` -- still sees as "running", since ps lists zombies too).
        # Reproduced and fixed on a fresh container: identical install
        # fails every time without --init, succeeds cleanly every time with
        # it. Applies to all three containers, not just victim -- any of
        # them could run a daemonizing installer during their own setup.
        red = docker_client.containers.run(
            RED_IMAGE, name=f"gr-red-{run_suffix}", network=NETWORK_NAME,
            detach=True, remove=False, init=True,
        )
        blue = docker_client.containers.run(
            BLUE_IMAGE, name=f"gr-blue-{run_suffix}", network=NETWORK_NAME,
            detach=True, remove=False, init=True,
        )

        victim_cpe = scenario.get("victim_cpe", "")
        victim_image = _resolve_cpe_to_image(victim_cpe) if victim_cpe else "ubuntu:22.04"
        try:
            docker_client.images.pull(victim_image)
        except docker.errors.NotFound:
            # NotFound, not the narrower ImageNotFound subclass -- confirmed
            # via a real live failure 2026-08-10: pulling a nonexistent
            # remote tag (e.g. httpd:1.3.1, a real historic Apache version
            # with no matching official image) raises the broader NotFound,
            # which ImageNotFound alone never catches (ImageNotFound IS a
            # NotFound, but pull() raises the parent, not the subclass).
            # This crashed every application-CPE scenario whose resolved
            # image tag didn't actually exist, with no fallback ever firing.
            victim_image = "ubuntu:22.04"
            docker_client.images.pull(victim_image)

        # A purpose-built image (e.g. the official httpd image, resolved via
        # _CPE_IMAGE_MAP) already runs the right service through its own
        # default CMD -- overriding that with "sleep infinity" would
        # silently defeat the whole point of picking it. Only force
        # sleep-infinity on generic base images with no meaningful default
        # service, then separately install+start the real vulnerable
        # software via _resolve_victim_service(). Found missing entirely via
        # a real live test 2026-08-10: every scenario's victim ran nothing
        # at all, so every attack silently found no target regardless of
        # whether red's tool/technique choice was actually correct.
        is_generic_base = victim_image.split(":")[0] in ("ubuntu", "debian")
        run_command = "sleep infinity" if is_generic_base else None
        victim = docker_client.containers.run(
            victim_image, name=f"gr-victim-{run_suffix}", network=NETWORK_NAME,
            detach=True, remove=False, command=run_command, init=True,
        )

        service_status = "not_attempted"
        install_exit = start_exit = None
        if is_generic_base and victim_cpe:
            service = _resolve_victim_service(victim_cpe)
            service_status = service["status"]
            if service_status == "mapped":
                install_cmd = service["install_command"]
                start_cmd = service["start_command"]
                # List form -- see deliver_tool()'s comment on why. This is
                # exactly the case that would have broken: the version-pinned
                # build recipes are full of sed '...' patterns.
                #
                # Exit codes checked, not discarded -- found live 2026-08-13
                # testing an unseen (unvalidated) MySQL version through this
                # exact path: the fallback install left the package
                # unconfigured (a real dpkg dependency failure) and the
                # start_command named a service that was never installed
                # ("mariadb" vs. the real "mysql" service -- see
                # _INSTALL_MAP's own comment). service_status came back
                # "mapped" regardless, because nothing here ever looked at
                # exec_run()'s return value -- confirmed via a real failed
                # `SELECT VERSION()` against a victim this code had just
                # reported as successfully mapped. Still not a full health
                # check (a start_command that backgrounds itself with `&`,
                # which several version-pinned recipes do, returns exit 0
                # immediately regardless of whether the backgrounded
                # process later dies) -- but it now catches the actual
                # class of failure found here: the command itself failing
                # to run at all.
                install_exit, _ = victim.exec_run(["sh", "-c", install_cmd])
                if install_exit != 0:
                    service_status = "install_failed"
                else:
                    start_exit, _ = victim.exec_run(["sh", "-c", start_cmd])
                    if start_exit != 0:
                        service_status = "start_failed"

        return {"red_id": red.id, "blue_id": blue.id, "victim_id": victim.id,
                "victim_service_status": service_status,
                "install_exit_code": install_exit, "start_exit_code": start_exit}
    except Exception:
        # containers.run() does create-then-start internally; if .start()
        # fails after .create() succeeds, the exception propagates without
        # ever returning a container object, so the local variable (red/
        # blue/victim) stays None even though a real container now exists.
        # The names are deterministic (gr-{role}-{run_suffix}) regardless
        # of whether the local variable got assigned, so look each one up
        # by name instead of trusting the local variable -- found live
        # 2026-08-10 as a genuine orphaned container (a missing Docker
        # network made .start() fail after .create() had already run,
        # and this loop's `if c is not None` skipped it since `red` was
        # never assigned).
        for role, c in (("red", red), ("blue", blue), ("victim", victim)):
            if c is None:
                try:
                    c = docker_client.containers.get(f"gr-{role}-{run_suffix}")
                except docker.errors.NotFound:
                    continue
            try:
                c.stop(timeout=5)
                c.remove()
            except docker.errors.NotFound:
                pass
        raise


# ---------------------------------------------------------------------------
# 4. collect_output
# ---------------------------------------------------------------------------
def collect_output(container_name: str, command: str) -> str:
    """ARGUS-LAYER-7: exec a command in a running container, return raw stdout."""
    container = docker_client.containers.get(container_name)
    # List form -- see deliver_tool()'s comment on why.
    _, output = container.exec_run(["sh", "-c", command])
    return output.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# 5. teardown_scenario
# ---------------------------------------------------------------------------
def teardown_scenario(red_id: str, blue_id: str, victim_id: str) -> None:
    """ARGUS-LAYER-7: stop + remove all three containers. Called after every
    scenario regardless of outcome — never leaves containers running."""
    for container_id in (red_id, blue_id, victim_id):
        if not container_id:
            continue
        try:
            container = docker_client.containers.get(container_id)
            container.stop(timeout=5)
            container.remove()
        except docker.errors.NotFound:
            pass


# ---------------------------------------------------------------------------
# HTTP API — what agents/red.py, agents/blue.py, graphrange/run_scenario.py
# actually call (per Phase 4/7 spec)
# ---------------------------------------------------------------------------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/tool_request", methods=["POST"])
def http_tool_request():
    body = request.get_json(force=True)
    result = receive_tool_request(body["agent"], body["capability"])
    return jsonify(result)


@app.route("/exec", methods=["POST"])
def http_exec():
    body = request.get_json(force=True)
    container = body["container"]
    command = body["command"]
    if re.search(r"install", command):
        ok = deliver_tool(container, command)
        return jsonify({"success": ok})
    stdout = collect_output(container, command)
    return jsonify({"stdout": stdout})


@app.route("/spawn_scenario", methods=["POST"])
def http_spawn_scenario():
    scenario = request.get_json(force=True)
    return jsonify(spawn_scenario(scenario))


@app.route("/teardown", methods=["POST"])
def http_teardown():
    body = request.get_json(force=True)
    teardown_scenario(body.get("red_id"), body.get("blue_id"), body.get("victim_id"))
    return jsonify({"status": "torn_down"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
