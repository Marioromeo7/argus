#!/usr/bin/env python3
"""
ARGUS Kaggle GPU tunnel kernel.

Serves Ollama (qwen3:8b + nomic-embed-text) on a Kaggle GPU behind a cloudflared
tunnel, so the LOCAL ARGUS project can point OLLAMA_BASE_URL at it and offload
inference (~37 tok/s on a P100 vs ~8 tok/s local). This is the "tunnel" compute
model agreed for R1 (narrowing validation): Neo4j + the runner stay local, only
the LLM calls cross the wire -- which also sidesteps the local GPU/RAM
contention that killed every prior R1 run.

USAGE
  1. kaggle kernels push -p kaggle/        (GPU + internet must be ON -- see
     kernel-metadata.json; toggle in the Kaggle UI if the push doesn't set it)
  2. Watch the kernel log for:  ARGUS_TUNNEL_URL=https://<random>.trycloudflare.com
  3. Locally, put that URL in .env:  OLLAMA_BASE_URL=https://<random>.trycloudflare.com
     (config.py reads it; nothing else changes)
  4. Verify locally:
       python -c "import config,requests;print(requests.get(config.OLLAMA_TAGS_URL).json())"
  5. Run R1 one node at a time:
       python scripts/run_narrowing_single.py <node>   # inference now on Kaggle

PROVENANCE / STATUS
  Reconstructed from BACKLOG.md's 2026-08-12 notes -- the setup was validated
  live that day but never committed as reusable code. **Not yet re-run from this
  file**, so treat it as a starting point to validate on the next real Kaggle
  session, not a proven artifact. The three non-obvious problems it works
  around, all hit live that day:
    - Ollama's install script needs `zstd`, absent from Kaggle's base image.
    - cloudflared block-buffers stdout when it is not a TTY, so the URL never
      appears if you just pipe it -- run under `stdbuf -oL` to a file and poll.
    - OLLAMA_ORIGINS=* does NOT bypass Ollama's Host-header check (that is a
      CORS-only setting); a non-localhost Host is rejected. An nginx reverse
      proxy rewrites Host -> localhost before forwarding, and the tunnel points
      at nginx, not Ollama directly.
"""
import json
import os
import re
import subprocess
import textwrap
import time
import urllib.request

OLLAMA_PORT = 11434
PROXY_PORT = 8080
MODELS = ["qwen3:8b", "mistral:latest", "nomic-embed-text"]


def sh(cmd, check=False):
    print(f"$ {cmd}", flush=True)
    return subprocess.run(cmd, shell=True, check=check)


def main():
    # 1. Dependencies Ollama's installer + the proxy need but Kaggle lacks.
    sh("apt-get update -qq && apt-get install -y -qq zstd nginx >/dev/null 2>&1")

    # 2. Install Ollama.
    sh("curl -fsSL https://ollama.com/install.sh | sh")

    # 3. Start `ollama serve` bound to localhost (default). We proxy to it.
    os.environ["OLLAMA_HOST"] = f"127.0.0.1:{OLLAMA_PORT}"
    ollama_proc = subprocess.Popen(
        ["ollama", "serve"],
        stdout=open("/tmp/ollama.log", "w"), stderr=subprocess.STDOUT,
    )
    time.sleep(8)

    # 4. Pull models (reasoning + embeddings).
    for m in MODELS:
        sh(f"ollama pull {m}")

    # 5. nginx reverse proxy: rewrite Host -> localhost so Ollama accepts
    #    tunneled requests. Long timeouts because qwen3:8b /think can take
    #    minutes per call.
    nginx_conf = textwrap.dedent(f"""
        server {{
            listen {PROXY_PORT};
            location / {{
                proxy_pass http://127.0.0.1:{OLLAMA_PORT};
                proxy_set_header Host localhost:{OLLAMA_PORT};
                proxy_read_timeout 900s;
                proxy_send_timeout 900s;
            }}
        }}
    """)
    with open("/etc/nginx/conf.d/ollama.conf", "w") as f:
        f.write(nginx_conf)
    sh("rm -f /etc/nginx/sites-enabled/default 2>/dev/null; "
       "nginx -t && (nginx || nginx -s reload)")

    # 6. cloudflared tunnel -> nginx. Block-buffered stdout, so stdbuf -oL to a
    #    file and poll for the URL.
    sh("wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/"
       "cloudflared-linux-amd64 -O /usr/local/bin/cloudflared "
       "&& chmod +x /usr/local/bin/cloudflared")
    cf_proc = subprocess.Popen(
        f"stdbuf -oL cloudflared tunnel --url http://127.0.0.1:{PROXY_PORT} "
        "--no-autoupdate > /tmp/cf.log 2>&1",
        shell=True,
    )

    # 7. Poll for the tunnel URL (up to ~2 min).
    url = None
    for _ in range(60):
        time.sleep(2)
        try:
            log = open("/tmp/cf.log").read()
        except FileNotFoundError:
            continue
        m = re.search(r"https://[a-z0-9-]+\.trycloudflare\.com", log)
        if m:
            url = m.group(0)
            break
    if not url:
        print("!! tunnel URL not found -- last cloudflared log:")
        print(open("/tmp/cf.log").read()[-2000:])
        raise SystemExit(1)

    print("\n" + "=" * 60)
    print(f"ARGUS_TUNNEL_URL={url}")
    print("=" * 60 + "\n", flush=True)

    # 8. External self-verify THROUGH the tunnel (proves end-to-end, not just
    #    that the processes started) -- same discipline as the 2026-08-12 run.
    try:
        tags = json.load(urllib.request.urlopen(f"{url}/api/tags", timeout=30))
        print("models visible through tunnel:",
              [m["name"] for m in tags.get("models", [])], flush=True)
    except Exception as e:  # noqa: BLE001 - diagnostic only
        print("tunnel verify (tags) failed:", e, flush=True)

    try:
        payload = json.dumps({
            "model": "qwen3:8b",
            "messages": [{"role": "user", "content": "/no_think\nSay OK."}],
            "stream": False,
        }).encode()
        req = urllib.request.Request(f"{url}/api/chat", data=payload,
                                     headers={"Content-Type": "application/json"})
        t = time.time()
        r = json.load(urllib.request.urlopen(req, timeout=300))
        dt = time.time() - t
        ec, ed = r.get("eval_count", 0), r.get("eval_duration", 0) / 1e9
        rate = f"~{ec / ed:.0f} tok/s" if ed else "rate n/a"
        print(f"inference OK in {dt:.1f}s ({rate})", flush=True)
    except Exception as e:  # noqa: BLE001 - diagnostic only
        print("tunnel verify (chat) failed:", e, flush=True)

    # 9. Keep the kernel (and tunnel) alive until Kaggle's session cap or a
    #    process dies. Restart ollama if it drops; give up if the tunnel does.
    print("\nTunnel live. Set OLLAMA_BASE_URL locally to the URL above.", flush=True)
    while True:
        time.sleep(60)
        if ollama_proc.poll() is not None:
            print("ollama serve exited -- restarting", flush=True)
            ollama_proc = subprocess.Popen(
                ["ollama", "serve"],
                stdout=open("/tmp/ollama.log", "a"), stderr=subprocess.STDOUT,
            )
        if cf_proc.poll() is not None:
            print("cloudflared exited -- tunnel down, stopping.", flush=True)
            break


if __name__ == "__main__":
    main()
