# Colab GPU offload (tunnel model)

Backup/alternate compute lane to `kaggle/`, built and live-verified 2026-08-24
when Kaggle's weekly 30hr GPU quota was exhausted. Same shape as the Kaggle
tunnel: serves Ollama on a real Colab GPU, reached via SSH port-forward from
the local machine; Neo4j and the runners stay **local**, only LLM calls cross
the wire. Point `.env`'s `OLLAMA_BASE_URL`/`OLLAMA_HOST` at the forwarded local
port and nothing else changes (`config.py` is still the one source of truth).

Unlike Kaggle, Google shipped an **official** headless CLI for this in June
2026 (`google-colab-cli`, https://github.com/googlecolab/google-colab-cli) --
no cloudflared/nginx tunnel needed, no port-guessing. It supports Linux/macOS
only (not Windows), so this whole workflow runs through **WSL2 Ubuntu**, not
Git Bash/PowerShell directly.

## One-time setup (per WSL Ubuntu install)

```bash
wsl -d Ubuntu -e bash -c "curl -LsSf https://astral.sh/uv/install.sh | sh"
wsl -d Ubuntu -e bash -c "source ~/.local/bin/env && uv tool install git+https://github.com/googlecolab/google-colab-cli"
wsl -d Ubuntu -e bash -c "ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N '' -C 'argus-colab'"
```

## Per-session workflow

1. **Create a GPU session** (only `T4` is available on a free-tier account --
   `L4`/`G4`/`A100`/`H100` are rejected outright with an *entitlement* error,
   not a quota error, confirmed live 2026-08-24: a plain CPU session created
   fine at the same time T4 was refused with "Service Unavailable," and
   L4/G4/A100 all failed with "Backend rejected accelerator ... no quota or
   entitlement" -- this is a permanent account-tier restriction, not
   something to retry around):
   ```bash
   wsl -d Ubuntu -e bash -c "source ~/.local/bin/env && colab new --gpu T4"
   ```
   First run on a fresh WSL install needs a one-time interactive OAuth step
   (prints a Google consent URL, then prompts `Enter the authorization
   code:` in the SAME terminal -- this genuinely needs a human at a
   browser, can't be scripted). `colab status` shows the session ID and
   confirms `Hardware: T4`.

2. **Point SSH at this session's ID** (session IDs change every `colab new`
   -- update this file before connecting):
   ```bash
   wsl -d Ubuntu -e bash -c "cat > ~/.ssh/config << 'EOF'
   Host argus-colab
       User root
       ProxyCommand /home/USERNAME/.local/bin/colab ssh --proxy-mode -s SESSION_ID
       StrictHostKeyChecking no
       UserKnownHostsFile /dev/null
   EOF
   chmod 600 ~/.ssh/config"
   ```

3. **Install zstd + Ollama** (same `zstd` gap as Kaggle's base image):
   ```bash
   wsl -d Ubuntu -e bash -c "source ~/.local/bin/env && ssh argus-colab 'apt-get update -qq && apt-get install -y -qq zstd && curl -fsSL https://ollama.com/install.sh | sh'"
   ```

4. **Start Ollama with the GPU library path AND real parallelism**:
   ```bash
   wsl -d Ubuntu -e bash -c "source ~/.local/bin/env && ssh argus-colab 'export LD_LIBRARY_PATH=/usr/lib64-nvidia:\$LD_LIBRARY_PATH; export OLLAMA_HOST=0.0.0.0:11434; export OLLAMA_NUM_PARALLEL=2; setsid nohup ollama serve > /tmp/ollama.log 2>&1 < /dev/null & disown'"
   ```
   `LD_LIBRARY_PATH=/usr/lib64-nvidia` is required -- the driver and
   `/dev/nvidia*` device nodes are real, but `libnvidia-ml.so` lives outside
   the default search path, so `nvidia-smi`/Ollama can't find the GPU
   without it (confirmed live: `nvidia-smi` failed with "couldn't find
   libnvidia-ml.so" until this was set, then correctly reported a real
   Tesla T4). `OLLAMA_NUM_PARALLEL=2`, not higher -- see **Real throughput**
   below for why.

5. **Pull the model**:
   ```bash
   wsl -d Ubuntu -e bash -c "source ~/.local/bin/env && ssh argus-colab 'export OLLAMA_HOST=127.0.0.1:11434; ollama pull qwen3:8b'"
   ```

6. **Open the port-forward tunnel** -- must be ONE compound command (see
   **Gotcha: backgrounding across separate WSL invocations** below):
   ```bash
   wsl -d Ubuntu -e bash -c "source ~/.local/bin/env && setsid nohup ssh -N -L 19434:127.0.0.1:11434 argus-colab > /tmp/portforward.log 2>&1 < /dev/null & disown; sleep 5; curl -s -m 10 http://127.0.0.1:19434/api/tags"
   ```
   WSL2's default localhost-forwarding makes `http://localhost:19434` also
   reachable from native Windows processes (confirmed live) -- no extra
   config needed on the Windows side.

7. **Point `.env` at it**:
   ```
   OLLAMA_BASE_URL=http://localhost:19434
   OLLAMA_HOST=http://localhost:19434
   ```

## Real throughput -- measured, not assumed (2026-08-24)

The first instinct -- "3 parallel client workers, so 3x speedup" -- was
**wrong twice**, in opposite directions:

1. Ollama defaults to `OLLAMA_NUM_PARALLEL=1` if not set explicitly, so
   naive concurrent client requests just queue server-side. Real observed
   pace with this misconfigured: ~27.7s/file, not the ~17.6s/3-workers the
   naive math assumed.
2. Fixed that by setting `OLLAMA_NUM_PARALLEL=6` + matching client
   concurrency -- and throughput got *worse* (142.4s for 6 concurrent
   calls), because a T4 has fixed compute throughput and 6 concurrent
   8B-parameter inference streams genuinely compete for the same
   compute/memory bandwidth, each individually slowing down enough to
   cancel out the added concurrency.

A real sweep (N=1/2/4 concurrent calls, identical content) found the actual
sweet spot:

| Concurrency (N) | Effective s/file | Est. 1391-file scan |
|---|---|---|
| 1 | 13.1s | 5.07 hr |
| 2 | 8.6s | 3.33 hr |
| 4 | 8.5s | 3.30 hr |

Throughput improves 1->2, then **flatlines** 2->4 -- the T4 is compute-bound
at ~2 concurrent qwen3:8b streams, not queue-bound. `OLLAMA_NUM_PARALLEL=2`
and matching client-side `MAX_WORKERS=2` is the real, measured optimum for
this GPU + model combination. Don't assume a bigger number is faster --
measure it, the same way, if the tunnel ever points at a different
GPU/model.

## Known reliability gaps (real, hit live 2026-08-24)

- **Sessions can die unannounced.** A session was killed by Colab's backend
  after only a few minutes of light use (`colab status` returned "No active
  sessions" with no warning). Not something this project can control or
  predict -- budget for a full account switch or session recreation
  mid-task, don't assume a session survives a multi-hour unattended run.
- **The SSH proxy endpoint can go stale independently of the tunnel.** A
  live, still-working port-forward kept passing traffic while brand-new
  `colab ssh` connection attempts failed with "this runtime does not expose
  the /colab/ssh endpoint" -- the tool's own suggested fix (`colab new` for
  a fresh session) is the real fix; don't waste time debugging the stale
  one.
- **GPU quota is per-account and opaque.** No visible remaining-quota
  command (unlike Kaggle's explicit "30.00 hours" message) -- you only find
  out it's exhausted when `colab new --gpu T4` returns "Service
  Unavailable." A CPU session (`colab new`, no `--gpu`) working at the same
  time confirms it's a GPU-specific limit, not a general outage.
- **Switching accounts**: back up (don't delete) `~/.config/colab-cli/token.json`
  before re-authenticating with a different Google account --
  `mv ~/.config/colab-cli/token.json ~/.config/colab-cli/token.json.bak`,
  then any `colab` command re-triggers the OAuth flow. Restore the `.bak`
  file to switch back.

## Gotcha: backgrounding across separate WSL invocations

Each `wsl -d Ubuntu -e bash -c "..."` call from the host is its own
`wsl.exe` process. A background job started with `setsid nohup ... & disown`
in one such call does **not** reliably survive into a later, separate `wsl
...` call -- confirmed live: splitting "start the port-forward" and "test
it" into two separate Bash tool calls produced a background process that
was already gone (`ps aux` showed nothing, curl got connection-refused) by
the time the second call ran. Keep the backgrounding, the `sleep`, and the
verification `curl`/`cat` all in **one** compound `wsl -d Ubuntu -e bash -c
"... & disown; sleep N; verify"` command, matching the working examples
above -- don't split it for readability.

## Scope

Same as Kaggle's tunnel: an alternate/backup GPU-offload lane, not a
replacement for local hardware or a claim about paper-reportable latency
(Claim 4 still must come from local). Useful when Kaggle's weekly quota is
exhausted, or as a faster option generally given `google-colab-cli`'s
lower setup friction (no manual kernel push, no cloudflared/nginx).
