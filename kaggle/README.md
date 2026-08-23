# Kaggle GPU offload (tunnel model)

Reusable artifact for the **R1** compute lane (narrowing-thesis validation) and
the R2 sweeps. Serves Ollama on a Kaggle GPU behind a cloudflared tunnel; the
local ARGUS project points `OLLAMA_BASE_URL` at it and offloads inference
(~37 tok/s on a P100 vs ~8 local). Neo4j and the runners stay **local** — only
LLM calls cross the wire, which also removes the local GPU/RAM contention that
killed every prior R1 run.

> **Status:** reconstructed from `BACKLOG.md`'s 2026-08-12 notes (the setup was
> validated live that day but never committed as code). **Not yet re-run from
> these files** — validate on the next real Kaggle session before trusting it.

## Files
- `ollama_tunnel_kernel.py` — the kernel: installs Ollama, pulls `qwen3:8b` +
  `nomic-embed-text`, starts an nginx Host-rewrite proxy, opens the tunnel,
  self-verifies through it, then stays alive.
- `kernel-metadata.json` — Kaggle push metadata. **Edit `id`**: replace
  `KAGGLE_USERNAME` with your Kaggle username. GPU + internet are enabled here.

## Workflow
1. **Push** (from repo root): `kaggle kernels push -p kaggle/`
   - If the push doesn't enable GPU/internet, toggle them in the Kaggle UI and
     re-run. (Kaggle free P100 ≈ 30 h/week; the CLI can't read remaining quota —
     check kaggle.com/settings.)
2. **Get the URL**: watch the kernel log for
   `ARGUS_TUNNEL_URL=https://<random>.trycloudflare.com`.
3. **Point local config at it**: set `OLLAMA_BASE_URL=<that url>` in `.env`
   (`config.py` reads it; nothing else changes).
4. **Verify locally**:
   `python -c "import config,requests;print(requests.get(config.OLLAMA_TAGS_URL).json())"`
5. **Run R1** one node at a time (user-gated, per the standing rule):
   `python scripts/run_narrowing_single.py <node>`

## Why the kernel is shaped the way it is
Three non-obvious problems, all hit live 2026-08-12:
- Ollama's installer needs `zstd`, absent from Kaggle's base image → apt-install it first.
- cloudflared block-buffers stdout when not a TTY → run under `stdbuf -oL` to a
  file and poll for the URL.
- `OLLAMA_ORIGINS=*` does **not** bypass Ollama's Host-header check (CORS-only) →
  an nginx proxy rewrites `Host` to `localhost` before forwarding; the tunnel
  points at nginx, not Ollama.

## Scope
- **R1 + R2 correctness sweeps** run through this tunnel. Any **latency number
  destined for the paper (Claim 4) must come from local**, not Kaggle.
- The self-contained *kernel* model (Neo4j-in-kernel + graph dump) for the longer
  R2 sweeps is a separate future artifact — see ROADMAP R2.
