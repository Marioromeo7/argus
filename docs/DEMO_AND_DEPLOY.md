# ARGUS — Demo & Free Deployment Guide

*Addresses roadmap items #5 (deploy guide), #10 (export script), #11 (public-safe dashboard mode),
and #12 (demo walkthrough).* Companion to the strategy in
[PRODUCT_HOSTING_HANDOFF.md](../PRODUCT_HOSTING_HANDOFF.md) — that file is the *why*; this is the
*how*.

**Golden rule:** the public demo is **read-only**. No agent execution, no crawler, no writes, no
live Ollama, no arbitrary target input, no secrets in the frontend.

---

## #10 — `scripts/export_public_demo.py` (spec)

A one-shot exporter that snapshots the local Neo4j graph to static JSON the frontend can read
without any database.

**Inputs:** live local Neo4j (`argus` db). **Outputs:**

```
dashboard/public/demo_graph.json      # nodes + edges (curated/capped)
dashboard/public/demo_results.json    # eval summaries (retrieval, grain, co-evolution)
dashboard/public/demo_examples.json   # curated guided paths
```

**Behavior:**
- Export nodes with only presentation-safe fields: `label`, `node_type`, `grain_confidence`,
  `open_questions`, and a whitelist of properties. **Strip** anything operational.
- Export edges with `relation_type`, `confidence`, `context_conditions`, `directionality`.
- Parse stringified Neo4j properties with `ast.literal_eval()` (they are `str(dict)`, **not** JSON).
- **Cap size** (e.g. top-N nodes by connectivity + all techniques/tactics) so the JSON stays light
  for static hosting; `log()` what was dropped so the demo doesn't silently look complete.
- Curate 3 example paths: (1) RCE CVE → ATT&CK technique → tactic, (2) a low-grain node needing
  refinement, (3) one red/blue/reflexion cycle.

**Definition of done:** running the script produces the three JSON files; opening the static
frontend against them renders the graph with no backend.

---

## #11 — Public-safe dashboard mode (spec)

Add a `DEMO_MODE` (env flag) to `dashboard/api/main.py` and the React app.

**When `DEMO_MODE=1`:**
- Serve **only** these read-only routes:
  `GET /api/health`, `GET /api/graph`, `GET /api/node/{id}`, `GET /api/search?q=`,
  `GET /api/results`, `GET /api/examples/attack-paths`.
- **Disable/return 404** for anything that writes or triggers agents/crawler/challenger.
- No Neo4j credentials shipped to the browser; if using static JSON, the frontend fetches the
  `demo_*.json` files directly and the API isn't needed at all.
- Add visible banners: *"research demo — not production security advice"* and defensive framing on
  attack-path views.
- Narrow CORS to the demo domain once it exists; add basic rate limiting if any backend is public.

**Definition of done:** with `DEMO_MODE=1`, no route can mutate the graph or invoke a model, and the
UI shows the demo disclaimers.

---

## #5 / #12 — Deploy the read-only demo (two free paths + walkthrough)

### Option A — Static JSON (cheapest, safest — recommended first)
1. `python scripts/export_public_demo.py` → produces `dashboard/public/demo_*.json`.
2. Point the frontend at the static JSON (no API).
3. `cd dashboard/ui && npm run build`.
4. Deploy `dist/` to **Netlify / Vercel / GitHub Pages / Hugging Face Spaces**.
- **Pros:** no DB, no credentials, no write surface. **Cons:** not live unless re-exported.

### Option B — Read-only FastAPI + Neo4j AuraDB Free
1. Import the exported graph into **Neo4j AuraDB Free**.
2. Deploy `dashboard/api` (with `DEMO_MODE=1`) to **Render Free Web Service**; set Neo4j creds as
   env vars (never in frontend).
3. Deploy the React frontend (static or alongside).
- **Pros:** feels like a real app on the live DB. **Cons:** Render free spins down after ~15 min
  idle; AuraDB Free has no SLA/backups.

> Do **not** deploy Ollama/Qwen3 to free hosting — it can't run reliably and would expose the agent
> system. Keep all inference and all agents **local**.

### #12 — Demo walkthrough (what a visitor should experience)
1. Land directly in the **graph explorer** (not a marketing page).
2. **Search** a CVE or ATT&CK technique → graph centers on it.
3. Click a node → sidebar shows `grain_confidence`, `open_questions`, edge confidence, challenger
   history — *the epistemic fields are the pitch.*
4. Open a **guided example**: "RCE CVE → technique → tactic", then "low-grain node", then a
   "red/blue/reflexion cycle".
5. **Results panel**: GraphRAG vs vector RAG, grain convergence curve, co-evolution oscillation.
6. Every attack-path view is framed defensively ("how systems reason about risk", not an exploit).

**Definition of done:** a public URL where a stranger can explore the graph and results, learns the
uncertainty-aware angle in under a minute, and cannot trigger any write or model call.
