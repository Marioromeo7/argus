# ARGUS Product + Free Hosting Handoff

## Purpose

This file explains how to turn ARGUS into a public-facing product/demo using
free hosting options only.

ARGUS is currently a local-first cyber research prototype, not a production
SaaS. The safest and most realistic hosted product is a read-only public demo
called something like **ARGUS Lab**:

> An uncertainty-aware cyber knowledge graph for exploring CVEs, ATT&CK
> techniques, attack paths, mitigations, and epistemic confidence.

The full agent system should remain local for now. Do not expose unrestricted
red-team or crawler functionality to public users.

## Current Project Shape

ARGUS has six code layers:

1. Graph schema and ingestion: `graph/schema.py`, `graph/ingestion/`
2. Graph retrieval: `graph/retrieval.py`
3. Challenger refinement: `agents/challenger.py`
4. Web/crawler updates: `agents/crawler.py`
5. Red/blue agents: `agents/red.py`, `agents/blue.py`
6. Reflexion memory: `memory/reflexion.py`

There is also a dashboard:

- Backend: `dashboard/api/main.py` using FastAPI
- Frontend: `dashboard/ui/` using React/Vite
- Local launch: `docker compose up --build`
- Expected URL: `http://localhost:3000`

The dashboard is already the closest thing to a public product surface.

## Product Positioning

Best first product:

> ARGUS Lab: a public, read-only uncertainty-aware cyber knowledge graph and
> research demo.

Users should be able to:

- Search a CVE or ATT&CK technique.
- Explore related techniques, tactics, mitigations, memories, and engagements.
- Inspect `grain_confidence`, `open_questions`, edge confidence, and
  challenger history.
- View safe explanations of attack paths focused on defensive understanding.
- Compare existing evaluation results, such as GraphRAG vs vector RAG.
- Browse precomputed red/blue/reflexion cycles.

Do not let public users:

- Run arbitrary red-team planning against real targets.
- Trigger crawler writes.
- Trigger challenger writes.
- Run local Qwen/Ollama inference from the hosted free service.
- Submit external domains/IPs for offensive analysis.

## Why Not Host Full ARGUS Yet

The full system depends on:

- Local Ollama/Qwen3 8B
- Neo4j writes
- Long-running agent calls
- Cyber-sensitive red/blue planning

Free hosts are not suitable for this yet. They sleep, restart, have limited CPU,
often have ephemeral filesystems, and generally cannot run Qwen3 8B reliably.

Also, public cyber-agent generation needs safety controls, rate limits, auth,
tenant isolation, logging, and abuse prevention. Those do not exist yet.

## Free Hosting Options

### Best Practical Stack

Use one of these two paths:

#### Option A: Static JSON Demo

- Export the current graph from Neo4j to JSON.
- Modify the dashboard API/frontend to read static JSON.
- Host the frontend on GitHub Pages, Netlify, Vercel, Render Static Sites, or
  Hugging Face Spaces.

Pros:

- Cheapest and safest.
- No database credentials.
- No public write surface.
- Great for demos, papers, advisors, and early users.

Cons:

- Not live unless graph snapshots are re-exported.

#### Option B: Read-Only AuraDB Demo

- Import graph data into Neo4j AuraDB Free.
- Deploy the FastAPI dashboard backend on Render Free Web Service.
- Deploy the React frontend either with the backend or as a static site.
- Set Neo4j credentials as environment variables.
- Keep all API routes read-only.

Pros:

- Feels more like a real hosted app.
- Still free.
- Uses the real graph database.

Cons:

- Render free web services spin down after idle time.
- AuraDB Free has learning/exploration limits and no production SLA/backups.
- Public backend needs careful read-only hardening.

### Notes on Providers

- Render Free Web Services can host Python/FastAPI but spin down after about
  15 minutes idle and have ephemeral local filesystems. Good for demos, not
  production.
- Neo4j AuraDB Free is `$0` and does not require a payment method, but is for
  learning/exploration, not production.
- Hugging Face Spaces free CPU gives enough for a lightweight demo, but free
  Spaces sleep when unused and disk is not persistent by default.
- Railway is not a good "free only" default; its free path is a limited trial.
- Fly.io is not a good "free only" default for new users; free allowances are
  mostly legacy/discontinued.

## MVP Build Plan

### Phase 1: Public-Safe Demo Mode

Add a public-safe mode to the dashboard/API:

- Read-only endpoints only.
- No agent execution endpoints.
- No crawler endpoints.
- No write queries.
- No public Neo4j credentials in frontend code.
- Add clear demo labels: "research demo", "not production security advice".

Suggested API endpoints:

- `GET /api/health`
- `GET /api/graph`
- `GET /api/node/{node_id}`
- `GET /api/search?q=...`
- `GET /api/results`
- `GET /api/examples/attack-paths`

### Phase 2: Product UI

Make the first screen useful immediately:

- Search bar for CVE/technique lookup.
- Graph explorer.
- Node sidebar with uncertainty fields.
- Metrics strip.
- Evaluation/results panel.
- Example guided paths:
  - "Remote code execution CVE to ATT&CK technique"
  - "Low grain node needing refinement"
  - "Red/blue/reflexion cycle"

Avoid making this a marketing landing page first. The product should open into
the usable graph/research experience.

### Phase 3: Graph Export

Create a script like:

```text
scripts/export_public_demo.py
```

It should export:

- nodes
- edges
- type counts
- selected result summaries
- curated example paths

Output:

```text
dashboard/public/demo_graph.json
dashboard/public/demo_results.json
dashboard/public/demo_examples.json
```

For the static demo, the frontend can fetch these JSON files directly.

For the AuraDB demo, use the export as backup/fallback content.

### Phase 4: Deploy

Free deployment preference:

1. Static JSON demo on Netlify/Vercel/GitHub Pages/Hugging Face Spaces.
2. Read-only FastAPI + AuraDB Free on Render if a live backend is needed.

Do not deploy Ollama/Qwen3 to free hosting.

## Safety Boundaries

Public demo should frame attack paths defensively:

- "This shows how systems reason about risk."
- "This is not an exploit generator."
- "No real target scanning."
- "No instructions for unauthorized access."

Implementation rules:

- No public write endpoints.
- No arbitrary target input.
- No shell execution.
- No live external crawling from public requests.
- No live red-agent generation from public requests.
- No secrets in frontend.
- Keep CORS narrow once a domain exists.
- Add basic request limits if any backend is public.

## Monetization Path

Free hosted demo is not the business. It is proof.

Likely product ladder:

1. Public ARGUS Lab demo: free, read-only, credibility builder.
2. Private alpha: user uploads limited asset/CVE lists, ARGUS returns graph
   risk maps and uncertainty reports.
3. Research/evaluation workbench: compare security agents and graph reasoning.
4. Paid SaaS later: authenticated teams, persistent projects, audit logs,
   integrations, safe simulation workflows, billing.

Best initial buyers/users:

- Security researchers
- Red-team labs
- Cyber education teams
- AI safety/security evaluation teams
- Early security teams evaluating agentic workflows

## Near-Term Repository Tasks

1. Clean README contradictions:
   - Remove Groq as current setup.
   - State all current inference is local via Ollama.
   - Reframe status as v0 research prototype, not Phase 1 only.

2. Add public-safe dashboard mode:
   - Static JSON fallback or read-only AuraDB mode.
   - Search endpoint or frontend search.
   - Results/examples panels.

3. Add graph export script:
   - Export curated demo graph and result summaries.

4. Add deployment docs:
   - `DEPLOY_FREE.md`
   - Include static deployment and Render + AuraDB deployment.

5. Keep agent execution local:
   - Public hosting is for exploration, not autonomous cyber operations.

## One-Sentence Strategy

Make ARGUS public as a safe, read-only cyber knowledge graph demo first; use it
to earn trust, feedback, and credibility before trying to host the expensive and
sensitive agent system.
