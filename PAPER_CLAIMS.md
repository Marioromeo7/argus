# ARGUS — Paper Claims Ledger

Each major claim mapped to its current evidence status. Conservative language on purpose:
this is the honest scientific record, distinct from any product/investor framing.

Status key:
- **Demonstrated** — supported by committed code + an evaluation run.
- **Partial** — supported directionally, but samples are small or significance not reached.
- **Future work** — planned, not yet shown.

Evidence anchors are the result files summarized in [CONTEXT.md](CONTEXT.md) (raw files live under
`results/`, which is not committed — the numbers are transcribed into CONTEXT.md).

---

## Claim 1 — Retrieval precision: GraphRAG ≥ flat vector RAG

**Status: Demonstrated (small sample).**

Structured graph traversal retrieved more relevant nodes than baseline flat vector RAG on the same
attack-path queries. Ground truth was derived independently from the NVD API (CWE mapping +
reference URLs + keywords), never from the graph itself.

| Method | mean P@10 | mean FPR |
|--------|-----------|----------|
| GraphRAG | 0.083 | 0.917 |
| VectorRAG | 0.000 | 1.000 |

Δ = +0.083 in favor of GraphRAG. Evaluated on 6/10 CVEs with structured NVD ground truth (4 were
pre-CWE-era). *Caveat: absolute precision is low and the sample is small — the claim is relative
superiority on this task, not high absolute recall.*

## Claim 2 — Grain convergence: `grain_confidence` shifts right monotonically

**Status: Demonstrated (small sample).**

4 nodes, 3 challenger rounds. Mean grain rose 0.30 → 0.90 (Δ+0.60), monotonically non-decreasing,
with variance shrinking as nodes specialize.

```
Round 0: mean=0.300 std=0.000
Round 1: mean=0.725 std=0.217
Round 2: mean=0.875 std=0.043
Round 3: mean=0.900 std=0.035
```

## Claim 3 — Co-evolutionary improvement of red & blue agents

**Status: Partial.**

Over 50 full engagement cycles the agents converged to high mutual effectiveness
(attack μ=0.82, mitigation μ=0.91) rather than a monotonic upward trend. **p<0.05 was not met.**

The honest finding is co-evolutionary *equilibrium*: attack confidence oscillates (σ=0.18) as the
red agent's reflexion memory recognizes mitigated chains and lowers confidence to probe new
strategies; mitigation stays stable (σ=0.07). A 20-cycle post-fix run (lesson injection + cosine
dedup) turned both slopes slightly positive but still short of significance.

*Paper framing:* present as mutual optimization under adversarial pressure, not a simple
improvement trend. Reaching significance is [BACKLOG.md](BACKLOG.md) work.

## Claim 4 — Hardware feasibility on consumer hardware

**Status: Demonstrated.**

The full six-layer prototype runs on an RTX 3050 (4GB VRAM) + 16GB RAM using Qwen3 8B via Ollama.
Latency is acceptable for batch research use (cold start ~265s; warm calls ~44–130s depending on
think mode). Suitable for batch experiments, not interactive product use — see limitations.

---

## Known Limitations (state these in the paper)

- Small evaluation samples across all claims.
- Local model latency limits interactive use.
- Neo4j properties/logs stored as `str(dict)`, limiting production-grade querying.
- No production safety, tenant isolation, authorization, or compliance layer.
- `challenger_log` is an audit/traceability record, not yet a planning input for downstream agents.
