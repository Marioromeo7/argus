#!/usr/bin/env python
"""Direct R2.3 runner - cycles 81-100."""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Force output to file
outfile = open("results/r2_3_direct.log", "w", 1)  # Line buffered
def log(msg):
    outfile.write(msg + "\n")
    outfile.flush()
    print(msg, flush=True)

log("[START] R2.3 direct runner")

# Load checkpoint
checkpoint_file = "results/coevolution_50.json"
with open(checkpoint_file) as f:
    data = json.load(f)

cycles_done = len(data['attack_confs'])
log(f"[CHECKPOINT] Loaded: {cycles_done} cycles completed")
log(f"[TARGET] Running cycles {cycles_done+1} to 100", flush=True)

# Import after checkpoint loaded
log("[IMPORT] Neo4j...", flush=True)
from graph.retrieval import get_driver
log("[IMPORT] Reflexion...", flush=True)
from memory.reflexion import run_full_cycle
log("[IMPORT] Done", flush=True)

# Connect to Neo4j
log("[CONNECT] Neo4j...", flush=True)
driver = get_driver()
log("[CONNECT] OK", flush=True)

# Run remaining cycles
log(f"\n  {'Cycle':<7} {'Atk':>6} {'Mit':>6} {'Memories':>10}")
log(f"  {'-'*35}", flush=True)

try:
    for i in range(cycles_done, 100):
        cycle_num = i + 1
        result = run_full_cycle(driver)

        data['attack_confs'].append(result['attack_confidence'])
        data['mit_effs'].append(result['mitigation_effectiveness'])
        data['memory_counts'].append(result['total_memories'])
        data['cycles_completed'] = cycle_num

        log(f"  {cycle_num:<7} {result['attack_confidence']:>6.2f} {result['mitigation_effectiveness']:>6.2f} {result['total_memories']:>10}", flush=True)

        if cycle_num % 10 == 0:
            with open(checkpoint_file, 'w') as f:
                json.dump(data, f, indent=2)
            log(f"  [CHECKPOINT] Saved at cycle {cycle_num}", flush=True)

    # Final save
    with open(checkpoint_file, 'w') as f:
        json.dump(data, f, indent=2)
    log(f"\n[COMPLETE] Finished all 100 cycles", flush=True)

finally:
    driver.close()
