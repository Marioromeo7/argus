#!/usr/bin/env python
"""R2.3: Run cycles 81-100 from checkpoint."""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Direct file logging
L = open("results/r2_3_100.log", "w", 1)
def log(m): L.write(m+"\n"); L.flush()

log("[1] START")

# Load checkpoint
log("[2] Loading checkpoint...")
with open("results/coevolution_50.json") as f:
    data = json.load(f)
start = len(data['attack_confs'])
log(f"[3] Checkpoint: {start} cycles done. Running {start+1}-100")

# Import
log("[4] Importing...")
from graph.retrieval import get_driver
from memory.reflexion import run_full_cycle
log("[5] Imports OK")

# Connect
log("[6] Connecting Neo4j...")
driver = get_driver()
log("[7] Connected")

# Run cycles
log(f"\n  {'Cycle':<7} {'Atk':>6} {'Mit':>6} {'Mem':>8}")
log(f"  {'-'*33}")

try:
    for i in range(start, 100):
        cycle = i + 1
        result = run_full_cycle(driver)
        c = result['cycle']

        data['attack_confs'].append(c['attack_confidence'])
        data['mit_effs'].append(c['mitigation_effectiveness'])
        data['memory_counts'].append(len(c.get('memories', [])))
        data['cycles_completed'] = cycle

        log(f"  {cycle:<7} {c['attack_confidence']:>6.2f} {c['mitigation_effectiveness']:>6.2f} {len(c.get('memories', [])):>8}")

        if cycle % 10 == 0:
            with open("results/coevolution_50.json", 'w') as f:
                json.dump(data, f, indent=2)
            log(f"  [CP] Saved cycle {cycle}")

    # Final save
    with open("results/coevolution_50.json", 'w') as f:
        json.dump(data, f, indent=2)
    log(f"\n[DONE] All 100 cycles complete")

except Exception as e:
    log(f"[ERROR] {e}")
    import traceback
    log(traceback.format_exc())
finally:
    driver.close()
    L.close()
