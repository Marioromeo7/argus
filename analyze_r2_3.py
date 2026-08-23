import json
import numpy as np
from scipy import stats

with open('results/coevolution_50.json') as f:
    data = json.load(f)

attack = np.array(data['attack_confs'])
mitigation = np.array(data['mit_effs'])

print("R2.3 PARTIAL RESULTS — Extended Run (82 Cycles)")
print("=" * 60)
print(f"\nAttack Confidence (Red Agent):")
print(f"  Cycles completed: {len(attack)}")
print(f"  Mean: {attack.mean():.3f} ± {attack.std():.3f}")
print(f"  Range: [{attack.min():.2f}, {attack.max():.2f}]")

x = np.arange(len(attack))
slope_a, intercept_a, r_a, p_a, se_a = stats.linregress(x, attack)
print(f"  Slope: +{slope_a:.5f}/cycle")
print(f"  R²: {r_a**2:.3f}")
sig_a = "[SIGNIFICANT p<0.05]" if p_a < 0.05 else "[NOT significant p>=0.05]"
print(f"  p-value: {p_a:.4f} {sig_a}")

print(f"\nMitigation Effectiveness (Blue Agent):")
print(f"  Cycles completed: {len(mitigation)}")
print(f"  Mean: {mitigation.mean():.3f} ± {mitigation.std():.3f}")
print(f"  Range: [{mitigation.min():.2f}, {mitigation.max():.2f}]")

slope_m, intercept_m, r_m, p_m, se_m = stats.linregress(x, mitigation)
print(f"  Slope: +{slope_m:.5f}/cycle")
print(f"  R²: {r_m**2:.3f}")
sig_m = "[SIGNIFICANT p<0.05]" if p_m < 0.05 else "[NOT significant p>=0.05]"
print(f"  p-value: {p_m:.4f} {sig_m}")

print(f"\nEpisodic Memories: {data.get('memory_counts', 'N/A')}")
print("\n[WARNING] INCOMPLETE: Run stopped at cycle 82 (target was 100)")
print("  Cause: Cloudflare 524 timeout on cycle 83")
print("  Coordinator exhausted all 5 retries")
