# Ground-truth evaluation sets — CyberTwin SOC

Each subdirectory contains a `manifest.json` describing synthetic events,
expected alerting rule identifiers, and (optionally) rules that **must**
not appear (false-positive guardrails).

## Layout

```
datasets/ground_truth/
  ransomware_small/manifest.json
  lateral_movement/manifest.json
  defense_evasion_logs/manifest.json
  cloud_identity/manifest.json
  benign_baseline/manifest.json
```

## Metrics (per scenario)

Definitions used by `benchmarks/evaluate_ground_truth.py` and
`tests/test_ground_truth.py`:

| Metric     | Formula |
|-----------|---------|
| **Recall**| \|expected ∩ fired\| / \|expected\| *(undefined if expected is empty).* |
| **Precision** | \|expected ∩ fired\| / \|fired\| *(1.0 if fired is empty and expected empty).* |

For `benign_baseline`, expected is ∅ — success means **zero** alerts
(or `max_alerts_allowed` if annotated for noisy lab environments).

## Reproduce

```bash
python benchmarks/evaluate_ground_truth.py
pytest tests/test_ground_truth.py -v
```
