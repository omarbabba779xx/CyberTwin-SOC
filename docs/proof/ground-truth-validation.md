# Ground Truth Dataset — SOC Detection Validation

> Created: **2026-04-28** · Reproduce: `pytest tests/test_ground_truth.py -v`

## Purpose

The `datasets/ground_truth/` manifests provide **deterministic synthetic
logs** paired with:

- **`expected_rule_ids`** — minimum rules that must alert (recall gate).
- **`forbidden_rule_ids`** — rules that must **never** alert on those
  events (explicit false-positive guardrail).
- **`max_alerts_allowed`** — benign scenarios only; caps noise when the
  expected set is intentionally empty.

This is complementary to MITRE technique-level behavioural tests in
[`mitre-rule-validation.md`](mitre-rule-validation.md): ground truth
measures **alert production** from the full **DetectionEngine**, not
individual rule `condition()` functions in isolation.

## Scenarios shipped in v3.2

| ID | Directory | MITRE anchor(s) | Expected alert rules |
|----|-----------|-------------------|----------------------|
| `ransomware_small` | `ransomware_small/` | T1486 | RULE-044 |
| `lateral_movement` | `lateral_movement/` | T1021.002 | RULE-019 |
| `defense_evasion_logs` | `defense_evasion_logs/` | T1070.004 | RULE-026 |
| `cloud_identity` | `cloud_identity/` | T1552.005 | RULE-043 |
| `benign_baseline` | `benign_baseline/` | *(none)* | *(empty — max 2 stray alerts)* |

## Metrics

CLI summary (attack scenarios only for micro precision / recall):

```bash
python benchmarks/evaluate_ground_truth.py | tail -5
```

| Metric | Meaning |
|--------|---------|
| **Micro precision** | Sum of TP rules / (TP + FP) across manifests with `expected_rule_ids` |
| **Micro recall** | Sum of TP rules / (TP + FN) across the same |

Benign scenarios are excluded from micro-averaging — they use a
presence / noise cap instead.

## Reproduction

```bash
pytest tests/test_ground_truth.py -v
python benchmarks/evaluate_ground_truth.py
```

## Roadmap

Future work (not yet in this release):

- Curated **false-positive** fixtures with explicit `forbidden_rule_ids`.
- Larger **multi-host** replay files (10k+ events) for scale validation.
- Automated **drift detection** when semantic rule logic changes.
