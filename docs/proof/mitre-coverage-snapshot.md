# MITRE ATT&CK — Coverage Snapshot

> **Generated**: 2026-04-27 (UTC) · raw JSON: [`mitre-coverage-snapshot.json`](./mitre-coverage-snapshot.json)
> **Regenerate**: `python -m benchmarks.mitre_snapshot`

## Headline numbers

| Metric                                  | Value          |
|-----------------------------------------|---------------:|
| Detection rules loaded                  | **46**         |
| Techniques in MITRE Enterprise catalog  | **622**        |
| Tactics in catalog                      | **14**         |
| Rule-mapped techniques                  | **40 (6.43%)** |
| Untested rule-mapped techniques         | 40             |
| Validated by simulation                 | 0              |
| Failed validation (regression!)         | 0              |
| Not covered                             | 582            |
| **High-risk gaps**                      | **293**        |

> **Honesty note**: `validated = 0` because validation requires running the
> end-to-end simulation pipeline AND the rule firing. The current snapshot
> is *static* (rule → technique mapping only). Run `python -m benchmarks.bench_pipeline`
> followed by `python -m benchmarks.mitre_snapshot` after pipeline execution
> to see `validated` move.

## Coverage by tactic

| Tactic                   | Code    | Total | Covered | Cover % | High-risk gaps |
|--------------------------|---------|------:|--------:|--------:|---------------:|
| **Credential Access**    | TA0006  | 59    | 10      | 16.9%   | 0              |
| **Initial Access**       | TA0001  | 19    | 4       | 21.0%   | 15             |
| **Impact**               | TA0040  | 28    | 4       | 14.3%   | 24             |
| **Persistence**          | TA0003  | 107   | 3       | 2.8%    | 104            |
| **Privilege Escalation** | TA0004  | 27    | 3       | 11.1%   | 24             |
| **Execution**            | TA0002  | 38    | 3       | 7.9%    | 35             |
| **Collection**           | TA0009  | 28    | 3       | 10.7%   | 0              |
| **Discovery**            | TA0007  | 40    | 2       | 5.0%    | 0              |
| **Defense Evasion**      | TA0005  | 116   | 2       | 1.7%    | 114            |
| **Lateral Movement**     | TA0008  | 17    | 2       | 11.8%   | 0              |
| **Exfiltration**         | TA0010  | 19    | 2       | 10.5%   | 17             |
| **Command and Control**  | TA0011  | 36    | 2       | 5.6%    | 34             |
| **Reconnaissance**       | TA0043  | 43    | 0       | 0.0%    | 0              |
| **Resource Development** | TA0042  | 45    | 0       | 0.0%    | 0              |

## Reading this honestly

This is the **conservative** view a CISO actually wants:

- **6.43%** is the right number for "what fraction of MITRE Enterprise can we
  even *attempt* to detect today" — not "what we claim to detect".
- The biggest gaps are **Defense Evasion (114 high-risk)**, **Persistence (104)**
  and **Execution (35)**. These are the techniques an actual adversary will
  reach for *after* gaining initial access — closing them is the next clear
  detection-engineering goal.
- Tactics like **Reconnaissance** and **Resource Development** are 0% covered
  because they happen *before* an adversary touches our perimeter — most
  enterprise SOCs accept this gap and shift it to the threat-intel function.

## Backlog impact

This snapshot directly feeds two items in
[`docs/IMPROVEMENTS.md`](../IMPROVEMENTS.md):

- **Tier S #4 — Detection-as-Code GitOps**: every PR will display its delta
  against this baseline.
- **Tier A #6 — STIX/TAXII publishing**: our detection set becomes shareable.

## Reproduction

```bash
python -m benchmarks.mitre_snapshot
# Output: docs/proof/mitre-coverage-snapshot.json
```

Re-run after every detection rule added to keep this file honest.
