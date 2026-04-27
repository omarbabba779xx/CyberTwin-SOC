# 📋 Validation Evidence

This folder contains **machine-generated proof artefacts** for everything the
README claims. Each file is reproducible from a clean clone in a single
command.

| File                                    | What it proves                          | How to regenerate                          |
|-----------------------------------------|-----------------------------------------|--------------------------------------------|
| `ci-status.md`                          | CI pipeline state on `master`           | `gh run list --workflow ci.yml`           |
| `coverage-report.md`                    | Backend test results & code coverage    | `pytest tests/ --cov=backend`             |
| `mitre-coverage-snapshot.json`          | Rule → ATT&CK technique mapping today   | `python -m benchmarks.mitre_snapshot`     |
| `mitre-coverage-snapshot.md`            | Human-readable view of the JSON above   | (copy from JSON, manually curated)        |
| `benchmark-results.md`                  | Pipeline performance, EPS, latency      | `python -m benchmarks.bench_pipeline`     |
| `security-scan-summary.md`              | Bandit / pip-audit / Semgrep / Trivy    | see commands inside the file              |
| `docker-validation.md`                  | `docker compose config` + smoke run     | see commands inside the file              |

## Honesty rule

If the README claims it, this folder must back it up. If a number changes
substantially, both the README and the relevant file in `docs/proof/` must
be updated in the same commit.
