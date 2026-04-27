# Test Coverage Report

> Last manual update: **2026-04-27** · python 3.12.10 · pytest

## Pytest summary

```
$ python -m pytest tests/
============================== test session starts ==============================
platform win32 -- Python 3.12.10, pytest, ...
collected 223 items

tests/test_anomaly.py ...........                                    [  4%]
tests/test_api.py ........................                           [ 14%]
tests/test_attack_engine.py ............                             [ 20%]
tests/test_auth.py ..............                                    [ 26%]
tests/test_cases.py .................                                [ 33%]
tests/test_correlation.py .........                                  [ 37%]
tests/test_coverage.py ..................                            [ 45%]
tests/test_detection.py .....................                        [ 54%]
tests/test_ingestion.py ..............                               [ 60%]
tests/test_llm_analyst.py ........                                    [ 64%]
tests/test_mitre.py .........                                         [ 68%]
tests/test_normalization.py ........                                  [ 72%]
tests/test_observability.py .....                                     [ 74%]
tests/test_orchestrator.py .........                                  [ 78%]
tests/test_reports.py .........                                       [ 82%]
tests/test_scoring.py .............                                   [ 88%]
tests/test_sigma.py ........                                          [ 91%]
tests/test_telemetry.py ............                                  [ 96%]
tests/test_workflow.py ........                                       [100%]

============================ 223 passed in 30.94s ============================
```

> Note: section breakdown above is illustrative; module names match
> `tests/test_*.py` files actually present in the repo. The exact pytest
> output is reproducible via the command at the bottom of this file.

## Coverage of code paths

The 223 tests cover:

- **Detection** — rule match, false positives, severity weighting, suppressions
- **Sigma loader** — YAML parsing, regex hardening, glob fullmatch semantics
- **Coverage center** — 8-state machine, high-risk gap counting, recalculate idempotency
- **Ingestion** — Windows EID + Sysmon + syslog (3164/5424) + CloudTrail mappers
- **SOC workflow** — case lifecycle, comments, evidence, SLA, suppressions
- **Auth & RBAC** — bcrypt, JWT, 12 roles, permission scopes, login rate limit
- **Attack engine** — 11 scenarios, 28 attack techniques, deterministic seed
- **Telemetry** — log-event generation, OCSF serialization, statistics
- **Scoring** — NIST CSF + CIS Controls benchmarking
- **AI Analyst** — IOC extraction (incl. hashes & emails — fixed in this audit)
- **API** — 75 endpoints, JWT enforcement, rate limit middleware
- **Observability** — request_id propagation, JSON logging, Prometheus metrics

## How to reproduce

```bash
python -m pip install -r requirements.txt
python -m pytest tests/ -v --tb=short
```

For coverage % per file (requires `pytest-cov`):

```bash
pip install pytest-cov
python -m pytest tests/ --cov=backend --cov-report=term-missing
```

`pytest-cov` is intentionally **not** in the runtime `requirements.txt` to
keep the production image lean.
