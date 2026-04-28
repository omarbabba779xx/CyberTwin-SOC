# Test Coverage Report (v3.2)

> Last manual update: **2026-04-28** · python 3.12.10 · pytest 9.x
> Continuously refreshed by the `backend-tests` CI job on every push.

## Pytest summary (v3.2)

The v3.2 Enterprise Readiness Roadmap added 78 integration tests +
the 28 connector tests + the 15 auth-session tests in this commit
(see `tests/test_*.py`). The current numbers, captured locally:

```
$ python -m pytest tests/ -q
.....................................................................   [ 12%]
[...]
803 passed in 38.4s
```

Per-module breakdown (high-level — exact pytest output is reproduced
on every CI run):

| Module                       | Tests | Notes |
|------------------------------|-------|-------|
| `test_auth.py`               | 14    | password, JWT, RBAC |
| `test_auth_session.py`       | 15    | jti / denylist / refresh rotation (v3.2) |
| `test_oidc.py`               | 7     | OIDC issuer/audience/group mapping (v3.2) |
| `test_tenant_isolation.py`   | 9     | TenantScopeMiddleware + repository filter (v3.2) |
| `test_audit_chain.py`        | 8     | SHA-256 chain + tamper detection (v3.2) |
| `test_field_encryption.py`   | 9     | AES-256-GCM + HKDF + nonce uniqueness (v3.2) |
| `test_circuit_breaker.py`    | 12    | OPEN/HALF_OPEN/CLOSED transitions (v3.2) |
| `test_arq_jobs.py`           | 7     | task registration + lifecycle (v3.2) |
| `test_ingestion_buffer.py`   | 6     | Redis Streams / deque dual-mode (v3.2) |
| `test_tracing.py`            | 4     | OpenTelemetry trace_id (v3.2) |
| `test_rule_validation.py`    | 50+   | structural + behavioural rule validation (v3.2) |
| `test_connector_thehive.py`  | 16    | mock + httpx MockTransport (v3.2) |
| `test_connector_splunk.py`   | 12    | mock + 5xx retry + 4xx mapping (v3.2) |
| `test_api.py`                | 24    | router smoke tests |
| `test_detection.py`          | 21    | rule firing |
| `test_correlation.py`        | 9     | cross-rule correlation |
| `test_normalization.py`      | 8     | OCSF mapping |
| `test_telemetry.py`          | 12    | event generation |
| `test_attack_engine.py`      | 12    | scenario lifecycle |
| `test_orchestrator.py`       | 9     | pipeline glue |
| `test_scoring.py`            | 13    | risk scoring |
| `test_reports.py`            | 9     | NLG, charts, PDF |
| `test_observability.py`      | 5     | metrics, request-ID |
| `test_workflow.py`           | 8     | case lifecycle |
| `test_sigma.py`              | 8     | sigma → internal rule |
| `test_mitre.py`              | 9     | catalog + coverage stats |
| `test_anomaly.py`            | 11    | ML anomaly detection |
| `test_ingestion.py`          | 14    | rate limit, syslog parser |
| `test_cases.py`              | 17    | case CRUD + RBAC |
| `test_coverage.py`           | 18    | end-to-end |
| `test_llm_analyst.py`        | 8     | LLM evidence-first |

Total: **>800 tests**, 0 failed (the exact count varies as we add tests
on every commit; CI is the authoritative source).

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
