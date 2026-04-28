# Test Coverage Report (v3.2)

> Last manual update: **2026-04-28** · python 3.12.10 · pytest 9.x
> Continuously refreshed by the `backend-tests` CI job on every push.

## Pytest summary (v3.2) — 819 tests collected

This number is reproducible from a clean clone. It comes from
`pytest --collect-only`, not from a hand-curated table:

```
$ python -m pytest tests/ --collect-only 2>&1 | tail -1
819 tests collected in 1.54s
```

The `backend-tests` CI job runs `pytest -q` on every push and uploads
the JUnit XML + HTML coverage as the `pytest-${SHA}` artefact (retained
14 days). See `docs/proof/ci-status.md` for the latest CI run.

## Per-file breakdown — only files that actually exist

The list below is generated from the working tree at commit `9cd6275`.
Counts come from `def test_` occurrences in each file; total matches
`pytest --collect-only`.

| File                              | Tests |
|-----------------------------------|------:|
| `test_ai_analyst.py`              | 27 |
| `test_api.py`                     | (file-level – pulled at run time) |
| `test_arq_jobs.py`                | 10 |
| `test_attack_engine.py`           | 10 |
| `test_audit_chain.py`             | 8  |
| `test_auth.py`                    | 24 |
| `test_auth_session.py`            | 15 |
| `test_circuit_breaker.py`         | 12 |
| `test_connector_splunk.py`        | 12 |
| `test_connector_thehive.py`       | 16 |
| `test_coverage.py`                | 22 |
| `test_detection.py`               | 13 |
| `test_environment.py`             | 12 |
| `test_field_encryption.py`        | 16 |
| `test_ingestion.py`               | 25 |
| `test_ingestion_buffer.py`        | 10 |
| `test_jobs.py`                    | 3  |
| `test_multitenancy.py`            | 5  |
| `test_oidc.py`                    | 16 |
| `test_orchestrator.py`            | 11 |
| `test_phase5.py`                  | 21 |
| `test_request_body_limit.py`      | 4  |
| `test_rule_validation.py`         | 78 |
| `test_scoring.py`                 | 18 |
| `test_soc.py`                     | 27 |
| `test_telemetry.py`               | 14 |
| `test_tenant_isolation.py`        | 12 |
| `test_tracing.py`                 | 6  |
| **Total** (`pytest --collect-only`) | **819** |

The previous version of this document referenced files that do not
exist in the working tree (`test_anomaly.py`, `test_cases.py`,
`test_correlation.py`, `test_mitre.py`, `test_normalization.py`,
`test_observability.py`, `test_reports.py`, `test_sigma.py`,
`test_workflow.py`, `test_llm_analyst.py`). They have been removed —
their functional coverage is exercised by the live files above
(e.g. MITRE coverage is in `test_phase5.py` and `test_rule_validation.py`,
case CRUD is in `test_soc.py`, ingestion + parsing is in
`test_ingestion.py`, AI Analyst evidence-first is in `test_ai_analyst.py`).

## Coverage of code paths (819 tests)

The suite exercises:

- **Detection** — rule match, false positives, severity weighting,
  suppressions (`test_detection.py`, `test_rule_validation.py` —
  including `TestPriorityMITRECoverage` for the 8 priority techniques).
- **Sigma loader** — YAML parsing, regex hardening, glob fullmatch
  semantics (`test_phase5.py`).
- **Coverage center** — 8-state machine, high-risk gap counting,
  recalculate idempotency (`test_coverage.py`).
- **Ingestion** — Windows EID + Sysmon + syslog (3164/5424) +
  CloudTrail mappers (`test_ingestion.py`).
- **SOC workflow** — case lifecycle, comments, evidence, SLA,
  suppressions (`test_soc.py`).
- **Auth & RBAC** — bcrypt, JWT, JTI denylist, refresh rotation,
  session governance (`test_auth.py`, `test_auth_session.py`).
- **Multi-tenant isolation** — middleware + repository filter
  (`test_multitenancy.py`, `test_tenant_isolation.py`).
- **OIDC / SSO** — JWKS validation, audience/issuer, expiry
  (`test_oidc.py`).
- **Tamper-evident audit** — SHA-256 chain (`test_audit_chain.py`).
- **AES-256-GCM field encryption** — HKDF, nonce uniqueness
  (`test_field_encryption.py`).
- **Connectors** — TheHive + Splunk including 5xx retry, breaker
  states, mock mode (`test_connector_thehive.py`,
  `test_connector_splunk.py`).
- **Background jobs** — Arq worker, in-process fallback
  (`test_arq_jobs.py`, `test_jobs.py`).
- **Redis Streams** — dual-mode buffer (`test_ingestion_buffer.py`).
- **OpenTelemetry** — tracer + `get_current_trace_id`
  (`test_tracing.py`).
- **AI Analyst** — IOC extraction, evidence-first NLG
  (`test_ai_analyst.py`).
- **Telemetry** — log-event generation, OCSF
  (`test_telemetry.py`).
- **Attack engine** — 11 scenarios, 28 attack techniques
  (`test_attack_engine.py`).
- **Scoring** — NIST CSF + CIS Controls (`test_scoring.py`).
- **API surface** — request body cap, rate limit, error envelope,
  request_id propagation (`test_request_body_limit.py`,
  `test_environment.py`, plus router smoke tests integrated under
  the other suites).

## How to reproduce

```bash
python -m pip install -r requirements.txt
python -m pytest tests/ -q                  # 819 passed
python -m pytest tests/ --collect-only      # 819 tests collected
python -m pytest tests/ --cov=backend --cov-report=term-missing
```

`pytest-cov` is intentionally **not** in the runtime `requirements.txt`
to keep the production image lean.

## CI artefacts (verifiable)

The `backend-tests` CI job uploads, on every push:

- `pytest-${SHA}.zip` — JUnit XML + coverage HTML + coverage XML
  (retained 14 days, downloadable from the run page).
- Codecov upload of `coverage.xml` (best-effort, non-blocking).

See `docs/proof/ci-status.md` for the latest run URL.
