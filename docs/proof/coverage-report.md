# Test Coverage Report (v3.2)

> Last manual update: **2026-04-28** · python 3.12.10 · pytest 9.x
> Continuously refreshed by the `backend-tests` CI job on every push.

## Pytest summary (v3.2) — **836** tests collected

This number is the **only** authoritative headline. It includes every
expanded `@pytest.mark.parametrize` case (especially the exhaustive
per-rule matrix inside `tests/test_rule_validation.py`).

```bash
$ python -m pytest tests/ --collect-only -q
836 tests collected
```

### Modules under `tests/`

Twenty-nine `test_*.py` modules, including **`test_ground_truth.py`**
(labelled SOC detection scenarios in `datasets/ground_truth/`),
**`test_rule_validation.py`** (~440 parametrized cases — rules ×
structures), and integration suites for connectors, auth-session,
PostgreSQL-backed paths, ingestion, SOC workflow, tracing, OIDC,
field-level encryption, and request-body limits.

Historical references to phantom files (`test_anomaly.py`, `test_sigma.py`,
etc.) are **invalid** — they never existed on `master`; any MITRE /
Sigma behaviour is exercised through `test_rule_validation.py` and
`test_phase5.py` today.

## Coverage of code paths (836 tests)

The suite exercises:

- **Detection** — rule match, false positives, severity weighting,
  suppressions (`test_detection.py`, `test_rule_validation.py` —
  including `TestPriorityMITRECoverage` for **12 validated techniques**
  plus **`tests/test_ground_truth.py`** against frozen manifests).
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
python -m pytest tests/ -q                  # 836 passed
python -m pytest tests/ --collect-only -q # 836 tests collected
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
