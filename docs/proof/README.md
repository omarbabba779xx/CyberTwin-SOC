# Validation Evidence

This folder contains **machine-generated proof artefacts** for everything the
README claims. Each file is reproducible from a clean clone in a single
command.

## Authoritative entry point

| Document | Purpose |
|---|---|
| [`audit-report-v3.2.md`](audit-report-v3.2.md) | **Single-source-of-truth audit for v3.2.** Maps every README claim to its proof artefact and lists residual roadmap items. |
| [`audit-report.md`](audit-report.md) | Historical (v3.1) audit, now a redirect to v3.2. |

## Per-feature proofs (v3.2)

| File | What it proves | How to regenerate |
|---|---|---|
| `auth-session-validation.md` | JWT jti, denylist, refresh-token rotation, revoke-all, session cap | `pytest tests/test_auth_session.py -v` |
| `oidc-sso-validation.md` | OIDC issuer + audience + group-mapping + expiry | `pytest tests/test_oidc.py -v` |
| `multitenancy-isolation-report.md` | TenantScopeMiddleware + repository filter | `pytest tests/test_tenant_isolation.py -v` |
| `audit-chain-validation.md` | SHA-256 chained audit trail + tamper detection | `pytest tests/test_audit_chain.py -v` |
| `encryption-validation.md` | AES-256-GCM + per-tenant HKDF keys | `pytest tests/test_field_encryption.py -v` |
| `circuit-breaker-validation.md` | OPEN / HALF_OPEN / CLOSED transitions | `pytest tests/test_circuit_breaker.py -v` |
| `arq-worker-validation.md` | Task registration, lifecycle, in-process fallback | `pytest tests/test_arq_jobs.py -v` |
| `redis-streams-validation.md` | Dual-mode buffer (Redis Streams ↔ deque) | `pytest tests/test_ingestion_buffer.py -v` |
| `opentelemetry-validation.md` | OTel opt-in + `get_current_trace_id` | `pytest tests/test_tracing.py -v` |
| `connectors-validation.md` | TheHive + Splunk production-grade with retry & breaker | `pytest tests/test_connector_thehive.py tests/test_connector_splunk.py -v` |

## Cross-cutting proofs

| File | What it proves | How to regenerate |
|---|---|---|
| `ci-status.md` | CI pipeline state on `master` | `gh run list --workflow ci.yml` |
| `coverage-report.md` | Backend test results & code coverage | `pytest tests/ --cov=backend` |
| `frontend-tests-report.md` | Vitest results for the React UI | `cd frontend && npm test` |
| `postgres-migration-report.md` | Alembic forward + rollback + index coverage | `alembic upgrade head && alembic downgrade base && alembic upgrade head` |
| `database-indexing-report.md` | Tenant_id-covering indexes on every multi-tenant table | (validated by the `postgres-migration` CI job) |
| `mitre-coverage-snapshot.md` | Rule → ATT&CK technique mapping today | `python -m benchmarks.mitre_snapshot` |
| `benchmark-results.md` | Pipeline performance, EPS, latency, k6 / Locust / Docker | see commands inside the file |
| `security-scan-summary.md` | pip-audit / Bandit / Semgrep / Gitleaks / Trivy / Checkov / kubeconform | see commands inside the file |
| `docker-validation.md` | `docker compose config` + smoke run + CI gate description | see commands inside the file |

## Honesty rule

If the README claims it, this folder must back it up. If a number changes
substantially, both the README and the relevant file in `docs/proof/` must
be updated in the **same commit**.
