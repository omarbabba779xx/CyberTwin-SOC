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
| `test-report-v3.2.md` | **Backend (806) + frontend (10) + coverage (69.8 %)** | `pytest tests/ --cov=backend` + `cd frontend && npx vitest --run` |
| `coverage-report.md` | Per-module test breakdown | `pytest tests/ --cov=backend --cov-report=term-missing` |
| `frontend-tests-report.md` | Vitest results for the React UI | `cd frontend && npm test` |
| `frontend-lighthouse-report.md` | Frontend perf / a11y / best-practices / SEO | CI artefact `lighthouse-${SHA}` |
| `postgres-migration-report.md` | Alembic forward + rollback + index coverage | `alembic upgrade head && alembic downgrade base && alembic upgrade head` |
| `database-indexing-report.md` | Tenant_id-covering indexes on every multi-tenant table | (validated by the `postgres-migration` CI job) |
| `mitre-coverage-snapshot.md` | Rule → ATT&CK technique mapping today | `python -m benchmarks.mitre_snapshot` |
| `mitre-rule-validation.md` | **Rule-mapped vs validated split + roadmap** | `pytest tests/test_rule_validation.py -v` |

## Performance proofs

| File | Tool | Reproduce |
|---|---|---|
| `benchmark-results.md` | In-process pipeline (deterministic) | `python -m benchmarks.bench_pipeline` |
| `benchmark-http-k6.md` | k6 — HTTP API p95 | `k6 run benchmarks/k6_api.js …` |
| `benchmark-ingestion-locust.md` | Locust — sustained EPS | `locust -f benchmarks/locust_ingestion.py …` |
| `benchmark-websocket.md` | asyncio + `websockets` lib | `python benchmarks/ws_load.py …` |
| `benchmark-postgres.md` | SQLAlchemy + Postgres 16 | `python benchmarks/postgres_query_latency.py …` |
| `benchmark-docker-startup.md` | docker compose timing harness | `python benchmarks/docker_startup.py …` |

## Security proofs

| File | What it proves | How to regenerate |
|---|---|---|
| `security-scan-summary.md` | pip-audit / Bandit / Semgrep / Gitleaks / Trivy / Checkov / kubeconform — including the explicit blocking vs advisory contract | see commands inside the file |
| `docker-validation.md` | `docker compose config` + smoke run + CI gate description | see commands inside the file |
| `production-deployment.md` | Production hardening guide: required env vars, TLS / reverse-proxy, secret management, NetworkPolicy, `values-secure.yaml` | see commands inside the file |

## Honesty rule

If the README claims it, this folder must back it up. If a number changes
substantially, both the README and the relevant file in `docs/proof/` must
be updated in the **same commit**.
