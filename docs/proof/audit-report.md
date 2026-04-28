# CyberTwin SOC — Audit Report (HISTORICAL — superseded)

> **This file has been superseded by [`audit-report-v3.2.md`](audit-report-v3.2.md).**
>
> Every "TODO", "MEDIUM", or "LOW" item that previously lived here has been
> addressed by the v3.2 Enterprise Readiness work and is now demonstrated
> by a dedicated proof artifact. The list below maps each historical
> concern to its current proof file:

| Historical concern (v3.1) | Status (v3.2) | Proof |
|---|---|---|
| Token revocation (no denylist) | ✅ JTI denylist + refresh rotation in Redis | [`auth-session-validation.md`](auth-session-validation.md) |
| SQLite-only (no PostgreSQL) | ✅ SQLAlchemy ORM + Alembic + CI smoke against PG 16 | [`postgres-migration-report.md`](postgres-migration-report.md) |
| CORS allows `*` methods/headers | ✅ Strict allowlist in `backend/api/main.py` | [`audit-report-v3.2.md`](audit-report-v3.2.md) |
| Frontend nginx runs as root | ✅ `nginx-unprivileged:1.27-alpine` on port 8080 | [`docker-validation.md`](docker-validation.md) |
| No background job queue | ✅ Arq worker + Redis | [`arq-worker-validation.md`](arq-worker-validation.md) |
| No SSO / OIDC | ✅ OIDC/SSO via Authlib (mock-tested) | [`oidc-sso-validation.md`](oidc-sso-validation.md) |
| Audit log not tamper-evident | ✅ SHA-256 chained integrity hash | [`audit-chain-validation.md`](audit-chain-validation.md) |
| No multi-tenancy isolation | ✅ JWT-bound tenant_id + middleware + repository filter | [`multitenancy-isolation-report.md`](multitenancy-isolation-report.md) |
| No field-level encryption | ✅ AES-256-GCM with per-tenant HKDF keys | [`encryption-validation.md`](encryption-validation.md) |
| Connectors are stubs | ✅ TheHive + Splunk production-grade with retry/breaker | `tests/test_connector_thehive.py`, `tests/test_connector_splunk.py` |
| No distributed tracing | ✅ OpenTelemetry (FastAPI + SQLAlchemy + Redis) | [`opentelemetry-validation.md`](opentelemetry-validation.md) |
| No tenant-scoped rate limiting | ✅ `key_func` uses `{tenant_id}:{user}` | [`audit-report-v3.2.md`](audit-report-v3.2.md) |
| Security gates non-blocking | ✅ pip-audit, npm audit (high+), gitleaks all blocking | [`security-scan-summary.md`](security-scan-summary.md) |
| Database has no indexes | ✅ tenant_id-covering indexes on every multi-tenant table | [`database-indexing-report.md`](database-indexing-report.md) |

## How to read the v3.2 audit

Start with [`audit-report-v3.2.md`](audit-report-v3.2.md). It contains:

- a one-page validation matrix (one row per claim → one proof file)
- the v3.1 → v3.2 closure table
- the residual roadmap items that are honestly still open

The original v3.1 baseline (commit `42863b7`) is preserved in git history
and can be inspected via:

```bash
git show 42863b7:docs/proof/audit-report.md
```

---

**Date this redirect was created**: 2026-04-28
**Replacement file**: [`audit-report-v3.2.md`](audit-report-v3.2.md)
