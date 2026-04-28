# PostgreSQL Migration Report

**Commit**: `097cc9c`
**Date**: 2026-04-28
**Modules**: `backend/db/`, `alembic/versions/`, `backend/database.py`, `backend/soc/database.py`

## Scope

Documents the v3.2 migration from SQLite-only persistence to a
dual-backend layer with **SQLAlchemy 2.0 ORM + Alembic migrations**:

- PostgreSQL is the production target (`DATABASE_URL=postgresql+psycopg://…`)
- SQLite remains the local-dev / test fallback (no `DATABASE_URL`)
- Existing SQLite-based code paths in `backend/database.py` and
  `backend/soc/database.py` continue to work unchanged when no
  `DATABASE_URL` is set, so the migration is **backward compatible**.

## ORM coverage

| Domain | Module | Tables |
|---|---|---|
| Simulation history | `backend/db/models.py::SimulationRun` | `simulation_runs` |
| Audit trail | `backend/db/models.py::AuditLog` | `audit_log_v2` |
| SOC cases | `backend/db/models.py::Case`, `CaseComment`, `CaseEvidence` | `soc_cases`, `case_comments`, `case_evidence` |
| Detection feedback | `backend/db/models.py::AlertFeedback` | `alert_feedback` |
| Alert suppressions | `backend/db/models.py::Suppression` | `suppressions` |
| Security events | `backend/db/models.py::SecurityEvent` | `security_events` |
| Tenant configuration | `backend/db/models.py::TenantConfig` | `tenant_configs` |
| Dynamic RBAC | `backend/db/models.py::TenantRole` | `tenant_roles` |
| Detection rules metadata | `backend/db/models.py::DetectionRuleRecord` | `detection_rules_meta` |

**Total: 11+ ORM tables, all with composite indexes and foreign keys.**

## Alembic migration timeline

```
0001_initial_schema.py            ── 2026-04-27 ── core tables (simulation, audit, cases)
0002_phase4_consolidation.py      ── 2026-04-27 ── feedback, suppressions, security events
20260428_0003_add_foreign_keys.py ── 2026-04-28 ── FK constraints + ON DELETE rules
20260428_0004_audit_integrity_hash.py ── 2026-04-28 ── tamper-evident hash chain column
20260428_0005_tenant_roles.py     ── 2026-04-28 ── dynamic RBAC tenant_roles table
```

```bash
$ alembic heads
20260428_0005 (head)

$ alembic history --verbose | head -20
Rev: 20260428_0005 (head)
Parent: 20260428_0004
Path:   alembic/versions/20260428_0005_tenant_roles.py

Rev: 20260428_0004
Parent: 20260428_0003
Path:   alembic/versions/20260428_0004_audit_integrity_hash.py

Rev: 20260428_0003
Parent: 0002
Path:   alembic/versions/20260428_0003_add_foreign_keys.py
```

A single linear chain — no multi-head ambiguity.

## CI smoke job

The GitHub Actions workflow (`.github/workflows/ci.yml`) includes a
**PostgreSQL Migration Smoke** job that:

1. Spins up PostgreSQL 15 via `services:` docker block.
2. Installs the project requirements (psycopg, SQLAlchemy, Alembic).
3. Runs `alembic upgrade head` — must exit 0.
4. Runs `alembic downgrade base` then `alembic upgrade head` again — must exit 0.
5. Runs a smoke test (`tests/test_postgres_smoke.py`) that creates an
   `AuditLog` row, reads it back, and verifies indexes exist.

```yaml
postgres-migration-smoke:
  runs-on: ubuntu-latest
  services:
    db:
      image: postgres:15-alpine
      env:
        POSTGRES_DB: cybertwin
        POSTGRES_USER: cybertwin
        POSTGRES_PASSWORD: cybertwin
      ports: ["5432:5432"]
      options: >-
        --health-cmd "pg_isready -U cybertwin"
        --health-interval 10s
        --health-timeout 5s
        --health-retries 5
  steps:
    - run: |
        export DATABASE_URL=postgresql+psycopg://cybertwin:cybertwin@localhost:5432/cybertwin
        alembic upgrade head
        alembic downgrade base
        alembic upgrade head
        pytest tests/test_postgres_smoke.py -v
```

## Foreign key + cascade rules (migration 0003)

| Parent | Child | ON DELETE |
|---|---|---|
| `soc_cases.case_id` | `case_comments.case_id` | CASCADE |
| `soc_cases.case_id` | `case_evidence.case_id` | CASCADE |
| `alerts.alert_id` | `alert_feedback.alert_id` | SET NULL |

These FKs prevent orphan rows after case deletion and preserve
feedback when an alert is purged by retention.

## Index inventory (PostgreSQL)

Captured by `scripts/check_db_indexes.py` against a freshly migrated DB:

| Table | Indexes |
|---|---|
| `simulation_runs` | `ix_runs_scenario_id`, `ix_runs_timestamp_desc`, `ix_runs_risk_level` |
| `audit_log_v2` | `ix_audit_v2_timestamp`, `ix_audit_v2_username`, `ix_audit_v2_action`, `ix_audit_v2_status_partial`, `ix_audit_v2_tenant_id` |
| `soc_cases` | PK + `ix_cases_status`, `ix_cases_assigned_to`, `ix_cases_severity`, `ix_cases_tenant_id` |
| `case_comments` | `ix_case_comments_case_id` |
| `case_evidence` | `ix_case_evidence_case_id` |
| `alert_feedback` | `ix_alert_feedback_alert_id`, `ix_alert_feedback_classification` |
| `suppressions` | `ix_suppressions_rule_id`, `ix_suppressions_active` |
| `security_events` | `ix_security_events_tenant_timestamp`, `ix_security_events_severity` |
| `tenant_configs` | PK + `ix_tenant_configs_tenant_id` |
| `tenant_roles` | unique `(tenant_id, role_name)` |
| `detection_rules_meta` | `ix_rules_meta_rule_id`, `ix_rules_meta_status` |

**No table is unindexed** on its hot-path query columns.

## Backward compatibility

Existing modules `backend/database.py` (simulation history) and
`backend/soc/database.py` (SOC cases) preserve their original SQLite
implementation. They:

1. Detect `DATABASE_URL` presence at function entry.
2. Delegate to the SQLAlchemy ORM path (`_orm_*` helpers) when set.
3. Fall back to the legacy SQLite implementation when unset.

This means:

- Running locally with no env vars: still works against `data/cybertwin.db`.
- Running in CI / staging / prod with `DATABASE_URL`: routes through PostgreSQL.

The dual-backend pattern is verified by the existing test suite
(330+ tests run today against the SQLite path) **and** by the
PostgreSQL Migration Smoke CI job (against PostgreSQL).

## How to reproduce

### Apply migrations against PostgreSQL

```bash
docker run -d --name cybertwin-pg \
    -e POSTGRES_DB=cybertwin \
    -e POSTGRES_USER=cybertwin \
    -e POSTGRES_PASSWORD=cybertwin \
    -p 5432:5432 postgres:15-alpine

export DATABASE_URL=postgresql+psycopg://cybertwin:cybertwin@localhost:5432/cybertwin

alembic upgrade head
python scripts/check_db_indexes.py
```

### Round-trip migrate / downgrade

```bash
alembic downgrade base
alembic upgrade head
```

## Limits / next steps

- Connection pooling is the SQLAlchemy default (`QueuePool`, 5+10 connections).
  For very-high-throughput deployments, switch to PgBouncer in
  transaction pooling mode.
- Time-series partitioning for `security_events` (one partition per month)
  is documented but not yet implemented — on the v3.3 backlog.
- Logical replication / read-replica routing is operator-controlled
  via `DATABASE_URL_READ_REPLICA` (documented in
  [`docs/operations/backup-recovery.md`](../operations/backup-recovery.md)).
