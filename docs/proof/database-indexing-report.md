# Database Index Audit

> **Scope**: SQLite legacy audit (7 tables). For the full PostgreSQL schema
> (10 ORM tables, 19 composite indexes, `tenant_id` coverage), see the
> `postgres-migration` CI job which validates forward + rollback + index
> completeness on every push.

- Database: SQLite (`data/cybertwin.db`) — legacy path
- Tables checked: **7** (pre-v3.1.0 schema)
- Missing indexes: **0**

## `simulation_runs`

**Existing indexes**
- `ix_runs_risk_level` on (risk_level)
- `ix_runs_timestamp` on (timestamp)
- `ix_runs_scenario_id_id` on (scenario_id, id)

**Expected coverage**
- ✅ `scenario_id_filter` → (scenario_id)
- ✅ `timestamp_window` → (timestamp)
- ✅ `risk_level_filter` → (risk_level)

## `audit_log`

**Existing indexes**
- `ix_audit_status` on (status) [PARTIAL]
- `ix_audit_action` on (action)
- `ix_audit_username_id` on (username, id)
- `ix_audit_timestamp` on (timestamp)

**Expected coverage**
- ✅ `timestamp_window` → (timestamp)
- ✅ `username_filter` → (username)
- ✅ `action_filter` → (action)
- ✅ `status_filter` → (status)

## `alert_feedback`

**Existing indexes**
- `ix_feedback_alert` on (alert_id)
- `ix_feedback_rule` on (rule_id)

**Expected coverage**
- ✅ `rule_id_filter` → (rule_id)
- ✅ `alert_id_filter` → (alert_id)

## `soc_cases`

**Existing indexes**
- `ix_cases_assignee` on (assignee)
- `ix_cases_severity` on (severity)
- `ix_cases_status` on (status)
- `sqlite_autoindex_soc_cases_1` on (case_id) [UNIQUE]

**Expected coverage**
- ✅ `status_filter` → (status)
- ✅ `severity_filter` → (severity)
- ✅ `assignee_filter` → (assignee)

## `case_comments`

**Existing indexes**
- `ix_comments_case` on (case_id)

**Expected coverage**
- ✅ `case_id_filter` → (case_id)

## `case_evidence`

**Existing indexes**
- `ix_evidence_case` on (case_id)

**Expected coverage**
- ✅ `case_id_filter` → (case_id)

## `suppressions`

**Existing indexes**
- `ix_suppressions_expires` on (expires_at)
- `ix_suppressions_scope` on (scope, active)

**Expected coverage**
- ✅ `scope_active_filter` → (scope)
- ✅ `expires_at_filter` → (expires_at)

## Result: PASS
Every required index is present.

---

## v3.2 — PostgreSQL schema (the production target)

The SQLite report above is the legacy/fallback path. The production
schema is PostgreSQL, validated on every push by the `postgres-migration`
CI job in `.github/workflows/ci.yml`. That job:

1. spins up `postgres:16-alpine` as a service container,
2. runs `alembic upgrade head` (forward migration),
3. introspects the resulting schema and asserts that **every multi-tenant
   table has a `tenant_id`-covering index**,
4. runs `alembic downgrade base` then re-applies forward (idempotency check).

Tables validated by the v3.2 schema:

| Table | tenant_id index? | Other indexes |
|---|---|---|
| `simulation_runs` | ✅ | timestamp, scenario_id+id, risk_level |
| `security_events` | ✅ | timestamp, source_type |
| `alerts` | ✅ | rule_id, severity, timestamp |
| `soc_cases` | ✅ | status, severity, assignee |
| `case_comments` | ✅ | case_id |
| `case_evidence` | ✅ | case_id |
| `alert_feedback` | ✅ | alert_id, rule_id |
| `suppressions` | ✅ | scope+active, expires_at |
| `audit_log_v2` | ✅ | timestamp, username+id, action, status (partial), `integrity_hash` (UNIQUE) |
| `tenant_roles` | ✅ | (tenant_id, role_name) |

The CI job script that performs this introspection lives in
`.github/workflows/ci.yml` under `postgres-migration › Verify tenant_id
index coverage`.