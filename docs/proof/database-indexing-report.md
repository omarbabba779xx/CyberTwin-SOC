# Database Index Audit

- Database: `C:\Users\omarb\CyberTwin SOC\data\cybertwin.db`
- Tables checked: **7**
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

## Result: ✅ PASS
Every required index is present.