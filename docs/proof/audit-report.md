# CyberTwin SOC — Senior Architect Audit Report (v3.1 baseline — HISTORICAL)

> ⚠️ **This document describes the project state BEFORE the v3.2
> Enterprise Readiness Roadmap (commits prior to `097cc9c`).**
> For the current state, including how every "Remaining Issue" listed
> below has been resolved, see [`audit-report-v3.2.md`](audit-report-v3.2.md).
> This file is retained for historical traceability only.

**Date**: 2026-04-27
**Auditor**: Automated deep-dive + manual code review
**Commit baseline**: `42863b7` (pre-audit)
**Scope**: Security · Performance · Database · CI/CD · Docker/K8s · SOC Logic

---

## Executive Summary

| Domain | Score | Trend |
|---|---|---|
| **Security** | 7.5/10 | ↑ after patches (was 5/10) |
| **Performance** | 7/10 | Ingestion caps + indexes added |
| **Database / Indexing** | 8/10 | ↑ from 4/10 (7 missing → 0 missing) |
| **CI/CD** | 9/10 | 6/6 green, 3 blocking gates |
| **Docker / Kubernetes** | 8/10 | Non-root, securityContext, probes |
| **SOC Logic** | 7/10 | Evidence-first AI, honest coverage |
| **Enterprise Readiness** | 7/10 | Ready for POC; gaps below for GA |

**Risk level**: MEDIUM — no show-stopper for a demo/POC deployment, but
5 HIGH-priority items remain before production GA.

---

## Critical Issues Found & Fixed (This Audit)

### 🔴 FIXED — No database indexes (was HIGH)
- **Files**: `backend/database.py`, `backend/audit.py`
- **Problem**: `simulation_runs` had ZERO indexes. `get_runs_by_scenario()`
  did a sequential scan on every dashboard page load. `audit_log` had no
  indexes on `timestamp`, `username`, or `action`.
- **Fix**: Added 3 indexes on `simulation_runs` (scenario_id+id, timestamp,
  risk_level) and 4 on `audit_log` (timestamp, username+id, action,
  partial status).
- **Validation**: `scripts/check_db_indexes.py` — 7 tables, 0 missing.

### 🔴 FIXED — LLM prompt injection & PII exfiltration (was HIGH)
- **File**: `backend/llm_analyst.py`
- **Problem**: Alert descriptions, scenario names, and threat-actor names
  were interpolated RAW into the Ollama prompt. An attacker pushing a
  crafted log like `"description": "\n\nIgnore previous instructions…"`
  could hijack the LLM. PII (passwords, JWT tokens, AWS keys) in log
  fields would be sent verbatim to Ollama.
- **Fix**: New `_sanitise()` function applied at every interpolation point:
  - 10+ regex-based secret/PII redaction patterns (AWS, JWT, Bearer,
    PEM, passwords, emails, credit cards)
  - Prompt-injection marker detection & neutralisation
  - Per-field 512-char cap + newline collapse
  - Total prompt hard-capped at 32 KB
  - System-message preamble telling the LLM to treat context as DATA.
- **Validation**: Manual test with injected fields → redacted correctly.

### 🔴 FIXED — Ingestion DoS via unbounded payloads (was HIGH)
- **File**: `backend/api/main.py`
- **Problem**: `IngestBatchRequest` capped event count at 5000 but not
  per-event size. 5000 × 100 KB = 500 MB. `IngestSyslogRequest.lines`
  had NO cap at all (unlimited lines of unlimited length).
- **Fix**: Per-event 64 KB cap, syslog 5000 lines × 8 KB cap, explicit
  `_approx_size()` check on every event in a batch.
- **Validation**: `pytest tests/` — 223/223 pass.

### 🔴 FIXED — Zero security headers (was MEDIUM)
- **Files**: `backend/observability/security_headers.py` (new),
  `frontend/nginx.conf`
- **Problem**: No CSP, X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy, Permissions-Policy, or HSTS on any response.
  Clickjacking, MIME-sniffing, and XSS via injected content were possible.
- **Fix**: New `SecurityHeadersMiddleware` (backend) + 8 nginx `add_header`
  directives (frontend). CSP relaxed only on `/docs` and `/redoc`.
  HSTS conditional on `ENV=production` + `x-forwarded-proto: https`.
- **Validation**: `pytest` passes; `server_tokens off` in nginx.

---

## Remaining Issues (Not Yet Fixed)

### 🟡 HIGH — No token revocation / refresh token flow
- **File**: `backend/auth.py`
- JWT tokens are valid until expiry (default 24h). No revocation list,
  no refresh flow. A leaked token stays valid.
- **Recommendation**: Add a Redis-backed JWT denylist checked on every
  `verify_token()` call. Add `/api/auth/refresh` + `/api/auth/logout`.

### 🟡 HIGH — SQLite in production
- **File**: `backend/database.py`
- Current deployment manifests no longer advertise a PostgreSQL runtime,
  because `database.py` still hard-codes SQLite. There is no SQLAlchemy,
  Alembic migration path, or connection pooling yet.
- **Recommendation**: Phase 3 migration — abstract DB behind a repository
  layer, add Alembic, dual-backend (SQLite for demo, PostgreSQL for prod).

### 🟡 MEDIUM — No max request body limit at ASGI layer
- Uvicorn default is ~1 MB but not explicitly configured. A custom
  `--limit-max-body-size` should be set in the Dockerfile CMD.
- **Recommendation**: Add `--limit-max-body-size 16777216` (16 MB) to
  the uvicorn start command.

### 🟡 MEDIUM — CORS allows all methods/headers
- `allow_methods=["*"]` and `allow_headers=["*"]` in the CORS middleware.
- **Recommendation**: Restrict to `GET,POST,PATCH,DELETE,OPTIONS` and
  `Authorization,Content-Type,X-Request-ID`.

### 🟡 MEDIUM — Frontend nginx runs as root
- The official `nginx:1.27-alpine` image binds port 80 as root. With
  K8s `runAsNonRoot: true` in the Helm chart, the pod would crash.
- **Recommendation**: Switch to `nginxinc/nginx-unprivileged:1.27-alpine`
  listening on port 8080, update `docker-compose.yml` port mapping.

### 🟢 LOW — No pagination max on audit_log
- `get_audit_log(limit=200)` — caller can pass `limit=999999`.
- **Recommendation**: Cap to 1000 server-side.

### 🟢 LOW — `full_result` JSON blob grows unbounded
- Each simulation dumps the entire result (can be MBs) as a TEXT column.
- **Recommendation**: Archive to S3/MinIO after 30 days, keep only
  summary fields in the DB.

### 🟢 LOW — No background job queue
- Simulation, AI analysis, SOAR push, PDF export all run synchronously
  in the request handler.
- **Recommendation**: Celery / Dramatiq / Arq with Redis broker. Return
  `202 Accepted` + `task_id`, poll via `/api/tasks/{id}`.

---

## Security Audit Detail

| Category | Status | Notes |
|---|---|---|
| Secrets in code | ✅ Fixed | JWT_SECRET rotated, `.env.example` safe, Gitleaks blocking |
| Password hashing | ✅ OK | bcrypt direct (no passlib) |
| Brute force | ✅ OK | 5/min rate limit on login |
| RBAC | ✅ OK | 13 permissions, 3 roles, `require_permission()` on sensitive endpoints |
| Input validation | ✅ Improved | Pydantic models + ingestion caps + path traversal fix |
| SQL injection | ✅ OK | Parameterised queries everywhere |
| Command injection | ✅ OK | No `os.system`, `subprocess`, `eval`, `exec` in code paths |
| XSS / CSP | ✅ Fixed | Security headers on backend + nginx |
| Prompt injection | ✅ Fixed | `_sanitise()` on all LLM interpolation points |
| PII/secret redaction | ✅ Fixed | 10+ patterns redacted before Ollama |
| Supply chain | ✅ OK | pip-audit 0 CVE, npm audit 0 HIGH, Gitleaks 0 secrets |
| Token revocation | 🟡 TODO | No denylist yet |
| SSO / OIDC | 🟡 TODO | Not implemented |

---

## Performance Audit Detail

| Area | Status | Notes |
|---|---|---|
| DB indexes | ✅ Fixed | 7 new indexes across 2 tables |
| Ingestion rate limit | ✅ OK | 600/min single, 60/min batch, per-event 64 KB cap |
| Detection engine | ⚠️ Watch | O(events × rules) — fine for simulation (<10k events), needs index for 100k+ |
| API pagination | ⚠️ Partial | Most endpoints have LIMIT, audit_log missing server-side max |
| Cache | ✅ OK | Redis/memory dual-backend, 2h TTL on results |
| Background jobs | 🟡 TODO | All sync — acceptable for POC, blocks at scale |
| Frontend bundle | ⚠️ Watch | html2pdf.js = 982 KB gzipped; recommend lazy-loading |
| WebSocket | ✅ OK | Pacing, phase markers, progress — no backpressure issue at demo scale |

---

## Database & Indexing Audit Detail

**Full report**: [`docs/proof/database-indexing-report.md`](database-indexing-report.md)

| Table | Indexes Before | Indexes After | Status |
|---|---|---|---|
| `simulation_runs` | 0 | 3 | ✅ |
| `audit_log` | 0 | 4 (1 partial) | ✅ |
| `alert_feedback` | 2 | 2 | ✅ (already OK) |
| `soc_cases` | 3 + PK | 3 + PK | ✅ (already OK) |
| `case_comments` | 1 | 1 | ✅ |
| `case_evidence` | 1 | 1 | ✅ |
| `suppressions` | 2 | 2 | ✅ |

**Migration to PostgreSQL** is the #1 remaining database priority. Proposed:
1. Abstract DB behind a `Repository` protocol
2. Add SQLAlchemy models + Alembic migrations
3. `DATABASE_URL` env var switches between SQLite (demo) and PostgreSQL (prod)

---

## CI/CD Audit Detail

| Job | Status | Notes |
|---|---|---|
| Backend Tests | ✅ 223/223 | 30s, comprehensive |
| Frontend Build | ✅ | 18s, Vite production build |
| Code Quality | ✅ | Flake8 0 errors |
| Security Scans | ✅ | 3 BLOCKING gates (pip-audit, npm audit, gitleaks) |
| Docker Build | ✅ | Retry-loop healthcheck, 3 profiles validated |
| Helm Lint | ✅ | lint + template + artifact upload |

**Remaining**: Add `checkov` for Dockerfile/Helm scanning, `kubeconform`
for K8s manifest validation, coverage upload to Codecov.

---

## Docker / Kubernetes Audit Detail

| Check | Status |
|---|---|
| Non-root user (backend) | ✅ `USER cybertwin` (uid 1000) |
| Non-root user (frontend) | 🟡 nginx runs as root — switch to nginx-unprivileged |
| Multi-stage build | ✅ Backend + Frontend |
| Image pinning | ✅ `python:3.12-slim`, `nginx:1.27-alpine`, `node:20-alpine` |
| Healthchecks | ✅ Backend + Frontend + Redis |
| Resource limits | ⚠️ In Helm values, not in docker-compose |
| securityContext (Helm) | ✅ runAsNonRoot, drop ALL caps, no privilege escalation |
| readOnlyRootFilesystem | 🟡 `false` — needs writable `/app/data`, use emptyDir |
| NetworkPolicy | 🟡 Not defined — add to restrict pod-to-pod traffic |
| Secrets | ✅ K8s Secret template, `.env.example` for compose |

---

## SOC Logic Audit Detail

| Check | Status |
|---|---|
| MITRE catalog ≠ coverage (honest) | ✅ 40/622 (6.43%) clearly stated |
| Evidence-first AI Analyst | ✅ `analyse_with_evidence()` — guardrails, limitations, no fabrication |
| LLM prompt safety | ✅ Fixed — sanitise + redact + cap |
| False positive feedback | ✅ `/api/alerts/{id}/feedback` with TP/FP/Benign |
| Noisy rule detection | ✅ `/api/alerts/feedback/noisy-rules` |
| Detection rule tests | ⚠️ No automated test suite for individual rules |
| Coverage snapshot | ✅ `benchmarks/mitre_snapshot.py` → JSON |
| Ground truth | 🟡 No labeled dataset for precision/recall measurement |

---

## Implementation Roadmap

### Phase 1 — Immediate (this commit) ✅
- [x] DB indexes (simulation_runs + audit_log)
- [x] LLM prompt sanitisation + PII redaction
- [x] Ingestion payload size caps
- [x] Security headers middleware (backend + nginx)
- [x] `scripts/check_db_indexes.py`

### Phase 2 — Next sprint (1-2 weeks)
- [ ] Token revocation (Redis denylist)
- [ ] Refresh token flow
- [ ] Pagination max enforcement (server-side cap 1000)
- [ ] CORS restrict methods/headers
- [ ] nginx-unprivileged image
- [ ] Background job queue (Celery/Arq)
- [ ] Uvicorn `--limit-max-body-size`

### Phase 3 — Database enterprise (2-4 weeks)
- [ ] SQLAlchemy + Alembic migrations
- [ ] PostgreSQL dual-backend
- [ ] Connection pooling
- [ ] Retention policy + archival
- [ ] Partitioning by date for events table

### Phase 4 — SOC validation (2-4 weeks)
- [ ] Detection rule unit tests (test each rule against ground truth)
- [ ] Labeled dataset for precision/recall
- [ ] Coverage delta reporting (before/after rule changes)
- [ ] Detection latency benchmarks

### Phase 5 — Production GA (4-8 weeks)
- [ ] SSO / OIDC integration
- [ ] Checkov + kubeconform in CI
- [ ] K8s NetworkPolicy
- [ ] readOnlyRootFilesystem + emptyDir
- [ ] Locust / k6 load tests
- [ ] Lighthouse frontend audit
- [ ] SOC 2 audit-log immutability (hash chain)
