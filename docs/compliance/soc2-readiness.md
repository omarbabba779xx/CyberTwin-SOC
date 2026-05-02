# SOC 2 Readiness Mapping - CyberTwin SOC

Version: 2.0

Date: 2026-05-02

Classification: Internal - Compliance readiness

This document maps CyberTwin SOC repository controls to the SOC 2 Trust
Service Criteria. It is readiness material for an auditor, not a signed SOC 2
report. A formal SOC 2 Type II opinion still requires a production observation
period, management assertions, auditor sampling, and signed workpapers outside
this repository.

## Readiness Summary

| Area | Repository readiness | Evidence |
| --- | --- | --- |
| Control environment | Ready for maintainer/operator review | `AGENTS.md`, CI gates, role model, audit evidence |
| Communication and information | Ready for auditor handoff | `README.md`, runbooks, API docs, compliance pack |
| Risk assessment | Ready for project-level review | MITRE coverage center, validation matrix, production checklist |
| Monitoring activities | Implemented | Prometheus metrics, deep health, traces, security scans |
| Control activities | Implemented | RBAC, tenant isolation, request limits, NetworkPolicy, backup runbook |
| Logical access | Implemented | JWT, refresh rotation, revocation, OIDC option, dynamic tenant RBAC |
| System operations | Implemented | SOC cases, feedback, suppressions, SOAR surfaces, DR material |
| Change management | CI-ready | Git history, CI/CD workflow, tests, migration smoke, Helm render |
| Vendor and third-party risk | Documented for operator ownership | Optional dependencies are inventoried; live vendor review is environment-specific |

## Trust Service Criteria Mapping

| Criteria | Status | Repository evidence |
| --- | --- | --- |
| CC1 Control environment | Readiness documented | Maintainer guidance, role catalog, audit trail |
| CC2 Communication | Ready | README, API docs, operational runbooks, evidence pack |
| CC3 Risk assessment | Ready | MITRE coverage, production readiness check, attack validation matrix |
| CC4 Monitoring | Implemented | Metrics middleware, health routes, OpenTelemetry wiring |
| CC5 Control activities | Implemented | Auth dependencies, rate limits, body limits, security headers |
| CC6 Logical access | Implemented | `backend/auth/`, tenant RBAC, token revocation, session governance |
| CC7 System operations | Implemented | Ingestion, alert queue, cases, suppressions, SOAR connectors |
| CC8 Change management | CI-ready | GitHub Actions, pytest, Playwright, Vitest, Alembic smoke |
| CC9 Risk mitigation | Operator-owned | Optional third-party services are explicit in docs and deployment config |

## Evidence Commands

```bash
python scripts/production_readiness_check.py
python scripts/profile_ingestion.py --events 10000 --batch-size 500 --detect
python scripts/validate_atomic_catalog.py --path /path/to/atomic-red-team --limit 80
python -m pytest tests/test_api.py tests/test_soc.py tests/test_soc_orm_runtime.py tests/test_attack_validation_matrix.py -q
cd frontend && npm test && npm run test:e2e
```

## Auditor Handoff Notes

- Repository controls are mapped and testable.
- The audit trail is tenant-scoped and tamper-evident.
- Production mode refuses missing or non-PostgreSQL `DATABASE_URL`.
- Helm secure values render default-deny NetworkPolicy, PDB, probes, and
  read-only filesystem mounts.
- Atomic Red Team is metadata-only and validated against the ATT&CK v19
  upstream migration without command exposure.

Formal SOC 2 certification remains outside repository scope. The operator must
provide production evidence over the observation period, including access
reviews, incident records, change approvals, backup drill records, vendor
reviews, and monitoring samples.
