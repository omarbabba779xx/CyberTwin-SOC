# Compliance Audit Evidence Pack

This pack organizes repository evidence for SOC 2, ISO 27001, GDPR, and
security-engineering review. It is audit-ready material, not a substitute for
an external auditor's signed certification.

## Evidence Index

| Area | Evidence |
| --- | --- |
| Authentication and sessions | `docs/proof/auth-session-validation.md` |
| Authorization and tenant isolation | `docs/proof/multitenancy-isolation-report.md` |
| Audit trail integrity | `docs/proof/audit-chain-validation.md` |
| Encryption and secret handling | `docs/proof/encryption-validation.md` |
| Production hardening | `docs/operations/production-hardening-checklist.md` |
| Backup and recovery | `docs/operations/backup-recovery.md` |
| PostgreSQL readiness | `docs/proof/postgres-migration-report.md`, `tests/test_soc_orm_runtime.py` |
| Detection coverage | `docs/proof/mitre-rule-validation.md`, `tests/test_attack_validation_matrix.py` |
| Atomic Red Team metadata safety | `docs/proof/atomic-red-team-validation.md`, `scripts/validate_atomic_catalog.py`, `tests/test_atomic_red_team.py` |
| Security scans | `docs/proof/security-scan-summary.md` |
| CI status | `docs/proof/ci-status.md` |

## External Audit Handoff

Give the auditor:

1. Current commit SHA.
2. Full test report and CI logs.
3. Environment configuration with secrets redacted.
4. Backup/restore drill record.
5. Data-flow diagram from `README.md`.
6. Compliance readiness mappings:
   - `docs/compliance/soc2-readiness.md`
   - `docs/compliance/iso27001-readiness.md`
   - `docs/compliance/gdpr-data-processing.md`

## Internal Pre-Audit Command Set

```bash
python scripts/production_readiness_check.py
python scripts/profile_ingestion.py --events 10000 --batch-size 500 --detect
python scripts/validate_atomic_catalog.py --path /path/to/atomic-red-team --limit 80
python -m pytest tests/test_api.py tests/test_soc.py tests/test_soc_orm_runtime.py tests/test_attack_validation_matrix.py -q
cd frontend && npm test && npm run test:e2e
```

## Statement Of Scope

CyberTwin provides controls, evidence, and repeatable checks that support
external review. Formal SOC 2 / ISO 27001 / GDPR certification still requires
an independent auditor, production environment sampling, management assertions,
and signed audit workpapers outside the repository.
