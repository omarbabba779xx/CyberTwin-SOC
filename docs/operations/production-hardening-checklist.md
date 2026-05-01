# Production Hardening Checklist

CyberTwin SOC now ships an executable readiness check plus the operational
runbooks required for a production-like deployment.

## Automated Check

Run before deployment:

```bash
python scripts/production_readiness_check.py
```

The check validates:

- `JWT_SECRET` length and presence.
- PostgreSQL-backed `DATABASE_URL`.
- Shared Redis `REDIS_URL`.
- Explicit `CORS_ORIGINS`.
- Non-default bootstrap passwords.
- Presence of backup, recovery, production, and Helm hardening material.

## Required Operational Controls

| Control | Repository artifact |
| --- | --- |
| Secrets hardening | `backend/auth/_core.py`, `scripts/production_readiness_check.py` |
| PostgreSQL production runtime | `backend/soc/orm_store.py`, Alembic `0006` |
| Backup and restore | `scripts/backup.sh`, `docs/operations/backup-recovery.md` |
| Kubernetes hardening | `deploy/helm/cybertwin-soc/values-secure.yaml` |
| Deployment proof | `docs/proof/production-deployment.md` |
| Security scan proof | `docs/proof/security-scan-summary.md` |

## Disaster-Recovery Drill

1. Run `scripts/backup.sh`.
2. Restore into a clean PostgreSQL database using `docs/operations/backup-recovery.md`.
3. Start backend with restored `DATABASE_URL` and `REDIS_URL`.
4. Run:

```bash
python scripts/production_readiness_check.py
python -m pytest tests/test_soc_orm_runtime.py tests/test_api.py -q
```

5. Record results in `docs/proof/` with date, operator, commit SHA, and
   restore target.
