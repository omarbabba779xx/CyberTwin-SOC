# CI Status — `master`

> Last sync: **2026-04-28** · Commit reflected: `4777047`
> The badges in the README link to live data; this file is a frozen snapshot.

## Latest run on `master`

```
$ gh run list --limit 1 --workflow ci.yml --branch master
STATUS  TITLE                                                       ELAPSED
✓       fix(ci)+docs: bump CI JWT_SECRET to 64 chars, rewrite       2m01s
        README v3.1.0
```

## Job-by-job result (v3.1.0 pipeline — 8 jobs + final quality-gate)

| Job                            | Result | Required | Notes                                                      |
|--------------------------------|--------|:--------:|------------------------------------------------------------|
| **Backend Tests**              | ✅ pass |    ✅    | 239 tests green (pytest) · coverage 69.8 % (gate ≥ 60 %) |
| **Frontend Build**             | ✅ pass |    ✅    | `npm ci` + `npm run build` clean                          |
| **Code Quality** (flake8)      | ✅ pass |    ✅    | 0 errors with documented ignore list                       |
| **Security Scans**             | ✅ pass |    ✅    | `pip-audit`, `npm audit`, `gitleaks` are **blocking**; Bandit, Semgrep, Trivy, CycloneDX informational |
| **Docker Build**               | ✅ pass |    ✅    | `compose config` + build + retry-loop healthcheck (port 8080)  |
| **Helm Chart Validation**      | ✅ pass |    ✅    | `helm lint` + render artefact uploaded                     |
| **Checkov IaC Security Scan**  | ✅ pass |          | Dockerfile + Helm — soft-fail (informational)              |
| **Quality Gate**               | ✅ pass |    ✅    | Final aggregate — single check for branch protection rules |

## How to reproduce locally

```bash
# All blocking gates
python -m pytest tests/                                   # 239 passed
python -m flake8 backend/ \
    --max-line-length=120 \
    --ignore=E501,W503,E402,E241,E231,E704                # 0 errors
python -m pip_audit -r requirements.txt --strict          # 0 known CVEs
( cd frontend && npm audit --audit-level=high )           # 0 high

# Compose smoke (same loop as CI)
cat > .env <<'EOF'
ENV=production
JWT_SECRET=ci-only-secret-for-compose-validation-0000000000000000000000000000
AUTH_ADMIN_PASSWORD=ci-admin-password-0000
AUTH_ANALYST_PASSWORD=ci-analyst-password-0000
AUTH_VIEWER_PASSWORD=ci-viewer-password-0000
EOF
docker compose config                                      # valid
docker compose build
docker compose up -d
for i in $(seq 1 30); do
  curl -fsS http://localhost:8000/api/health && break
  sleep 5
done
curl -fsS http://localhost/health
docker compose down -v
```

## Annotations / known warnings

- **Node.js 20 deprecation**: `actions/checkout@v4` warns about Node 20 being
  deprecated by GitHub on 2026-09-16. Pin migration tracked in `docs/IMPROVEMENTS.md`.
- **Lighthouse CI**: integrated into `frontend-build` job (see `frontend/.lighthouserc.json`).
  Soft-fail today, hardening planned for v3.2.
- **PostgreSQL**: backend tests run against SQLite in CI; PostgreSQL service
  added in this same commit — Alembic `upgrade head` is exercised on every PR.
