# CI Status — `master`

> Last manual update: **2026-04-27**.
> The badges in the README link to live data; this file is a frozen snapshot.

## Latest run on `master`

```
$ gh run list --limit 1 --workflow ci.yml --branch master
STATUS  TITLE                                                       ELAPSED
✓       fix(ci): make .env optional in docker-compose so Docker     2m05s
        Build job passes
```

## Job-by-job result

| Job                            | Result | Duration | Notes                                                    |
|--------------------------------|--------|----------|----------------------------------------------------------|
| **Backend Tests**              | ✅ pass | ~1m 04s  | 223/223 tests green (pytest)                            |
| **Frontend Build**             | ✅ pass | ~24s    | `npm ci` + `npm run build` clean                        |
| **Code Quality** (flake8)      | ✅ pass | ~16s    | 0 errors with documented ignore list                     |
| **Security Scans**             | ✅ pass | ~1m 22s  | Non-blocking — Bandit, pip-audit, Semgrep, Gitleaks, Trivy, CycloneDX |
| **Docker Build**               | ✅ pass | ~1m 17s  | `compose config` + build + retry-loop healthcheck       |
| **Helm Chart Validation**      | (new)  | —        | Added in this same commit — first run pending           |

## How to reproduce locally

```bash
# All test gates the CI runs
python -m pytest tests/                                   # 223/223
python -m flake8 backend/ \
    --max-line-length=120 \
    --ignore=E501,W503,E402,E241,E231,E704                # 0 errors
python -m pip_audit -r requirements.txt --strict          # 0 known CVEs
docker compose config                                      # valid

# Smoke up + healthcheck (same loop as CI)
touch .env
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

- **Node.js 20 deprecation**: `actions/checkout@v4` and `actions/setup-python@v5`
  warn about Node.js 20 being deprecated by GitHub on 2026-09-16. Tracked in
  `docs/IMPROVEMENTS.md` (tier C); to opt in early, set
  `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24=true`.

- **CodeQL workflow** mentioned in `.github/workflows/codeql.yml` is independent
  from `ci.yml` and is not included above.
