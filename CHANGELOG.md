# Changelog

All notable changes to CyberTwin SOC are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed (Phase 1.5 — Documentation & deployment honesty)

- README documented the WebSocket as `/ws/simulation/{id}` but the actual
  endpoint is `/ws/simulate/{scenario_id}`. Aligned README, kept code stable.
- Quick Start instructions used `cd "CyberTwin SOC"` (with a space) right
  after `git clone`, which always failed because `git clone` creates the
  directory `CyberTwin-SOC` (with a hyphen). Fixed in two locations.
- Replaced the `YOUR_USERNAME` placeholder in the second Quick Start block
  with the real `omarbabba779xx` org.
- `frontend/src/components/LiveSimulation.jsx` had a hardcoded
  `ws://localhost:8000/ws/simulate/...` URL, which broke the live feed when
  the app was served behind nginx in production. Now derives the URL from
  `VITE_API_URL` if set, otherwise from `window.location` (relative URL,
  works through any reverse proxy with `wss://` upgrade).

### Added (Phase 1.5)

- `CODE_OF_CONDUCT.md` — Contributor Covenant 2.1.
- `docker-compose.yml`: new `postgres` service under the opt-in
  `--profile prod-db` (PostgreSQL 16, named volume, healthcheck), plus a
  `postgres-data` named volume. Documented in the file's header.
- `.env.example`: new `POSTGRES_PASSWORD` variable, commented `DATABASE_URL`
  example, and clearer profile documentation.
- CI security job extended with non-blocking scanners:
  `semgrep` (multi-language SAST), `gitleaks` (secret scanning),
  `npm audit` (frontend deps), `trivy` (filesystem CVE scan), and
  CycloneDX SBOM generation for both Python and JS, uploaded as a
  CI artifact tagged with the commit SHA.

### Fixed

- **Critical**: `/api/soar/push/{id}` and `/api/soar/analyze-iocs/{id}` were
  calling `_orchestrator.get_result(id)`, a method that does not exist. They
  now use the cache-backed `_get_cached_result()` helper like every other
  result endpoint, returning 404 when no run is cached.
- CI workflow now runs on the `master` branch (previously only `main` /
  `develop`, so no commit had triggered CI). Added `workflow_dispatch` for
  manual runs.
- CI no longer silently swallows `black` failures with `|| true`. Black is
  warn-only (`continue-on-error: true`) until the codebase is fully
  reformatted; flake8 remains blocking.
- All `datetime.utcnow()` calls replaced with `datetime.now(timezone.utc)`
  across `auth.py`, `audit.py`, `api/main.py`, and
  `telemetry/log_generator.py`. Removes the bulk of pytest deprecation
  warnings under Python 3.12.
- Replaced deprecated `@app.on_event("startup")` with FastAPI's modern
  `lifespan` async context manager.

### Added

- `LICENSE` (MIT), `SECURITY.md`, `CONTRIBUTING.md`, and this `CHANGELOG.md`.
- `auth.check_production_safety()` — refuses to start the API in production
  mode (`ENV=production`) if `JWT_SECRET` is missing/weak or if any default
  user password is detected. Soft-warns in development.
- CI security scans job: non-blocking `bandit` (Python static analysis) and
  `pip-audit` (CVE scan) on every push.
- `Honest Limitations` section in `README.md` clarifying the difference
  between MITRE catalog loading and real detection coverage.

### Changed

- `.env.example` rewritten with strong placeholders, alignment with Vite
  (port 5173) and nginx (port 80), `ENV=development` default, Redis URL,
  Ollama config, and the SOAR variables. Every secret now displays
  `REPLACE` or `CHANGE-ME` so misconfiguration is obvious.

## [3.0.0] - 2026-04-26

### Added

- **Phase 12 — SOAR integration**: `backend/soar/thehive.py` (TheHive 5
  client) and `backend/soar/cortex.py` (Cortex 3 client). Endpoints
  `/api/soar/status`, `/api/soar/push/{id}`, `/api/soar/analyze-iocs/{id}`,
  `/api/soar/analyzers`. New frontend page `SOAR.jsx`.
- **Phase 11 — Production Docker**: multi-stage `Dockerfile.backend`
  (Python 3.12, non-root user, healthcheck, MITRE bundle baked in at build
  time), `frontend/Dockerfile` (Node build → nginx 1.27), full
  `docker-compose.yml` with Redis + optional `--profile soar` (TheHive,
  Cortex, Elasticsearch).
- **Phase 10 — Test suite**: 128 pytest tests covering auth, detection
  engine, scoring, MITRE, attack engine, orchestrator, AI analyst,
  telemetry, and the API. 100% passing.

## [2.0.0] - Earlier

- Phases 1–9 (initial public release): JWT/RBAC auth, 11 attack scenarios,
  46 detection rules + Sigma loader, LLM AI analyst with NLG fallback,
  Isolation Forest + UEBA anomaly detection, MITRE ATT&CK 622 techniques
  catalog, Redis cache, NIST CSF v1.1 + CIS Controls v8 benchmarking,
  React frontend with Benchmark / Anomaly / LLM-status pages.

[Unreleased]: https://github.com/omarbabba779xx/CyberTwin-SOC/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/omarbabba779xx/CyberTwin-SOC/releases/tag/v3.0.0
