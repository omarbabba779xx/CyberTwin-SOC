# Changelog

All notable changes to CyberTwin SOC are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added (Phase 3 — SOC Operational Workflow)

- New module `backend/soc/` with persistent SQLite tables and business logic for:
    - **Alert Feedback** (`feedback.py`): record analyst verdicts
      (`true_positive`, `false_positive`, `benign_positive`, `duplicate`,
      `needs_more_data`, `escalated`, `closed`); aggregate FP rate;
      detect noisy rules.
    - **Case Management** (`cases.py`): full Alert → Incident → Case workflow
      with comments, evidence, assignment, severity-based SLA computation,
      mandatory closure reason, status enum
      (`new`, `open`, `in_progress`, `pending`, `resolved`, `closed`,
      `false_positive`).
    - **Suppressions** (`suppressions.py`): silence noise without deleting it;
      every suppression **MUST** have an expiration (no permanent bypass);
      6 scopes (`rule`, `user`, `host`, `ip`, `process`, `tenant`); soft-delete
      preserves audit trail.
- **Suppression integration in DetectionEngine**: alerts that match an active,
  non-expired suppression are tagged with `suppressed_by=<id>` and excluded
  from the analyst queue, but the alert object is preserved internally.
- **Evidence-first AI analysis** (`ai_analyst.AIAnalyst.analyse_with_evidence`):
  strict structured output schema with `evidence[]` linking each claim to a
  specific `event_id` + `field` + `value`, plus `confidence`, `mitre[]`,
  `hypotheses[]`, `recommended_actions[]`, `iocs`, `limitations[]`,
  `guardrails[]`. PII / secrets are redacted. Refuses to invent IOCs or
  threat-actor attribution.
- **15 new API endpoints**:
    - `POST /api/alerts/{id}/feedback`
    - `GET /api/alerts/feedback/summary`
    - `GET /api/alerts/feedback/noisy-rules`
    - `POST /api/cases`, `GET /api/cases`, `GET/PATCH /api/cases/{id}`
    - `POST /api/cases/{id}/comments|evidence|assign|close`
    - `POST /api/suppressions`, `GET /api/suppressions`,
      `DELETE /api/suppressions/{id}`
    - `GET /api/results/{id}/ai-evidence`
- **3 new frontend pages**:
    - `pages/AlertQueue.jsx` — triage UI with verdict buttons + noisy-rule panel
    - `pages/CaseManagement.jsx` — create + drill-down + comments + evidence + close
    - `pages/Suppressions.jsx` — admin form + active list with expiration display
  Wired into the sidebar under a new **SOC Workflow** section.
- **27 new tests** in `tests/test_soc.py` covering the business logic AND the
  HTTP API for feedback, cases (full lifecycle), suppressions (admin RBAC,
  mandatory expiration), and the evidence-first analyst (no-evidence-no-claim,
  secret redaction). Total: **177 / 177 passing**.

### Changed (Phase 3)

- `DetectionEngine.analyse()` now applies active suppressions transparently,
  logging the count of suppressed alerts at INFO level.
- `lifespan` startup now calls `init_soc_tables()` so the SOC tables are
  ready before the first request lands.
- Pydantic deprecation cleaned up: `payload.dict()` → `payload.model_dump()`.

### Added (Phase 2 — Detection Coverage Center)

- New module `backend/coverage/` (`models.py`, `calculator.py`, `gap_analyzer.py`)
  that joins four sources into a real, measurable coverage view:
    1. The MITRE catalog (622 techniques)
    2. Built-in + Sigma detection rules
    3. Attack scenarios
    4. Recent simulation results from the cache
- 8-state honest status enum (`TechniqueStatus`):
  `not_covered`, `rule_exists`, `rule_exists_untested`, `tested_and_detected`,
  `tested_but_failed`, `noisy`, `needs_data_source`, `not_applicable`.
- Six new API endpoints under `/api/coverage/`:
  - `GET /api/coverage/summary` — global score + status breakdown
  - `GET /api/coverage/mitre` — full per-technique table (filter by status / tactic)
  - `GET /api/coverage/technique/{tid}` — single-technique drill-down
  - `GET /api/coverage/gaps` — actionable gaps with recommendations
  - `GET /api/coverage/gaps/high-risk` — critical/high-risk gaps shortcut
  - `POST /api/coverage/recalculate` — admin force-refresh (bypasses 30 s cache)
- Frontend page `frontend/src/pages/CoverageCenter.jsx` with Score banner,
  status distribution bar, filterable techniques list with detail panel,
  and a Gaps tab. Wired into the sidebar under *Analysis → Coverage Center*.
- 22 new tests in `tests/test_coverage.py` (calculator, gap analyzer, and
  full HTTP integration of the 6 endpoints). Total: **150 / 150 passing**.

### Changed (Phase 2)

- `DetectionRule` dataclass extended with optional metadata
  (`status`, `version`, `author`, `required_logs`, `required_fields`,
  `false_positives`, `recommendations`, `confidence`). All have defaults so
  the 46 existing rules continue to work without modification.
- README *Honest Limitations* section updated: the 8-state coverage matrix
  is now described as **Live** (was Roadmap) and the Global Score formula
  is documented.

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
