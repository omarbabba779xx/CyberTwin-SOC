# CyberTwin SOC

CyberTwin SOC is an open-source SOC digital twin for simulating adversary
behavior, ingesting telemetry, testing detection coverage, and running a
tenant-aware analyst workflow.

It is best described as an advanced pilot-grade security engineering platform:
it has serious architecture, CI, tests, RBAC, audit, ingestion, MITRE mapping,
case workflow, and SOAR connector surfaces, but it is not yet a turnkey
enterprise SOC product. The README is intentionally honest about what is
implemented today and what remains roadmap work.

## At A Glance

| Area | Current state |
| --- | --- |
| Backend | FastAPI, Python 3.12, modular routers, JWT auth, OIDC option, RBAC dependencies |
| Frontend | React 18 + Vite dashboard, Vitest unit tests, Playwright smoke suite |
| Simulation | Built-in attack scenarios executed through `SimulationOrchestrator` |
| Detection | Rule engine, Sigma loader, anomaly/UEBA modules, MITRE coverage center |
| Ingestion | OCSF-style normalization, bounded in-memory buffer or Redis Streams |
| SOC workflow | Tenant-scoped cases, comments, evidence, feedback, suppressions, SLA logic |
| Persistence | SQLite local/demo runtime; SQLAlchemy/Alembic PostgreSQL schema for production paths |
| Multi-tenancy | JWT `tenant_id`, middleware tenant scope, tenant-scoped history/SOC/ingestion |
| Atomic Red Team | Optional local metadata catalog via `ATOMIC_RED_TEAM_PATH`; no command execution |
| Quality gate | Pytest coverage gate, Vitest, build, lint, Bandit, pip-audit, npm audit, Compose validation |

## Core Product Loop

```mermaid
flowchart LR
    A["Simulate adversary behavior"] --> B["Generate and ingest telemetry"]
    B --> C["Normalize events"]
    C --> D["Run detection rules and Sigma"]
    D --> E["Create alerts and incidents"]
    E --> F["Open SOC cases"]
    F --> G["Capture feedback, evidence, suppressions"]
    G --> H["Measure MITRE coverage and operational maturity"]
    H --> A
```

## Architecture

```mermaid
flowchart TB
    subgraph Client["User Interface"]
        UI["React dashboard\nVite build\nVitest + Playwright"]
    end

    subgraph API["FastAPI backend"]
        AUTH["Auth and RBAC\nJWT, refresh, revocation\nOIDC optional"]
        SIM["Simulation\nSimulationOrchestrator\nAttack scenarios"]
        ING["Ingestion\nOCSF normalization\nRedis Streams or deque"]
        DET["Detection\nRule engine\nSigma loader\nAnomaly / UEBA"]
        SOC["SOC workflow\nCases, feedback, suppressions\nTenant scoped"]
        MITRE["MITRE and Atomic metadata\nATT&CK bundle\nAtomic Red Team catalog"]
        SOAR["SOAR connectors\nTheHive, Cortex, Jira, MISP,\nSplunk, Sentinel, stubs"]
    end

    subgraph Data["Data and runtime state"]
        SQLITE[("SQLite local/demo\nhistory + SOC workflow")]
        PG[("PostgreSQL optional\nSQLAlchemy + Alembic")]
        REDIS[("Redis\ncache, sessions, streams, jobs")]
    end

    UI --> API
    API --> AUTH
    API --> SIM
    API --> ING
    API --> DET
    API --> SOC
    API --> MITRE
    API --> SOAR

    AUTH --> REDIS
    SIM --> SQLITE
    ING --> REDIS
    ING --> DET
    SOC --> SQLITE
    PG -. "DATABASE_URL production schema" .-> API
```

## Request Security Flow

```mermaid
sequenceDiagram
    participant Browser
    participant API as FastAPI
    participant Auth as JWT/RBAC
    participant Tenant as Tenant Scope
    participant Service as Domain Service
    participant Store as Store/Buffer

    Browser->>API: Request with Bearer token
    API->>Auth: Verify access token, jti, expiry
    Auth-->>API: user, role, tenant_id
    API->>Auth: require_permission(permission)
    Auth-->>API: static or tenant DB permissions
    API->>Tenant: derive tenant_id from token
    Tenant->>Service: call tenant-scoped operation
    Service->>Store: query/write with tenant_id filter
    Store-->>Browser: tenant-safe response
```

## What The Project Does

### 1. Simulate Attacks

CyberTwin runs attack scenarios through the backend orchestrator and stores
results in tenant-scoped history. Simulation duration is bounded to avoid
uncontrolled CPU, memory, and database pressure.

Key modules:

- `backend/orchestrator.py`
- `backend/simulation/attack_engine.py`
- `backend/api/routes/simulation.py`
- `backend/database.py`

### 2. Ingest Telemetry

The ingestion pipeline accepts individual events, batches, syslog lines, and
NDJSON uploads. Events are normalized and buffered per tenant. Redis Streams
are used when Redis is available; otherwise a bounded in-memory deque is used
for local/demo mode.

Key modules:

- `backend/ingestion/pipeline.py`
- `backend/normalization/`
- `backend/api/routes/ingestion.py`

### 3. Detect And Correlate

The detection engine analyzes normalized events, applies built-in rules and
Sigma rules, and correlates alerts into incidents. Suppressions are
tenant-scoped and always time-bound.

Key modules:

- `backend/detection/engine.py`
- `backend/detection/rules/`
- `backend/detection/sigma_loader.py`
- `backend/soc/suppressions.py`

### 4. Measure MITRE Coverage

The Coverage Center maps detection capability to MITRE ATT&CK techniques. It
distinguishes between catalog size, rule-mapped coverage, and actually
validated coverage.

```mermaid
flowchart LR
    T["ATT&CK technique"] --> R{"Detection rule mapped?"}
    R -->|No| NC["Not covered"]
    R -->|Yes| S{"Scenario exercises technique?"}
    S -->|No| RU["Rule only / untested"]
    S -->|Yes| F{"Rule fires in simulation?"}
    F -->|Yes| V["Validated"]
    F -->|No| FAIL["Failed validation"]
```

Key modules:

- `backend/coverage/`
- `backend/mitre/techniques_bundle.json`
- `backend/api/routes/coverage.py`
- `backend/api/routes/mitre.py`

### 5. Run SOC Workflow

CyberTwin includes a practical analyst workflow: cases, comments, evidence,
assignments, closures, alert feedback, and scoped suppressions.

```mermaid
stateDiagram-v2
    [*] --> New
    New --> InProgress: assign
    InProgress --> Resolved: resolve
    InProgress --> FalsePositive: mark false positive
    Resolved --> Closed: close
    FalsePositive --> Closed: close
    InProgress --> Pending: wait for data
    Pending --> InProgress: resume
```

Current runtime state:

- SOC workflow data is tenant-scoped in SQLite local/demo runtime.
- PostgreSQL ORM models exist, and migrations are part of CI smoke checks.
- A full PostgreSQL-only SOC CRUD runtime remains a roadmap item.

Key modules:

- `backend/soc/`
- `backend/api/routes/soc.py`

## Atomic Red Team Integration

Atomic Red Team is integrated as a safe local metadata source. CyberTwin reads
Atomic YAML files and exposes technique metadata such as supported platforms,
executors, dependencies, and input argument names. It does not execute Atomic
commands through the API.

This is deliberate: Atomic tests can contain real commands intended for
controlled security validation. CyberTwin uses them to enrich MITRE mapping and
exercise planning without turning the backend into an offensive execution API.

```mermaid
flowchart TB
    ART["Local atomic-red-team checkout"] --> YAML["atomics/Txxxx/Txxxx.yaml"]
    YAML --> PARSER["CyberTwin safe parser"]
    PARSER --> META["Sanitized metadata\ntechnique, platforms, executor names,\ndependencies, argument names"]
    PARSER -. "not exposed by default" .-> CMD["Commands and cleanup commands"]
    META --> API["/api/mitre/atomic-red-team"]
    META --> UI["Coverage and exercise planning"]
```

Setup:

```powershell
git clone https://github.com/redcanaryco/atomic-red-team.git ..\atomic-red-team
$env:ATOMIC_RED_TEAM_PATH = "C:\path\to\atomic-red-team"
```

Linux/macOS equivalent:

```bash
git clone https://github.com/redcanaryco/atomic-red-team.git ../atomic-red-team
export ATOMIC_RED_TEAM_PATH=/path/to/atomic-red-team
```

Endpoints:

| Method | Path | Permission | Purpose |
| --- | --- | --- | --- |
| `GET` | `/api/mitre/atomic-red-team` | `view_results` | List local Atomic technique IDs |
| `GET` | `/api/mitre/atomic-red-team/{technique_id}` | `view_results` | Return sanitized metadata for one technique |

## Security Model

```mermaid
flowchart TB
    U["User / service account"] --> JWT["Access token\nrole + tenant_id + jti"]
    JWT --> PERM["require_permission"]
    PERM --> RBAC{"DATABASE_URL configured?"}
    RBAC -->|Yes| DYN["tenant_roles table\ncustom permission set"]
    RBAC -->|No| STATIC["static ROLES fallback"]
    DYN --> ALLOW["Allow or deny"]
    STATIC --> ALLOW
    ALLOW --> TENANT["Tenant-scoped query or stream key"]
```

Implemented controls:

- JWT access and refresh tokens.
- Token revocation by `jti`.
- Concurrent session cap.
- Role and permission based FastAPI dependencies.
- Dynamic tenant RBAC lookup when the database-backed role store is available.
- Tenant-scoped history, SOC workflow, and ingestion buffers.
- Rate limiting through `slowapi`.
- Bounded request sizes for ingestion and SOC payloads.
- Time-bound suppressions only.
- Production safety checks for weak JWT secrets and default passwords.
- Security scans in CI: Bandit, pip-audit, npm audit, secret scanning, Trivy, Semgrep.

## Deployment Modes

```mermaid
flowchart LR
    DEV["Local development\nuvicorn + Vite"] --> DEMO["Docker Compose demo\nRedis + backend + frontend"]
    DEMO --> PRODLIKE["Production-like\nexternal PostgreSQL via DATABASE_URL"]
    PRODLIKE --> K8S["Kubernetes / Helm\nchart validation in CI"]
```

### Local Backend

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn backend.api.main:app --reload --port 8000
```

### Local Frontend

```powershell
cd frontend
npm ci
npm run dev
```

### Docker Compose Demo

```powershell
docker compose up -d
```

The Compose stack defaults to `ENV=development`. For production-like app
configuration, provide real secrets and an external PostgreSQL URL:

```powershell
$env:ENV = "production"
$env:DATABASE_URL = "postgresql+psycopg2://user:pass@host:5432/cybertwin"
docker compose up -d
```

### PostgreSQL Migrations

```bash
export DATABASE_URL=postgresql+psycopg2://user:pass@host:5432/cybertwin
alembic upgrade head
```

## API Surface

| Domain | Example paths | Notes |
| --- | --- | --- |
| Auth | `/api/auth/login`, `/api/auth/me`, `/api/auth/refresh` | JWT, refresh rotation, logout/revoke |
| Simulation | `/api/simulate`, `/ws/simulate/{scenario_id}` | Bounded simulation duration |
| History | `/api/history`, `/api/history/{run_id}` | Authenticated, tenant-scoped |
| Environment | `/api/environment`, `/api/environment/hosts` | Authenticated read surface |
| Ingestion | `/api/ingest/event`, `/api/ingest/batch`, `/api/ingest/detect` | Tenant from JWT, not request body |
| Coverage | `/api/coverage/summary`, `/api/coverage/technique/{id}` | MITRE coverage analysis |
| SOC | `/api/cases`, `/api/suppressions`, `/api/alerts/{id}/feedback` | Case workflow and feedback loop |
| MITRE | `/api/mitre/techniques`, `/api/mitre/atomic-red-team` | ATT&CK and Atomic metadata |
| Sigma | `/api/sigma/upload`, `/api/sigma/rules` | Rule upload/list |
| SOAR | `/api/soar/*`, connector routes | Integrations and stubs |
| Health/metrics | `/api/health`, `/api/health/deep`, `/api/metrics` | Operational checks |

## Quality And Verification

Recent local verification:

```bash
python -m pytest tests --cov=backend --cov-report=term-missing --cov-fail-under=71 -q
npm test
npm run build
python -m flake8 backend/ --max-line-length=120 --ignore=E501,W503,E402,E241,E231,E704 --count
python -m bandit -q -r backend -iii -lll --skip B101,B104
python -m pip_audit -r requirements.txt --strict
npm audit --audit-level=high
docker compose config --quiet
docker compose --profile soar config --quiet
```

Current observed results:

| Check | Result |
| --- | --- |
| Backend tests + coverage | Passing, 75.85% backend coverage, gate 71% |
| Frontend unit tests | Passing, 10 Vitest tests |
| Frontend production build | Passing; known large `html2pdf` chunk warning |
| Python lint | Passing, `flake8` count 0 |
| Bandit high/high | Passing with no blocking finding |
| Python dependency audit | No known vulnerabilities found |
| npm high+ audit | 0 vulnerabilities |
| Compose config | Default and SOAR profile validate |

## CI/CD Quality Gate

```mermaid
flowchart TB
    PUSH["Push / PR"] --> BACK["Backend tests + coverage"]
    PUSH --> PG["PostgreSQL migration smoke"]
    PUSH --> FRONT["Frontend build + Vitest"]
    PUSH --> E2E["Playwright smoke"]
    PUSH --> LINT["Lint"]
    PUSH --> SEC["Security scans"]
    PUSH --> DOCKER["Docker build + healthcheck"]
    PUSH --> HELM["Helm lint/render"]
    BACK --> GATE["Quality gate"]
    PG --> GATE
    FRONT --> GATE
    E2E --> GATE
    LINT --> GATE
    SEC --> GATE
    DOCKER --> GATE
    HELM --> GATE
```

## Repository Map

```text
backend/
  api/                 FastAPI app, dependencies, routers
  auth/                JWT, session governance, RBAC, OIDC
  coverage/            MITRE coverage models and gap analysis
  detection/           Rule engine, Sigma loader, rule catalog
  ingestion/           Normalization pipeline and buffer
  mitre/               ATT&CK bundle, TAXII sync, Atomic metadata
  soc/                 Cases, comments, evidence, feedback, suppressions
  connectors/          Splunk, Sentinel, TheHive, Jira, MISP, stubs
  simulation/          Attack scenarios, environment, telemetry generators
  db/                  SQLAlchemy models, repository helpers, session

frontend/
  src/                 React dashboard
  e2e/                 Playwright smoke tests

deploy/
  helm/                Kubernetes chart

tests/                 Backend regression, security, integration tests
```

## Honest Limits

CyberTwin SOC is strong for a portfolio, research, pilot, and security
engineering lab. It is not yet a finished commercial SOC platform.

Important remaining gaps:

- Full PostgreSQL runtime CRUD for SOC cases, feedback, evidence, and suppressions.
- Larger end-to-end frontend journeys beyond smoke coverage.
- Production hardening for deployment secrets, backups, retention, and disaster recovery.
- Deeper performance profiling under sustained ingestion load.
- More validated ATT&CK coverage; current coverage is honest and intentionally conservative.
- UI exposure of the new Atomic Red Team metadata endpoints.
- Formal third-party compliance audits; included mappings are readiness material, not certification.

## Roadmap

```mermaid
gantt
    title CyberTwin SOC Improvement Roadmap
    dateFormat  YYYY-MM-DD
    section Platform
    PostgreSQL SOC runtime        :active, 2026-05-01, 14d
    Tenant-scoped audit queries   :2026-05-08, 7d
    section Detection
    Atomic metadata UI            :2026-05-05, 10d
    More validated ATT&CK paths   :2026-05-12, 21d
    section Frontend
    Full analyst E2E journeys     :2026-05-10, 14d
    Bundle splitting              :2026-05-12, 7d
    section Operations
    Backup and restore drills     :2026-05-15, 10d
    Load and soak testing         :2026-05-20, 14d
```

## License

This project is released under the repository license. Atomic Red Team is a
separate upstream project from Red Canary and is used only as an optional local
metadata source when configured by the operator.
