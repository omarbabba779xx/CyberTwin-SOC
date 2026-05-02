<div align="center">

<img src="https://img.shields.io/badge/CyberTwin_SOC-v3.2-e63946?style=for-the-badge&labelColor=0d1117" alt="version"/>
<img src="https://img.shields.io/badge/Python-3.12-3776ab?style=for-the-badge&logo=python&logoColor=white&labelColor=0d1117"/>
<img src="https://img.shields.io/badge/React-18.3-61dafb?style=for-the-badge&logo=react&logoColor=white&labelColor=0d1117"/>
<img src="https://img.shields.io/badge/FastAPI-0.136-009688?style=for-the-badge&logo=fastapi&logoColor=white&labelColor=0d1117"/>
<img src="https://img.shields.io/badge/Tests-976_passed-3fb950?style=for-the-badge&labelColor=0d1117"/>
<img src="https://img.shields.io/badge/MITRE_ATT%26CK-622_techniques-e63946?style=for-the-badge&labelColor=0d1117"/>

<br/><br/>

# CyberTwin SOC

### Digital Twin Platform for Cyber Attack Simulation & SOC Readiness Assessment

*Simulate real-world adversary campaigns · Validate detection coverage · Measure SOC maturity*

<br/>

[**Architecture**](#architecture) &nbsp;·&nbsp; [**Quick Start**](#quick-start) &nbsp;·&nbsp; [**Scenarios**](#attack-scenarios) &nbsp;·&nbsp; [**API**](#api-surface) &nbsp;·&nbsp; [**Dashboard**](#dashboard-pages-28)

</div>

---

## Overview

CyberTwin SOC is a full-stack **Security Operations Center digital twin** that enables security engineers and SOC teams to:

- Replay authentic APT campaigns mapped to **MITRE ATT&CK v19** (622 techniques)
- Validate detection rule coverage with a **51-rule engine** + Sigma loader + UEBA anomaly detection
- Run an end-to-end SOC analyst workflow — cases, evidence, suppressions, feedback loops
- Measure operational maturity against the **NIST Cybersecurity Framework**
- Integrate with production SIEM/SOAR stacks via **6 native connectors**

---

## Core Detection Loop

```mermaid
flowchart LR
    A(["⚔️ Adversary\nSimulation"]):::red --> B(["📡 Telemetry\nGeneration"]):::blue
    B --> C(["🔄 OCSF\nNormalization"]):::blue
    C --> D(["🔍 Detection\nEngine"]):::orange
    D --> E(["🚨 Alert &\nIncident Triage"]):::orange
    E --> F(["📁 SOC Case\nWorkflow"]):::teal
    F --> G(["📊 MITRE Coverage\n& Maturity Score"]):::teal
    G --> A

    classDef red    fill:#e63946,color:#fff,stroke:none
    classDef blue   fill:#457b9d,color:#fff,stroke:none
    classDef orange fill:#f4a261,color:#1a1a1a,stroke:none
    classDef teal   fill:#2a9d8f,color:#fff,stroke:none
```

---

## Architecture

```mermaid
flowchart TB
    subgraph UI["🖥️  Frontend — React 18 · Vite 6 · 28 pages"]
        direction LR
        DASH["Dashboard\n& Analytics"]
        SIM_UI["Live Simulation\nWebSocket stream"]
        COVERAGE["Coverage Center\nMITRE heatmap"]
        CASES["Case Management\nSOC workflow"]
    end

    subgraph API["⚡  Backend — FastAPI · Python 3.12 · 15 routers"]
        direction TB
        AUTH_R["auth/\nJWT · RBAC · OIDC · bcrypt"]
        SIM_R["simulation/\nOrchestrator · 11 scenarios"]
        DET_R["detection/\n51 rules · Sigma · Anomaly/UEBA"]
        ING_R["ingestion/\nOCSF pipeline · Redis Streams"]
        SOC_R["soc/\nCases · Feedback · Suppressions"]
        COV_R["coverage/\nMITRE mapping · 8-state tracking"]
        OBS_R["observability/\nPrometheus · OpenTelemetry"]
    end

    subgraph CONN["🔌  SIEM / SOAR Connectors"]
        direction LR
        S1["Microsoft\nSentinel"]
        S2["Splunk"]
        S3["JIRA"]
        S4["MISP"]
        S5["TheHive"]
        S6["Cortex"]
    end

    subgraph DATA["🗄️  Data Layer"]
        direction LR
        SQLITE[("SQLite\ndemo / local")]
        PG[("PostgreSQL\nproduction")]
        REDIS[("Redis\ncache · jobs · streams")]
    end

    UI -->|HTTPS + WSS| API
    API --> CONN
    API --> DATA
```

---

## Detection Pipeline

```mermaid
flowchart LR
    RAW["Raw Events\nWindows · Sysmon\nLinux · Network"]
    NORM["OCSF\nNormalizer"]
    RULE["Rule Engine\n51 Sigma-compatible rules"]
    ANOM["Anomaly / UEBA\nscikit-learn baseline"]
    CORR["Incident\nCorrelator"]
    ALERT["Alert Store\ntenant-scoped"]
    CASE["SOC Case\nWorkflow"]

    RAW --> NORM
    NORM --> RULE --> CORR
    NORM --> ANOM --> CORR
    CORR --> ALERT --> CASE
```

---

## SOC Operational Workflow

```mermaid
stateDiagram-v2
    [*] --> New : Alert triggered
    New --> Investigating : Analyst assigns
    Investigating --> Resolved : Confirmed & remediated
    Investigating --> FalsePositive : No threat confirmed
    Investigating --> Escalated : Severity upgraded
    Escalated --> Resolved : Incident closed
    FalsePositive --> Suppressed : Suppression rule added
    Resolved --> [*]
    Suppressed --> [*]
```

---

## Multi-Tenancy Model

```mermaid
flowchart TB
    JWT["JWT Token\ntenant_id claim"]

    subgraph T1["Tenant A — Red Team"]
        A_SIM["Simulations"]
        A_SOC["Cases / Alerts"]
        A_SIG["Custom Sigma rules"]
        A_AUD["Audit trail"]
    end

    subgraph T2["Tenant B — Blue Team"]
        B_SIM["Simulations"]
        B_SOC["Cases / Alerts"]
        B_SIG["Custom Sigma rules"]
        B_AUD["Audit trail"]
    end

    JWT --> T1
    JWT --> T2
```

> All data stores (cases, alerts, history, ingestion, Sigma rules, audit chain) are scoped by `tenant_id` at middleware level — no cross-tenant data leakage possible.

---

## Attack Scenarios

| Scenario | Threat Actor | Key Techniques | Real-world Basis |
|---|---|---|---|
| 🎣 **Spear Phishing + C2** | APT29 / Cozy Bear 🇷🇺 | T1566, T1059, T1055, T1071 | SolarWinds supply chain / EnvyScout |
| 💥 **Credential Brute Force** | TeamTNT 🇩🇪 | T1110, T1078, T1610, T1496 | Cloud cryptojacking operations |
| 🕵️ **Lateral Movement** | APT28 / Fancy Bear 🇷🇺 | T1021, T1550, T1003, T1075 | DNC breach — Mimikatz + PsExec |
| 📤 **Data Exfiltration** | Insider Threat 🔴 | T1048, T1041, T1074, T1052 | Tesla / CERT insider threat case |
| 🛠️ **+ 7 custom scenarios** | Scenario Builder | Full ATT&CK mapping | Configurable per exercise |

---

## MITRE ATT&CK Coverage

```mermaid
xychart-beta
    title "Detection Rules per MITRE Tactic"
    x-axis ["Init.Access", "Execution", "Persistence", "Priv.Esc", "Def.Evasion", "Cred.Access", "Lateral Mvt", "Exfiltration"]
    y-axis "Active Rules" 0 --> 12
    bar [5, 8, 6, 7, 5, 9, 7, 4]
```

| Metric | Value |
|---|---|
| Techniques mapped | **622** (ATT&CK v19 Enterprise) |
| Tactics covered | **14 / 14** |
| Custom detection rules | **51** (Sigma-compatible) |
| External Sigma rules | Loader included |
| UEBA / Anomaly baselines | scikit-learn powered |
| Atomic Red Team catalog | Optional via `ATOMIC_RED_TEAM_PATH` |

---

## Security Architecture

```mermaid
flowchart LR
    subgraph AuthFlow["Auth Flow"]
        direction TB
        LOGIN["POST /api/auth/login\nbcrypt verify"] --> ISSUE["Issue JWT\naccess 15min · refresh 7d"]
        ISSUE --> RBAC["RBAC enforcement\nadmin · analyst · viewer"]
        REFRESH["POST /api/auth/refresh"] --> ISSUE
        REVOKE["POST /api/auth/revoke\nRedis blocklist"] --> BLOCK["401 on next request"]
    end

    subgraph Controls["Security Controls"]
        direction TB
        H1["🔐 bcrypt password hashing — cost 12"]
        H2["🔑 JWT RS256 · short-lived access + rotating refresh"]
        H3["🛡️ RBAC 3-tier enforced per endpoint"]
        H4["🏢 Multi-tenant isolation at middleware layer"]
        H5["🔒 AES-256-GCM field-level encryption"]
        H6["⚡ Rate limiting per route via slowapi"]
        H7["🌐 Security headers — HSTS · CSP · X-Frame-Options"]
        H8["📦 MaxBodySize middleware — ingestion cap"]
        H9["🔄 Circuit breaker on all external connectors"]
    end
```

---

## Tech Stack

### Backend

| Component | Technology | Version |
|---|---|---|
| API Framework | FastAPI + Uvicorn | 0.136 / 0.32 |
| Auth | PyJWT + bcrypt + Authlib (OIDC) | 2.12 / 4.2 / 1.6 |
| ORM / Migrations | SQLAlchemy + Alembic | 2.0 / 1.14 |
| Cache / Jobs | Redis + Arq | 5.2 / 0.26 |
| ML / Anomaly | scikit-learn + NumPy + SciPy | 1.5 / 2.2 / 1.14 |
| Threat Intel | STIX2 + TAXII2 | 3.0 / 2.3 |
| Observability | Prometheus client + OpenTelemetry | 0.21 / 1.29 |
| Encryption | cryptography (AES-256-GCM / HKDF) | 46.0 |
| Validation | Pydantic v2 | 2.10 |
| Language | Python | 3.12 |

### Frontend

| Component | Technology |
|---|---|
| Framework | React 18.3 + Vite 6.4 |
| Charts | Recharts (bar, pie, radar, line) |
| Network topology | React Flow |
| World threat map | react-simple-maps + TopoJSON |
| Styling | Tailwind CSS v3 |
| Code splitting | React.lazy + Suspense (28 chunks) |
| PDF export | html2pdf.js |
| i18n | Custom FR / EN toggle |

---

## Quality & CI/CD

```mermaid
flowchart LR
    PUSH["git push"] --> LINT

    subgraph Pipeline["GitHub Actions — 7 quality gates"]
        direction TB
        LINT["flake8 + isort\nlinting"]
        TEST["pytest\n976 tests · ≥60% coverage"]
        SEC["Bandit · Semgrep\npip-audit — 0 CVE"]
        BUILD["Vite build\nVitest unit tests"]
        E2E["Playwright\nanalyst E2E journeys"]
        DOCKER["Docker build\nHelm lint"]
        READY["Readiness check\nproduction gates"]
    end

    LINT --> TEST --> SEC --> BUILD --> E2E --> DOCKER --> READY --> MERGE["✅ Merge"]
```

| Gate | Tool | Status |
|---|---|---|
| Unit tests | pytest | **976 passing, 0 failed** |
| Coverage | pytest-cov | ≥ 60% enforced |
| Security scan | Bandit + pip-audit | **0 HIGH / CRITICAL CVE** |
| Lint | flake8 + isort | 0 errors |
| Frontend build | Vite + Vitest | pass |
| E2E journeys | Playwright | analyst flow |
| Container | Docker + Helm lint | pass |

---

## Quick Start

### Prerequisites

```
Python 3.12+   Node.js 18+   Redis (optional — memory fallback included)
```

### 1 — Clone & configure

```bash
git clone https://github.com/omarbabba779xx/CyberTwin-SOC.git
cd CyberTwin-SOC
cp .env.example .env
# Edit .env: set JWT_SECRET (required), DATABASE_URL + REDIS_URL (optional)
```

### 2 — Backend

```bash
pip install -r requirements.txt
python -m uvicorn backend.api.main:app --host 0.0.0.0 --port 8000 --reload
```

> API → http://localhost:8000 &nbsp;·&nbsp; Swagger → http://localhost:8000/docs

### 3 — Frontend

```bash
cd frontend
npm install
npm run dev
```

> Dashboard → http://localhost:3000

### 4 — Docker (all-in-one)

```bash
docker compose up --build
```

### Default credentials

| Role | Username | Password | Permissions |
|---|---|---|---|
| Admin | `admin` | `cybertwin2024` | Full — manage users, delete history, configure |
| Analyst | `analyst` | `soc2024` | Run simulations, manage alerts & cases |
| Viewer | `viewer` | `view2024` | Read-only access to results and reports |

### PostgreSQL (production)

```bash
export DATABASE_URL=postgresql://user:pass@localhost:5432/cybertwin
alembic upgrade head
```

---

## Dashboard Pages (28)

```mermaid
mindmap
  root((CyberTwin SOC))
    Overview
      Dashboard
      Executive
      Analytics
    Simulation
      Scenarios
      Scenario Builder
      Attack Tree
      Atomic Red Team
      Benchmark
    Detection
      Alert Queue
      Timeline
      MITRE ATT&CK
      Coverage Center
      Anomaly Detection
      Log Explorer
    Intelligence
      Threat Intel Feed
      Threat Map
      Risk Matrix
    SOC Operations
      Case Management
      Suppressions
      SOAR Integration
      Ingestion Pipeline
    Assessment
      SOC Maturity
      AI Analysis
      Report
      Comparison
    Infrastructure
      Network Topology
```

---

## API Surface

```
# Authentication
POST   /api/auth/login              Authenticate → JWT access + refresh tokens
POST   /api/auth/refresh            Rotate access token using refresh token
POST   /api/auth/revoke             Invalidate token (Redis blocklist)
GET    /api/auth/me                 Current authenticated user + role

# Simulation
GET    /api/scenarios               List available attack scenarios
GET    /api/scenarios/{id}          Scenario detail + phases
POST   /api/scenarios/custom        Save custom scenario
POST   /api/simulate                Run full simulation (sync, returns summary)
WS     /ws/simulate/{id}            Live event stream (WebSocket)

# Results
GET    /api/results/{id}            Full simulation result
GET    /api/results/{id}/alerts     Alert list with MITRE mapping
GET    /api/results/{id}/timeline   Chronological event stream
GET    /api/results/{id}/mitre      MITRE coverage analysis
GET    /api/results/{id}/ai-analysis Automated incident narrative

# Detection & Coverage
GET    /api/coverage                Detection coverage matrix (8-state per technique)
GET    /api/mitre/techniques        ATT&CK technique catalog

# Ingestion
POST   /api/ingestion/events        Ingest OCSF-normalized events
GET    /api/ingestion/stats         Pipeline throughput + buffer stats

# SOC Workflow
GET    /api/soc/cases               List cases (tenant-scoped)
POST   /api/soc/cases               Create case from alert
PUT    /api/soc/cases/{id}          Update — status, evidence, assignee
POST   /api/soc/feedback            Submit analyst feedback on alert
GET    /api/soc/suppressions        Active suppression rules

# Observability
GET    /api/metrics                 Prometheus metrics (text/plain)
GET    /api/health                  Health check
GET    /docs                        Swagger UI (interactive)
GET    /redoc                       ReDoc documentation
```

---

## Repository Structure

```
CyberTwin-SOC/
├── backend/
│   ├── api/
│   │   └── routes/          # 15 FastAPI routers (auth, simulation, soc, ingestion…)
│   ├── ai_analyst/          # Automated incident analysis — NLG narrative engine
│   ├── auth/                # JWT · RBAC (admin/analyst/viewer) · OIDC · bcrypt
│   ├── connectors/          # Sentinel · Splunk · Jira · MISP · TheHive · Cortex
│   ├── coverage/            # MITRE detection coverage engine (8-state per technique)
│   ├── db/                  # SQLAlchemy models · Alembic migrations
│   ├── detection/
│   │   ├── rules/           # 51-rule catalogue (Sigma-compatible)
│   │   ├── sigma_loader.py  # External Sigma rule ingestion
│   │   └── anomaly.py       # UEBA / ML anomaly detection
│   ├── ingestion/           # OCSF normalization pipeline + buffer
│   ├── jobs/                # Arq background tasks (retention, coverage)
│   ├── mitre/               # ATT&CK v19 bundle — 622 techniques
│   ├── observability/       # Prometheus metrics · OpenTelemetry · security headers
│   ├── simulation/          # AttackScenarioEngine · 11 built-in scenarios
│   ├── soar/                # TheHive + Cortex connector surface
│   ├── soc/                 # Cases · feedback · suppressions · tenant ORM store
│   └── telemetry/           # Windows / Sysmon / Linux event generators
├── frontend/
│   └── src/
│       ├── pages/           # 28 pages — React lazy-loaded chunks
│       ├── components/      # ErrorBoundary · Toast · Skeleton · PlaybookViewer
│       ├── hooks/           # useKeyboardShortcuts · useAnimatedCounter
│       └── utils/           # export.js — CSV + JSON download
├── scenarios/               # 4 built-in JSON scenarios + custom/ directory
├── tests/                   # 44 test files · 976 tests
├── data/                    # Simulated environment (hosts, users, network)
├── .github/workflows/       # CI/CD — 7 quality gates
└── docker-compose.yml
```

---

## Observability

```mermaid
flowchart LR
    APP["FastAPI\nApplication"]

    APP --> PROM["Prometheus\nGET /api/metrics"]
    APP --> OTEL["OpenTelemetry\ntraces + spans"]

    PROM --> GRAFANA["Grafana\ndashboard"]
    OTEL --> JAEGER["Jaeger\ntrace explorer"]

    subgraph Metrics["Exported Metrics"]
        M1["http_requests_total{method,path,status}"]
        M2["simulation_duration_seconds"]
        M3["alerts_generated_total{severity}"]
        M4["detection_rule_hits_total{rule_id}"]
        M5["ingestion_events_total{source}"]
    end
```

Enable OpenTelemetry: `OTEL_ENABLED=true OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4317`

---

## License

MIT — see [LICENSE](LICENSE)

---

<div align="center">

**CyberTwin SOC** — Security engineering platform for detection validation and SOC readiness

<br/>

`976 tests · 0 failed` &nbsp;|&nbsp; `622 MITRE techniques` &nbsp;|&nbsp; `51 detection rules` &nbsp;|&nbsp; `28 dashboard pages` &nbsp;|&nbsp; `6 SIEM/SOAR connectors`

</div>
