<div align="center">

# 🛡️ CyberTwin SOC

### Open-source SOC digital twin — multi-tenant, MITRE-mapped, OCSF-aware

*An open-source digital twin of a modern SOC.* **Architecture and CI take cues from production systems** (Compose, Helm, OIDC/SSO, tamper-evident audit chain, multi-tenant isolation, observability gates), but **feature maturity is advanced POC / pilot-grade** — not a turnkey enterprise product. See **[Scope & honesty](#-scope-honesty--limits)** for the straight answer on what is and isn't validated. The platform emulates adversary tradecraft, ingests OCSF telemetry, runs 46 rules + Sigma, drives a case workflow, exposes a deterministic AI analyst + ML anomaly module, ships SOAR adapters, AES-256-GCM field encryption, and Helm/K8s charts. SOC 2 and ISO 27001 docs are **internal readiness mappings** — not third-party audited certification statements.

<table>
<tr><td align="center" width="100%">

🆕 **v3.2.0 — Multi-tenancy, audit chain & OIDC hardening**

🏢 **Real multi-tenancy** (JWT tenant_id · TenantScopeMiddleware · TenantRepository) · 🔄 **Arq worker** (Redis broker, separate container) · 📡 **Redis Streams** ingestion buffer · 🔐 **OIDC/SSO** (Entra ID, Okta, Keycloak) · 🔒 **AES-256-GCM** field encryption · 🧩 **Session governance** · 📋 **Tamper-evident audit** (SHA-256 chain) · 📊 **OpenTelemetry** traces · 🎯 **Dynamic RBAC** per tenant · ⚡ **Circuit breaker** on connectors · 📈 **Executive dashboard** · 📝 **SOC 2 / ISO 27001** readiness docs

</td></tr>
</table>

[![CI](https://github.com/omarbabba779xx/CyberTwin-SOC/actions/workflows/ci.yml/badge.svg)](https://github.com/omarbabba779xx/CyberTwin-SOC/actions)
[![Backend tests](https://img.shields.io/badge/backend%20pytest-855-passing-brightgreen)](#-quality--testing)
[![Automated tests](https://img.shields.io/badge/automated%20total-867-success)](#-quality--testing)
[![Coverage](https://img.shields.io/badge/coverage-%7E72%25-success)](#-quality--testing)
[![Python](https://img.shields.io/badge/python-3.12-blue?logo=python&logoColor=white)](https://python.org)
[![React](https://img.shields.io/badge/react-18-61DAFB?logo=react&logoColor=white)](https://react.dev)
[![CVE](https://img.shields.io/badge/known%20CVEs-0-brightgreen)](#-security-posture)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-622%20techniques-red)](https://attack.mitre.org/)
[![OCSF](https://img.shields.io/badge/OCSF-1.0-blueviolet)](https://schema.ocsf.io/)
[![Helm](https://img.shields.io/badge/Helm-chart%20linted-0F1689?logo=helm&logoColor=white)](deploy/helm)
[![SBOM](https://img.shields.io/badge/SBOM-CycloneDX-2596be)](https://cyclonedx.org/)

[**🚀 Quick start**](#-quick-start) · [**🏗 Architecture**](#-architecture) · [**🚀 Features**](#-features) · [**🔐 Security**](#-security-posture) · [**📚 Documentation**](#-documentation) · [**🗺 Roadmap**](#-roadmap)

</div>

---

## 📖 Table of contents

<table>
<tr>
<td width="33%" valign="top">

**🎯 Overview**
- [Why CyberTwin SOC?](#-why-cybertwin-soc)
- [What's new in v3.2.0](#-whats-new-in-v320)
- [Project at a glance](#-project-at-a-glance)
- [Validation status](#-validation-status)

</td>
<td width="33%" valign="top">

**🏗 Engineering**
- [Architecture](#-architecture)
- [Features](#-features)
- [Live OCSF ingestion](#-live-telemetry-ingestion-ocsf)
- [Detection Coverage Center](#-detection-coverage-center)
- [SOC workflow](#-soc-workflow)

</td>
<td width="33%" valign="top">

**🔐 Operations**
- [Quick start](#-quick-start)
- [Security posture](#-security-posture)
- [CI/CD pipeline](#-cicd-pipeline)
- [Observability & metrics](#-observability--metrics)
- [Production deployment](#-production-deployment)
- [Quality & testing](#-quality--testing)

</td>
</tr>
</table>

---

## 🎯 Why CyberTwin SOC?

> **The hardest problem in detection engineering is not writing rules — it's knowing which adversary behaviour you can actually catch, and proving it under pressure.**

CyberTwin SOC is **not** a SIEM, not a SOAR, and not yet another dashboard. It is a **digital twin of a Security Operations Center** that closes the four loops every mature SOC needs:

```mermaid
flowchart LR
    A["SIMULATE<br/>11 scenarios<br/>28 attack techniques<br/>Custom Sigma"]
    B["DETECT<br/>46 rules + Sigma<br/>622 MITRE techniques<br/>OCSF normalisation"]
    C["RESPOND<br/>SOC cases · SLA<br/>SOAR · Suppressions · Feedback"]
    D["MEASURE<br/>Coverage Center<br/>NIST CSF + CIS<br/>Benchmarks"]

    A --> B --> C --> D
    D -. continuous improvement .-> A

    classDef sim fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef det fill:#dbeafe,stroke:#3b82f6,color:#1e3a8a
    classDef resp fill:#fee2e2,stroke:#ef4444,color:#7f1d1d
    classDef mes fill:#d1fae5,stroke:#10b981,color:#064e3b
    class A sim
    class B det
    class C resp
    class D mes
```

It answers, in concrete numbers — not bullet points — questions every CISO and detection engineer eventually asks:

| Question | Where the answer lives |
|----------|------------------------|
| *Of the 622 published ATT&CK techniques, which can my SOC actually detect today?* | **Detection Coverage Center** — 8 honest states (Validated / Failed / Untested / Rule-only / Not-covered / …) |
| *What's the false-positive rate of my detection rules in the last 30 days?* | **SOC Workflow** — analyst feedback loop on every alert |
| *If a Solorigate-style supply-chain attack hits us today, will we catch it before exfiltration?* | Run `scenario apt_campaign` and read the report |
| *Are my log sources sufficient for detecting credential dumping?* | `required_logs` per technique × `available_logs` per host group |
| *How fast can analysts triage? What's the SLA breach rate?* | SOC cases store SLA, status transitions and time-to-close |
| *Which detection-engineer change broke detection?* | Versioned rule store + benchmark comparison |

---

## 🆕 What's new in v3.2.0

<table>
<tr>
<th width="25%">🏢 Multi-tenancy & Auth</th>
<th width="25%">🔐 Security & Compliance</th>
<th width="25%">📊 Observability & Ops</th>
<th width="25%">⚡ Hardening features</th>
</tr>
<tr valign="top">
<td>

- `tenant_id` in **JWT** payload
- **TenantScopeMiddleware**
- **TenantRepository** pattern
- Rate-limit by **tenant:user**
- **OIDC/SSO** (Entra ID, Okta, Keycloak)
- **Session governance** (concurrent limit)
- ORM-first DB (SQLite dev fallback)

</td>
<td>

- **Tamper-evident audit** (SHA-256 chain)
- **AES-256-GCM** field encryption (per-tenant HKDF)
- **FK constraints** with CASCADE (3 migrations)
- **Data retention** purge job (GDPR-aware)
- **SOC 2** Type II readiness mapping
- **ISO 27001:2022** Annex A assessment
- **GDPR** data processing documentation

</td>
<td>

- **OpenTelemetry** traces (OTLP exporter)
- FastAPI + SQLAlchemy + Redis instrumentation
- `X-API-Version: v1` on all responses
- **Backup/DR** script + professional runbook
- **Frontend test suite** (Vitest + RTL)
- **Real Arq worker** (Redis broker, separate container)

</td>
<td>

- **Dynamic RBAC** per tenant in DB
- **Circuit breaker** on connectors
- Exponential retry with `@with_retry`
- **Redis Streams** ingestion buffer
- Unified **error envelope** + global handlers
- Complete **health checks** (per-component latency)
- **Executive dashboard** (MTTD/MTTR/SLA KPIs)

</td>
</tr>
</table>

<details>
<summary>v3.1.0 — Hardening release (click to expand)</summary>

- JWT **jti denylist** via Redis · **Refresh token rotation** (1h / 7d) · CORS strict · **nginx-unprivileged**
- `main.py` **1561 → 135 LoC** · **14 router modules** · **Arq-shaped jobs** + `/api/tasks`
- **SQLAlchemy 2.0** ORM · **Alembic** · **PostgreSQL CI smoke** · 10 ORM models · 19 indexes
- **30+ AI security tests** · **Checkov** IaC · **Lighthouse CI** · `quality-gate` (9 jobs)

</details>

### 📦 v3.2.0 — Hardening track (5 phases, 22 deliverables)

| Phase | Title | Key Deliverables |
|------:|-------|-----------------|
| **1** | Operational Reliability | Real **Arq worker** (Redis broker + separate container) · **Redis Streams** buffer (persistent 50k events) · Unified **error envelope** · Complete **health checks** (Redis PING, PG, per-component latency) |
| **2** | Multi-tenancy E2E | `tenant_id` in **JWT** · `TenantScopeMiddleware` · `TenantRepository` pattern · ORM-first database (SQLite fallback for dev) · Rate-limit by **tenant:user** |
| **3** | Security & Compliance | **Tamper-evident audit** (SHA-256 chain + PostgreSQL) · **OIDC/SSO** (Entra ID, Okta, Keycloak) · **Session governance** (concurrent limit + force-logout) · FK constraints with CASCADE · **Data retention** + GDPR docs |
| **4** | Observability & Ops | **OpenTelemetry** traces (OTLP + FastAPI/SQLAlchemy/Redis instrumentation) · `X-API-Version: v1` header · **Backup/DR** script + runbook · **Frontend test suite** (Vitest + RTL) |
| **5** | Tenant-aware controls & exec view | **Dynamic RBAC** per tenant in DB · **Circuit breaker** on connectors · **AES-256-GCM** field encryption (per-tenant HKDF) · **Executive dashboard** (MTTD/MTTR/SLA KPIs) · **SOC 2 / ISO 27001** readiness docs |

```mermaid
gantt
    title CyberTwin SOC — release timeline
    dateFormat YYYY-MM-DD
    axisFormat %b %d

    section v3.0.x · stabilised
        Live OCSF ingestion           :done, a1, 2026-04-19, 1d
        Helm chart + 6-job CI         :done, a2, 2026-04-20, 1d
        Senior architect audit        :done, a3, 2026-04-25, 1d

    section v3.1.0 · hardening
        JWT jti + refresh rotation          :done, b1, 2026-04-27, 1d
        nginx-unprivileged · CORS strict    :done, b2, 2026-04-27, 1d
        Split 13 routers · AI sec tests     :done, b3, 2026-04-27, 1d
        SQLAlchemy + Alembic + tenant_id    :done, b4, 2026-04-27, 1d
        quality-gate CI · Checkov · 64-char :done, b5, 2026-04-27, 1d

    section v3.2.0 · multi-tenancy & hardening
        Phase 1 — Arq worker + Redis Streams   :done, d1, 2026-04-28, 1d
        Phase 2 — Multi-tenancy runtime         :done, d2, 2026-04-28, 1d
        Phase 3 — OIDC + audit chain + sessions :done, d3, 2026-04-28, 1d
        Phase 4 — OpenTelemetry + backup/DR     :done, d4, 2026-04-28, 1d
        Phase 5 — RBAC + encryption + exec dash :done, d5, 2026-04-28, 1d
```

---

## 📊 Project at a glance

```mermaid
flowchart TB
    ROOT(("CyberTwin SOC v3.2"))

    BE["Backend"]
    FE["Frontend"]
    DET["Detection"]
    SOC["SOC"]
    OPS["Ops"]
    ENT["Enterprise"]

    ROOT --> BE & FE & DET & SOC & OPS & ENT

    BE --- BE1["Python 3.12<br/>18+ packages · Arq worker"]
    BE --- BE2["80+ endpoints · 855 pytest · 867 automated QA ✅"]

    FE --- FE1["React 18 + Vite<br/>27 pages · Vitest"]
    FE --- FE2["Recharts + ReactFlow"]

    DET --- DET1["46 rules + Sigma loader"]
    DET --- DET2["622 MITRE techniques · 14 tactics"]
    DET --- DET3["OCSF 1.0"]

    SOC --- SOC1["Cases · SLA<br/>Feedback · Suppressions"]
    SOC --- SOC2["AI analyst · ML anomaly"]

    OPS --- OPS1["Docker Compose · Helm · Arq worker"]
    OPS --- OPS2["Prometheus + OpenTelemetry"]
    OPS --- OPS3["Backup/DR · 9-job CI"]

    ENT --- ENT1["Multi-tenancy · OIDC/SSO"]
    ENT --- ENT2["AES-256-GCM · Audit chain"]
    ENT --- ENT3["Dynamic RBAC · Circuit breaker"]

    classDef root fill:#1e293b,stroke:#0f172a,color:#fff
    classDef cat fill:#dbeafe,stroke:#3b82f6,color:#1e3a8a
    classDef item fill:#f8fafc,stroke:#cbd5e1,color:#334155

    class ROOT root
    class BE,FE,DET,SOC,OPS,ENT cat
    class BE1,BE2,FE1,FE2,DET1,DET2,DET3,SOC1,SOC2,OPS1,OPS2,OPS3,ENT1,ENT2,ENT3 item
```

| Metric                              |   Count | Notes                                                                     |
|-------------------------------------|--------:|---------------------------------------------------------------------------|
| **Backend Python**                  |  18 000+ | 20+ packages — `api`, `detection`, `soc`, `ingestion`, `db`, `auth`, `crypto`, `middleware`, `observability`, … |
| **Frontend React/JSX**              |  13 000+ | 27 pages (incl. Executive dashboard), Vitest test suite, Recharts         |
| **Unit & integration tests**        |    867  | Backend: pytest (855) · Vitest RTL (10) · Playwright smoke (2) · see [`docs/proof/test-report-v3.2.md`](docs/proof/test-report-v3.2.md) |
| **REST + WebSocket endpoints**      |     80+ | Rate-limited per tenant:user, RBAC-scoped, `X-API-Version: v1` header    |
| **MITRE ATT&CK techniques**         |     622 | Full Enterprise matrix · 14 tactics · TAXII 2.1 sync                      |
| **Built-in detection rules**        |      46 | 14 platforms · severity-tiered · runtime Sigma upload                     |
| **Attack scenarios**                |      11 | Solorigate, ProxyShell, Log4Shell, Insider, Ransomware, …                 |
| **RBAC roles / scoped permissions** | 12 / 30+ | 3 legacy + 9 enterprise + **dynamic per-tenant roles in DB**              |
| **Connectors (extensible)**         |  15 (**5** production-grade) | Splunk, Sentinel (Log Analytics), TheHive, **Jira**, **MISP** — REST + retry + breaker + `mock_mode` tests; 10 remaining stubs share the same hardened surface |
| **Known CVEs in dependencies**      |       0 | Verified by `pip-audit --strict` and `npm audit`                          |
| **Database**                        |  11+ tables | Alembic migrations `0001`–`0005` · FK constraints · ORM-first (SQLite dev fallback) |
| **v3.2.0 hardening features**       |   22   | Multi-tenancy · OIDC/SSO · AES-256-GCM encryption · OTel · session governance · audit chain · backup/DR |

---

## ⚖ Scope, honesty & limits

CyberTwin SOC is built for teams that want a **credible SOC twin** backed by reproducible artefacts — **not** a turnkey commercial SIEM substitute. Useful framing:

| Topic | Straight answer |
|------|-----------------|
| **Test counts** | **867** automated runs (**855** `pytest` + **10** Vitest + **2** Playwright). Authoritative proof: [`docs/proof/test-report-v3.2.md`](docs/proof/test-report-v3.2.md). Reproducible locally — `python -m pytest -q` reports `855 passed`. |
| **MITRE rule-mapped** | **40 / 622 (6.43 %)** ([`docs/proof/mitre-coverage-snapshot.md`](docs/proof/mitre-coverage-snapshot.md)). The 622 number is the count of entries (194 top-level + 428 sub-techniques) in [`backend/mitre/techniques_bundle.json`](backend/mitre/techniques_bundle.json). Honest for a POC benchmark; far from exhaustive production detection coverage. |
| **Frontend quality** | Vitest RTL (`frontend-tests-report`) + Playwright **`frontend/e2e/`** smoke in CI — extended login→case journeys still backlog ([`docs/IMPROVEMENTS.md`](docs/IMPROVEMENTS.md)). |
| **Connectors** | **15** surface areas; **five** production-style integrations (Splunk, Sentinel, TheHive, Jira, MISP) + **10** stubs with the same hardened surface ([Connector framework diagram](#connector-framework)). |
| **Demo visuals** | **No** binary GIF in-repo yet — storyboard lives in [`docs/demo/README.md`](docs/demo/README.md). |
| **Source layout** | Key entry points (**e.g.** [`backend/api/main.py`](backend/api/main.py), [`backend/detection/engine.py`](backend/detection/engine.py)) are normal PEP 8 modules. If GitHub “raw” or diff looks like one mega-line, reopen the formatted view or clone locally — the repo itself is maintainability-oriented. |

---

## ✅ Validation status

> **Honesty rule** — every claim in this README has a corresponding artefact in [`docs/proof/`](docs/proof/). When a number changes, both the README and the proof file are updated in the same commit.

| Area                      | Status                                                | Evidence |
|---------------------------|-------------------------------------------------------|----------|
| **Backend tests**         | ✅ 855 passing                                         | [`docs/proof/test-report-v3.2.md`](docs/proof/test-report-v3.2.md) |
| **Frontend tests**        | ✅ 10 passing (Vitest + RTL smoke)                     | [`docs/proof/frontend-tests-report.md`](docs/proof/frontend-tests-report.md) |
| **Playwright E2E**       | ✅ 2 smoke (Chromium)                                  | [`frontend/e2e/`](frontend/e2e/) |
| **Combined automated QA** | ✅ **867** (855 + 10 + 2)                              | Proof files above |
| **Code coverage**         | ✅ ~72 % (gate: ≥ **71** %, **goal 80 %+**)              | `pytest --cov=backend --cov-fail-under=71` |
| **Frontend build**        | ✅ Passing                                             | GitHub Actions `Frontend Build` job |
| **Docker build**          | ✅ Retry-loop healthcheck on `/api/health` & `/health` | [`docs/proof/docker-validation.md`](docs/proof/docker-validation.md) |
| **Helm chart**            | ✅ Lint + render in CI                                 | `helm-lint` job + uploaded `helm-rendered-{sha}` artefact |
| **Compose profiles**      | ✅ default + `soar`                                    | [`docs/proof/docker-validation.md`](docs/proof/docker-validation.md) |
| **Code quality**          | ✅ flake8 = 0 errors                                   | `Code Quality` CI job |
| **Security gates**        | ✅ `pip-audit`, `npm audit`, `gitleaks` — **blocking** | [`docs/proof/security-scan-summary.md`](docs/proof/security-scan-summary.md) |
| **Known CVEs**            | ✅ **0**                                               | [`docs/proof/security-scan-summary.md`](docs/proof/security-scan-summary.md) |
| **MITRE coverage**        | 📊 **40 / 622** rule-mapped (6.43 %) — honest         | [`docs/proof/mitre-coverage-snapshot.md`](docs/proof/mitre-coverage-snapshot.md) |
| **Pipeline benchmarks**   | 📊 3 scenarios × 3 runs · 4–13 s end-to-end           | [`docs/proof/benchmark-results.md`](docs/proof/benchmark-results.md) |
| **Audit report (deep)**   | 📋 7 domains scored · 4 critical issues fixed         | [`docs/proof/audit-report.md`](docs/proof/audit-report.md) |
| **SOC 2 readiness**       | 📋 CC1–CC9 mapped · gap analysis                      | [`docs/compliance/soc2-readiness.md`](docs/compliance/soc2-readiness.md) |
| **ISO 27001 readiness**   | 📋 Annex A control mapping                            | [`docs/compliance/iso27001-readiness.md`](docs/compliance/iso27001-readiness.md) |
| **GDPR data processing**  | 📋 Data categories, retention, rights                 | [`docs/compliance/gdpr-data-processing.md`](docs/compliance/gdpr-data-processing.md) |
| **Backup/DR runbook**     | 📋 PostgreSQL + Redis + verification                  | [`docs/operations/backup-recovery.md`](docs/operations/backup-recovery.md) |

Legend: ✅ green, continuously enforced · 📊 measured snapshot · 📋 narrative report · ⏳ work in progress.

---

## 🏗 Architecture

### High-level component diagram

```mermaid
flowchart TB
    subgraph Client["👤 Client tier"]
        UI["🖥️ React 18 + Vite SPA<br/>26 pages · Recharts · ReactFlow"]
    end

    subgraph Edge["🌐 Edge"]
        NX["nginx-unprivileged (uid 101)<br/>CSP · HSTS · X-Frame-Options"]
    end

    subgraph API["⚙️ API tier — FastAPI 0.136"]
        MW["Middleware<br/>RequestID · Metrics · Audit · CORS · RateLimit · CSP"]
        ROUT["14 Routers<br/>health · auth · simulation · results · ingestion · scenarios<br/>coverage · soc · soar · mitre · environment · history"]
        DEPS["Shared deps<br/>JWT (jti+refresh) · 12-role scoped RBAC · slowapi"]
    end

    subgraph Core["🧠 Core domain"]
        SIM["🎭 Simulation<br/>11 scenarios · 28 techniques"]
        TEL["📡 Telemetry<br/>LogEvent → OCSF"]
        DET["🔍 Detection engine<br/>46 rules + Sigma loader"]
        COR["🧩 Correlation<br/>Alerts → Incidents"]
        SCO["🏆 Scoring<br/>NIST CSF + CIS"]
        AI["🤖 AI Analyst<br/>Ollama + NLG fallback<br/>PII redaction · prompt sanitise"]
        ANO["📈 ML Anomaly<br/>IsolationForest · UEBA"]
        SOC["🚨 SOC Workflow<br/>Cases · SLA · Feedback · Suppressions"]
        COV["🎯 Coverage Center<br/>8-state machine"]
    end

    subgraph Data["💾 Data tier"]
        DB[("PostgreSQL / SQLite<br/>11+ ORM tables · 5 migrations<br/>SQLAlchemy 2.0 + Alembic")]
        REDIS[("Redis<br/>cache · jti · rate-limit<br/>Streams · sessions · jobs")]
        BUF["Redis Streams<br/>50 k events<br/>(deque fallback)"]
    end

    subgraph Obs["📊 Observability"]
        PROM["Prometheus<br/>/api/metrics"]
        OTEL["OpenTelemetry<br/>OTLP traces"]
        LOG["JSON logs<br/>W3C trace context"]
    end

    subgraph Ext["🔌 External"]
        SOAR["SOAR<br/>TheHive 5 + Cortex 3"]
        TAXII["TAXII 2.1<br/>MITRE ATT&CK"]
        CONN["Connectors<br/>Splunk · Sentinel · Elastic · Defender · Jira · ServiceNow · MISP …"]
    end

    UI -->|HTTPS + JWT| NX --> MW --> ROUT --> DEPS
    DEPS --> SIM & DET & SOC & COV & AI & ANO
    SIM --> TEL --> DET --> COR --> SCO --> AI
    DET --> SOC
    BUF --> DET
    SOC <--> DB
    DET --> COV
    SOC <--> REDIS
    DET <--> REDIS
    DEPS --> PROM & OTEL & LOG
    SOC <--> SOAR
    COV <--> TAXII
    SOC <--> CONN
    DET <--> CONN

    classDef client fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef api fill:#dbeafe,stroke:#3b82f6,color:#1e3a8a
    classDef core fill:#e0e7ff,stroke:#6366f1,color:#312e81
    classDef data fill:#dcfce7,stroke:#22c55e,color:#14532d
    classDef obs fill:#f3e8ff,stroke:#a855f7,color:#581c87
    classDef ext fill:#fee2e2,stroke:#ef4444,color:#7f1d1d

    class UI client
    class NX,MW,ROUT,DEPS api
    class SIM,TEL,DET,COR,SCO,AI,ANO,SOC,COV core
    class DB,REDIS,BUF data
    class PROM,OTEL,LOG obs
    class SOAR,TAXII,CONN ext
```

### 🔐 Token lifecycle (v3.2.0)

```mermaid
sequenceDiagram
    autonumber
    participant U as User
    participant API as FastAPI
    participant CACHE as "Redis — jti denylist"
    participant DB as audit_log

    rect rgb(220, 252, 231)
    Note over U,DB: LOGIN
    U->>API: POST /api/auth/login {user, pass}
    API->>API: bcrypt verify · sign access (1h, jti_1) + refresh (7d, jti_2)
    API->>DB: log LOGIN
    API-->>U: {access_token, refresh_token, expires_in: 3600}
    end

    rect rgb(219, 234, 254)
    Note over U,DB: NORMAL CALL
    U->>API: GET /api/anything (Bearer jti_1)
    API->>CACHE: GET revoked_jti:jti_1
    CACHE-->>API: nil (still valid)
    API-->>U: 200 OK
    end

    rect rgb(254, 252, 232)
    Note over U,DB: REFRESH
    U->>API: POST /api/auth/refresh (refresh_token jti_2)
    API->>CACHE: SET revoked_jti:jti_2 TTL=remaining
    API->>API: sign new access (jti_3) + refresh (jti_4)
    API-->>U: {access_token, refresh_token}
    end

    rect rgb(254, 226, 226)
    Note over U,DB: LOGOUT
    U->>API: POST /api/auth/logout (Bearer jti_3)
    API->>CACHE: SET revoked_jti:jti_3 TTL=remaining
    API->>DB: log LOGOUT
    API-->>U: 200 {status: "logged_out"}
    Note over CACHE: Subsequent calls with jti_3 return 401
    end
```

### End-to-end simulation pipeline

```mermaid
sequenceDiagram
    autonumber
    participant U as 🧑 Analyst
    participant API as ⚙️ FastAPI
    participant ORC as 🎼 Orchestrator
    participant ENV as 🏢 Environment
    participant ATK as 🎭 AttackEngine
    participant TEL as 📡 Telemetry
    participant DET as 🔍 Detection
    participant SCO as 🏆 Scoring
    participant AI as 🤖 AI Analyst
    participant WS as 🔌 WebSocket

    U->>API: POST /api/simulate {scenario_id}
    API->>ORC: run_pipeline()
    ORC->>ENV: load_assets() / load_users()
    ORC->>ATK: execute(scenario)
    ATK-->>ORC: attack events (28 techniques)
    ORC->>TEL: generate(events + benign noise)
    TEL-->>ORC: log events (OCSF)
    ORC->>DET: run(rules + sigma)
    DET-->>ORC: alerts + incidents
    ORC->>SCO: compute(alerts, incidents)
    SCO-->>ORC: NIST CSF + CIS scores
    ORC->>AI: analyse_with_evidence(report)
    AI-->>ORC: narrative + IOCs + recommendations
    ORC-->>API: final_report
    API-->>WS: progress · phase · alerts (live)
    API-->>U: 200 + report URL
```

### Live SOC ingestion (OCSF)

```mermaid
flowchart LR
    subgraph Sources["🛰 Sources"]
        W["Windows EventLog<br/>4624 · 4625 · 4688 · …"]
        S["Sysmon<br/>1 · 3 · 7 · 8 · …"]
        SY["Syslog 3164 / 5424"]
        CT["AWS CloudTrail"]
        JS["Generic JSON"]
    end

    subgraph Norm["🔄 Normaliser"]
        M["mappers.py<br/>→ OCSF 1.0"]
    end

    subgraph Ingest["📥 Ingestion API · 9 endpoints"]
        E1["/event"]
        E2["/batch ≤ 5000"]
        E3["/syslog"]
        E4["/upload NDJSON ≤ 25 MB"]
        E5["/detect"]
    end

    subgraph Buf["💾 Redis Streams buffer"]
        B["50 000 events<br/>persistent · MAXLEN<br/>(deque fallback)"]
    end

    subgraph Det["🧠 Same Detection brain"]
        R["46 rules + Sigma uploads"]
    end

    Sources --> Norm --> Ingest --> Buf --> Det
    Det -->|alerts| SOC["🚨 SOC Workflow"]
    Det -->|metrics| Prom["📊 Prometheus"]

    classDef src fill:#fef3c7,stroke:#f59e0b
    classDef nrm fill:#dbeafe,stroke:#3b82f6
    classDef ing fill:#e0e7ff,stroke:#6366f1
    classDef buf fill:#dcfce7,stroke:#22c55e
    classDef det fill:#fee2e2,stroke:#ef4444

    class W,S,SY,CT,JS src
    class M nrm
    class E1,E2,E3,E4,E5 ing
    class B buf
    class R det
```

### Backend module dependency graph

```mermaid
flowchart TB
    api["📡 api/<br/>(routes + deps)"]
    auth["🔑 auth/<br/>JWT · OIDC · RBAC · sessions"]
    audit["📋 audit.py<br/>SHA-256 chain"]
    cache["🔴 cache.py<br/>(Redis · in-mem)"]

    db["🗄️ db/<br/>SQLAlchemy ORM<br/>TenantRepository"]
    crypto["🔒 crypto/<br/>AES-256-GCM"]
    mw["🔄 middleware/<br/>TenantScope"]

    sim["🎭 simulation/"]
    tel["📡 telemetry/"]
    det["🔍 detection/"]
    cov["🎯 coverage/"]
    soc["🚨 soc/"]
    ing["📥 ingestion/"]
    norm["🔄 normalization/"]
    mitre["🎯 mitre/"]

    ai["🤖 ai_analyst/<br/>5 mixins"]
    llm["💬 llm_analyst.py"]
    orch["🎼 orchestrator.py"]
    score["🏆 scoring/"]

    obs["📊 observability/"]
    rep["📄 reports/"]
    soar["🤝 soar/"]
    conn["🔌 connectors/"]

    api --> auth & audit & cache
    api --> sim & det & cov & soc & ing & mitre & soar
    auth --> cache
    sim --> tel & orch
    det --> norm & mitre
    ing --> norm & det
    soc --> db
    api --> mw & crypto
    cov --> det & mitre
    orch --> sim & det & score & ai & rep
    ai --> llm
    soar --> conn

    classDef pl fill:#dbeafe,stroke:#3b82f6
    classDef dom fill:#e0e7ff,stroke:#6366f1
    classDef data fill:#dcfce7,stroke:#22c55e
    classDef ai fill:#f3e8ff,stroke:#a855f7
    classDef ops fill:#fef3c7,stroke:#f59e0b

    class api,auth,audit,cache pl
    class sim,tel,det,cov,soc,ing,norm,mitre dom
    class db,crypto,mw data
    class ai,llm,orch,score ai
    class obs,rep,soar,conn ops
```

---

## 🚀 Features

### 🎭 Adversary simulation engine
- **11 turn-key scenarios** — Solorigate, ProxyShell, Log4Shell, Insider, Lateral movement, Cryptominer, Watering Hole, Living-off-the-Land, Ransomware, Cloud Attack, DDoS Infrastructure
- **28 baked-in attack techniques** with MITRE ATT&CK ID on every event
- **Path-traversal-proof scenario builder** with strict id validation
- **Realistic timeline generator** that interleaves benign user activity with adversarial actions

### 🔍 Multi-source detection engine
- **46 built-in rules** — Windows EID, Sysmon, Linux audit, web access, DNS, network, AWS CloudTrail, Azure activity, Office 365
- **Sigma loader** — upload `*.yml` rules at runtime, **ReDoS-hardened** (`re.escape` + `fullmatch`, 256 KB body cap)
- **Severity tiering** + confidence weighting + tactic-diversity bonus
- **Incident correlation** — alerts → incidents (kill-chain phase aggregation, multi-host pivot detection)

### 🎯 MITRE ATT&CK Coverage Center *(honest, not vapourware)*

```mermaid
stateDiagram-v2
    direction LR
    [*] --> NOT_COVERED
    NOT_COVERED --> RULE_EXISTS: enable rule
    RULE_EXISTS --> RULE_UNTESTED: rule loaded
    RULE_UNTESTED --> TESTED_DETECTED: scenario triggers rule ✅
    RULE_UNTESTED --> TESTED_FAILED: scenario fails to trigger ❌
    TESTED_DETECTED --> LOG_MISSING: required log absent
    RULE_EXISTS --> MUTED: noisy → suppressed
    RULE_EXISTS --> DEPRECATED: replaced
    TESTED_FAILED --> RULE_UNTESTED: re-test

    note right of TESTED_DETECTED: Validated (time-to-detect measured)
    note right of TESTED_FAILED: Regression (blocks merge)
```

8 honest states (`NOT_COVERED`, `RULE_EXISTS`, `RULE_UNTESTED`, `TESTED_DETECTED`, `TESTED_FAILED`, `LOG_MISSING`, `MUTED`, `DEPRECATED`) with **time-to-detect**, **severity-weighted confidence**, and **per-tactic risk score** weighted toward Initial Access, Privilege Escalation and Exfiltration.

### 🤖 AI Analyst (LLM + deterministic fallback)
- Ollama-compatible (Llama 3, Mistral, Qwen) with automatic fallback to a **fully deterministic NLG template**, so reports are always produced
- **Evidence-first** narrative — every claim grounded on an alert ID or log timestamp
- **Prompt-injection hardened** — `_sanitise()` redacts AWS/GCP/JWT/PEM keys, emails, passwords, credit cards, neutralises injection markers, hard-caps the prompt at 32 KB
- IOC extractor — external/internal IPs, domains, URLs, **MD5/SHA1/SHA256 hashes**, **emails**, compromised accounts
- **30+ adversarial tests** in `tests/test_ai_analyst.py` covering prompt-injection, PII redaction, APT attribution guard and IOC integrity

### 📈 ML anomaly detection & UEBA
- IsolationForest baseline trained on benign telemetry
- Per-user behavioural drift score
- Configurable contamination rate; warm-start on retrain

### 🚨 SOC workflow (alerts → cases → SLA)

```mermaid
flowchart LR
    AL[("🛎 Alert")] --> CA{Case<br/>auto/manual}
    CA -->|new| NEW["📝 NEW"]
    NEW -->|assign| IP["🛠 IN_PROGRESS"]
    IP -->|resolved| RES["✅ RESOLVED"]
    IP -->|false-positive| FP["🟡 FALSE_POSITIVE"]
    RES -->|verify| CL["🔒 CLOSED"]
    FP -->|verify| CL

    IP -. comment / evidence .-> IP
    IP -. SLA timer by severity hrs .-> IP
    FP -- updates rule confidence --> RULE["📊 Rule confidence"]
    FP -- suggests --> SUP["🤫 Suppression w/ TTL"]

    classDef state fill:#dbeafe,stroke:#3b82f6
    classDef done fill:#dcfce7,stroke:#22c55e
    classDef fp fill:#fef3c7,stroke:#f59e0b
    class NEW,IP state
    class RES,CL done
    class FP fp
```

- PostgreSQL-backed case store (SQLite dev fallback) · status transitions · comments · evidence attachments · SLA hours per severity · FK constraints with CASCADE
- Analyst feedback (`true_positive` / `false_positive`) feeds back into rule confidence
- Scoped suppressions with TTL to silence known-noisy rules per host/user
- **SQL-injection-hardened** UPDATE composer (column allowlist + identifier regex, double-belt defence)

### 🤝 SOAR integration
- Optional `--profile soar` in docker-compose
- **TheHive 5** — auto-create cases, attach observables
- **Cortex 3** — run analyzers, enrich IOCs
- Bidirectional webhook in/out

### 🧪 Compliance benchmarking
- Maps every detection capability to **NIST CSF v1.1** sub-categories (`DE.AE-2`, `DE.CM-7`, …) and **CIS Controls v8** (CIS 8.11, CIS 13.6, …)
- Generates a compliance score per simulation
- Trend dashboard for posture improvement

### 🏷 Enterprise RBAC — 12 static roles × 30+ scoped permissions + dynamic per-tenant roles

```mermaid
flowchart TB
    subgraph L["⚪ Legacy roles"]
        ADM["🔴 admin"]
        ANA["🟢 analyst"]
        VIE["🔵 viewer"]
    end

    subgraph T["🟠 Tier-1 ops"]
        T1["tier1_analyst"]
        SE["senior_analyst"]
        SM["soc_manager"]
    end

    subgraph E["🟣 Engineering"]
        DE["detection_engineer"]
        TH["threat_hunter"]
    end

    subgraph R["🟡 Read-only / audit"]
        AU["auditor"]
        RX["read_executive"]
        SA["service_account"]
    end

    subgraph P["⚫ Platform"]
        PA["platform_admin"]
    end

    classDef leg fill:#f1f5f9,stroke:#64748b
    classDef tier fill:#fed7aa,stroke:#f97316
    classDef eng fill:#e9d5ff,stroke:#a855f7
    classDef ro fill:#fef3c7,stroke:#f59e0b
    classDef plat fill:#1e293b,stroke:#0f172a,color:#fff
    class ADM,ANA,VIE leg
    class T1,SE,SM tier
    class DE,TH eng
    class AU,RX,SA ro
    class PA plat
```

| Permission scope    | analyst | tier1 | senior | manager | det_eng | hunter | auditor | platform_admin |
|---------------------|:-------:|:-----:|:------:|:-------:|:-------:|:------:|:-------:|:--------------:|
| `simulation:run`    |   ✅    |       |   ✅   |   ✅    |    ✅   |   ✅   |         |       ✅       |
| `case:read/write`   |   ✅    |   ✅  |   ✅   |   ✅    |    ✅   |   ✅   |   👁️    |       ✅       |
| `case:assign`       |   ✅    |       |   ✅   |   ✅    |         |        |         |       ✅       |
| `case:close`        |   ✅    |       |   ✅   |   ✅    |         |        |         |       ✅       |
| `rule:create`       |         |       |        |         |    ✅   |        |         |       ✅       |
| `rule:approve`      |         |       |   ✅   |   ✅    |    ✅   |        |         |       ✅       |
| `rule:deploy`       |         |       |        |         |    ✅   |        |         |       ✅       |
| `ingestion:write`   |   ✅    |       |   ✅   |   ✅    |         |   ✅   |         |       ✅       |
| `ingestion:read`    |   ✅    |   ✅  |   ✅   |   ✅    |         |   ✅   |   👁️    |       ✅       |
| `ai:evidence`       |   ✅    |   ✅  |   ✅   |   ✅    |         |   ✅   |         |       ✅       |
| `suppression:create`|         |       |   ✅   |   ✅    |         |        |         |       ✅       |
| `audit:read/export` |         |       |        |   ✅    |         |        |   ✅    |       ✅       |

✅ = granted · 👁️ = read-only · empty = denied. Permissions are **scoped** (`resource:action`) — never blanket admin. Source: [`backend/auth/`](backend/auth/). Tenants can override with **dynamic roles** stored in `tenant_roles` DB table.

### 🔌 Connector framework

```mermaid
classDiagram
    direction LR
    class BaseConnector {
        <<interface>>
        +name
        +health() bool
    }
    class SIEMConnector { +query(qs) }
    class SOARConnector { +create_case(data) }
    class EDRConnector { +contain_host(id) }
    class ITSMConnector { +open_ticket(data) }
    class TIConnector { +lookup_ioc(ioc) }

    BaseConnector <|-- SIEMConnector
    BaseConnector <|-- SOARConnector
    BaseConnector <|-- EDRConnector
    BaseConnector <|-- ITSMConnector
    BaseConnector <|-- TIConnector

    SIEMConnector <|.. SplunkStub
    SIEMConnector <|.. SentinelStub
    SIEMConnector <|.. ElasticStub
    SOARConnector <|.. TheHiveStub
    EDRConnector <|.. CrowdStrikeStub
    EDRConnector <|.. DefenderStub
    ITSMConnector <|.. JiraStub
    ITSMConnector <|.. ServiceNowStub
    TIConnector <|.. MISPStub
    TIConnector <|.. OpenCTIStub

    class SplunkStub
    class SentinelStub
    class ElasticStub
    class TheHiveStub
    class CrowdStrikeStub
    class DefenderStub
    class JiraStub
    class ServiceNowStub
    class MISPStub
    class OpenCTIStub
```

---

## ⚡ Quick start

### Option A — Docker Compose (recommended)

```bash
git clone https://github.com/omarbabba779xx/CyberTwin-SOC.git
cd CyberTwin-SOC

# Set strong secrets BEFORE first run
cp .env.example .env
# edit .env: set JWT_SECRET (>= 64 chars in production) + AUTH_*_PASSWORD

docker compose up -d
```

| Service        | URL                                         | Notes                                        |
|----------------|---------------------------------------------|----------------------------------------------|
| Frontend       | <http://localhost>                          | nginx-unprivileged, port 80→8080             |
| API + OpenAPI  | <http://localhost:8000/docs>                |                                              |
| Prometheus     | <http://localhost:8000/api/metrics>         | restrict via `RESTRICT_INTERNAL_ENDPOINTS=true` |
| Health (deep)  | <http://localhost:8000/api/health/deep>     | restrict via env var in prod                 |

### Option B — Local development

```bash
# Backend
python -m venv .venv && .venv/Scripts/Activate.ps1   # Windows
pip install -r requirements.txt

# Optional: PostgreSQL via DATABASE_URL + Alembic migrations
export DATABASE_URL=postgresql+psycopg2://user:pass@host:5432/cybertwin
alembic upgrade head

uvicorn backend.api.main:app --reload --port 8000

# Frontend
cd frontend && npm ci && npm run dev    # http://localhost:5173
```

### Option C — Kubernetes via Helm

```bash
helm install cybertwin deploy/helm/cybertwin-soc \
  --set ingress.host=soc.example.com \
  --set serviceMonitor.enabled=true \
  --create-namespace -n cybertwin
```

`runAsNonRoot`, `drop:[ALL]`, liveness/readiness/startup probes, and a `ServiceMonitor` for `kube-prometheus-stack` are all pre-wired.

---

## 📥 Live telemetry ingestion (OCSF)

### Single Windows logon event

```bash
curl -X POST http://localhost:8000/api/ingest/event \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "source": "windows_security",
        "event_id": 4625,
        "host": "WIN-DC-01",
        "user": "alice",
        "src_ip": "203.0.113.45",
        "raw": "..."
      }'
```

### NDJSON bulk upload (≤ 25 MB)

```bash
curl -X POST http://localhost:8000/api/ingest/upload \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/x-ndjson" \
  --data-binary @sample.ndjson
```

### Run detection over the event buffer

```bash
curl -X POST http://localhost:8000/api/ingest/detect -H "Authorization: Bearer $TOKEN"
```

> **One detection brain** — the ingestion path reuses the **same** 46 rules + every Sigma rule uploaded at runtime. Zero duplication between simulation and live detection.

**Hardening shipped (Apr 2026 audit)**: `ingestion:write` scoped permission · per-event 64 KB cap · syslog 5 000 lines × 8 KB cap · `_approx_size()` total guard · 600 req/min single, 60 req/min batch.

---

## 🎯 Detection Coverage Center

```bash
curl http://localhost:8000/api/coverage \
  -H "Authorization: Bearer $TOKEN" | jq '.summary'
```

```json
{
  "catalog_total": 622,
  "validated": 0,
  "untested": 40,
  "rule_mapped": 40,
  "not_covered": 582,
  "high_risk_gaps": 293,
  "rule_mapped_pct": 6.43
}
```

> The number of validated techniques is conservative on purpose: **a rule is validated only when a scenario exercises the technique AND the rule fires.** This is the number a CISO actually wants — not the catalogue size with optimistic mapping.

Latest snapshot: [`docs/proof/mitre-coverage-snapshot.md`](docs/proof/mitre-coverage-snapshot.md)

---

## 🎫 SOC workflow

| Method  | Path                                  | Permission         | Purpose                                    |
|--------:|---------------------------------------|--------------------|--------------------------------------------|
| `POST`  | `/api/cases`                          | `case:write`       | Open a case from an alert                  |
| `GET`   | `/api/cases`                          | `case:read`        | List with filters & SLA status             |
| `GET`   | `/api/cases/{id}`                     | `case:read`        | Fetch full case (comments + evidence)      |
| `PATCH` | `/api/cases/{id}`                     | `case:write`       | Update status/assignee (allowlist)         |
| `POST`  | `/api/cases/{id}/comments`            | `case:write`       | Append a comment                           |
| `POST`  | `/api/cases/{id}/evidence`            | `case:write`       | Attach evidence artefact                   |
| `POST`  | `/api/cases/{id}/assign`              | `case:assign`      | Assign analyst                             |
| `POST`  | `/api/cases/{id}/close`               | `case:close`       | Close with closure reason                  |
| `POST`  | `/api/alerts/{alert_id}/feedback`     | `feedback:write`   | TP / FP feedback for a rule                |
| `POST`  | `/api/suppressions`                   | `suppression:create` | Add scoped suppression with TTL          |

---

## ⚙️ Background jobs (Arq worker)

Heavy workloads (long simulations, report exports, data retention) run in a
**separate Arq worker container** backed by Redis. The API enqueues tasks via
`arq.create_pool()` and falls back to in-process execution if the worker is
unavailable (seamless for tests and local dev without Redis).

| Method  | Path                       | Permission       | Purpose                                                       |
|--------:|----------------------------|------------------|---------------------------------------------------------------|
| `GET`   | `/api/tasks`               | `view_results`   | List registered task types                                    |
| `GET`   | `/api/tasks/{task_id}`     | `view_results`   | Poll status (`queued` / `running` / `succeeded` / `failed`)   |
| `DELETE`| `/api/tasks/{task_id}`     | `simulation:run` | Cancel (cooperative for in-process executor today)            |

```mermaid
sequenceDiagram
    autonumber
    participant U as 🧑 Analyst
    participant API as ⚙️ FastAPI
    participant REG as 🗂 jobs/registry
    participant CACHE as 🔴 Redis
    participant TASK as 🛠 task fn

    U->>API: POST /api/coverage/recalculate
    API->>REG: enqueue("coverage_recalculate")
    REG->>CACHE: set cybertwin:task:{id} status=queued
    REG->>TASK: await fn(task_id, **kw)
    TASK->>CACHE: progress 30 → 100
    TASK-->>REG: result
    REG->>CACHE: set status=succeeded · result
    API-->>U: 202 {task_id}

    Note over U,API: Client polls
    U->>API: GET /api/tasks/{id}
    API->>CACHE: read cybertwin:task:{id}
    CACHE-->>API: {status, progress, result}
    API-->>U: 200 {status: succeeded, progress: 100, result: ...}
```

Status payload:

```json
{
  "task_id": "a1b2c3d4e5f6g7h8",
  "task": "coverage_recalculate",
  "status": "succeeded",
  "progress": 100,
  "result": { "summary": { "catalog_total": 622, "validated": 0 } },
  "error": null,
  "enqueued_at": "2026-04-28T09:14:02+00:00",
  "started_at":  "2026-04-28T09:14:02+00:00",
  "finished_at": "2026-04-28T09:14:03+00:00"
}
```

---

## 📊 Observability & metrics

```mermaid
flowchart LR
    REQ["📥 Inbound request"] --> RID["RequestIDMiddleware<br/>X-Request-ID"]
    RID --> TNT["TenantScopeMiddleware<br/>JWT → tenant_id"]
    TNT --> AUTH["AuthMiddleware<br/>JWT (jti check) + RBAC"]
    AUTH --> RL["RateLimit<br/>tenant:user key"]
    RL --> AUD["AuditMiddleware<br/>SHA-256 chained → audit_log"]
    AUD --> METR["MetricsMiddleware<br/>Prometheus + OTel spans"]
    METR --> VER["APIVersionMiddleware<br/>X-API-Version: v1"]
    VER --> SEC["SecurityHeadersMiddleware<br/>CSP · HSTS · X-Frame · …"]
    SEC --> APP["⚙️ Application logic"]
    APP --> LOG["🪵 JSON log<br/>W3C trace context"]
    APP --> RESP["📤 Response"]

    classDef mw fill:#dbeafe,stroke:#3b82f6,color:#1e3a8a
    class RID,TNT,AUTH,RL,AUD,METR,VER,SEC mw
```

```promql
# p95 API latency per endpoint
histogram_quantile(0.95,
  sum by (path,le)(rate(cybertwin_request_latency_seconds_bucket[5m])))

# ingestion EPS by source
sum by (source)(rate(cybertwin_ingest_events_total[1m]))

# rolling FP rate per rule
sum by (rule_id)(rate(cybertwin_feedback_total{verdict="false_positive"}[24h]))
  / sum by (rule_id)(rate(cybertwin_feedback_total[24h]))
```

---

## 🔐 Security posture

```mermaid
flowchart TB
    subgraph L1["🌐 Edge"]
        N["nginx-unprivileged<br/>uid 101 · CSP · HSTS"]
    end
    subgraph L2["🔑 Auth & sessions"]
        A1["bcrypt 12 rounds"]
        A2["JWT HS256 · 64-char min"]
        A3["jti denylist (Redis)"]
        A4["Refresh rotation 1h/7d"]
    end
    subgraph L3["🛡️ Request"]
        R1["CORS strict"]
        R2["12-role scoped RBAC"]
        R3["slowapi rate-limit"]
        R4["Pydantic validation"]
    end
    subgraph L4["💉 Code-level"]
        C1["SQL allowlist + regex"]
        C2["YAML safe_load"]
        C3["ReDoS-proof regex"]
        C4["_safe_path() traversal guard"]
    end
    subgraph L5["🤖 AI"]
        I1["PII redaction"]
        I2["Prompt-injection sanitise"]
        I3["32 KB hard cap"]
    end
    subgraph L6["📋 Audit & supply chain"]
        S1["audit_log on every state-change"]
        S2["pip-audit · gitleaks · Checkov"]
        S3["CycloneDX SBOM"]
    end

    N --> A1
    A4 --> R1
    R4 --> C1
    C4 --> I1
    I3 --> S1
    classDef layer fill:#1e293b,color:#fff,stroke:#0f172a
    classDef ctrl fill:#dbeafe,stroke:#3b82f6
    class L1,L2,L3,L4,L5,L6 layer
    class N,A1,A2,A3,A4,R1,R2,R3,R4,C1,C2,C3,C4,I1,I2,I3,S1,S2,S3 ctrl
```

| Surface         | Control                                                                                              |
|-----------------|------------------------------------------------------------------------------------------------------|
| Auth            | bcrypt (12 rounds) · JWT HS256 (64-char key in prod) · **jti denylist** · **refresh rotation** · **OIDC/SSO** (Entra ID, Okta, Keycloak) |
| Sessions        | **Concurrent session limit** (configurable) · `POST /api/auth/revoke-all` force-logout · Redis-backed session tracking |
| Tokens          | 1h access token · 7d refresh token · `tenant_id` claim · `POST /api/auth/logout` revokes via denylist |
| API             | Rate-limit by **tenant:user** · CORS strict · 12-role scoped RBAC + **dynamic per-tenant roles in DB** |
| Encryption      | **AES-256-GCM** field-level encryption · per-tenant HKDF key derivation · `EncryptedString` TypeDecorator |
| HTTP headers    | `SecurityHeadersMiddleware` (backend) + `nginx.conf` (frontend) — CSP · HSTS · X-Frame              |
| File uploads    | `_safe_path()` regex + path-resolution check — no traversal possible                                 |
| Sigma loader    | YAML safe_load · 256 KB max · ReDoS-proof globbing · `re.fullmatch`                                  |
| SQL             | Parametrised queries · column allowlist + regex for dynamic `UPDATE` · SQLAlchemy 2.0 ORM            |
| LLM             | `_sanitise()` redacts PII/keys · prompt-injection markers neutralised · 32 KB hard cap              |
| Ingestion       | `ingestion:write` scoped permission · per-event 64 KB · syslog 5 000 × 8 KB · `_approx_size()` guard |
| Secrets         | env-driven · prod gate refuses start if weak · `.gitleaks.toml` allowlist                            |
| Containers      | `nginx-unprivileged` (uid 101) · `runAsNonRoot` · `drop:[ALL]` · multi-stage builds                 |
| Audit           | **Tamper-evident** audit trail with **SHA-256 chained hashing** · PostgreSQL append-only · `verify_audit_chain()` |
| DB              | SQLAlchemy 2.0 + Alembic · 11+ ORM tables · **FK constraints** with CASCADE · `tenant_id` on every model |
| Connectors      | **Circuit breaker** (CLOSED→OPEN→HALF_OPEN) + exponential retry on all external calls |
| Compliance      | **SOC 2 Type II** readiness mapping · **ISO 27001:2022** Annex A mapping · **GDPR** data processing docs |

### Continuous security checks

| Tool          | Scope                                          | Status |
|---------------|------------------------------------------------|:------:|
| **pip-audit** | Python dependency CVEs                         | ✅ **blocking** · 0 known CVE |
| **npm audit** | Frontend dependency CVEs (high+)               | ✅ **blocking** · 0 high |
| **Gitleaks**  | Secret scanning across full git history        | ✅ **blocking** · 0 leaks |
| **Bandit**    | Python static security analysis                | ⚠ non-blocking · 0 high |
| **Semgrep**   | Multi-language SAST                            | ⚠ non-blocking |
| **Trivy**     | Filesystem + container vuln scan               | ⚠ non-blocking |
| **Checkov**   | IaC scan (Dockerfile + Helm)                   | ⚠ non-blocking |
| **CycloneDX** | SBOM (Python + npm)                            | 📦 artefact upload |

Full audit report (7 domains scored, 4 critical issues fixed): [`docs/proof/audit-report.md`](docs/proof/audit-report.md).

---

## 🔄 CI/CD pipeline

```mermaid
flowchart LR
    PUSH["📥 git push / PR"] --> JOBS{9 parallel jobs}

    JOBS --> J1["🧪 Backend Tests<br/>pytest · ~30 s · cov ≥ 71 %"]
    JOBS --> J2["🐘 PostgreSQL Migration<br/>upgrade · downgrade · idempotency"]
    JOBS --> J3["⚛️ Frontend Build<br/>vite + Lighthouse CI"]
    JOBS --> J4["✨ Code Quality<br/>flake8 · 0 errors"]
    JOBS --> J5["🔐 Security Scans<br/>pip-audit · npm audit · gitleaks"]
    JOBS --> J6["🐳 Docker Build<br/>compose smoke + healthcheck"]
    JOBS --> J7["⎈ Helm Lint<br/>lint + render artefact"]
    JOBS --> J8["🏗️ Checkov<br/>Dockerfile · Helm IaC<br/>soft-fail"]

    J1 & J2 & J3 & J4 & J5 & J6 & J7 --> QG["🎯 quality-gate<br/>(7 blocking jobs<br/>for branch protection)"]
    J8 -.->|non-blocking| QG
    QG -->|✅| MERGE["🟢 Merge allowed"]
    QG -->|❌| BLOCK["🔴 Blocked"]

    classDef job fill:#dbeafe,stroke:#3b82f6,color:#1e3a8a
    classDef soft fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef pass fill:#dcfce7,stroke:#22c55e,color:#14532d
    classDef fail fill:#fee2e2,stroke:#ef4444,color:#7f1d1d
    class J1,J2,J3,J4,J5,J6,J7 job
    class J8 soft
    class QG,MERGE pass
    class BLOCK fail
```

---

## 🚢 Production deployment

### Docker Compose

```bash
# Full SOC stack (incl. SOAR)
docker compose --profile soar up -d

# Just the SOC core
docker compose up -d
```

| Service     | Port (host→container) | Purpose                                          |
|-------------|----------------------:|--------------------------------------------------|
| `frontend`  | 80 → 8080             | nginx-unprivileged (uid 101) React SPA           |
| `backend`   | 8000                  | FastAPI uvicorn (uid 1000 non-root)              |
| `worker`    | —                     | **Arq background worker** (Redis broker)         |
| `redis`     | 6379                  | cache · Streams · sessions · jobs · jti denylist |
| `thehive`   | 9000                  | (`soar` profile only — demo, no auth)            |
| `cortex`    | 9001                  | (`soar` profile only — demo, no auth)            |

### Helm

```bash
helm upgrade --install cybertwin deploy/helm/cybertwin-soc \
  --set image.backend.tag=v3.2.0 \
  --set image.frontend.tag=v3.2.0 \
  --set ingress.host=soc.example.com \
  --set ingress.tls.enabled=true \
  --set serviceMonitor.enabled=true
```

### Database migrations (PostgreSQL)

```bash
# Set DATABASE_URL once
export DATABASE_URL=postgresql+psycopg2://user:pass@host:5432/cybertwin

# Apply Alembic migrations (11+ tables, FK constraints, audit hash, tenant roles)
alembic upgrade head

# Roll back last migration
alembic downgrade -1
```

### Load benchmarks

```bash
# k6 — API load test (p95 < 500 ms gate)
k6 run benchmarks/k6_api_test.js -e BASE=http://localhost:8000 -e TOKEN=$JWT

# Locust — ingestion throughput
locust -f benchmarks/locust_ingestion.py --host http://localhost:8000

# Pipeline — end-to-end timing
python -m benchmarks.bench_pipeline
```

---

## 📂 Project structure

```mermaid
flowchart TB
    ROOT["📁 CyberTwin-SOC"]
    ROOT --> BE["🐍 backend/<br/>16 357 LoC · Python 3.12"]
    ROOT --> FE["⚛️ frontend/<br/>12 396 LoC · React 18 + Vite"]
    ROOT --> TS["🧪 tests/<br/>867 automated (855 py +10 RTL +2 E2E)<br/>100 % passing"]
    ROOT --> AL["🗄️ alembic/<br/>migration infra"]
    ROOT --> BM["📊 benchmarks/<br/>k6 · locust · pipeline · MITRE snapshot"]
    ROOT --> DEP["⎈ deploy/helm/<br/>chart + ServiceMonitor"]
    ROOT --> SC["📜 scenarios/<br/>11 attack JSON"]
    ROOT --> SCR["🔧 scripts/"]
    ROOT --> DOC["📖 docs/<br/>proof/ · compliance/ · operations/"]
    ROOT --> CI["🔄 .github/workflows/<br/>ci.yml — 9 jobs + gate"]
    ROOT --> JB["⚙️ backend/jobs/<br/>Arq-shaped task registry"]

    BE --> BE1["api/ — 14 routers + main.py + deps.py + errors.py"]
    BE --> BE2["detection/ — rules/ pkg (46 rules, by-tactic) + Sigma + correlation"]
    BE --> BE3["coverage/ — 8-state machine + gap analyzer"]
    BE --> BE4["soc/ — cases · feedback · suppressions"]
    BE --> BE5["ingestion/ — Redis Streams + pipeline"]
    BE --> BE6["mitre/ — 622 techniques · TAXII sync"]
    BE --> BE7["auth/ — JWT · OIDC · RBAC store · sessions"]
    BE --> BE8["observability/ — Prometheus · OpenTelemetry · JSON logs"]
    BE --> BE9["db/ — SQLAlchemy ORM (11+ models · TenantRepository)"]
    BE --> BE10["crypto/ — AES-256-GCM field encryption · HKDF"]
    BE --> BE11["middleware/ — TenantScope · RequestID · APIVersion"]
    BE --> BE12["connectors/ — circuit breaker · retry · 15 integrations"]
    BE --> BE13["jobs/ — Arq worker + task registry + data retention"]

    FE --> FE1["src/pages/ — 26 pages"]
    FE --> FE2["src/components/ — 10 reusable"]
    FE --> FE3["nginx.conf — CSP · HSTS · X-Frame · port 8080"]

    classDef root fill:#fef3c7,stroke:#f59e0b
    classDef be fill:#dbeafe,stroke:#3b82f6
    classDef fe fill:#fee2e2,stroke:#ef4444
    classDef ops fill:#dcfce7,stroke:#22c55e

    class ROOT root
    class BE,BE1,BE2,BE3,BE4,BE5,BE6,BE7,BE8,BE9,BE10,BE11,BE12,BE13 be
    class FE,FE1,FE2,FE3 fe
    class TS,AL,BM,DEP,SC,SCR,DOC,CI,JB ops
```

---

## 🧪 Quality & testing

### Test pyramid

```mermaid
flowchart TB
    E2E["🌐 End-to-end<br/>compose smoke · CI Postgres job<br/>breadth-first scenarios"]
    API["🔌 API · integration routers<br/>test_api · test_soc · test_ingestion · test_jobs<br/>router + workflow coverage"]
    UNIT["⚙️ Domain-heavy pytest (~bulk of 855)<br/>auth · tenancy · detection · rules · SOC · crypto · orch…"]

    UNIT --> API --> E2E

    classDef u fill:#dcfce7,stroke:#22c55e,stroke-width:2px
    classDef a fill:#dbeafe,stroke:#3b82f6,stroke-width:2px
    classDef e fill:#fef3c7,stroke:#f59e0b,stroke-width:2px
    class UNIT u
    class API a
    class E2E e
```

### Run locally

```bash
# Full suite
python -m pytest tests/ -v

# With coverage (gate: ≥ 71 %, goal 80 %+)
python -m pytest tests/ --cov=backend --cov-report=term-missing

# CI-equivalent lint
flake8 backend/ --max-line-length=120 --ignore=E501,W503,E402,E241,E231,E704

# Frontend E2E (Chromium smoke; CI job playwright-e2e)
cd frontend && npm ci && npm run test:e2e

# Local security scans
bandit -r backend/ -ll --skip B101,B104
pip-audit -r requirements.txt --strict
```

Current `master`:

```
============================ 855 passed in … s =============================
flake8: 0 errors · pip-audit: 0 CVE · npm audit: 0 high · gitleaks: 0 leaks
coverage: ~72 % (gate ≥ 71 % · target 80 %+)
```

---

## 📚 Documentation

| Document | Purpose |
|----------|---------|
| [`docs/proof/audit-report.md`](docs/proof/audit-report.md)                                 | Senior architect audit · 7 domains scored · 4 critical fixes |
| [`docs/proof/coverage-report.md`](docs/proof/coverage-report.md)                           | Pytest summary · code-path coverage |
| [`docs/proof/database-indexing-report.md`](docs/proof/database-indexing-report.md)         | DB index audit · 7 tables · 0 missing |
| [`docs/proof/mitre-coverage-snapshot.md`](docs/proof/mitre-coverage-snapshot.md)           | Honest 6.43 % rule-mapped snapshot |
| [`docs/proof/security-scan-summary.md`](docs/proof/security-scan-summary.md)               | pip-audit / Bandit / Gitleaks / Trivy / npm audit |
| [`docs/proof/benchmark-results.md`](docs/proof/benchmark-results.md)                       | Pipeline EPS · latency |
| [`docs/proof/docker-validation.md`](docs/proof/docker-validation.md)                       | Compose + Docker build proof |
| [`docs/operations/backup-recovery.md`](docs/operations/backup-recovery.md)                 | Backup/DR runbook (PostgreSQL, Redis, verification) |
| [`docs/compliance/soc2-readiness.md`](docs/compliance/soc2-readiness.md)                   | SOC 2 Type II readiness — CC1–CC9 mapping + gap analysis |
| [`docs/compliance/iso27001-readiness.md`](docs/compliance/iso27001-readiness.md)           | ISO 27001:2022 Annex A control mapping + remediation |
| [`docs/compliance/gdpr-data-processing.md`](docs/compliance/gdpr-data-processing.md)       | GDPR data categories, retention, subject rights |
| [`docs/IMPROVEMENTS.md`](docs/IMPROVEMENTS.md)                                             | Tiered backlog (Playwright GIF, connectors, polish) |
| [`CHANGELOG.md`](CHANGELOG.md)                                                             | Versioned change log |
| [`SECURITY.md`](SECURITY.md)                                                               | Vulnerability disclosure policy |
| [`CONTRIBUTING.md`](CONTRIBUTING.md)                                                       | How to contribute |
| [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)                                                 | Community standards |

---

## 🗺 Roadmap

> ✅ All 20 phases below are *delivered* on `master`.

```mermaid
gantt
    title CyberTwin SOC — delivery timeline
    dateFormat YYYY-MM-DD
    axisFormat %b
    section Foundation
    Sim engine + 11 scenarios     :done, p1, 2025-09-01, 30d
    Telemetry + LogEvent          :done, p2, after p1, 14d
    Detection 46 rules + Sigma    :done, p3, after p2, 21d
    section Intelligence
    LLM AI Analyst                :done, p4, after p3, 21d
    ML anomaly + UEBA             :done, p5, after p4, 14d
    MITRE 622 + TAXII             :done, p6, after p5, 14d
    section Platform
    Redis · WebSocket · async     :done, p7, after p6, 14d
    NIST CSF + CIS                :done, p8, after p7, 14d
    Frontend pages                :done, p9, after p8, 21d
    Test suite                    :done, p10, after p9, 14d
    section Operations
    Docker Compose                :done, p11, after p10, 7d
    SOAR (TheHive + Cortex)       :done, p12, after p11, 14d
    Stabilisation + governance    :done, p13, after p12, 14d
    Coverage Center 8-state       :done, p14, after p13, 14d
    SOC Workflow                  :done, p15, after p14, 14d
    Live OCSF ingestion           :done, p16, after p15, 14d
    Enterprise (Helm · RBAC ×12)  :done, p17, after p16, 21d
    section Hardening
    Audit Apr 2026                :done, p18, 2026-04-20, 7d
    v3.1.0 hardening release      :done, p19, 2026-04-27, 1d
    section Enterprise
    v3.2.0 hardening track        :done, p20, 2026-04-28, 1d
```

### Next ideas (not yet on `master`)

See [`docs/IMPROVEMENTS.md`](docs/IMPROVEMENTS.md) — **purple-team workflows**, **STIX/TAXII feed publishing**, **eBPF agent**, **detection-as-code GitOps**, **MFA**, etc. Connector-wise, **Splunk · Sentinel · TheHive · Jira · MISP** are wired with tests (`docs/proof/connectors-validation.md`); **Elastic, ServiceNow, OpenCTI, Defender**, … remain next.

---

## 🤝 Contributing & license

PRs welcome. The bar is:

1. `pytest tests/` is green (855+) and frontend `npm run test:e2e` passes locally when touching UI.
2. `flake8` is clean with the same flags CI uses.
3. New endpoints get a unit test **and** a scoped permission (`resource:action`).
4. New ATT&CK techniques get added to `backend/mitre/attack_data.py`.
5. No secrets, no hard-coded credentials, no path-traversal-prone string ops.
6. Security scans (`pip-audit`, `npm audit`, `gitleaks`) stay green — they are blocking.

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) before opening a PR.

**License**: MIT — see [`LICENSE`](LICENSE).

---

<div align="center">

**Built with ❤️ for the cybersecurity community.**

If this project saves your team a sprint, **[⭐ star the repo](https://github.com/omarbabba779xx/CyberTwin-SOC)** — it's the only metric I track.

</div>
