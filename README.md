<div align="center">

# 🛡️ CyberTwin SOC

### **Enterprise-Grade Security Operations Center — Open Source**

*A complete cyber-range that emulates real adversary tradecraft, exercises 622 MITRE ATT&CK techniques, ingests live security telemetry in OCSF, and ships with full SOC workflow, AI analyst, ML anomaly detection, SOAR integration, Prometheus observability, and Helm/Kubernetes deployment.*

[![CI](https://github.com/omarbabba779xx/CyberTwin-SOC/actions/workflows/ci.yml/badge.svg)](https://github.com/omarbabba779xx/CyberTwin-SOC/actions)
[![Tests](https://img.shields.io/badge/tests-223%2F223%20passing-brightgreen)](#testing)
[![Coverage](https://img.shields.io/badge/python-3.12-blue)](https://python.org)
[![CVE](https://img.shields.io/badge/known%20CVEs-0-brightgreen)](#security-posture)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![MITRE](https://img.shields.io/badge/MITRE%20ATT%26CK-622%20techniques-red)](https://attack.mitre.org/)
[![OCSF](https://img.shields.io/badge/OCSF-1.0-blueviolet)](https://schema.ocsf.io/)

[**Quick Start**](#-quick-start) · [**Architecture**](#-architecture) · [**Features**](#-features) · [**Live Demo**](#-screenshots) · [**Documentation**](#-documentation) · [**Roadmap**](#-roadmap)

</div>

---

## 📖 Table of Contents

- [Why CyberTwin SOC?](#-why-cybertwin-soc)
- [Project at a Glance](#-project-at-a-glance)
- [Architecture](#-architecture)
- [Features](#-features)
- [Quick Start](#-quick-start)
- [Live Telemetry Ingestion](#-live-telemetry-ingestion-ocsf)
- [Detection Coverage Center](#-detection-coverage-center)
- [SOC Workflow](#-soc-workflow)
- [Observability & Metrics](#-observability--metrics)
- [Security Posture](#-security-posture)
- [Production Deployment](#-production-deployment)
- [Project Structure](#-project-structure)
- [Testing](#-testing)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🎯 Why CyberTwin SOC?

> **The hardest problem in detection engineering is not writing rules — it's knowing which adversary behaviour you can actually catch, and proving it under pressure.**

CyberTwin SOC is **not** a SIEM, not a SOAR, and not yet another dashboard. It is a **digital twin of a Security Operations Center** that ties together the four loops every mature SOC needs:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│   1. SIMULATE         2. DETECT          3. RESPOND        4. MEASURE   │
│   ─────────          ─────────          ─────────         ─────────     │
│   11 scenarios       46 rules +         SOC cases +       Coverage      │
│   28 attack         622 MITRE          SOAR (TheHive +    Center +      │
│   techniques        techniques          Cortex)            Benchmarks    │
│   Custom Sigma                                                          │
│                                                                         │
│         ↑__________ continuous improvement loop ___________↓            │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

It answers in concrete numbers — not bullet points — questions every CISO and detection engineer eventually asks:

| Question | Where the answer lives |
|----------|------------------------|
| *Of the 622 published ATT&CK techniques, which can my SOC actually detect today?* | `Detection Coverage Center` — 8 honest states (Validated / Failed / Untested / Rule-only / Not-covered / …) |
| *What's the false-positive rate of my detection rules in the last 30 days?* | `SOC Workflow` — analyst feedback loop on every alert |
| *If a Solorigate-style supply-chain attack hits us today, will we catch it before exfiltration?* | Run `scenario sc-008-solorigate` and look at the report |
| *Are my logs sources sufficient for detecting credential dumping?* | `required_logs` per technique × `available_logs` per host group |
| *How fast can my analysts triage? What's the SLA breach rate?* | SOC cases store SLA, status transitions, and time-to-close |
| *Which detection engineer changes broke detection?* | Versioned rule store + benchmark comparison |

---

## 📊 Project at a Glance

```
                                ┌──────────────────────┐
                                │   CyberTwin SOC v3   │
                                │   25 000+ LoC        │
                                └──────────┬───────────┘
                                           │
            ┌──────────────────────────────┼──────────────────────────────┐
            │                              │                              │
       ┌────▼─────┐                  ┌────▼─────┐                   ┌────▼─────┐
       │  PYTHON  │                  │  REACT   │                   │  TESTS   │
       │ 13 352   │                  │ 11 539   │                   │ 223/223  │
       │   LoC    │                  │   LoC    │                   │ passing  │
       └──────────┘                  └──────────┘                   └──────────┘
```

| Metric                        | Count   |  Notes                                                              |
|-------------------------------|--------:|---------------------------------------------------------------------|
| **Backend Python**            |  13 352 | Across 8 packages (api, detection, scoring, ai_analyst, …)         |
| **Frontend React/JSX**        |  11 539 | 26 pages, 10 reusable components, Recharts visualisations           |
| **Unit & integration tests**  |     223 | All passing on `pytest tests/`                                      |
| **REST + WebSocket endpoints**|      75 | All rate-limited, all RBAC-scoped, OpenAPI documented               |
| **MITRE ATT&CK techniques**   |     622 | Full Enterprise matrix, 14 tactics, TAXII 2.1 sync                  |
| **Detection rules (built-in)**|      46 | 14 platforms, severity-tiered, plus runtime Sigma upload            |
| **Attack scenarios**          |      11 | Solorigate, ProxyShell, Log4Shell, Insider, Ransomware, …           |
| **Frontend pages**            |      26 | Dashboard, Detection, Coverage, Cases, Ingestion, MITRE matrix, …   |
| **Roles (RBAC)**              |      12 | 3 legacy + 9 enterprise (tier1/senior/manager/hunter/auditor/…)     |
| **Connectors (extensible)**   |      15 | 5 mocks deterministic + 10 real-system stubs (Splunk, Sentinel, …) |
| **Known CVEs in deps**        |       0 | Verified by `pip-audit` after Apr 2026 dependency upgrade           |
| **Container scan**            |   clean | Trivy CRITICAL/HIGH = 0 (non-blocking gate in CI)                  |

---

## 🏗 Architecture

### High-level component diagram

```
                                     ┌────────────────────────────┐
                                     │     ANALYSTS / SOC LEAD     │
                                     │      (Browser, mobile)      │
                                     └─────────────┬──────────────┘
                                                   │ HTTPS (JWT)
                                                   ▼
   ┌───────────────────────────────────────────────────────────────────┐
   │                      FRONTEND  (React 18 + Vite)                   │
   │  Dashboard · Detection · Coverage · Cases · Ingestion · MITRE      │
   │  Real-time: WebSocket /ws/simulate/{id}   Charts: Recharts          │
   └───────────────────────────────────────────────────────────────────┘
                                                   │
                                                   ▼
   ┌───────────────────────────────────────────────────────────────────┐
   │                   API LAYER  (FastAPI 0.136 + slowapi)             │
   │  75 endpoints · OpenAPI · Rate limit · CORS · CSP · 12-role RBAC   │
   │  Middleware: RequestId · MetricsRecorder · JSONLogging · Audit      │
   └─┬────────┬────────┬────────┬────────┬────────┬────────┬────────┬──┘
     │        │        │        │        │        │        │        │
     ▼        ▼        ▼        ▼        ▼        ▼        ▼        ▼
  ┌─────┐ ┌─────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐
  │SIM- │ │TELE-│ │DETEC-│ │SCOR- │ │  AI  │ │ ANO- │ │ SOC  │ │ SOAR │
  │ULA- │ │METRY│ │TION  │ │ ING  │ │ANAL- │ │MALY  │ │WORK- │ │  +   │
  │TION │ │ GEN │ │ENGINE│ │ENGINE│ │ YST  │ │ ML   │ │FLOW  │ │COV-  │
  └─────┘ └─────┘ └──────┘ └──────┘ └──────┘ └──────┘ └──────┘ │ERAGE │
   28 t.   46 r.   46 r.   nist+cis Ollama   IsoFor  cases    └──────┘
   11 sc.  →OCSF   sigma   →BENCH   /NLG     UEBA    SLA      TheHive
                  +sigma                     drift  →feedback Cortex

      ┌─────────────────────────────────────────────────────────────┐
      │  PERSISTENCE   ·  Redis (cache+pubsub)  ·  SQLite/Postgres  │
      └─────────────────────────────────────────────────────────────┘
                                  │
      ┌─────────────────────────────────────────────────────────────┐
      │  OBSERVABILITY  · Prometheus /metrics  · Structured JSON     │
      │                  ·  X-Request-ID propagation                  │
      └─────────────────────────────────────────────────────────────┘
                                  │
      ┌─────────────────────────────────────────────────────────────┐
      │  INGESTION      ·  Win Event · Sysmon · Syslog · CloudTrail │
      │                 ·  → OCSF normalisation → ring-buffer 50k    │
      │                 ·  → fed back into the same DETECTION engine │
      └─────────────────────────────────────────────────────────────┘
                                  │
      ┌─────────────────────────────────────────────────────────────┐
      │  CONNECTORS     ·  SIEM · SOAR · EDR · ITSM · TI            │
      │                 (Splunk · Sentinel · Elastic · TheHive · …)  │
      └─────────────────────────────────────────────────────────────┘
```

### Data flow — full simulation pipeline

```
   SCENARIO ──► AttackEngine ─► raw events ─┐
                                            ├──► Telemetry ─► logs (JSON+OCSF)
   ENV (hosts) ─► generate normal noise ────┘                        │
                                                                     ▼
                                       ┌───────────────────► Detection ─► alerts
                                       │                        │
                                       │                        ▼
                                       │                   Correlation ─► incidents
                                       │                        │
                                       │                        ▼
                                       │                   ScoringEngine
                                       │                        │
                              ┌────────┴───────┐                ▼
                              ▼                ▼            AI analyst
                          Anomaly          Coverage              │
                            (ML)         (8-state)               ▼
                              │                │            Final report
                              ▼                ▼          (markdown + JSON)
                          UEBA score        gaps[]
```

---

## 🚀 Features

### 🎭 1 — Adversary simulation engine

- **11 turn-key scenarios** — Solorigate, ProxyShell, Log4Shell, Insider, Lateral movement, Cryptominer, Watering Hole, Living-off-the-Land, …
- **28 attack techniques** baked into the engine; every event is tagged with its MITRE ATT&CK ID
- **Custom scenario builder** with strict path-traversal-proof persistence
- **Realistic timeline generator** that interleaves benign user activity with adversarial actions

### 🔍 2 — Detection engine (multi-source)

- **46 built-in rules** spanning Windows EID, Sysmon, Linux audit, web access, DNS, network, AWS CloudTrail, Azure activity, Office365
- **Sigma rule loader** — upload `*.yml` Sigma rules at runtime, properly **ReDoS-hardened** (`re.escape` + `fullmatch` semantics, max 256 KB body)
- **Severity tiering** + confidence weighting + tactic diversity bonus
- **Incident correlation** — alerts → incidents (kill-chain phase aggregation, multi-host pivot detection)

### 🎯 3 — MITRE ATT&CK Coverage Center *(honest, not vapourware)*

```
                Coverage state machine
                ─────────────────────

   ┌───────────────┐      enable rule     ┌─────────────┐
   │  NOT_COVERED  │ ───────────────────► │ RULE_EXISTS │
   └───────────────┘                      └──────┬──────┘
                                                 │ run scenario
                                                 ▼
                                         ┌────────────────┐
                                         │  RULE_UNTESTED │
                                         └────┬───────┬───┘
                                              │       │
                                          PASS│       │FAIL
                                              ▼       ▼
                              ┌─────────────────┐ ┌────────────────┐
                              │ TESTED_DETECTED │ │ TESTED_FAILED  │
                              └─────────────────┘ └────────────────┘
                                  validated          regression!
```

8 honest states (`NOT_COVERED`, `RULE_EXISTS`, `RULE_UNTESTED`, `TESTED_DETECTED`, `TESTED_FAILED`, `LOG_MISSING`, `MUTED`, `DEPRECATED`) with **time-to-detect**, **confidence weighted by severity**, and a **per-tactic risk score** weighted toward `Initial Access`, `Privilege Escalation`, and `Exfiltration`.

### 🤖 4 — AI Analyst (LLM + deterministic fallback)

- Ollama-compatible (Llama 3, Mistral, Qwen) with automatic fallback to a **fully deterministic NLG template** so reports are always produced
- **Evidence-first** narrative — every claim is grounded on an alert ID or log timestamp
- IOC extractor: external/internal IPs, domains, URLs, **file hashes (MD5/SHA1/SHA256)**, **email addresses**, compromised accounts (the hash + email regexes were dead code in v2 — fixed in this audit, see `backend/ai_analyst.py:434`)

### 📈 5 — ML Anomaly Detection & UEBA

- IsolationForest baseline trained on benign telemetry
- UEBA: per-user behavioural drift score
- Configurable contamination rate; warm-start when retrained

### 🚨 6 — SOC Workflow (alerts → cases → SLA)

- **SQLite-backed Case store** (Postgres ready)
- Status transitions, comments, evidence attachments, SLA hours per severity
- Analyst feedback (`true_positive` / `false_positive`) feeds back into rule confidence
- **Suppressions** with TTL to silence known-noisy rules per host/user
- **SQL-injection-hardened** UPDATE composer (column allowlist + identifier regex, double-belt defence)

### 📡 7 — Live SOC Telemetry Ingestion (OCSF)

```
┌──────────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│ Windows EventLog     │    │   Sysmon         │    │  Syslog 3164/   │
│ (4624,4625,4688,…)  │    │   (1,3,7,8,…)    │    │     5424        │
└──────────┬───────────┘    └─────────┬────────┘    └─────────┬───────┘
           │                          │                        │
           └──────────────┬───────────┴────────────┬──────────┘
                          ▼                        ▼
                  ┌──────────────────────────────────────┐
                  │      OCSF NORMALISER  (mappers.py)    │
                  └──────────────────┬───────────────────┘
                                     ▼
                           ┌────────────────────┐
                           │ Ring-buffer 50 k    │
                           │ events  (thread-    │
                           │ safe, per-source)   │
                           └─────────┬──────────┘
                                     ▼
                           ┌────────────────────┐
                           │ Same Detection      │
                           │ Engine as the       │
                           │ simulator           │
                           └────────────────────┘
```

- **9 ingestion endpoints** — `/api/ingest/event`, `/batch` (≤5 000), `/syslog`, `/upload` (NDJSON ≤25 MB), `/detect`, `/stats`, `/sources`, `/health`, `/buffer`
- Sources covered: Windows Security & Sysmon, Linux syslog (RFC 3164 & 5424), AWS CloudTrail, generic JSON
- **Same** detection engine: zero-cost reuse of all 46 rules + Sigma uploads

### 🤝 8 — SOAR Integration (TheHive 5 + Cortex 3)

- Optional `--profile soar` in docker-compose
- Auto-create cases, run analysers (Cortex), enrich IOCs
- Webhook in / webhook out for bidirectional sync

### 🧪 9 — Compliance Benchmarking (NIST CSF v1.1 + CIS v8)

- Maps every detection capability to NIST sub-categories (`DE.AE-2`, `DE.CM-7`, …) and CIS Controls (CIS 8.11, CIS 13.6, …)
- Generates a compliance score per simulation
- Trend dashboard for improving posture over time

### 📊 10 — Observability (production-ready)

- **Prometheus**: 9 metrics under the `cybertwin_*` namespace (counters + histograms; p50/p95/p99 ready)
- **JSON structured logs** when `ENABLE_JSON_LOGS=1`
- **`X-Request-ID`** propagation through every request, every log line, every metric
- **`/api/health/deep`** that 503s if cache or DB is degraded — designed for K8s readiness probes
- **kube-prometheus-stack** ready: a `ServiceMonitor` template ships in `deploy/helm/`

### 🏷 11 — Enterprise RBAC (12 roles, scoped permissions)

| Tier         | Roles                                                                          |
|--------------|--------------------------------------------------------------------------------|
| **Legacy**   | `admin` · `analyst` · `viewer`                                                 |
| **Tier-1**   | `tier1_analyst` · `senior_analyst` · `soc_manager`                            |
| **Engineering** | `detection_engineer` · `threat_hunter`                                       |
| **Read-only**| `auditor` · `read_executive` · `service_account`                              |
| **Platform** | `platform_admin`                                                                |

Permissions are **scoped** (`case:write`, `rule:disable`, `ingestion:read`, `audit:export`, …) — never blanket admin.

### 🔌 12 — Connector framework (extensible)

```
backend/connectors/
├── base.py        ← 5 abstract interfaces (SIEM, SOAR, EDR, ITSM, TI)
├── mock.py        ← deterministic in-memory mocks for local dev
├── stubs.py       ← real-system stubs (Splunk, Sentinel, Elastic, TheHive,
│                    Defender, CrowdStrike, Jira, ServiceNow, MISP, OpenCTI)
└── registry.py    ← `get_connector(kind, name)` lookup
```

`/api/connectors` lists every registered backend; `/api/connectors/{kind}/{name}/check` runs a health-probe.

---

## 📸 Screenshots

> *Screenshots live in `docs/screenshots/`. Add yours via PR.*

| Page | Purpose |
|------|---------|
| `Dashboard.jsx` | Live overview: KPIs, recent simulations, rule status |
| `Detection.jsx` | Rule catalogue, confidence per rule, last-seen, true/false-positive ratio |
| `Coverage.jsx` | 622-technique heat-map with the 8 honest states |
| `Cases.jsx` | Kanban-style case board with SLA timers |
| `Ingestion.jsx` | Live counters per source + run-detection button |
| `MitreView.jsx` | Full ATT&CK matrix, click-through to technique → rules → scenarios |

---

## ⚡ Quick Start

### Option A — Docker Compose (recommended)

```bash
git clone https://github.com/omarbabba779xx/CyberTwin-SOC.git
cd CyberTwin-SOC

# Set strong secrets BEFORE first run
cp .env.example .env
# edit .env: set JWT_SECRET (>=32 chars) + AUTH_*_PASSWORD

docker compose up -d
```

Open:
- Frontend → http://localhost:3001
- API & docs → http://localhost:8000/docs
- Prometheus metrics → http://localhost:8000/api/metrics

Default users (override via env vars):

| Username   | Default password (override!)        | Role     |
|-----------|--------------------------------------|----------|
| `admin`   | `AUTH_ADMIN_PASSWORD`                | admin    |
| `analyst` | `AUTH_ANALYST_PASSWORD`              | analyst  |
| `viewer`  | `AUTH_VIEWER_PASSWORD`               | viewer   |

### Option B — Local development (Python + Node)

```bash
# Backend
python -m venv .venv && .venv/Scripts/Activate.ps1   # Windows
pip install -r requirements.txt
uvicorn backend.api.main:app --reload --port 8000

# Frontend
cd frontend
npm ci
npm run dev    # http://localhost:3001
```

### Option C — Kubernetes via Helm

```bash
helm install cybertwin deploy/helm/cybertwin-soc \
  --set ingress.host=soc.example.com \
  --create-namespace -n cybertwin
```

`runAsNonRoot`, `drop:[ALL]`, `liveness/readiness/startup` probes, `ServiceMonitor` for kube-prometheus-stack — all pre-wired.

---

## 📥 Live Telemetry Ingestion (OCSF)

### Send a single Windows logon event

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

### Run detection over the in-memory ring-buffer

```bash
curl -X POST http://localhost:8000/api/ingest/detect -H "Authorization: Bearer $TOKEN"
```

Detection results re-use the 46 built-in rules + every Sigma rule uploaded at runtime. **The ingestion path is the simulation path** — there's a single detection brain.

---

## 🎯 Detection Coverage Center

Open `Coverage.jsx` in the frontend or call:

```bash
curl http://localhost:8000/api/coverage \
  -H "Authorization: Bearer $TOKEN" | jq '.summary'
```

Sample response:

```json
{
  "catalog_total": 622,
  "validated": 47,
  "failed": 3,
  "untested": 18,
  "rule_mapped": 68,
  "not_covered": 554,
  "high_risk_gaps": 41,
  "by_tactic": {
    "Initial Access": {"validated": 6, "covered_pct": 24.0, "high_risk_gaps": 12},
    "Execution":      {"validated": 9, "covered_pct": 31.0, "high_risk_gaps": 4},
    "...": "..."
  }
}
```

The number of validated techniques is conservative on purpose: **a rule is validated only when a scenario exercises the technique AND the rule fires.**

---

## 🎫 SOC Workflow

```
  alert ──► Case (auto or manual)
              │
              ├─► comment / evidence
              ├─► assign analyst
              ├─► SLA timer (severity → hours)
              ├─► transition: NEW → IN_PROGRESS → RESOLVED / FALSE_POSITIVE / CLOSED
              └─► feedback → updates rule confidence + suppression suggestion
```

Endpoints:

| Method | Path                                   | Purpose                          |
|-------:|----------------------------------------|----------------------------------|
| `POST` | `/api/cases`                           | Open a case from an alert        |
| `GET`  | `/api/cases`                           | List with filters & SLA status   |
| `PATCH`| `/api/cases/{id}`                      | Update status/assignee (allowlist-validated)   |
| `POST` | `/api/cases/{id}/comment`              | Append a comment                 |
| `POST` | `/api/cases/{id}/evidence`             | Attach evidence artefact         |
| `POST` | `/api/feedback/{alert_id}`             | TP / FP feedback for a rule      |
| `POST` | `/api/suppressions`                    | Add scoped suppression with TTL  |

---

## 📊 Observability & Metrics

```
# HELP cybertwin_requests_total HTTP requests received
# TYPE cybertwin_requests_total counter
cybertwin_requests_total{method="GET",path="/api/coverage",status="200"} 1245
cybertwin_request_latency_seconds_bucket{path="/api/ingest/batch",le="0.01"} 312
cybertwin_ingest_events_total{source="windows_security"} 50124
cybertwin_detection_alerts_total{severity="high"} 87
cybertwin_cases_open{severity="critical"} 3
```

Sample Grafana queries (one-liners):

```promql
# p95 API latency per endpoint
histogram_quantile(0.95, sum by (path,le)(rate(cybertwin_request_latency_seconds_bucket[5m])))

# ingestion EPS by source
sum by (source)(rate(cybertwin_ingest_events_total[1m]))

# rolling FP rate per rule
sum by (rule_id)(rate(cybertwin_feedback_total{verdict="false_positive"}[24h]))
  / sum by (rule_id)(rate(cybertwin_feedback_total[24h]))
```

---

## 🔐 Security Posture

This project takes its own threat model seriously.

### Hardening that ships in the codebase

| Surface               | Control                                                                 |
|-----------------------|-------------------------------------------------------------------------|
| Auth                  | bcrypt (12 rounds) · JWT (HS256, 32-byte key) · 5/min login rate-limit   |
| API                   | slowapi rate-limit on every endpoint · CORS allowlist · 12-role RBAC    |
| File uploads          | `_safe_path()` regex + path-resolution check (no traversal possible)    |
| Sigma loader          | YAML safe_load · 256 KB max · ReDoS-proof globbing · `re.fullmatch`     |
| SQL                   | Parametrised queries · column allowlist + regex for dynamic UPDATE      |
| Secrets               | `.jwt_secret` git-ignored & untracked · env-driven · prod warning gate  |
| Containers            | `runAsNonRoot` · `drop:[ALL]` · multi-stage builds · `HEALTHCHECK`     |
| Audit                 | Every state-changing endpoint logs to `audit_log` (user, role, IP, action) |

### Continuous security checks (CI)

| Tool          | Purpose                                       | Status          |
|---------------|-----------------------------------------------|-----------------|
| **Bandit**    | Python static security analysis               | non-blocking    |
| **pip-audit** | CVE scan on `requirements.txt`                | **0 known CVEs** ✅ |
| **Semgrep**   | multi-language SAST (Python + JS)             | non-blocking    |
| **Gitleaks**  | secret scanning across full git history       | non-blocking    |
| **Trivy**     | filesystem + container vuln scan              | non-blocking    |
| **CycloneDX** | SBOM generation (Python + npm)                | artefact upload |
| **npm audit** | frontend dependency vulnerabilities           | high gate       |

### Findings fixed in the most recent audit (Apr 2026)

| ID    | Finding                                           | Status |
|------:|---------------------------------------------------|--------|
| CRIT-1| Path traversal via `scenario.id`                 | ✅ Fixed (`_safe_path`) |
| CRIT-2| Path traversal via Sigma `rule_id`               | ✅ Fixed (`_safe_path`) |
| CRIT-3| ReDoS in Sigma matcher (`(.*)*` patterns)         | ✅ Fixed (escape + fullmatch) |
| CRIT-4| `re.search` semantics → wrong matches            | ✅ Fixed (fullmatch) |
| CRIT-5| `data/.jwt_secret` was tracked in git             | ✅ Fixed (`git rm --cached`) |
| CRIT-6| 9 known CVEs in dependency closure               | ✅ Fixed (FastAPI 0.136 / starlette 0.49 / pyjwt 2.12 / multipart 0.0.26) |
| BUG-1 | F601 — `T1053.003` & `T1052.001` defined twice   | ✅ Fixed (merged, no data loss) |
| BUG-2 | Dead code: `hash_re` & `email_re` never extracted | ✅ Fixed (now actually used in IOC extractor) |
| BUG-3 | Dead code: `severity_weights` duplicate          | ✅ Fixed |
| BUG-4 | flake8 1127 errors on PR                         | ✅ Fixed (intentional patterns ignored, real bugs enforced) |

---

## 🚢 Production Deployment

### Docker Compose (with optional profiles)

```bash
# Full SOC stack (incl. SOAR + Postgres)
docker compose --profile soar --profile prod-db up -d

# Just the SOC core
docker compose up -d
```

Service map:

| Service       | Port  | Purpose                       |
|---------------|------:|-------------------------------|
| `frontend`    | 3001  | nginx-served React SPA        |
| `backend`     | 8000  | FastAPI uvicorn               |
| `redis`       | 6379  | cache, pubsub, rate-limiter   |
| `postgres`    | 5432  | (`prod-db` profile)           |
| `thehive`     | 9000  | (`soar` profile)              |
| `cortex`      | 9001  | (`soar` profile)              |

### Helm

```bash
helm upgrade --install cybertwin deploy/helm/cybertwin-soc \
  --set image.backend.tag=v3.0.0 \
  --set image.frontend.tag=v3.0.0 \
  --set ingress.host=soc.example.com \
  --set ingress.tls.enabled=true \
  --set serviceMonitor.enabled=true
```

### Benchmarks

```bash
# k6 — API load test (p95 < 500 ms gate)
k6 run benchmarks/k6_api_test.js \
  -e BASE=http://localhost:8000 -e TOKEN=$JWT

# locust — ingestion throughput
locust -f benchmarks/locust_ingestion.py --host http://localhost:8000
```

---

## 📂 Project Structure

```
CyberTwin SOC/
├── backend/                       Python — 13 352 LoC
│   ├── api/                       FastAPI app, 75 endpoints, RBAC, rate-limit
│   ├── auth.py                    bcrypt + JWT + 12 roles
│   ├── ai_analyst.py              LLM/NLG analyst & IOC extractor
│   ├── connectors/                15 SIEM/SOAR/EDR/ITSM/TI connectors
│   ├── coverage/                  Coverage Center (8-state machine)
│   ├── detection/                 46 rules + Sigma loader + correlation
│   ├── ingestion/                 OCSF ring-buffer & pipeline
│   ├── mitre/                     622 techniques, 14 tactics, TAXII sync
│   ├── ml_anomaly/                IsolationForest + UEBA
│   ├── normalization/             Win EID / Sysmon / syslog / CloudTrail
│   ├── observability/             Prometheus, JSON logs, request_id
│   ├── orchestrator.py            Full simulation pipeline
│   ├── reports/                   Markdown + JSON report builder
│   ├── scoring/                   NIST CSF + CIS benchmark
│   ├── simulation/                28 attack-technique builder
│   ├── soc/                       Cases, comments, evidence, SLA, suppressions
│   └── telemetry/                 Log generator (LogEvent objects)
├── frontend/                      React 18 + Vite — 11 539 LoC
│   ├── src/pages/                 26 pages
│   ├── src/components/            10 reusable
│   └── Dockerfile                 nginx-served, multi-stage
├── tests/                         223 tests, all passing
├── benchmarks/                    k6 + locust load tests
├── deploy/helm/                   Helm chart + ServiceMonitor
├── scenarios/                     11 attack scenarios (JSON)
├── data/sigma_rules/              runtime-uploaded Sigma rules
├── docker-compose.yml             core + soar + prod-db profiles
├── Dockerfile.backend             multi-stage, non-root
├── .github/workflows/ci.yml       6-job CI (tests, build, lint, security, docker)
└── README.md
```

---

## 🧪 Testing

```bash
# Full test suite
python -m pytest tests/ -v

# With coverage
python -m pytest tests/ --cov=backend --cov-report=term-missing

# A single area
python -m pytest tests/test_detection.py -k "sigma"

# CI-equivalent lint
flake8 backend/ --max-line-length=120 \
       --ignore=E501,W503,E402,E241,E231,E704

# Security scans (local)
bandit -r backend/ -ll --skip B101,B104
pip-audit -r requirements.txt --strict
```

Current state on `master`:

```
============================ 223 passed in 33.97s ============================
```

---

## 🗺 Roadmap

> ✅ All 17 phases below are *delivered* on `master`.

| Phase | Theme                                                                  | Status |
|------:|------------------------------------------------------------------------|:------:|
|     1 | Stable simulation engine + 11 scenarios                               | ✅ |
|     2 | Telemetry + LogEvent dataclass                                        | ✅ |
|     3 | 46 detection rules + Sigma loader                                     | ✅ |
|     4 | LLM AI Analyst (Ollama + NLG fallback)                                | ✅ |
|     5 | ML anomaly detection (IsolationForest + UEBA)                          | ✅ |
|     6 | MITRE ATT&CK 622 techniques + TAXII 2.1 sync                          | ✅ |
|     7 | Infrastructure (Redis cache, WebSocket, async)                         | ✅ |
|     8 | NIST CSF + CIS Controls benchmarking                                  | ✅ |
|     9 | Frontend pages — Benchmark, Anomaly, SOAR, LLM status                 | ✅ |
|    10 | Unit test suite (now 223 tests)                                        | ✅ |
|    11 | Docker Compose production deployment                                   | ✅ |
|    12 | SOAR integration (TheHive 5 + Cortex 3)                                | ✅ |
|    13 | Stabilisation (CI fixes, governance, secret guards, doc honesty)      | ✅ |
|    14 | Detection Coverage Center (8-state honest status)                     | ✅ |
|    15 | SOC Workflow (cases, feedback, suppressions, AI evidence-first)        | ✅ |
|    16 | Live SOC ingestion (OCSF: Win/Sysmon/syslog/CloudTrail)               | ✅ |
|    17 | Enterprise (Prometheus + JSON logs + 12-role RBAC + connectors + Helm)| ✅ |

### Next ideas (not yet on `master`)

See [`docs/IMPROVEMENTS.md`](docs/IMPROVEMENTS.md) — a 30-item backlog covering **multi-tenancy**, **real connectors (Splunk/Sentinel/Jira live)**, **executive dashboard**, **purple-team dashboards**, **STIX/TAXII feed publishing**, **eBPF live agent**, **JA3/JA3S TLS fingerprinting**, **detection-as-code GitOps flow**, **Looker Studio export**, …

---

## 🤝 Contributing

PRs are welcome. The bar is:

1. `pytest tests/` is green (223/223).
2. `flake8` is clean with the same flags CI uses.
3. New endpoints get a unit test **and** a permission scope.
4. New ATT&CK techniques get added to `backend/mitre/attack_data.py`.
5. No secrets, no hard-coded credentials, no path-traversal-prone string ops.

---

## 📜 License

MIT — see [LICENSE](LICENSE).

---

<div align="center">

**Built with ❤️ for the cybersecurity community.**

If this project saves your team a sprint, **[⭐ star the repo](https://github.com/omarbabba779xx/CyberTwin-SOC)** — it's the only metric I track.

</div>
