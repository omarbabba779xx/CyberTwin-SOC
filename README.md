<div align="center">

# 🛡️ CyberTwin SOC

### Enterprise Digital Twin Platform for Cyber Attack Simulation & SOC Readiness

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white&style=for-the-badge)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-3.0-009688?logo=fastapi&logoColor=white&style=for-the-badge)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black&style=for-the-badge)](https://react.dev)
[![Vite](https://img.shields.io/badge/Vite-5-646CFF?logo=vite&logoColor=white&style=for-the-badge)](https://vitejs.dev)

[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-622%20Techniques-red?style=flat-square)](https://attack.mitre.org)
[![Detection Rules](https://img.shields.io/badge/Detection%20Rules-46-orange?style=flat-square)](backend/detection/rules.py)
[![Attack Scenarios](https://img.shields.io/badge/Attack%20Scenarios-11-critical?style=flat-square)](scenarios/)
[![Tests](https://img.shields.io/badge/Tests-128%20passing-brightgreen?style=flat-square)](tests/)
[![NIST CSF](https://img.shields.io/badge/NIST%20CSF-v1.1-blue?style=flat-square)](https://www.nist.gov/cyberframework)
[![CIS Controls](https://img.shields.io/badge/CIS%20Controls-v8-purple?style=flat-square)](https://www.cisecurity.org/controls)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&style=flat-square)](docker-compose.yml)
[![SOAR](https://img.shields.io/badge/SOAR-TheHive%20%2B%20Cortex-8B5CF6?style=flat-square)](backend/soar/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Architecture](#-architecture)
- [Simulation Pipeline](#-simulation-pipeline)
- [MITRE ATT\&CK Coverage](#-mitre-attck-coverage)
- [Detection Engine](#-detection-engine)
- [ML Anomaly Detection](#-ml-anomaly-detection)
- [AI Analyst](#-ai-analyst)
- [Scoring & Benchmarking](#-scoring--benchmarking)
- [Attack Scenarios](#-attack-scenarios)
- [Frontend Dashboard](#-frontend-dashboard)
- [SOAR Integration](#-soar-integration)
- [Docker Deployment](#-docker-deployment)
- [API Reference](#-api-reference)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Project Structure](#-project-structure)

---

## 🎯 Overview

**CyberTwin SOC** is an enterprise-grade **Digital Twin** platform that replicates a complete corporate network environment and runs realistic cyber attack simulations against it. It validates detection capabilities, measures SOC readiness, and provides compliance benchmarking against NIST CSF and CIS Controls — all without touching production infrastructure.

### What makes it unique?

```
┌─────────────────────────────────────────────────────────────────────┐
│                       CyberTwin SOC Concept                         │
│                                                                     │
│   Real Environment          Digital Twin                            │
│   ─────────────────         ──────────────────────────────────      │
│   Production servers   ──►  Simulated hosts + users + services      │
│   Actual threats       ──►  622 MITRE ATT&CK techniques             │
│   Manual pen-tests     ──►  Automated attack scenario engine        │
│   Guesswork scoring    ──►  ML-based scoring + NIST/CIS benchmarks  │
│   Slow SOC reviews     ──►  Real-time AI analyst (LLM + NLG)        │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Metrics at a Glance

| Capability | Value |
|---|---|
| MITRE ATT&CK techniques | **622** (194 base + 428 sub-techniques) |
| Attack scenarios | **11** pre-built (ransomware, APT, cloud, kerberoasting…) |
| Detection rules | **46** (Sigma-compatible + ML-based) |
| MITRE tactics covered | **14 / 14** |
| Benchmarking standards | NIST CSF v1.1 + CIS Controls v8 |
| API endpoints | **30+** REST + WebSocket |
| Frontend pages | **20** interactive dashboards |

---

## 🏗️ Architecture

```
┌────────────────────────────────────────────────────────────────────────────────┐
│                             CyberTwin SOC v3.0                                 │
│                                                                                │
│  ┌─────────────────────────────────────────────────────────────────────────┐   │
│  │                        React Frontend (Vite)                            │   │
│  │                                                                         │   │
│  │  Dashboard  │ MITRE View  │ Anomaly  │ Benchmark  │ AI Analyst  │ ...   │   │
│  │  Timeline   │ Alerts      │ Network  │ Scenarios  │ Reports     │ +14   │   │
│  └────────────────────────────┬────────────────────────────────────────────┘   │
│                               │ REST / WebSocket                               │
│  ┌────────────────────────────▼────────────────────────────────────────────┐   │
│  │                      FastAPI Backend (Python 3.12)                      │   │
│  │                                                                         │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌───────────┐  │   │
│  │  │ Auth & RBAC  │  │  Rate Limit  │  │  Audit Log   │  │   Cache   │  │   │
│  │  │ (bcrypt/JWT) │  │  (slowapi)   │  │  (SQLite)    │  │(Redis/mem)│  │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘  └───────────┘  │   │
│  │                                                                         │   │
│  │  ┌──────────────────────────────────────────────────────────────────┐  │   │
│  │  │                   Simulation Orchestrator                         │  │   │
│  │  │                                                                   │  │   │
│  │  │  ┌─────────────┐  ┌─────────────┐  ┌────────────┐  ┌─────────┐  │  │   │
│  │  │  │   Attack    │  │  Detection  │  │   Scoring  │  │   AI    │  │  │   │
│  │  │  │   Engine    │  │   Engine    │  │   Engine   │  │ Analyst │  │  │   │
│  │  │  │             │  │             │  │            │  │         │  │  │   │
│  │  │  │ 11 scenarios│  │ 46 rules    │  │ NIST CSF  │  │ Ollama  │  │  │   │
│  │  │  │ 622 MITRE   │  │ Sigma rules │  │ CIS Ctrl  │  │ + NLG   │  │  │   │
│  │  │  │ techniques  │  │ IsolForest  │  │ 6 metrics │  │fallback │  │  │   │
│  │  │  └─────────────┘  └─────────────┘  └────────────┘  └─────────┘  │  │   │
│  │  └──────────────────────────────────────────────────────────────────┘  │   │
│  │                                                                         │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐                  │   │
│  │  │ MITRE ATT&CK │  │  Sigma Rules │  │  TAXII 2.1  │                  │   │
│  │  │ 622 entries  │  │  Loader      │  │  Sync        │                  │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘                  │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
│                               │                                                │
│  ┌────────────────────────────▼────────────────────────────────────────────┐   │
│  │                          Data Layer                                     │   │
│  │  SQLite (runs + audit)  │  Redis (optional cache)  │  JSON (scenarios)  │   │
│  └─────────────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔄 Simulation Pipeline

Each simulation runs through a 6-stage pipeline in under 10 seconds:

```
  SCENARIO LOAD           EVENT GENERATION          LOG SYNTHESIS
  ─────────────           ────────────────          ─────────────
  JSON file with    ──►   Attack engine maps   ──►  Realistic syslog,
  MITRE phases,           each technique to         Windows Events,
  TTPs, targets           realistic events          network flows

         │                                                │
         ▼                                                ▼

  DETECTION ENGINE        SCORING ENGINE            AI ANALYSIS
  ─────────────────       ──────────────            ───────────
  46 rules + Sigma  ──►   6 score dimensions  ──►  LLM narrative
  IsolationForest         NIST CSF tiers            + IOCs
  UEBA behavioral         CIS Controls IG           + recommendations
  anomaly detection       Overall maturity
```

### Simulation Output Example

```
Scenario : Ransomware Attack (sc-ransomware-001)
Duration : 30 min simulated

Events generated    :  1,842
Logs produced       :  3,156
Alerts triggered    :     14   ← detection rules fired
Anomalies detected  :     15   ← ML / UEBA flagged
Incidents created   :      3

┌──────────────────────────────────────────────┐
│              SCORES (0–100)                  │
│  Detection       ████████████░░  78.5        │
│  Coverage        ████████░░░░░░  62.3        │
│  Response        ███████████░░░  82.1        │
│  Visibility      ████████████░░  79.4        │
│  Compliance      █████████░░░░░  68.7        │
│  OVERALL         ████████████░░  80.3  ✅    │
├──────────────────────────────────────────────┤
│  Risk Level   : Low                          │
│  Maturity     : Managed (Level 3)            │
│  NIST Tier    : Tier 4 — Adaptive            │
│  CIS Group    : IG3 — Large Enterprise       │
└──────────────────────────────────────────────┘
```

---

## 🎯 MITRE ATT&CK Coverage

CyberTwin SOC implements the **complete MITRE ATT&CK Enterprise v14** framework — all 14 tactics and 622 technique entries.

### Coverage by Tactic

```
Tactic                      ID        Base    Sub    Total
──────────────────────────────────────────────────────────
Reconnaissance              TA0043      10     33      43
Resource Development        TA0042       8     36      44
Initial Access              TA0001       9     12      21
Execution                   TA0002      14     42      56
Persistence                 TA0003      17     74      91  ← largest
Privilege Escalation        TA0004       5     22      27
Defense Evasion             TA0005      23     79     102  ← most complex
Credential Access           TA0006      17     30      47
Discovery                   TA0007      30      9      39
Lateral Movement            TA0008       8     10      18
Collection                  TA0009      15      9      24
Command & Control           TA0011      16     23      39
Exfiltration                TA0010       9     12      21
Impact                      TA0040      16     15      31
──────────────────────────────────────────────────────────
TOTAL                                  194    428     622
```

### MITRE ATT&CK Navigator Heat Map (detection coverage)

```
          T1059  T1055  T1003  T1110  T1078  T1021  T1566  T1486  T1558  T1070
TA0002     ██     ██
TA0004            ██
TA0006                   ██     ██
TA0001                                 ██           ██
TA0008                                        ██
TA0040                                                     ██
TA0006                                                            ██
TA0005                                                                   ██

  ██ = Detection rule exists    □ = Gap (visibility only)
```

### Data Sources

| Source | Method | Count |
|---|---|---|
| **Embedded catalogue** | `generate_bundle.py` | 622 techniques (offline) |
| **Live TAXII 2.1 sync** | `GET /api/mitre/sync-taxii` | Full MITRE GitHub feed |
| **Gap analysis** | `GET /api/mitre/gap-analysis/{id}` | Per-simulation coverage |

---

## 🔍 Detection Engine

The detection engine applies **46 rules** across 5 categories in real-time:

```
┌────────────────────────────────────────────────────────────────────┐
│                     Detection Pipeline                             │
│                                                                    │
│  Raw Events                                                        │
│      │                                                             │
│      ├──► Rule-based Detection (46 rules)                          │
│      │       ├─ RULE-001  Mimikatz credential dump                 │
│      │       ├─ RULE-002  PowerShell encoded command               │
│      │       ├─ RULE-003  Lateral movement via SMB                 │
│      │       ├─ RULE-010  Kerberoasting SPN request                │
│      │       ├─ RULE-022  Ransomware mass encryption               │
│      │       ├─ RULE-035  DNS-based C2 (DGA detection)             │
│      │       ├─ RULE-040  Container escape attempt                 │
│      │       └─ ... 39 more rules                                  │
│      │                                                             │
│      ├──► Sigma Rules (dynamic YAML loading)                       │
│      │       └─ data/sigma_rules/*.yml                             │
│      │                                                             │
│      └──► ML Anomaly Detection                                     │
│              ├─ IsolationForest  (statistical outliers)            │
│              └─ UEBA             (user behavior baseline)          │
│                                                                    │
│  Output: Alerts + Anomalies + Incidents                            │
└────────────────────────────────────────────────────────────────────┘
```

### Rule Categories

| Category | Rules | Examples |
|---|---|---|
| **Credential Access** | 9 | Mimikatz, DCSync, Kerberoasting, Pass-the-Hash |
| **Execution** | 8 | PowerShell obfuscation, WMI, LOLBAS |
| **Lateral Movement** | 7 | SMB, RDP, PsExec, WinRM |
| **Defense Evasion** | 7 | Log clearing, AV disabling, timestomping |
| **Persistence** | 6 | Registry Run keys, scheduled tasks, services |
| **Impact** | 5 | Ransomware, shadow copy deletion, DDoS |
| **C2 / Exfiltration** | 4 | DGA, DNS tunneling, large transfers |

---

## 🤖 ML Anomaly Detection

Two complementary detection models run on every simulation:

```
┌──────────────────────────────────────────────────────────────────┐
│                    ML Anomaly Detection Stack                    │
│                                                                  │
│  ┌─────────────────────────────────┐                            │
│  │      IsolationForest Model      │                            │
│  │                                 │                            │
│  │  Features:                      │                            │
│  │  • Events/minute rate           │  Detects:                  │
│  │  • Failed auth count            │  • Volumetric spikes       │
│  │  • Network bytes transferred    │  • Statistical outliers    │
│  │  • Process spawn rate           │  • Lateral movement bursts │
│  │  • Unique dest. hosts           │                            │
│  │                                 │  Anomaly score: -1 → 0     │
│  └─────────────────────────────────┘  (closer to -1 = worse)   │
│                                                                  │
│  ┌─────────────────────────────────┐                            │
│  │         UEBA Model              │                            │
│  │                                 │                            │
│  │  Per-user behavioral baseline:  │  Detects:                  │
│  │  • Normal working hours         │  • Off-hours access        │
│  │  • Typical login sources        │  • New geographic origin   │
│  │  • Resource access patterns     │  • Privilege escalation    │
│  │  • Peer group comparison        │  • Unusual data access     │
│  │                                 │                            │
│  └─────────────────────────────────┘                            │
│                                                                  │
│  Combined output → Anomaly alerts with severity (Low→Critical)  │
└──────────────────────────────────────────────────────────────────┘
```

**Typical results on a ransomware simulation:**
```
  15 anomalies detected
  ├── Critical  : 2  (mass file encryption burst, shadow copy deletion)
  ├── High      : 5  (credential dumping, lateral movement wave)
  ├── Medium    : 6  (off-hours logins, unusual process spawning)
  └── Low       : 2  (elevated network transfer volume)
```

---

## 🧠 AI Analyst

The AI analyst generates natural-language incident reports automatically:

```
┌─────────────────────────────────────────────────────────────────┐
│                      AI Analyst Flow                            │
│                                                                 │
│  Simulation Results                                             │
│        │                                                        │
│        ▼                                                        │
│  ┌──────────────┐     Online?    ┌────────────────────────┐    │
│  │  Try Ollama  │ ─── YES ──►   │  Ollama (local LLM)    │    │
│  │  LLM API     │               │  llama3 / mistral      │    │
│  └──────────────┘               │  Generates full report │    │
│        │                        └────────────────────────┘    │
│      Offline                                                    │
│   or unavail.                                                   │
│        │                                                        │
│        ▼                                                        │
│  ┌──────────────────────────────────────────────────┐          │
│  │           NLG Fallback Engine                    │          │
│  │                                                  │          │
│  │  Rule-based Natural Language Generation:         │          │
│  │  • Identifies top tactics used                   │          │
│  │  • Maps alerts to MITRE techniques               │          │
│  │  • Generates IOCs list                           │          │
│  │  • Produces actionable recommendations           │          │
│  │  • Outputs structured Markdown report            │          │
│  └──────────────────────────────────────────────────┘          │
│                                                                 │
│  Output: { summary, tactics, iocs, recommendations, source }   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📊 Scoring & Benchmarking

### Scoring Dimensions

```
  Overall Score = weighted average of 6 dimensions

  ┌─────────────────────────────────────────────────────┐
  │  Detection Score    — Did rules/ML fire correctly?  │  25%
  │  Coverage Score     — MITRE tactic breadth covered  │  25%
  │  Response Score     — Alert → Incident quality      │  20%
  │  Visibility Score   — Log completeness              │  15%
  │  Compliance Score   — Policy adherence              │  15%
  └─────────────────────────────────────────────────────┘
```

### NIST Cybersecurity Framework Mapping

```
  NIST CSF v1.1 — Five Core Functions

  IDENTIFY ──────── Asset & risk inventory coverage
  PROTECT  ──────── Prevention controls quality
  DETECT   ──────── Detection rule effectiveness
  RESPOND  ──────── Incident response capability
  RECOVER  ──────── Recovery readiness

  Tier 1 (Partial) → Tier 2 (Risk Informed) → Tier 3 (Repeatable) → Tier 4 (Adaptive)
```

### CIS Controls v8 Assessment

```
  18 Critical Security Controls scored 0–100

  IG1 — Essential (small org)     Controls 1–6
  IG2 — Foundational (medium)     Controls 1–14
  IG3 — Large Enterprise          Controls 1–18

  Example output (Ransomware scenario):
  ┌──────────────────────────────────────────────┐
  │  CIS-01  Inventory & Control of Assets  82   │
  │  CIS-02  Inventory of Software          77   │
  │  CIS-03  Data Protection                71   │
  │  CIS-04  Secure Configuration           84   │
  │  CIS-05  Account Management             68   │
  │  CIS-06  Access Control Management      73   │
  │  ...                                         │
  │  Average: 77.8 / 100  →  IG3 Large Enterprise│
  └──────────────────────────────────────────────┘
```

---

## ⚔️ Attack Scenarios

11 pre-built scenarios covering major threat categories:

| ID | Scenario | Category | Techniques | Difficulty |
|---|---|---|---|---|
| `sc-ransomware-001` | **Ransomware Attack** | Impact | T1486, T1490, T1059 | 🔴 Critical |
| `sc-kerberoasting-001` | **Kerberoasting + Pass-the-Hash** | Credential Access | T1558.003, T1550.002 | 🟠 High |
| `sc-apt-001` | **APT Campaign** | Multi-stage | T1566, T1055, T1021 | 🔴 Critical |
| `sc-cloud-001` | **Cloud Credential Theft** | Cloud Attack | T1552.005, T1530, T1580 | 🟠 High |
| `sc-container-001` | **Container Escape** | Privilege Esc | T1611, T1610 | 🟠 High |
| `sc-insider-001` | **Insider Threat** | Exfiltration | T1078, T1560 | 🟡 Medium |
| `sc-ddos-001` | **DDoS Infrastructure** | Impact | T1498, T1499 | 🟡 Medium |
| `sc-lateral-001` | **Lateral Movement Wave** | Movement | T1021, T1570 | 🟠 High |
| `sc-phishing-001` | **Spearphishing Campaign** | Initial Access | T1566.001, T1204 | 🟡 Medium |
| `sc-supply-chain-001` | **Supply Chain Attack** | Initial Access | T1195, T1574 | 🔴 Critical |
| `sc-custom-*` | **Custom (Builder)** | Any | Any | Configurable |

### Scenario Anatomy

```yaml
# Example: scenarios/ransomware.json
{
  "id": "sc-ransomware-001",
  "name": "Ransomware Attack",
  "phases": [
    {
      "name": "Initial Access",
      "techniques": ["T1566.001"],   # Spearphishing attachment
      "duration_minutes": 10
    },
    {
      "name": "Execution",
      "techniques": ["T1059.001"],   # PowerShell dropper
      "duration_minutes": 5
    },
    {
      "name": "Defense Evasion",
      "techniques": ["T1562.001", "T1070.001"],  # Disable AV, clear logs
      "duration_minutes": 10
    },
    {
      "name": "Impact",
      "techniques": ["T1486", "T1490"],   # Encrypt files, delete backups
      "duration_minutes": 5
    }
  ]
}
```

---

## 🖥️ Frontend Dashboard

20 interactive pages built with React 18 + TailwindCSS:

```
  ┌─────────────────────────────────────────────────────────────────┐
  │  OVERVIEW          ANALYSIS            INTELLIGENCE             │
  │  • Dashboard       • Alerts            • Network Map            │
  │  • Scenarios       • Timeline          • AI Analyst  [AI]       │
  │                    • MITRE ATT&CK      • Threat Intel [NEW]     │
  │  ANALYSIS cont.    • Log Explorer      • Threat Map             │
  │  • Anomaly [ML]    • Attack Tree                                │
  │  • Maturity        • Analytics         TOOLS                    │
  │                                        • Benchmark  [NEW]       │
  │                                        • Risk Matrix            │
  │                                        • Report                 │
  │                                        • Compare                │
  │                                        • Scenario Builder       │
  └─────────────────────────────────────────────────────────────────┘
```

### Dashboard Features

- **Live Simulation** — real-time event feed via WebSocket during simulation
- **MITRE ATT&CK View** — heatmap of techniques detected vs missed
- **Anomaly Detection** — ML anomaly list with severity filter and scores
- **Benchmark** — NIST CSF radar chart + CIS Controls score bars
- **AI Analyst** — LLM-generated narrative report with IOCs
- **Threat Map** — geographic visualization of attack origins
- **Attack Tree** — kill chain visualization per scenario
- **Scenario Builder** — drag-and-drop custom scenario creator

---

## 🔗 SOAR Integration

CyberTwin SOC connects to **TheHive 5** and **Cortex 3** to automate incident response after every simulation.

```
┌────────────────────────────────────────────────────────────────────────┐
│                       SOAR Automation Flow                             │
│                                                                        │
│  CyberTwin Simulation                                                  │
│        │                                                               │
│        │  POST /api/soar/push/{scenario_id}                            │
│        ▼                                                               │
│  ┌─────────────────────────────────────────────────────┐              │
│  │                   TheHive 5                          │              │
│  │                                                      │              │
│  │  Case created automatically with:                    │              │
│  │  ├─ Title      : [CyberTwin] Scenario — Score/Risk  │              │
│  │  ├─ Description: Full simulation report (Markdown)   │              │
│  │  ├─ Severity   : Low / Medium / High / Critical      │              │
│  │  ├─ Observables: IOCs extracted by AI analyst        │              │
│  │  ├─ Tasks      : Recommendations as response tasks   │              │
│  │  └─ Tags       : cybertwin, simulation, risk level   │              │
│  └──────────────────────┬──────────────────────────────┘              │
│                          │                                             │
│                          │  POST /api/soar/analyze-iocs/{id}          │
│                          ▼                                             │
│  ┌─────────────────────────────────────────────────────┐              │
│  │                   Cortex 3                           │              │
│  │                                                      │              │
│  │  IOCs analyzed automatically by:                     │              │
│  │  ├─ VirusTotal_GetReport_3_1  (hashes, domains)      │              │
│  │  ├─ AbuseIPDB_1_0             (IP addresses)         │              │
│  │  ├─ Shodan_DNSResolve_1_0     (domains)              │              │
│  │  └─ URLhaus_2_0               (URLs)                 │              │
│  │                                                      │              │
│  │  Job reports available via GET /api/soar/analyzers  │              │
│  └─────────────────────────────────────────────────────┘              │
└────────────────────────────────────────────────────────────────────────┘
```

### SOAR API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/soar/status` | TheHive + Cortex connectivity check |
| `POST` | `/api/soar/push/{id}` | Push simulation → TheHive case |
| `POST` | `/api/soar/analyze-iocs/{id}` | Submit IOCs → Cortex analyzers |
| `GET` | `/api/soar/analyzers` | List available Cortex analyzers |

### Enable SOAR (Docker)

```bash
# Start with TheHive 5 + Cortex 3 + Elasticsearch
docker-compose --profile soar up -d

# TheHive UI  →  http://localhost:9000
# Cortex UI   →  http://localhost:9001
```

### Configure in `.env`

```env
THEHIVE_URL=http://thehive:9000
THEHIVE_API_KEY=your-thehive-api-key
THEHIVE_ORG=cybertwin
CORTEX_URL=http://cortex:9001
CORTEX_API_KEY=your-cortex-api-key
```

---

## 🐳 Docker Deployment

```
┌─────────────────────────────────────────────────────────────────────────┐
│                   Production Docker Architecture                        │
│                                                                         │
│  Browser                                                                │
│    │  :80                                                               │
│    ▼                                                                    │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                    nginx:1.27-alpine                              │  │
│  │  (frontend container)                                            │  │
│  │                                                                  │  │
│  │  /          → React SPA (built dist/)                            │  │
│  │  /api/*     → proxy_pass http://backend:8000                     │  │
│  │  /ws/*      → proxy_pass http://backend:8000 (WebSocket upgrade) │  │
│  │  /health    → 200 OK (nginx healthcheck)                         │  │
│  └─────────────────────────┬────────────────────────────────────────┘  │
│                             │ :8000                                     │
│  ┌──────────────────────────▼───────────────────────────────────────┐  │
│  │              python:3.12-slim  (backend container)               │  │
│  │                                                                  │  │
│  │  uvicorn — 2 workers — non-root user                             │  │
│  │  MITRE ATT&CK bundle pre-generated at build time                 │  │
│  │  Healthcheck: GET /api/health every 30s                          │  │
│  └──────────┬──────────────────────────────────────────────────────┘  │
│             │ :6379                                                     │
│  ┌──────────▼──────────────┐                                           │
│  │  redis:7-alpine          │  256 MB RAM, LRU eviction               │
│  │  (cache container)       │  Persisted to named volume              │
│  └─────────────────────────┘                                           │
│                                                                         │
│  ── optional --profile soar ─────────────────────────────────────────  │
│  ┌───────────────┐  ┌───────────────┐  ┌────────────────────────────┐  │
│  │ strangebee/   │  │ thehiveproject │  │  elasticsearch:7.17        │  │
│  │ thehive:5.3   │  │ /cortex:3.1.8 │  │  (shared index store)      │  │
│  │ :9000         │  │ :9001         │  │                            │  │
│  └───────────────┘  └───────────────┘  └────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

### Quick Start

```bash
# 1. Clone
git clone https://github.com/omarbabba779xx/CyberTwin-SOC.git
cd "CyberTwin SOC"

# 2. Configure environment
cp .env.example .env          # edit passwords, JWT secret

# 3. Start production stack (Redis + FastAPI + nginx)
docker-compose up -d

# 4. Access
#    Dashboard  →  http://localhost
#    API docs   →  http://localhost/api/docs  (proxied via nginx)
#    Direct API →  http://localhost:8000/docs

# 5. With SOAR (TheHive + Cortex)
docker-compose --profile soar up -d
```

### Container Summary

| Container | Image | Port | Role |
|---|---|---|---|
| `cybertwin-frontend` | `nginx:1.27-alpine` | **80** | React SPA + API reverse proxy |
| `cybertwin-backend` | `python:3.12-slim` | 8000 | FastAPI — 2 uvicorn workers |
| `cybertwin-redis` | `redis:7-alpine` | 6379 | Session cache + rate limiting |
| `cybertwin-thehive` ⚙️ | `strangebee/thehive:5.3` | 9000 | Case management |
| `cybertwin-cortex` ⚙️ | `thehiveproject/cortex:3.1.8` | 9001 | IOC analyzers |
| `cybertwin-elasticsearch` ⚙️ | `elasticsearch:7.17` | 9200 | SOAR data store |

> ⚙️ = optional, started with `--profile soar`

---

## 📡 API Reference

### Authentication
```http
POST /api/auth/login
Content-Type: application/json
{ "username": "analyst", "password": "soc2024" }

→ { "access_token": "eyJ...", "role": "analyst", "permissions": [...] }
```

### Core Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Health check |
| `GET` | `/api/scenarios` | List all 11 scenarios |
| `POST` | `/api/simulate` | Run a simulation |
| `GET` | `/api/results/{id}/anomalies` | ML anomaly results |
| `GET` | `/api/results/{id}/benchmark` | NIST CSF + CIS scores |
| `GET` | `/api/mitre/techniques` | All 622 ATT&CK techniques |
| `GET` | `/api/mitre/tactics` | All 14 tactics |
| `GET` | `/api/mitre/gap-analysis/{id}` | Detection gap analysis |
| `POST` | `/api/mitre/sync-taxii` | Live TAXII 2.1 sync |
| `GET` | `/api/sigma/rules` | Loaded Sigma rules |
| `POST` | `/api/sigma/upload` | Upload new Sigma rule |
| `WS` | `/ws/simulation/{id}` | Live simulation stream |
| `GET` | `/api/audit` | Audit log (admin only) |
| `GET` | `/docs` | Interactive Swagger UI |

### Simulation Request / Response

```json
// POST /api/simulate
{
  "scenario_id": "sc-ransomware-001",
  "duration_minutes": 30
}

// Response
{
  "scenario": { "id": "sc-ransomware-001", "name": "Ransomware Attack" },
  "total_events": 1842,
  "total_alerts": 14,
  "total_anomalies": 15,
  "overall_score": 80.3,
  "risk_level": "Low",
  "maturity_level": "Managed",
  "scores": {
    "detection": 78.5,
    "coverage": 62.3,
    "response": 82.1,
    "visibility": 79.4
  },
  "mitre_coverage": { "TA0001": [...], "TA0005": [...] },
  "ai_analysis": {
    "summary": "The simulation revealed...",
    "iocs": ["powershell.exe -enc ...", "C:\\Windows\\Temp\\payload.exe"],
    "recommendations": ["Enable PowerShell ScriptBlock Logging", "..."],
    "source": "nlg_fallback"
  }
}
```

---

## 🚀 Installation

### Prerequisites

- Python 3.12+
- Node.js 18+
- (Optional) Redis for caching
- (Optional) Ollama for local LLM analysis

### Backend Setup

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/CyberTwin-SOC.git
cd "CyberTwin SOC"

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/macOS

# Install dependencies
pip install -r requirements.txt

# Generate the full MITRE ATT&CK technique bundle (offline, no internet needed)
python -m backend.mitre.generate_bundle

# Start the API server
python -m uvicorn backend.api.main:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend Setup

```bash
cd frontend
npm install
npm run dev       # Development (http://localhost:5173)
npm run build     # Production build
```

### Docker (All-in-one)

```bash
docker-compose up --build
# API  → http://localhost:8000
# UI   → http://localhost:3001
# Docs → http://localhost:8000/docs
```

---

## ⚙️ Configuration

Create a `.env` file in the project root:

```env
# Authentication
AUTH_ADMIN_PASSWORD=your-secure-admin-password
AUTH_ANALYST_PASSWORD=your-secure-analyst-password
AUTH_VIEWER_PASSWORD=your-secure-viewer-password

# JWT
JWT_EXPIRY_HOURS=24

# Cache (leave blank for in-memory)
REDIS_URL=redis://localhost:6379

# LLM (optional — uses NLG fallback if unavailable)
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=llama3

# CORS
CORS_ORIGINS=http://localhost:3001,http://localhost:5173

# App
APP_VERSION=3.0.0
```

### RBAC Roles

| Role | Permissions |
|---|---|
| `admin` | All permissions including audit log, user management |
| `analyst` | Run simulations, view results, upload Sigma rules |
| `viewer` | Read-only access to results and dashboards |

---

## 📁 Project Structure

```
CyberTwin SOC/
│
├── backend/
│   ├── api/
│   │   └── main.py              # FastAPI app — 30+ endpoints
│   ├── auth.py                  # JWT + bcrypt authentication
│   ├── audit.py                 # Audit logging
│   ├── cache.py                 # Redis / in-memory cache
│   ├── database.py              # SQLite persistence
│   ├── orchestrator.py          # Simulation coordinator
│   ├── llm_analyst.py           # Ollama LLM + NLG fallback
│   │
│   ├── detection/
│   │   ├── engine.py            # Detection pipeline
│   │   ├── rules.py             # 46 detection rules (RULE-001 → RULE-046)
│   │   ├── sigma_loader.py      # Dynamic Sigma YAML loader
│   │   └── anomaly.py           # IsolationForest + UEBA
│   │
│   ├── mitre/
│   │   ├── attack_data.py       # MITRE_TECHNIQUES dict (622 entries)
│   │   ├── generate_bundle.py   # Offline bundle generator
│   │   ├── download_attack.py   # Live STIX bundle downloader
│   │   ├── taxii_sync.py        # TAXII 2.1 live sync
│   │   ├── mapper.py            # Event → technique mapper
│   │   └── techniques_bundle.json  # Pre-generated ATT&CK v14 data
│   │
│   ├── scoring/
│   │   └── __init__.py          # ScoringEngine + NIST CSF + CIS Controls
│   │
│   └── simulation/
│       ├── attack_engine.py     # Scenario loader + event generator
│       ├── environment.py       # Virtual network environment
│       └── log_generator.py     # Realistic log synthesis
│
├── frontend/
│   └── src/
│       ├── pages/               # 20 dashboard pages
│       │   ├── Dashboard.jsx
│       │   ├── MitreView.jsx
│       │   ├── Anomaly.jsx      # ML anomaly dashboard
│       │   ├── Benchmark.jsx    # NIST/CIS benchmark view
│       │   ├── AIAnalysis.jsx
│       │   └── ...17 more
│       └── components/
│           ├── Sidebar.jsx      # Navigation + LLM status indicator
│           ├── LiveSimulation.jsx
│           └── ...
│
├── scenarios/                   # 11 attack scenario JSON files
│   ├── ransomware.json
│   ├── kerberoasting.json
│   ├── apt_campaign.json
│   ├── cloud_attack.json
│   └── ...7 more
│
├── data/
│   └── sigma_rules/             # Drop custom Sigma rules here (.yml)
│
├── requirements.txt
├── docker-compose.yml
└── README.md
```

---

## 🔒 Security Design

```
┌─────────────────────────────────────────────────────────────┐
│                    Security Architecture                    │
│                                                             │
│  Authentication   bcrypt (4.x direct) + JWT HS256           │
│  Authorization    RBAC — admin / analyst / viewer           │
│  Rate Limiting    slowapi — 5 req/min login, 60 req/min API │
│  Audit Trail      Every action logged to SQLite             │
│  Secrets          .env file (never committed to git)        │
│  CORS             Configurable allowed origins              │
│  Input Validation Pydantic v2 + regex sanitization          │
└─────────────────────────────────────────────────────────────┘
```

---

## ⚠️ Honest Limitations

CyberTwin SOC is a **digital-twin platform for SOC readiness evaluation**. It is **not** a turnkey production SOC and does **not** detect 100 % of real-world attacks. Read this section carefully before quoting numbers.

### What the badges actually mean

| Badge / metric                    | What it measures                                                              | What it does **not** mean                                                                 |
| --------------------------------- | ----------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| `MITRE ATT&CK 622 Techniques`     | Number of techniques **loaded into the catalog** for mapping and visualization | That CyberTwin **detects** all 622 techniques                                              |
| `Detection Rules: 46`             | Number of Sigma-style rules currently shipped                                 | That all 46 rules are tuned, validated, or noise-free in your environment                 |
| `Attack Scenarios: 11`            | Pre-built simulation scripts that emit known-bad telemetry                    | A complete adversary-emulation library — real APTs use thousands of variant procedures    |
| `Tests: 128 passing`              | Backend unit / integration tests covering Python modules and API endpoints    | End-to-end validation of every detection rule against every supported log source          |

### What CyberTwin SOC **is** good for

- Measuring **detection coverage** against a defined attack catalog and producing **honest gap reports**.
- Running **repeatable simulations** to compare configurations, rule sets, or analyst response over time.
- **Training analysts** on realistic-looking telemetry without touching production.
- Generating **executive-level reports** with NIST CSF / CIS Controls scoring and MITRE heatmaps.
- Serving as an **integration playground** for SIEM/SOAR/EDR/ITSM connectors before wiring them to real production systems.

### What CyberTwin SOC is **not** (yet)

- A **SIEM**. It does not replace Splunk, Sentinel, Elastic, etc. It is designed to *measure* their coverage.
- A **threat-intelligence platform**. The threat-intel views are illustrative.
- A **production EDR**. The endpoint events are synthetic unless you wire up a connector.
- A **certified compliance auditor**. NIST/CIS scoring is indicative and based on simulation outcomes, not formal audit evidence.

### MITRE coverage — the honest definitions

Future releases will distinguish these levels in the UI. Today, the project mostly reports **catalog coverage** and **alert-mapped coverage**:

| Level                            | Definition                                                                            | Status today |
| -------------------------------- | ------------------------------------------------------------------------------------- | ------------ |
| Catalog Coverage                 | Technique exists in the loaded MITRE bundle                                            | ✅ 622 / 622 |
| Rule-Mapped Coverage             | At least one detection rule references the technique                                   | Partial      |
| Tested Coverage                  | Rule has at least one passing detection-test fixture                                   | Roadmap      |
| Validated Detection Coverage     | Tested rule fired in a recent simulation **and** produced acceptable false-positive rate | Roadmap      |
| Noisy Coverage                   | Rule fires but is flagged by analyst feedback as high-FP                               | Roadmap      |
| High-Risk Gaps                   | Critical technique with **no rule, no test, and no telemetry source** available        | Roadmap      |

### Reproducibility & responsible use

- All detections, scores, and reports are **reproducible** for a given scenario + seed. They are **not** predictions of real-world incidents.
- The AI Analyst is a **decision-support tool**, not a source of truth. Always verify its output against the underlying events.
- Use the platform on lab environments, controlled tenants, or air-gapped networks — never paste production secrets into the SOAR / connector configuration without proper review.

> If you find a claim in this README that overstates what the code actually does, please open an issue — accuracy matters more than marketing here.

---

## 📈 Roadmap

- [x] Phase 1 — Security (JWT, RBAC, bcrypt, audit)
- [x] Phase 2 — 11 attack scenarios
- [x] Phase 3 — 46 detection rules + Sigma loader
- [x] Phase 4 — LLM AI analyst (Ollama + NLG fallback)
- [x] Phase 5 — ML anomaly detection (IsolationForest + UEBA)
- [x] Phase 6 — MITRE ATT&CK 622 techniques + TAXII sync
- [x] Phase 7 — Infrastructure (Redis cache, WebSocket, async)
- [x] Phase 8 — NIST CSF v1.1 + CIS Controls v8 benchmarking
- [x] Phase 9 — Frontend: Benchmark, Anomaly, SOAR, LLM status pages
- [x] Phase 10 — Unit test suite (128 tests, 100% passing)
- [x] Phase 11 — Docker Compose production deployment (multi-stage + nginx)
- [x] Phase 12 — SOAR integration (TheHive 5 + Cortex 3)

---

<div align="center">

Built with ❤️ for the cybersecurity community

**[⭐ Star this repo](https://github.com/omarbabba779xx/CyberTwin-SOC)** if you find it useful!

</div>

