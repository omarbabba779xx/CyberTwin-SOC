# 🚀 CyberTwin SOC — Improvement Backlog

> Living document. Each idea has an honest **value × effort** rating.
> "Value" = real-world SOC impact. "Effort" = how many person-weeks for a senior eng.

---

## Tier S — Highest leverage (do these next)

### 1. Multi-tenancy (`tenant_id` everywhere)
**Value: 5/5 · Effort: 3 weeks**
Add `tenant_id` to every DB row, every JWT claim, every Redis key. Add a tenant-scope dependency that filters every query. Without this, you can't sell to MSSPs or run shared-infra SOCs.

### 2. Real connector implementations
**Value: 5/5 · Effort: 4 weeks for top 4**
Today the connectors are interfaces + mocks + stubs. Implement at least:
- **Splunk** (search + push alerts) via `splunk-sdk`
- **Microsoft Sentinel** (Log Analytics ingestion + alerts) via `azure-monitor-query`
- **Jira Cloud** (case sync) via REST
- **MISP** (TI lookups) via `pymisp`

Each one needs auth (OAuth2 / API token), retry/backoff, circuit breaker, and a real-system integration test.

### 3. Executive dashboard
**Value: 4/5 · Effort: 1 week**
A dedicated `Executive.jsx` page that aggregates:
- KRIs over the last 30/60/90 days (mean MTTD, mean MTTR, false-positive rate)
- Coverage delta vs last quarter
- Top 5 attack trends from incoming threat intel
- SLA breach heat-map

This is what gets shown to the CISO. No dashboards = no budget.

### 4. Detection-as-Code (GitOps for rules)
**Value: 5/5 · Effort: 2 weeks**
Today rules live in Python. Move every rule into a `rules/*.yaml` file (Sigma-compatible). On push to `main`, CI validates them and live-reloads in production. Pair with the existing benchmark suite so every PR shows its detection delta vs `main`.

### 5. eBPF live agent (Linux endpoints)
**Value: 5/5 · Effort: 6 weeks**
A Rust + libbpf agent that tails `execve`, `connect`, `openat`, `bpf` itself, and ships normalised events to `/api/ingest/batch`. This closes the gap between "we ingested syslog" and "we have endpoint visibility on every Linux host".

---

## Tier A — Strong return on effort

### 6. STIX 2.1 / TAXII 2.1 *publishing* (not just consuming)
**Value: 4/5 · Effort: 2 weeks**
Right now we sync MITRE from TAXII. Flip it: expose our IOCs and validated detections as a STIX bundle so peer SOCs can subscribe.

### 7. Postgres-only SOC store with Alembic
**Value: 4/5 · Effort: 1 week**
SQLite is fine for dev but blocks horizontal scaling. Move cases/feedback/suppressions/audit to Postgres with proper Alembic migrations. Keep a SQLite fallback for the demo container.

### 8. JA3 / JA3S / HASSH fingerprinting in network rules
**Value: 4/5 · Effort: 1 week**
Add a `fingerprint` field to the network event schema, ship a Suricata sidecar that emits JA3/JA3S, and add 5–10 detections (rare client TLS fingerprints, mismatched JA3 vs UA, …).

### 9. Purple-team workflow page
**Value: 4/5 · Effort: 2 weeks**
Plan an exercise (pick scenario + target hosts + start time), execute, get a structured report comparing predicted detections vs actual fires. Connect with Atomic Red Team T# IDs out-of-the-box.

### 10. AI Analyst — local embeddings + RAG over IR runbooks
**Value: 4/5 · Effort: 2 weeks**
Today the LLM only sees the report context. Add a `runbooks/` directory of markdown IR procedures and use an embeddings store (Chroma / pgvector) so the AI cites the relevant playbook section when triaging.

### 11. Open Telemetry tracing
**Value: 3/5 · Effort: 1 week**
We expose Prometheus metrics — add OTLP traces. Slow-detection pipelines become trivially debuggable.

### 12. Frontend offline mode + service worker
**Value: 3/5 · Effort: 1 week**
Analysts often work in air-gapped environments. Cache the dashboards for read-only viewing, queue case updates locally, sync when connectivity returns.

---

## Tier B — Nice quality bumps

### 13. Replace SQLite-backed audit log with append-only WORM
**Value: 3/5 · Effort: 1 week**
For compliance — audit log mustn't be mutable. Move it to a write-only S3 bucket with object-lock, or to a hash-chain table where each row references the previous row's hash.

### 14. Rate-limit by *user*, not just by IP
**Value: 3/5 · Effort: 2 days**
slowapi today is keyed by `request.client.host`. Behind a corporate proxy this maps everyone to the same IP. Add a custom key function `f"{user.id}@{request.client.host}"`.

### 15. Field-level encryption for sensitive case fields
**Value: 3/5 · Effort: 1 week**
`description`, `evidence` and `comment` may contain PII. Encrypt at rest with a KMS-managed key.

### 16. Better Coverage Center charts
**Value: 3/5 · Effort: 4 days**
Today we have a heat-map. Add:
- Sankey diagram from "log sources available" → "techniques covered"
- Time-series of coverage % per tactic over the last 12 months
- Click-through that opens the rule + scenario that validated a technique

### 17. Pre-commit framework
**Value: 2/5 · Effort: 2 days**
`pre-commit` config with black + isort + flake8 + bandit + gitleaks. Stops broken commits from ever leaving the dev's machine.

### 18. Dependabot + auto-merge for patch CVEs
**Value: 3/5 · Effort: 1 day**
We just spent a session bumping 5 packages. Automate it.

### 19. Recharts → echarts/visx for big datasets
**Value: 2/5 · Effort: 1 week**
The 622-technique heat-map is sluggish in Recharts. Migrate to ECharts with WebGL or visx with virtualisation.

### 20. WebAuthn / passkeys for analyst login
**Value: 4/5 · Effort: 1 week**
Add a `/api/auth/webauthn/*` flow alongside JWT. Phishing-resistant SSO is table-stakes for SOC tooling now.

---

## Tier C — Long-tail polish

### 21. Generate playable PDF reports
PDFs from the existing markdown reports + Playwright headless render.

### 22. Slack / MS Teams notifier
Drop-in integration that posts SLA breaches and high-severity cases to a channel.

### 23. CLI client (`cybertwin-cli`)
For ops who don't want to click — `cybertwin coverage --tactic Initial-Access --json`.

### 24. SDK in TypeScript + Python
Auto-generated from OpenAPI. Makes 3rd-party integrations a one-liner.

### 25. Demo data seeder
`make seed-demo` populates 200 cases, 5 000 alerts, 10 simulations so the UI is never empty when investors land on it.

### 26. Browser-based attack replay
Pick a past incident, click "replay" — frontend re-streams the alerts at 5× speed for training.

### 27. Anomaly model A/B
Today we have one IsolationForest. Add a 2nd model (e.g. autoencoder) and vote, with confidence calibration via Platt scaling.

### 28. Honeypot integration (T-Pot, Cowrie)
Auto-ingest the SSH/Telnet sessions to enrich threat intel.

### 29. Containerise benchmarks
`docker run cybertwin-bench` runs the full k6 + locust suite against a target URL — turns the project into a pen-tester's stress-test tool.

### 30. Offline air-gapped install bundle
`make airgap-bundle` produces a single `.tar.gz` with all images, npm cache, and pip wheels — for classified networks.

---

## How priorities are decided

| Tier | Definition                                     | When to pull from this tier                         |
|------|------------------------------------------------|------------------------------------------------------|
| **S** | Mandatory before "real-world enterprise" v3.5  | Always work on something here unless blocked        |
| **A** | High value but not strictly blocking           | Pull during normal sprints                          |
| **B** | Quality / polish                                | Pull when running ahead of schedule                 |
| **C** | Long-tail fun stuff                             | Hack-day / community contribution candidates        |

---

*Last updated: April 2026. Keep this file honest.*
