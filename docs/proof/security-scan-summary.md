# Security Scan Summary (v3.2)

> Last manual update: **2026-04-28** (commit rolling on `master`).
> All scanners run in CI on every push (`.github/workflows/ci.yml`).

## At a glance

| Scanner          | Scope                                          | Result   | Blocking? |
|------------------|------------------------------------------------|----------|-----------|
| **pip-audit**    | Python `requirements.txt` dependency CVEs      | **0 known CVEs** ✅ | **BLOCKING on CRITICAL+HIGH** |
| **Bandit (high-conf, high-sev)** | Python static analysis (`-iii -lll`) | **0 high · 0 medium** ✅ | **BLOCKING** *(new in v3.2)* |
| **Bandit (full report)** | Python static analysis (low + medium tracking) | 103 low · 0 medium · 0 high | non-blocking *(advisory; promoted progressively)* |
| **Semgrep (ERROR severity)** | Multi-language SAST (Python + JS) | clean run | **BLOCKING** |
| **Gitleaks**     | Secret scanning across full git history        | 0 verified secrets ✅ | **BLOCKING** |
| **Trivy** (FS HIGH+CRITICAL) | Filesystem vulnerabilities (`ignore-unfixed: true`) | clean | **BLOCKING** |
| **CycloneDX**    | SBOM (Python + npm)                            | uploaded as artefact | mandatory artefact (informational) |
| **npm audit**    | Frontend dependency CVEs                       | clean    | **BLOCKING on HIGH** |
| **Checkov**      | Dockerfile + Helm chart IaC                    | clean    | non-blocking *(advisory; CRITICAL → BLOCKING in v3.3)* |
| **kubeconform**  | K8s manifest schema validation                 | clean    | **BLOCKING** |

### Progressive hardening plan

| Phase | Promotion | Scope | Status |
|---|---|---|---|
| 1 | Bandit `-iii -lll` (high-conf high-sev) → BLOCKING | Python critical SAST | **done** |
| 2 | Semgrep `--severity=ERROR` → BLOCKING | Python + JS | **done** |
| 3 | Trivy FS HIGH+CRITICAL (with `ignore-unfixed: true`) → BLOCKING | CVEs in tracked files | **done** |
| 4 | Bandit full medium bucket → tracked + capped gate | full SAST hygiene | planned |
| 5 | Checkov CRITICAL subset → BLOCKING | Dockerfile + Helm | planned |
| 6 | Lighthouse perf budget | frontend | planned |

## pip-audit — 0 known CVEs

```
$ python -m pip_audit -r requirements.txt --strict
No known vulnerabilities found
```

The dependency upgrade pass (commit `12298ae` and `e2fbc59`) fixed 9 CVEs.
v3.2 added: `authlib>=1.3` (OIDC), `cryptography>=44.0` (AES-GCM, HKDF),
and the OpenTelemetry stack — all current with **no known CVEs**.

## Bandit — 0 medium / 0 high (current snapshot)

Re-measured on **2026-04-28** at commit `d0f4e3f`:

```
$ bandit -r backend/ -ll --skip B101,B104
Total issues (by severity):
    Undefined: 0
    Low:    103
    Medium:   0
    High:     0
Total issues (by confidence):
    Low:      0
    Medium:   4
    High:    99
```

The 103 low-severity findings are tracked but not gated. The two skip
flags are kept by design and documented:

| Skip | Rationale |
|---|---|
| `B101` | `assert` is allowed inside test files — required by pytest |
| `B104` | `0.0.0.0` host bind is required by Docker Compose / Kubernetes |

### Historical medium findings — fully resolved in v3.2

The previous version of this document reported 5 medium-severity
findings (`B608` × 1, `B108` × 3, `B310` × 1). They have all been
**closed**, not silenced — see commit history:

| Issue ID  | Where (historic)                       | Resolution |
|-----------|----------------------------------------|------------|
| B608      | `backend/soc/cases.py:188`             | Refactored to allow-listed identifiers + parameterised query (`backend/soc/cases.py` v3.2). |
| B108 (×3) | `attack_engine.py`, `log_generator.py` | Replaced hard-coded `/tmp` paths with `tempfile.mkdtemp()` and `Path(tempfile.gettempdir())`. |
| B310 (×1) | `mitre/taxii_sync.py`                  | TAXII URL now allow-listed against the MITRE official endpoint at module load time and rejected otherwise. |

Re-running Bandit at full severity (`-ll`) on the v3.2 snapshot returns
**zero medium findings**. This is the snapshot the CI gate uses.

## Gitleaks — 0 secrets

```
$ gitleaks detect --source . --no-banner --redact
{"summary":"no leaks found"}
```

The `data/.jwt_secret` file was `git rm --cached`'d in commit `12298ae`,
and the v3.2 git history was scrubbed via `git filter-branch` to remove
trailing automation metadata. **Gitleaks is BLOCKING** as of v3.2.

## v3.2 — Quality Gate composition

Per `.github/workflows/ci.yml` (job `quality-gate`), the following gates
are **blocking** today (any failure fails the merge):

| Gate | Blocking on |
|---|---|
| `pip-audit --strict` | any known CVE in pinned Python deps |
| `bandit -iii -lll --skip B101,B104` | high-confidence high-severity SAST findings |
| `semgrep ERROR` (Docker) | actionable multi-language findings |
| `trivy fs` HIGH+CVSS gate | CVEs under `ignore-unfixed: true` |
| `gitleaks-action@v2` | any verified secret matched by `.gitleaks.toml` |
| `npm audit --audit-level=high` | HIGH or CRITICAL frontend CVEs |
| `flake8` | any non-style lint violation |
| `helm lint` + manifest render | malformed chart |
| `alembic upgrade head` + downgrade smoke (PG 16) | schema drift |
| Docker compose smoke (build + healthcheck) | image regression |

**Still advisory:** Bandit low/medium backlog (`bandit -ll`), Checkov IaC (`soft_fail` — noise control), Lighthouse CI budgets (soft gate), CycloneDX SBOM artefacts (never fails the workflow).

Semgrep/Trivy also emit informational SARIF uploads before the fatal step so Code Scanning still receives artefacts when a blocking regression occurs.

## Container hardening (v3.2)

| Check | Status |
|---|---|
| Backend image — non-root user | ✅ `USER cybertwin` (uid 1000) |
| Frontend image — non-root user | ✅ `nginxinc/nginx-unprivileged:1.27-alpine` (uid 101, port 8080) |
| 16 MiB request body cap (`MaxBodySizeMiddleware` + reverse-proxy) | ✅ tested by `tests/test_request_body_limit.py` |
| Image pinning | ✅ `python:3.12-slim`, `nginx-unprivileged:1.27-alpine`, `node:20-alpine` |
| Healthchecks | ✅ Backend + Frontend + Redis + Worker |
| `securityContext.runAsNonRoot=true` | ✅ Helm |
| `capabilities.drop: [ALL]` | ✅ Helm |
| `allowPrivilegeEscalation: false` | ✅ Helm |
| K8s NetworkPolicy default-deny | ✅ `deploy/helm/cybertwin-soc/templates/networkpolicy.yaml` |

## Application security (v3.2 additions)

| Control | Status | Reference |
|---|---|---|
| JWT JTI denylist (Redis) + refresh rotation | ✅ | `backend/auth/_core.py` |
| OIDC / SSO with JWKS validation | ✅ | [`oidc-sso-validation.md`](oidc-sso-validation.md) |
| Multi-tenant isolation (middleware + repository) | ✅ | [`multitenancy-isolation-report.md`](multitenancy-isolation-report.md) |
| Tamper-evident audit chain (SHA-256) | ✅ | [`audit-chain-validation.md`](audit-chain-validation.md) |
| AES-256-GCM field encryption (per-tenant HKDF) | ✅ | [`encryption-validation.md`](encryption-validation.md) |
| Connector circuit breaker + retry | ✅ | [`circuit-breaker-validation.md`](circuit-breaker-validation.md) |
| Session governance (concurrent-session cap) | ✅ | `backend/auth/_core.py::track_session` |
| LLM prompt injection / PII redaction | ✅ | `backend/llm_analyst.py::_sanitise` |
| CORS strict (methods + headers) | ✅ | `backend/api/main.py` |
| Rate limiting per `tenant:user` | ✅ | `backend/api/deps.py::_rate_limit_key` |

## How to reproduce locally

```bash
pip install bandit pip-audit
python -m pip_audit -r requirements.txt --strict
python -m bandit -r backend/ -ll --skip B101,B104
gitleaks detect --source . --no-banner --redact
docker run --rm -v "$PWD:/src" aquasec/trivy fs /src --severity HIGH,CRITICAL --exit-code 1
docker run --rm -v "$PWD:/src" bridgecrew/checkov -d /src
kubeconform deploy/k8s/*.yaml
```

All commands above run in CI on every push.
