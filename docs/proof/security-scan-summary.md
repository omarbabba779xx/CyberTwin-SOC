# Security Scan Summary

> Last manual update: **2026-04-27**.
> All scanners run in CI on every push (job: `Security Scans (non-blocking)`).

## At a glance

| Scanner          | Scope                                          | Result   | Blocking?      |
|------------------|------------------------------------------------|----------|----------------|
| **pip-audit**    | Python `requirements.txt` dependency CVEs      | **0 known CVEs** ✅ | non-blocking *(planned: blocking on CRITICAL)* |
| **Bandit**       | Python static analysis                         | 0 high · 5 medium · 98 low | non-blocking *(planned: blocking on high+confidence)* |
| **Semgrep**      | Multi-language SAST (Python + JS, default ruleset) | clean run | non-blocking |
| **Gitleaks**     | Secret scanning across full git history        | 0 verified secrets ✅ | non-blocking *(planned: **blocking** next)* |
| **Trivy** (FS)   | Filesystem vulnerabilities                     | clean run | non-blocking   |
| **Trivy** (image)| Container image scan (backend + frontend)      | clean run | non-blocking   |
| **CycloneDX**    | SBOM (Python + npm)                            | uploaded as artefact | informational |
| **npm audit**    | Frontend dependency CVEs                       | clean    | high gate (already blocking) |

## pip-audit — 0 known CVEs

```
$ python -m pip_audit -r requirements.txt --strict
No known vulnerabilities found
```

This is the result of the dependency upgrade pass on 2026-04-27 which fixed
9 CVEs across 5 packages (FastAPI 0.136, starlette 0.49, PyJWT 2.12,
python-multipart 0.0.26, python-dotenv 1.2.2, scikit-learn 1.5.2).

See commit `12298ae` and `e2fbc59` for the full diff.

## Bandit — 5 medium-severity findings (all reviewed)

```
Total issues (by severity):
    Undefined: 0
    Low: 98
    Medium: 5
    High: 0
```

The 5 medium findings are all **reviewed and accepted** false positives,
documented in code with `# nosec` comments where applicable:

| Issue ID  | Where                                  | Verdict                                                                  |
|-----------|----------------------------------------|--------------------------------------------------------------------------|
| B608      | `backend/soc/cases.py:188`             | False positive — column allowlist + identifier regex (defence-in-depth) |
| B108 (×3) | `attack_engine.py`, `log_generator.py` | Intentional — these are *simulated* attacker file paths, not real ops    |
| B310 (×1) | `mitre/taxii_sync.py`                  | Reviewed — TAXII URL is whitelisted to MITRE official endpoints          |

## Gitleaks — 0 secrets

The previous audit found `data/.jwt_secret` was tracked in git.
That file has been **`git rm --cached`**'d in commit `12298ae`. From now on,
Gitleaks will fail the CI if any secret matches the patterns in
`.gitleaks.toml`. Plan: make this scan **blocking** in the next sprint
(see `docs/IMPROVEMENTS.md` Tier B #18).

## Roadmap to blocking gates

Per the staged plan:

1. ✅ Step 1 — All scans run, results published as CI artefacts.
2. ⏳ Step 2 — Block on **secrets detected** (gitleaks → blocking).
3. ⏳ Step 3 — Block on **CVE CRITICAL** (pip-audit → strict on CRITICAL only).
4. ⏳ Step 4 — Block on **CRITICAL + HIGH exploitable** (Trivy + pip-audit).
5. ⏳ Step 5 — Block on **Bandit high-confidence** findings.

Each step is one PR, gated on a clean baseline first.

## How to reproduce locally

```bash
pip install bandit pip-audit gitleaks-py-bridge
python -m pip_audit -r requirements.txt --strict
python -m bandit -r backend/ -ll --skip B101,B104
gitleaks detect --source . --no-banner
```
