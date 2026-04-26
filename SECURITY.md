# Security Policy

CyberTwin SOC is a security-focused project. We take vulnerabilities seriously and appreciate any responsible disclosure.

## Supported Versions

Only the latest `master` branch is actively maintained at this time. Older
tagged releases receive security fixes on a best-effort basis.

| Version  | Supported |
|----------|-----------|
| `master` |     ✅     |
| `< 3.0`  |     ❌     |

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

Instead, report them privately by:

1. Opening a [GitHub Security Advisory](https://github.com/omarbabba779xx/CyberTwin-SOC/security/advisories/new) (preferred), or
2. Contacting the maintainer directly via the GitHub profile.

When reporting, please include:

- A description of the vulnerability and its potential impact
- Steps to reproduce (proof-of-concept if possible)
- The affected version / commit hash
- Your suggested fix, if any

You can expect:

- An acknowledgement within **72 hours**
- A first assessment within **7 days**
- A public fix within **30 days** for critical issues, when feasible

## Scope

In scope:

- Authentication / authorization bypass
- JWT or session-token weaknesses
- Injection vulnerabilities (SQL, command, prompt)
- CSRF / XSS in the frontend
- Privilege escalation between RBAC roles
- SSRF / RCE in any backend service
- Insecure default configurations
- Cryptographic weaknesses

Out of scope:

- Issues requiring physical access to the host
- Denial-of-service via resource exhaustion (already rate-limited)
- Vulnerabilities in third-party dependencies that are not yet exploitable
  in CyberTwin SOC's context (please report them upstream first)
- Findings from automated scanners without a working proof-of-concept

## Secure Defaults

CyberTwin SOC ships with **production-safety guards**:

- The application **refuses to start in production mode** (`ENV=production`)
  if any of the following are true:
  - `JWT_SECRET` is unset, shorter than 32 characters, or a known default value
  - Any default user password is detected (see `backend/auth.py`)
- All passwords are hashed with **bcrypt** (work factor 12)
- JWT secrets are persisted to disk if not provided via environment, so tokens
  survive container restarts in single-replica deployments

## Hardening Checklist Before Going Live

- [ ] Set `ENV=production` in your environment
- [ ] Generate a fresh `JWT_SECRET` (≥ 48 random chars)
- [ ] Replace **every** default password
- [ ] Restrict `CORS_ORIGINS` to your real domains (no wildcards)
- [ ] Front the API with TLS (nginx, Traefik, ingress controller…)
- [ ] Enable Redis with a password and TLS if exposed
- [ ] Enable audit-log retention and external log forwarding
- [ ] Configure rate-limit thresholds based on your expected traffic
- [ ] Run `pip-audit` and `bandit` regularly (already in CI)
- [ ] Pin Docker images by digest, not just by tag

## Honest Limitations

CyberTwin SOC is a **digital-twin platform for SOC readiness**. It is **not**
a complete production SOC, and it does not, by itself, detect 100% of real
attacks. See the *Honest Limitations* section in `README.md` for the full
context.
