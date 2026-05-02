# ISO 27001:2022 Readiness Mapping - CyberTwin SOC

Version: 2.0

Date: 2026-05-02

Classification: Internal - Compliance readiness

This document maps CyberTwin SOC repository controls to ISO/IEC 27001:2022
Annex A. It is readiness evidence for an ISMS or certification project, not a
certificate. A formal ISO 27001 certification still requires management scope,
risk acceptance, internal audit, certification-body review, and live operating
records outside this repository.

## Repository Readiness Summary

| ISO area | Repository readiness | Evidence |
| --- | --- | --- |
| A.5 Organizational controls | Ready for operator adoption | README, compliance pack, production checklist, runbooks |
| A.6 People controls | Operator-owned | Roles and audit accountability exist; HR/training records are external |
| A.7 Physical controls | External provider-owned | Deployment model delegates physical controls to infrastructure provider |
| A.8 Technological controls | Implemented | Auth, RBAC, tenant isolation, logging, backup, scans, Helm hardening |

## Annex A Mapping

| Control family | Status | Repository evidence |
| --- | --- | --- |
| Policies for information security | Ready for adoption | `docs/compliance/`, `docs/operations/` |
| Information security roles | Implemented | Static roles plus dynamic tenant RBAC |
| Segregation of duties | Implemented | Permission model and scoped FastAPI dependencies |
| Threat intelligence | Implemented | MITRE bundle, TAXII sync, Atomic Red Team metadata mode |
| Asset inventory | Ready | ORM models, Docker/Helm manifests, API surface map |
| Access control | Implemented | JWT, OIDC option, tenant isolation middleware |
| Identity management | Implemented | Session governance, token revocation, refresh rotation |
| Incident management | Implemented in product workflow | Cases, comments, evidence, feedback, SOAR routes |
| Business continuity | Ready for drill | Backup/restore runbook and production readiness check |
| Logging and monitoring | Implemented | Tenant-scoped audit chain, metrics, health, OTel tracing |
| Technical vulnerability management | Implemented | pip-audit, npm audit, Bandit, Trivy, Semgrep/Checkov CI surfaces |
| Configuration management | Ready | Docker Compose, Helm chart, secure overlay, production safety checks |
| Secure development lifecycle | CI-ready | Pytest, Vitest, Playwright, lint, migrations, compose and Helm checks |
| Cryptography | Implemented | bcrypt, JWT signing, AES-GCM field encryption utilities |
| Backup | Ready | `scripts/backup.sh`, `docs/operations/backup-recovery.md` |
| Network security | Implemented | Security headers, CORS, NetworkPolicy default-deny overlay |

## Evidence Commands

```bash
python scripts/production_readiness_check.py
python -m pytest tests/test_tenant_scoped_runtime.py tests/test_soc_orm_runtime.py tests/test_attack_validation_matrix.py -q
python -m bandit -q -r backend -iii -lll --skip B101,B104
python -m pip_audit -r requirements.txt --strict
npm audit --audit-level=high
helm template cybertwin deploy/helm/cybertwin-soc \
  --values deploy/helm/cybertwin-soc/values.yaml \
  --values deploy/helm/cybertwin-soc/values-secure.yaml \
  --set ingress.host=soc.example.com
```

## Certification Boundary

CyberTwin now provides a coherent technical and documentation baseline for an
ISO 27001 program. The certification owner must still define the ISMS scope,
approve risk treatment, operate the controls over time, run internal audits,
and provide environment-specific evidence to the certification body.
