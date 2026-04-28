# ISO 27001:2022 Readiness Assessment — CyberTwin SOC

**Version**: 1.0  
**Date**: 2026-04-28  
**Classification**: Internal — Compliance

---

## 1. Executive Summary

This document evaluates CyberTwin SOC's alignment with ISO/IEC 27001:2022 Annex A controls. The platform implements strong technical controls but lacks the formal ISMS (Information Security Management System) documentation required for certification. Estimated readiness: **60%** of Annex A controls are technically addressed; **35%** have the documentation required for certification.

---

## 2. ISMS Documentation Status

| Document | Status | Priority |
|----------|--------|----------|
| Information Security Policy | Gap | P0 |
| Risk Assessment Methodology | Gap | P0 |
| Risk Treatment Plan | Gap | P0 |
| Statement of Applicability (SoA) | Gap | P0 |
| Asset Inventory | Partial | P0 |
| Acceptable Use Policy | Gap | P1 |
| Access Control Policy | Implemented (in code) | P1 — needs formal doc |
| Incident Management Procedure | Partial | P1 |
| Business Continuity Plan | Gap | P1 |
| Supplier Security Policy | Gap | P2 |

---

## 3. Annex A Control Mapping

### A.5 — Organizational Controls

| Control | Title | Status | Notes |
|---------|-------|--------|-------|
| A.5.1 | Policies for information security | Gap | No formal ISMS policy document |
| A.5.2 | Information security roles | Partial | 12 RBAC roles defined; no organizational RACI |
| A.5.3 | Segregation of duties | Implemented | Role-based access with scoped permissions |
| A.5.4 | Management responsibilities | Gap | No formal management commitment document |
| A.5.5 | Contact with authorities | Gap | No documented contacts for incident reporting |
| A.5.6 | Contact with special interest groups | Partial | MITRE ATT&CK alignment; no formal memberships |
| A.5.7 | Threat intelligence | Implemented | STIX/TAXII feeds, MITRE mapping, 622 techniques |
| A.5.8 | InfoSec in project management | Partial | Security tests in CI; no formal security gate in SDLC |
| A.5.9 | Inventory of information assets | Partial | ORM models document data; no formal asset register |
| A.5.10 | Acceptable use of assets | Gap | No acceptable use policy |
| A.5.11-14 | Asset return, classification, labeling, transfer | Gap | Not implemented |
| A.5.15 | Access control | Implemented | JWT + RBAC + tenant isolation |
| A.5.16 | Identity management | Implemented | Local auth + OIDC federation |
| A.5.17 | Authentication | Implemented | bcrypt, JWT with jti, refresh rotation |
| A.5.18 | Access rights | Implemented | Permission-based with 12 roles |
| A.5.23 | Information security for cloud | Partial | Container security; no cloud security assessment |
| A.5.24 | InfoSec incident planning | Partial | Case management + alert queue; no formal IR plan |
| A.5.25 | InfoSec event assessment | Implemented | Detection engine with severity classification |
| A.5.26 | Response to incidents | Implemented | SOAR integration (TheHive/Cortex) |
| A.5.27 | Learning from incidents | Implemented | Feedback loop (TP/FP verdicts), noisy rule detection |
| A.5.28 | Evidence collection | Implemented | Tamper-evident audit trail with chained hashing |
| A.5.29 | InfoSec during disruption | Partial | Backup/recovery scripts; no BCP |
| A.5.30 | ICT readiness for business continuity | Partial | Docker Compose + Helm; no failover testing |
| A.5.31 | Legal and regulatory requirements | Gap | No compliance register |
| A.5.34 | Privacy and PII protection | Partial | PII redaction in AI analysis; field-level encryption |
| A.5.35 | Independent review | Partial | CI quality gate; no formal audit schedule |
| A.5.36 | Compliance with policies | Partial | Automated via CI; no compliance monitoring |
| A.5.37 | Documented operating procedures | Partial | README + ops runbooks; needs expansion |

### A.6 — People Controls

| Control | Title | Status | Notes |
|---------|-------|--------|-------|
| A.6.1 | Screening | N/A | Open-source project |
| A.6.2 | Terms of employment | N/A | Open-source project |
| A.6.3 | Security awareness training | Gap | No training program |
| A.6.4 | Disciplinary process | N/A | Open-source project |
| A.6.5 | Post-employment responsibilities | N/A | Open-source project |
| A.6.6 | Confidentiality agreements | Gap | No CLA or NDA templates |
| A.6.7 | Remote working | Partial | Secure API design; no remote work policy |
| A.6.8 | InfoSec event reporting | Implemented | Audit trail + structured logging |

### A.7 — Physical Controls

| Control | Title | Status | Notes |
|---------|-------|--------|-------|
| A.7.1-14 | Physical security controls | N/A | Cloud-hosted; delegated to infrastructure provider |

### A.8 — Technological Controls

| Control | Title | Status | Notes |
|---------|-------|--------|-------|
| A.8.1 | User endpoint devices | N/A | Server-side platform |
| A.8.2 | Privileged access rights | Implemented | `platform_admin` role with full permissions |
| A.8.3 | Information access restriction | Implemented | Tenant-scoped queries via `TenantRepository` |
| A.8.4 | Access to source code | Partial | GitHub access controls; no formal policy |
| A.8.5 | Secure authentication | Implemented | bcrypt + JWT + OIDC + session governance |
| A.8.6 | Capacity management | Partial | Redis MAXLEN on streams; no formal capacity plan |
| A.8.7 | Protection against malware | N/A | Server-side; no user-uploaded executables |
| A.8.8 | Technical vulnerability management | Implemented | pip-audit, npm audit, Checkov, Bandit in CI |
| A.8.9 | Configuration management | Partial | Docker Compose + Helm; no configuration baseline doc |
| A.8.10 | Information deletion | Implemented | Data retention job with configurable TTL per tenant |
| A.8.11 | Data masking | Implemented | PII redaction in AI analysis pipeline |
| A.8.12 | Data leakage prevention | Partial | gitleaks in CI; no runtime DLP |
| A.8.13 | Information backup | Implemented | `scripts/backup.sh` with PG + Redis backup |
| A.8.14 | Redundancy of information processing | Partial | Helm chart supports replicas; no HA documentation |
| A.8.15 | Logging | Implemented | Structured JSON logs, request IDs, OTel traces |
| A.8.16 | Monitoring activities | Implemented | Prometheus metrics, health probes, alert pipeline |
| A.8.17 | Clock synchronisation | Implemented | All timestamps in UTC via `datetime.now(timezone.utc)` |
| A.8.20 | Network security | Implemented | Docker network isolation, CORS, security headers |
| A.8.21 | Web services security | Implemented | CSP, X-Frame-Options, rate limiting, input validation |
| A.8.23 | Web filtering | N/A | Not applicable to backend platform |
| A.8.24 | Use of cryptography | Implemented | AES-256-GCM field encryption, bcrypt, JWT HS256 |
| A.8.25 | Secure development lifecycle | Partial | Security tests in CI; no formal SSDLC document |
| A.8.26 | Application security requirements | Partial | OWASP headers; no formal requirements specification |
| A.8.27 | Secure system architecture | Implemented | Layered architecture, ORM, middleware stack |
| A.8.28 | Secure coding | Implemented | Bandit, flake8, type hints, input validation |
| A.8.29 | Security testing in development | Implemented | 253 tests including 30+ security-focused tests |
| A.8.30 | Outsourced development | N/A | Not outsourced |
| A.8.31 | Separation of environments | Partial | Docker profiles; no formal env separation policy |
| A.8.33 | Test information | Partial | Synthetic test data; no formal test data policy |
| A.8.34 | Protection during audit testing | Implemented | Audit trail is append-only with integrity verification |

---

## 4. Gap Analysis Summary

| Category | Implemented | Partial | Gap | N/A |
|----------|-----------|---------|-----|-----|
| A.5 Organizational | 10 | 9 | 9 | 0 |
| A.6 People | 1 | 1 | 2 | 4 |
| A.7 Physical | 0 | 0 | 0 | 14 |
| A.8 Technological | 14 | 7 | 0 | 3 |
| **Total** | **25** | **17** | **11** | **21** |

**Technical controls**: Strong (83% implemented or partial)  
**Documentation**: Weak (35% formally documented)

---

## 5. Certification Roadmap

### Phase 1 — ISMS Foundation (Months 1-2)

1. Draft and approve Information Security Policy
2. Define risk assessment methodology (ISO 27005 aligned)
3. Conduct initial risk assessment
4. Produce Statement of Applicability
5. Create asset inventory from ORM models + infrastructure

### Phase 2 — Control Documentation (Months 3-4)

6. Document access control policy (formalize existing RBAC)
7. Write incident management procedure (based on existing case workflow)
8. Create business continuity plan
9. Document secure development lifecycle
10. Establish supplier security assessment process

### Phase 3 — Implementation & Evidence (Months 5-8)

11. Implement security awareness training program
12. Establish formal change management process
13. Schedule and conduct DR testing (quarterly)
14. Implement access review process (quarterly)
15. Set up compliance monitoring dashboard

### Phase 4 — Internal Audit & Certification (Months 9-12)

16. Conduct internal ISMS audit
17. Management review meeting
18. Address non-conformities
19. Engage certification body
20. Stage 1 audit (documentation review)
21. Stage 2 audit (implementation verification)

---

## 6. Risk Register Template

| ID | Risk | Likelihood | Impact | Current Controls | Residual Risk | Treatment |
|----|------|-----------|--------|-----------------|---------------|-----------|
| R1 | Unauthorized access | Low | Critical | JWT + RBAC + session governance | Low | Accept |
| R2 | Data breach | Low | Critical | Encryption + tenant isolation | Medium | Mitigate (add MFA) |
| R3 | Service disruption | Medium | High | Health checks + backup | Medium | Mitigate (add HA) |
| R4 | Insider threat | Low | High | Audit trail + role separation | Low | Monitor |
| R5 | Supply chain compromise | Low | High | pip-audit + gitleaks | Medium | Mitigate (add SCA) |

---

*This assessment should be reviewed annually and updated after significant changes to the platform.*
