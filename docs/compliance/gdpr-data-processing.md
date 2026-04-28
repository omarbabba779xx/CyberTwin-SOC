# GDPR Data Processing Documentation — CyberTwin SOC

**Version**: 1.0  
**Date**: 2026-04-28

---

## 1. Data Categories Processed

| Category | Examples | Legal Basis | Retention |
|----------|---------|-------------|-----------|
| Security Events | Source/dest IPs, hostnames, process names | Legitimate interest (Art. 6(1)(f)) | Configurable: `DATA_RETENTION_DAYS` (default 90) |
| User Accounts | Username, role, hashed password | Contract performance (Art. 6(1)(b)) | Account lifetime + 30 days |
| Audit Logs | Username, IP, action, timestamp | Legal obligation (Art. 6(1)(c)) | 365 days minimum (compliance) |
| Alert Data | Rule matches, technique IDs, severity | Legitimate interest (Art. 6(1)(f)) | Same as security events |
| Case Data | Analyst comments, evidence, assignee | Legitimate interest (Art. 6(1)(f)) | Case lifetime + 1 year |
| Session Data | JWT tokens, refresh tokens, jti | Contract performance (Art. 6(1)(b)) | Token lifetime (configurable) |

## 2. Data Protection Measures

| Measure | Implementation |
|---------|---------------|
| Encryption at rest | AES-256-GCM field-level encryption (`backend/crypto/`) |
| Encryption in transit | HTTPS enforced via nginx |
| Access control | RBAC with 12 roles + tenant isolation |
| Data minimization | PII redaction in AI analysis pipeline |
| Pseudonymization | Per-tenant encryption keys via HKDF derivation |
| Audit trail | Tamper-evident with chained SHA-256 hashing |
| Data retention | Automated purge job (`data_retention` task) |

## 3. Data Subject Rights

| Right | Implementation |
|-------|---------------|
| Right of access (Art. 15) | Audit log query by username via `/api/audit` |
| Right to erasure (Art. 17) | `DELETE /api/data/purge` (platform_admin) + retention job |
| Right to restriction (Art. 18) | Account deactivation via admin panel |
| Right to portability (Art. 20) | JSON export via API endpoints |
| Right to object (Art. 21) | Contact data controller; account suspension available |

## 4. Data Retention Schedule

| Data Type | Default Retention | Configurable | Purge Mechanism |
|-----------|------------------|--------------|-----------------|
| Security events | 90 days | `DATA_RETENTION_DAYS` env var | `data_retention` Arq job |
| Audit logs | 365 days | Configurable per compliance requirement | Retention job (respects legal hold) |
| Cases | Indefinite (active) | Closed cases: 1 year after closure | Manual + automated |
| User accounts | Account lifetime | 30 days after deactivation | Admin action |
| Session tokens | JWT expiry (1h access, 7d refresh) | `JWT_EXPIRY_HOURS`, `REFRESH_EXPIRY_DAYS` | Automatic expiry + jti denylist |

## 5. Third-Party Data Processors

| Processor | Data Shared | Purpose | DPA Status |
|-----------|-------------|---------|------------|
| Redis | Cached events, sessions, job state | Performance, session management | Self-hosted; no external transfer |
| PostgreSQL | All persistent data | Primary data store | Self-hosted; no external transfer |
| TheHive (optional) | Case data, alert references | SOAR integration | Self-hosted; requires DPA if cloud |
| OIDC Provider (optional) | Username, email | Authentication | Requires DPA with provider |

---

*Review this document when adding new data categories or third-party integrations.*
