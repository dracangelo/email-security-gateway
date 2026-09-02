# Privacy Impact Assessment (PIA) — email-auth-gateway

This Privacy Impact Assessment (PIA) analyzes the processing, storage, and protection of Personally Identifiable Information (PII) within the `email-auth-gateway` system.

---

## 1. Data Collection & Processing Scope

`email-auth-gateway` processes inbound (and outbound) email traffic to evaluate authentication posture (SPF, DKIM, DMARC, ARC, BIMI) and inspect email bodies and attachments for phishing, malware, and credential theft.

### PII Categories Processed:
- **Email Headers**: Sender (`From`, `Return-Path`), Recipient (`To`, `Cc`), Subject lines, IP addresses (`Received` headers).
- **Email Body Content**: Plain text, HTML bodies, embedded hyperlinks, signatures.
- **Attachments**: Documents (PDF, Office), images (OCR / QR code analysis), archives.
- **Audit & Log Data**: Operator identity, timestamp, action history, administrative decisions.

---

## 2. Privacy Risk Matrix & Technical Safeguards

| Privacy Risk | Severity | Technical Safeguard / Mitigation | Responsible Module |
| :--- | :--- | :--- | :--- |
| **Unauthorized Access to Quarantined Email Body** | High | Multi-tenant isolation, Fernet AES-128 payload encryption at rest, JWT RBAC scope validation. | `multi_tenancy/storage.py`, `audit/encryption.py` |
| **PII Leakage in System Logs** | High | Automated PII redaction filtering SSNs, credit cards, passwords, API tokens, and phone numbers before write. | `security/redact.py` |
| **Indefinite Data Retention** | High | Automated `DataPurgeEngine` enforcing configurable retention limits (Quarantine: 30d, Raw Mail: 14d, Audit: 90d). | `compliance/retention.py` |
| **Cross-Border Jurisdiction Violation** | High | `DataResidencyManager` enforcing regional storage bounds per tenant policy. | `compliance/residency.py` |
| **Inability to Fulfill DSAR / Erasure Requests** | Medium | `DataSubjectRequestManager` supporting automated data exports and Right-to-be-Forgotten erasures. | `compliance/gdpr.py` |

---

## 3. Data Subject Rights & Operator Controls

1. **Access Rights (DSAR)**: Data subjects or authorized operators can request complete data exports via `DataSubjectRequestManager.export_subject_data()`.
2. **Right to Erasure / Right to be Forgotten**: Data subjects can request full deletion of quarantined emails, raw mail logs, and audit log PII via `DataSubjectRequestManager.erase_subject_data()`.
3. **Legal Hold Exemption**: Data subject erasures are automatically checked against active Legal Holds (`LegalHoldManager`) to prevent unlawful deletion of evidence during active legal proceedings.
