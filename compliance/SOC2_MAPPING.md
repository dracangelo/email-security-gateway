# SOC 2 Trust Services Criteria Control Mapping — email-auth-gateway

This document maps `email-auth-gateway` system architecture and technical controls to the AICPA **SOC 2 Trust Services Criteria** (Security, Availability, Processing Integrity, Confidentiality, Privacy).

---

## 1. Security (Common Criteria)

| SOC 2 CC | Control Description | Technical Gateway Implementation | Verification Artifact / Test |
| :--- | :--- | :--- | :--- |
| **CC6.1** | Logical access control & identity management. | `identity/manager.py` (JWT / Bearer auth, RBAC roles: `admin`, `operator`, `viewer`, scope enforcement), `webhook_receiver/app.py` (`_verify_admin`). | `tests/test_identity_rbac.py` |
| **CC6.3** | Network segmentation & perimeter defenses. | `webhook_receiver/segmentation.py` (`create_inbound_app`, `create_admin_app`), splitting public webhook routes from administrative APIs. | `tests/test_segmentation.py` |
| **CC6.6** | Boundaries, encryption in transit & mTLS. | `security/mtls.py` (`MTLSContextBuilder`, mutual TLS client cert verification, TLS 1.3), `delivery/smtp.py` (STARTTLS / TLS enforcement). | `tests/test_mtls.py` |
| **CC6.7** | Data transmission & storage encryption. | `audit/encryption.py` (`RawMailCipher` Fernet AES-128-CBC encryption for raw MIME logs and quarantine payloads), `security/secrets_manager.py`. | `tests/test_audit_and_encryption.py` |
| **CC7.2** | Monitoring & threat detection. | `observability/metrics.py` (Prometheus metrics, OpenTelemetry distributed tracing), `observability/alerts.py` (SLO burn rate alerts). | `tests/test_observability.py` |
| **CC7.3** | Incident response & audit logging. | `audit/logger.py` (`AuditLogger.record_admin_action` with SHA-256 integrity checks), `security/redact.py` (extended PII redaction). | `tests/test_security.py` |

---

## 2. Availability & Reliability

| SOC 2 CC | Control Description | Technical Gateway Implementation | Verification Artifact / Test |
| :--- | :--- | :--- | :--- |
| **A1.2** | System redundancy, autoscaling & load management. | `scalability/queue.py` (`AsyncMessageQueue`), `scalability/pool.py` (`WorkerPool`), `scalability/autoscaler.py` (`WorkerAutoscaler`). | `tests/test_scalability.py`, `tests/test_autoscaler.py` |
| **A1.3** | Disaster recovery & storage backups. | `storage/backup.py` (`BackupManager`), `storage/restore.py` (`RestoreManager`). | `tests/test_backup.py`, `tests/test_restore.py` |

---

## 3. Confidentiality & Privacy

| SOC 2 CC | Control Description | Technical Gateway Implementation | Verification Artifact / Test |
| :--- | :--- | :--- | :--- |
| **C1.1** | Data retention & automated purge lifecycle. | `compliance/retention.py` (`DataPurgeEngine`, `RetentionPolicy`, `LegalHoldManager`). | `tests/test_compliance.py` |
| **P1.1** | Data Subject Rights (DSAR & Erasure / Right to be Forgotten). | `compliance/gdpr.py` (`DataSubjectRequestManager.export_subject_data`, `erase_subject_data`). | `tests/test_compliance.py` |
| **P2.1** | Geographic Data Residency. | `compliance/residency.py` (`DataResidencyManager.enforce_residency`). | `tests/test_compliance.py` |
