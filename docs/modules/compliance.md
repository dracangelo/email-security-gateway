# Module: compliance — GDPR, SOC 2 & Data Residency

## Purpose

Implements regulatory compliance controls: GDPR Data Subject Rights (access, erasure, portability), automated data retention and purge policies, geographic data residency enforcement, legal hold management, and a Privacy Impact Assessment. Maps technical controls to SOC 2 Trust Services Criteria.

---

## Module Structure

| File | Responsibility |
|---|---|
| `gdpr.py` | DSAR handling, erasure, portability export |
| `retention.py` | Automated retention policies, data purge engine, legal hold |
| `residency.py` | Geographic data residency enforcement |
| `PRIVACY_IMPACT_ASSESSMENT.md` | Formal PIA document |
| `SOC2_MAPPING.md` | SOC 2 Trust Services Criteria control mapping |

---

## GDPR (`gdpr.py`)

### Data Subject Access Request (DSAR)

`DataSubjectRequestManager` handles all GDPR Article 15 (right of access) and Article 17 (right to erasure) requests.

```python
from compliance import DataSubjectRequestManager

manager = DataSubjectRequestManager()

# Export all data for a subject (Article 15)
export = await manager.export_subject_data(
    subject_email="user@example.com",
    tenant_id="tenant_acme",
)
# Returns: { "quarantine_items": [...], "audit_entries": [...], "processed_messages": [...] }

# Erase all data for a subject (Article 17 - Right to be Forgotten)
result = await manager.erase_subject_data(
    subject_email="user@example.com",
    tenant_id="tenant_acme",
    requested_by="dpo@company.com",
)
```

### Personal Data Inventory

Email messages processed by the gateway may contain:

| Data Category | Location | Retention |
|---|---|---|
| Sender/recipient email addresses | Audit log, quarantine metadata | Per retention policy (default 90 days) |
| Raw MIME message (encrypted) | `QUARANTINE_DIR/*.eml.enc` | 90 days quarantine, 30 days raw logs |
| Processing metadata (scores, reasons) | `AUDIT_LOG_PATH` (JSONL) | 1 year |
| Admin action log | `ADMIN_AUDIT_LOG_PATH` | 3 years (for audit trail integrity) |

---

## Data Retention (`retention.py`)

### Retention Policies

`RetentionPolicy` defines how long data is kept:

```python
from compliance import RetentionPolicy, DataPurgeEngine

# Configure retention
policy = RetentionPolicy(
    raw_mail_retention_days=30,
    quarantine_retention_days=90,
    audit_log_retention_days=365,
    admin_audit_log_retention_days=1095,  # 3 years
)

# Run purge (typically scheduled daily)
engine = DataPurgeEngine(policy=policy)
purge_report = await engine.purge_expired_data(tenant_id="tenant_acme")
```

The purge engine:
1. Enumerates files older than the retention period
2. Skips files under a **Legal Hold** (see below)
3. Securely deletes (overwrites before unlink) encrypted `.eml` files
4. Records every purge in the admin audit log

### Legal Hold

`LegalHoldManager` prevents purge of specific messages during litigation or investigation:

```python
from compliance import LegalHoldManager

hold_manager = LegalHoldManager()

# Place a hold (survives retention period)
await hold_manager.place_hold(
    message_id="msg_abc123",
    reason="Litigation: Case #2026-0042",
    placed_by="legal@company.com",
)

# Release hold when litigation is complete
await hold_manager.release_hold(message_id="msg_abc123", released_by="legal@company.com")
```

---

## Data Residency (`residency.py`)

`DataResidencyManager` enforces that quarantine data for a tenant is only written to storage in the tenant's designated geographic region:

```python
from compliance import DataResidencyManager

residency = DataResidencyManager()

# Will raise ResidencyViolationError if tenant_acme's data
# is being written to a non-EU region and tenant is EU-only
await residency.enforce_residency(
    tenant_id="tenant_acme",
    target_region="us-east-1",  # raises: tenant requires eu-west-1
)
```

In Kubernetes, data residency is enforced at the infrastructure level by deploying tenant-specific pods to region-specific node groups (using node selectors and affinity rules).

---

## SOC 2 Control Mapping

See [`SOC2_MAPPING.md`](../../compliance/SOC2_MAPPING.md) for the full control matrix. Summary:

| SOC 2 Criteria | Control |
|---|---|
| CC6.1 — Access Control | `identity/manager.py` JWT RBAC + `_verify_admin` bearer auth |
| CC6.3 — Network Segmentation | `webhook_receiver/segmentation.py` — separate inbound/admin apps |
| CC6.6 — Encryption in Transit | `security/mtls.py` mTLS on internal channels; STARTTLS on SMTP relay |
| CC6.7 — Encryption at Rest | `security/encryption.py` Fernet encryption for all stored mail |
| CC7.2 — Threat Detection | Prometheus metrics + SLO burn rate alerts |
| CC7.3 — Audit Logging | `audit/logger.py` SHA-256-tied JSONL audit trail |
| A1.2 — Scalability | `scalability/queue.py` async queue + `autoscaler.py` |
| C1.1 — Data Retention | `compliance/retention.py` `DataPurgeEngine` |
| P1.1 — DSAR | `compliance/gdpr.py` `DataSubjectRequestManager` |
| P2.1 — Data Residency | `compliance/residency.py` `DataResidencyManager` |

---

## Privacy Impact Assessment

See [`PRIVACY_IMPACT_ASSESSMENT.md`](../../compliance/PRIVACY_IMPACT_ASSESSMENT.md) for the formal PIA covering:

- Types of personal data processed
- Processing purpose and legal basis
- Data flows and third-party processors (VirusTotal, RDAP)
- Risk assessment and mitigations
- Data Subject Rights procedures
