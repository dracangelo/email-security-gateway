# Module: audit — Audit Trail

## Purpose

Provides an append-only, redacted JSONL audit trail. One record per processed message, plus a separate admin action log for quarantine release/reject/admin operations. Records include a SHA-256 content hash for chain-of-custody without storing the message body twice.

---

## Module Structure

```
audit/
└── logger.py   # AuditLogger class
```

---

## Audit Record Format

### Message Processing Record

```json
{
  "event": "message_processed",
  "timestamp": "2026-09-10T12:34:56.789Z",
  "message_id": "msg_abc123",
  "tenant_id": "tenant_acme",
  "from": "[REDACTED]@evil.com",
  "to": ["[REDACTED]@company.com"],
  "subject_hash": "sha256:a3b4c5...",
  "content_hash": "sha256:f1e2d3...",
  "client_ip": "203.0.113.5",
  "action": "quarantine",
  "score": 95,
  "reasons": [
    "SPF hard fail",
    "DMARC fail under p=reject",
    "typosquat domain paypa1.com"
  ],
  "auth": {
    "spf": "fail",
    "dkim": "none",
    "dmarc": "fail",
    "arc": "none"
  },
  "processing_ms": 342
}
```

### Admin Action Record

```json
{
  "event": "admin_action",
  "timestamp": "2026-09-10T13:00:00.000Z",
  "action": "quarantine_release",
  "quarantine_id": "q_abc123",
  "message_id": "msg_abc123",
  "resolved_by": "analyst@company.com",
  "note": "false positive - known vendor",
  "tenant_id": "tenant_acme",
  "admin_ip": "10.0.1.50"
}
```

---

## Usage

```python
from audit import AuditLogger

logger = AuditLogger(audit_log_path="/var/log/email-gateway-audit.jsonl")

# Record a processed message
await logger.record(
    message_id="msg_abc123",
    tenant_id="tenant_acme",
    envelope_from="attacker@evil.com",
    envelope_to=["victim@company.com"],
    content_hash=sha256_hash,
    action="quarantine",
    score=95,
    reasons=["SPF hard fail", ...],
    auth_verdict=auth_result,
    processing_ms=342,
)

# Record an admin action
await logger.record_admin_action(
    action="quarantine_release",
    quarantine_id="q_abc123",
    resolved_by="analyst@company.com",
    note="false positive",
    tenant_id="tenant_acme",
)
```

---

## Design Decisions

### Redacted PII

The `From` and `To` email addresses in audit records are **redacted** by default — the local part is replaced with `[REDACTED]`, retaining the domain for analysis. The full envelope addresses are never written to the audit log.

Subject lines are stored as SHA-256 hashes (not plaintext) to prevent the audit log from becoming a sensitive data store in its own right.

### SHA-256 Chain of Custody

The `content_hash` is a SHA-256 of the raw MIME message. This links each audit record to the encrypted `.eml` file stored in `RAW_MAIL_LOG_DIR`:

```
audit record → content_hash = sha256(raw_bytes)
                                   ↕
raw mail store → decrypt → sha256(decrypted_bytes) must match
```

This allows post-incident forensics to verify that the message that was processed is the same as the one stored on disk.

### Append-Only

The audit logger opens the log file in append mode. Existing records are never modified. For production, ship audit records to an immutable log aggregator (CloudTrail, Splunk, Elasticsearch with write-once index settings) rather than relying on a local file.

---

## Production Log Shipping

The audit log is a local JSONL file by default. For production:

1. Use FluentBit or a sidecar to tail the file and ship to your aggregator:

```yaml
# FluentBit ConfigMap excerpt
[INPUT]
    Name  tail
    Path  /var/log/email-gateway-audit.jsonl
    Tag   email-gateway.audit
    Parser json

[OUTPUT]
    Name  es
    Match email-gateway.audit
    Host  elasticsearch.internal
    Index email-gateway-audit
```

2. Or replace `AuditLogger` with a custom implementation that writes directly to your aggregator.
