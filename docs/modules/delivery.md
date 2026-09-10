# Module: delivery — Mail Delivery & Quarantine

## Purpose

Acts on the routing decision produced by the decision engine. Three delivery paths: forward (relay as-is), warn-and-strip (modify then relay), and quarantine (encrypt, store, notify). Also handles: DLP scanning, time-of-click URL rewriting, direct mailbox actions (M365/Gmail), retroactive zap (post-delivery quarantine), user-reported phishing, and quarantine digest emails.

---

## Module Structure

| File | Responsibility |
|---|---|
| `pipeline.py` | Entry point `deliver()`; orchestrates all three delivery paths |
| `relay.py` | Async SMTP relay via `aiosmtplib` |
| `modify.py` | `WARN_AND_STRIP` message transformation |
| `quarantine.py` | Encrypted-at-rest quarantine storage |
| `notify.py` | Pluggable quarantine alert notifications |
| `models.py` | `DeliveryResult`, `QuarantineItem` data models |
| `dlp.py` | Data Loss Prevention scanning on outbound content |
| `smtp_receiver.py` | Own SMTP receiver (alternative to webhook-based ingestion) |
| `auto_zap.py` | Retroactive post-delivery quarantine engine |
| `mailbox_actions.py` | Direct M365 / Gmail mailbox API actions |
| `user_reports.py` | User-reported phishing handling |
| `quarantine_digest.py` | Periodic quarantine digest email generator |
| `confirmation.py` | Delivery confirmation tracking |

---

## Entry Point

```python
from delivery import deliver, SMTPRelay, QuarantineStore, LogNotifier

result = await deliver(
    decision=routing_decision,
    raw_message=raw_bytes,
    message_id="msg_abc123",
    relay=smtp_relay,           # None = dry-run
    quarantine_store=q_store,
    notifier=log_notifier,
    cipher=raw_mail_cipher,
    enable_tag_only_mode=False,
)
```

---

## Delivery Paths

### `FORWARD`

Relays the message as-is via SMTP. If `RELAY_HOST` is not configured, logs `"would relay"` and returns a dry-run result.

```
decision.action == FORWARD
    → relay.send(raw_message, envelope_to=[...])
    → DeliveryResult(action="forward", relayed=True)
```

### `WARN_AND_STRIP`

Transforms the message before relaying:

1. **Subject prefix**: Prepends `[SUSPICIOUS]` to the Subject header
2. **Link defanging**: Removes `href` attributes and replaces URLs with `hxxps[://]evil[.]com` form — still readable by investigators, not clickable
3. **Attachment stripping**: Removes all attachments, replaces each with a `[Attachment removed: filename.ext — flagged by email security gateway]` text part
4. Relays the modified message

If modification itself fails (malformed MIME, encoding error), the message is escalated to quarantine rather than relayed unmodified or dropped silently.

```
decision.action == WARN_AND_STRIP
    → modify(raw_message) → modified_bytes
    → relay.send(modified_bytes, ...)
    → DeliveryResult(action="warn_and_strip", relayed=True, modified=True)
```

> **Tag-only mode**: If `ENABLE_TAG_ONLY_MODE=true`, an `X-Gateway-Verdict: warn_and_strip; score=45` header is inserted instead of performing actual modification. Recommended for staging environments.

### `QUARANTINE`

Encrypts and stores the message; notifies the admin channel.

```
decision.action == QUARANTINE
    → quarantine_store.store(message_id, raw_message, metadata)
    → notifier.notify(quarantine_item)
    → DeliveryResult(action="quarantine", relayed=False)
```

#### Quarantine Storage Format

Each quarantined item consists of two files in `QUARANTINE_DIR`:

```
<id>.eml.enc    ← Fernet-encrypted raw MIME message
<id>.meta.json  ← Unencrypted metadata:
```

```json
{
  "id": "q_abc123",
  "message_id": "msg_abc123",
  "stored_at": "2026-09-10T12:34:56Z",
  "from": "attacker@evil.com",
  "to": ["victim@company.com"],
  "subject": "Urgent: Wire Transfer",
  "score": 95,
  "reasons": ["SPF fail", "DMARC fail", "malicious URL"],
  "status": "pending"
}
```

#### Release vs Reject

- **Release**: Decrypts and relays the **original, unmodified** message. The point of release is correcting a false positive — the message was already decided to be safe. Release re-runs no analysis.
- **Reject**: Marks the item as `rejected` in metadata; message stays on disk. Implements the "avoid blind dropping" design rule.

Both actions are cryptographically tied to the operator's identity in the admin audit log.

---

## SMTP Relay (`relay.py`)

```python
relay = SMTPRelay(
    host="smtp.example.com",
    port=587,
    use_tls=False,
    start_tls=True,
    username="...",
    password="...",
)
await relay.send(raw_message, envelope_to=["recipient@company.com"])
```

**Retry behavior**:
- Retries on connection-level failures (network timeout, TLS handshake, connection refused)
- **Never retries** on permanent SMTP 5xx rejection from the destination server — a `550 User unknown` is not a transient failure

---

## Notifications (`notify.py`)

Pluggable notifier for quarantine events:

| Notifier | Class | Behavior |
|---|---|---|
| Log (default) | `LogNotifier` | Logs quarantine event to `logger.warning` |
| Slack/webhook | `WebhookNotifier` | Posts to Slack-compatible incoming webhook |

Configure via `QUARANTINE_NOTIFY_WEBHOOK_URL`.

---

## DLP Scanning (`dlp.py`)

Scans outbound message content for sensitive data patterns before relaying:
- Credit card numbers (Luhn-validated)
- Social Security Numbers
- API keys / tokens / PEM private keys (via `security/redact.py` pattern library)

Intercepts `WARN_AND_STRIP` and `FORWARD` paths.

---

## Retroactive Zap (`auto_zap.py`)

When a phishing campaign is identified post-delivery, the `RetroactiveZapEngine` can issue direct mailbox API calls (Microsoft 365 Graph API or Gmail API) to move already-delivered messages to the Junk/Deleted folder. Triggered by:
- Analyst confirming a phishing verdict
- IOC feed match on a previously delivered message's URL/hash

---

## User-Reported Phishing (`user_reports.py`)

Processes `Report Phishing` button submissions from end users:
1. Feeds the report into the `FeedbackLoopEngine` (adjusts domain trust score)
2. Triggers retroactive zap for any matching message in delivered mail
3. Records the report in the audit log

---

## Data Models

```python
@dataclass
class DeliveryResult:
    action: str          # "forward", "warn_and_strip", "quarantine", "dry_run"
    relayed: bool
    modified: bool = False
    quarantine_id: str | None = None
    error: str | None = None
```
