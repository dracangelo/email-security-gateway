# Module: webhook_receiver — FastAPI Application

## Purpose

The `webhook_receiver` is the glue layer — a FastAPI application that wires all pipeline stages together, exposes all REST endpoints, and owns the core `process_message()` orchestration function. It handles provider-specific payload parsing, security checks, orchestrates analysis, acts on decisions via `delivery/`, and records audit entries.

---

## Module Structure

| File | Responsibility |
|---|---|
| `app.py` | FastAPI app, all route definitions, `process_message()` orchestrator |
| `segmentation.py` | `create_inbound_app()` / `create_admin_app()` — network segmentation |
| `parsers/` | Provider-specific payload parsers |
| `google_client.py` | Google Workspace Gmail API client |
| `m365_client.py` | Microsoft 365 Graph API client |

---

## Application Segmentation (`segmentation.py`)

The gateway runs as two logically separate FastAPI applications sharing the same process:

```python
# Public-facing: webhook ingestion, health probes
inbound_app = create_inbound_app()
# Routes: /webhooks/*, /healthz, /readyz, /toc/redirect

# Internal/admin: quarantine management, UI, tenant admin
admin_app = create_admin_app()
# Routes: /admin/*, /ui/*
```

This separation maps to the network segmentation in the [STRIDE threat model](../security/threat_model.md): public ingress nodes should not be on the same network segment as admin routes. In Kubernetes, `NetworkPolicy` enforces that only internal pods can reach admin routes.

---

## Core Orchestrator: `process_message()`

The provider-agnostic processing core. All provider parsers call this function after extracting a normalized representation from their payload:

```python
async def process_message(
    message_id: str,
    raw_message: bytes,          # Full MIME message
    client_ip: str,              # SMTP-connecting IP
    envelope_from: str,          # MAIL FROM
    envelope_to: list[str],      # RCPT TO
    text_body: str,
    html_body: str,
    from_header: str,            # From: display value
    reply_to_header: str,
    watchlist: list[str] | None,
    vip_display_names: list[str] | None,
    tenant_id: str,
) -> dict:
```

### Processing Steps (in order)

1. **Bounce / NDR detection** — skip pipeline for auto-reply loops
2. **Idempotency check** — skip reprocessing of duplicate webhook deliveries (SHA-256 dedup in Redis)
3. **Raw message store** — encrypt and persist to `RAW_MAIL_LOG_DIR`
4. **Auth checks** — `auth_checker.run_auth_checks()`
5. **Content analysis** — `content_analysis.analyze_content()`
6. **Attachment analysis** — `attachment_analysis.analyze_attachments()`
7. **Decision engine** — `decision_engine.decide()` with all policy layers
8. **Delivery** — `delivery.deliver()` — FORWARD / WARN_AND_STRIP / QUARANTINE
9. **Audit logging** — record full verdict to JSONL trail

---

## Provider Parsers (`parsers/`)

Each parser extracts a normalized set of fields from its provider's payload format and calls `process_message()`:

| Parser | Provider | Auth Method |
|---|---|---|
| `parse_sendgrid_payload` | SendGrid Inbound Parse | URL path secret |
| `parse_mailgun_payload` | Mailgun Routes | HMAC-SHA256 signature |
| `parse_aws_ses_payload` | AWS SES + SNS | SNS message signature |
| `parse_postmark_payload` | Postmark Inbound | Shared secret header |
| `parse_m365_graph_payload` | Microsoft 365 Graph | Azure AD JWT |
| `parse_google_workspace_payload` | Google Workspace Gmail | Service account JWT |

### SendGrid Payload Notes

SendGrid Inbound Parse sends `multipart/form-data`. When **"Post the raw, full MIME message"** is enabled in the provider dashboard, the `email` field contains the complete MIME message — this is required for accurate DKIM verification.

When only parsed fields arrive (headers without the full MIME), the parser reconstructs a synthetic MIME message from individual form fields. DKIM verification in this mode is unreliable. The gateway logs a warning at startup if it detects only parsed fields are arriving.

---

## Startup Checks

At startup, the gateway checks and warns about:

- `WEBHOOK_SHARED_SECRET` not set → **WARNING: running unauthenticated**
- `RAW_MAIL_ENCRYPTION_KEY` not set → **WARNING: stored mail is unencrypted**
- `RELAY_HOST` not set → **INFO: running in dry-run delivery mode**
- `ADMIN_SHARED_SECRET` not set → **WARNING: admin endpoints are unauthenticated**
- `ENABLE_TAG_ONLY_MODE=true` → **INFO: messages will be tagged, not modified/quarantined**
- Redis connectivity check (if `USE_REDIS=true`)

---

## Process-Wide Singletons

All shared dependencies are instantiated once at module load time:

```python
_store         # InMemoryStore or RedisStore
_rate_limiter  # Per-IP rate limiter
_cipher        # RawMailCipher (Fernet)
_audit_logger  # AuditLogger
_domain_age_provider  # CachedDomainAgeProvider
_url_reputation_provider  # CachedReputationProvider
_file_reputation_provider # VirusTotalFileProvider
_clamav        # ClamAVScanner
_relay         # SMTPRelay (or None if RELAY_HOST unset)
_quarantine_store  # QuarantineStore
_notifier      # LogNotifier or WebhookNotifier
```

These are not dependency-injected — they're module-level globals. For testing, the test suite patches these directly or uses a separate test `app` instance.

---

## Admin API Authentication

All `/admin/*` endpoints call `_verify_admin(request)`:

```python
def _verify_admin(request: Request) -> None:
    """Raises HTTP 401 if bearer token doesn't match ADMIN_SHARED_SECRET."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401)
    token = auth[7:]
    if not hmac.compare_digest(token, settings.admin_shared_secret):
        raise HTTPException(status_code=401)
```

Admin failures return `401 Unauthorized` (not `404`, unlike inbound webhooks — admin routes are not trying to hide their existence).
