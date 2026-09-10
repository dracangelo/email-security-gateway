# API Reference — email-auth-gateway

The gateway exposes two distinct FastAPI applications on the same process:

- **Inbound App** (`/webhooks/*`, `/healthz`, `/readyz`) — public-facing, authenticated via shared secret
- **Admin App** (`/admin/*`, `/ui/*`) — internal, authenticated via bearer token

---

## Authentication

### Inbound Webhook Endpoints

The shared secret is embedded in the URL path, not sent in a header:

```
POST /webhooks/sendgrid/inbound/{secret}
```

Auth failures return **`404 Not Found`** (not `401`) — this prevents probers from distinguishing "wrong secret" from "no endpoint here."

### Admin Endpoints

All `/admin/*` endpoints require a `Bearer` token:

```
Authorization: Bearer <ADMIN_SHARED_SECRET>
```

Auth failures return `401 Unauthorized`.

---

## Health Endpoints

### `GET /healthz`

Liveness probe. Returns `200 OK` if the process is alive.

```json
{"status": "ok"}
```

### `GET /readyz`

Readiness probe. Checks Redis connectivity (if configured), reports ClamAV and relay configuration status.

```json
{
  "status": "ready",
  "redis": "ok",
  "clamav": "configured",
  "relay": "configured"
}
```

Returns `503 Service Unavailable` if critical dependencies are down.

---

## Inbound Webhook Endpoints

### `POST /webhooks/sendgrid/inbound/{secret}`

Receives inbound email from SendGrid Inbound Parse.

**Security checks (in order):**
1. Constant-time secret comparison against `WEBHOOK_SHARED_SECRET`
2. Optional source IP allowlist check (CIDR matching)
3. Per-IP rate limit (fixed window)
4. Payload size check (Content-Length + actual body)
5. Bounce / NDR detection (skips pipeline for auto-reply loops)
6. SHA-256 idempotency dedup (webhook retries are silently skipped)

**Form fields (multipart/form-data):**

| Field | Required | Description |
|---|---|---|
| `envelope` | Yes | JSON: `{"from": "...", "to": [...]}` |
| `from` | Yes | From header value |
| `text` | No | Plain-text body |
| `html` | No | HTML body |
| `headers` | No | Raw headers blob (enables full DKIM verification) |
| `charsets` | No | JSON field encoding map |
| `attachments` | No | Integer count of attachments |
| `attachment-info` | No | JSON metadata for attachments |

**Response `200 OK`:**

```json
{
  "message_id": "msg_abc123",
  "action": "quarantine",
  "score": 95,
  "reasons": [
    "SPF hard fail",
    "DMARC fail under p=reject",
    "typosquat domain paypa1.com (distance 1 from paypal.com)"
  ],
  "auth": {
    "spf": "fail",
    "dkim": "pass",
    "dmarc": "fail"
  }
}
```

**Duplicate (idempotent retry):**
```json
{"message_id": "msg_abc123", "duplicate": true, "action": "skipped_duplicate"}
```

**Bounce / NDR:**
```json
{"message_id": "msg_xyz", "action": "skipped_bounce", "detail": "empty envelope-from (bounce)"}
```

---

### `POST /webhooks/mailgun/inbound`

Receives inbound email from Mailgun Routes. Verifies Mailgun HMAC signature using `MAILGUN_SIGNING_KEY`.

### `POST /webhooks/ses/inbound`

Receives AWS SNS notifications for SES inbound-to-S3 events. Verifies SNS message signature independently.

### `POST /webhooks/postmark/inbound`

Receives inbound email from Postmark Inbound Webhooks.

### `POST /webhooks/m365/inbound`

Receives journaled email from Microsoft 365 / Exchange Online via Graph API. Requires Azure AD client credentials auth.

### `POST /webhooks/google/inbound`

Receives email from Google Workspace Gmail API Pub/Sub subscription. Requires service account with domain-wide delegation.

---

## Admin: Quarantine Management

### `GET /admin/quarantine`

List all pending (unreviewed) quarantine items.

**Headers:** `Authorization: Bearer <ADMIN_SHARED_SECRET>`

**Response:**
```json
[
  {
    "id": "q_abc123",
    "message_id": "msg_abc123",
    "stored_at": "2026-09-10T12:34:56Z",
    "from": "attacker@evil.com",
    "to": ["victim@company.com"],
    "score": 95,
    "reasons": ["SPF hard fail", "malicious URL"],
    "status": "pending"
  }
]
```

---

### `GET /admin/quarantine/{id}`

Retrieve a single quarantine item including the decrypted message preview.

**Response:**
```json
{
  "id": "q_abc123",
  "message_id": "msg_abc123",
  "stored_at": "2026-09-10T12:34:56Z",
  "from": "attacker@evil.com",
  "subject": "[SUSPICIOUS] Urgent: Wire Transfer Required",
  "score": 95,
  "reasons": ["..."],
  "status": "pending",
  "preview": "<sanitized HTML preview>"
}
```

---

### `POST /admin/quarantine/{id}/release`

Release a quarantined message. Relays the **original, unmodified** message — the point of release is correcting a false positive, not re-delivering a modified version.

**Body:**
```json
{
  "resolved_by": "analyst@company.com",
  "note": "Known vendor - false positive on domain age"
}
```

**Response:**
```json
{"status": "released", "id": "q_abc123", "relayed": true}
```

This action is recorded in the admin audit log with the operator's identity, timestamp, and note.

---

### `POST /admin/quarantine/{id}/reject`

Reject a quarantined message. Marks it as reviewed; message stays on disk (per the "avoid blind dropping" rule).

**Body:**
```json
{
  "resolved_by": "analyst@company.com",
  "note": "Confirmed BEC phishing attempt"
}
```

**Response:**
```json
{"status": "rejected", "id": "q_abc123"}
```

---

## Admin: Tenant Management

### `GET /admin/tenants`

List all configured tenants (MSP view).

### `POST /admin/tenants`

Create a new tenant with isolated quarantine directory and per-tenant configuration.

### `GET /admin/tenants/{tenant_id}/quarantine`

List quarantine items scoped to a specific tenant.

---

## Admin: Dashboard UI

### `GET /ui/dashboard`

Returns the HTML admin dashboard (quarantine review, analytics, recent decisions). Requires `Authorization: Bearer` header or session cookie.

---

## Time-of-Click Redirect

### `GET /toc/redirect`

Validates HMAC-SHA256 signature on gateway-rewritten links and redirects to the original URL (after re-checking reputation at click time).

**Query params:** `url=<encoded-original>` + `sig=<hmac-signature>`

Returns `302 Found` on valid signature, `403 Forbidden` on invalid or expired.

---

## Error Responses

| Code | Meaning |
|---|---|
| `200` | Success |
| `302` | Redirect (time-of-click) |
| `400` | Bad request (malformed payload, oversized body) |
| `401` | Admin auth failure |
| `404` | Webhook secret mismatch (deliberate — see security design) |
| `429` | Rate limit exceeded |
| `500` | Internal server error (check logs) |
| `503` | Service unavailable (readiness probe) |
