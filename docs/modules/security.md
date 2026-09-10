# Module: security — Hardening & Protection

## Purpose

Provides all shared security primitives: webhook authentication (per-provider strategy), source IP allowlist, per-IP rate limiting, PII/credential redaction, Fernet at-rest encryption, mTLS client certificate verification, secrets management (Vault / AWS Secrets Manager), provider-specific auth strategies, bounce/NDR detection, and a pen-testing/fuzzing toolkit.

---

## Module Structure

| File | Responsibility |
|---|---|
| `webhook_auth.py` | Shared-secret webhook auth, source IP allowlist |
| `provider_auth.py` | Per-provider auth strategies (SendGrid, Mailgun, AWS SNS) |
| `rate_limit.py` | Fixed-window per-IP rate limiter |
| `redact.py` | PII / credential regex redactor |
| `encryption.py` | Fernet at-rest encryption (`RawMailCipher`) |
| `mtls.py` | mTLS context builder for internal service communication |
| `secrets_manager.py` | Secrets providers: Vault, AWS Secrets Manager, env fallback |
| `bounce_detector.py` | Bounce / NDR auto-reply loop detection |
| `fuzzer.py` | Property-based fuzzing toolkit (for security testing) |
| `pen_tester.py` | Structured penetration test runner |

---

## Webhook Authentication (`webhook_auth.py`)

### Shared-Secret URL Segment

The primary authentication mechanism for inbound webhooks. The `WEBHOOK_SHARED_SECRET` is embedded as a URL path segment:

```
POST /webhooks/sendgrid/inbound/<WEBHOOK_SHARED_SECRET>
```

**Why a URL path segment?** SendGrid Inbound Parse does not cryptographically sign its payloads (unlike their separate Event Webhook product). An unguessable secret in the URL is the real authentication mechanism — not a fabricated signature scheme.

**Constant-time comparison**: The secret comparison uses `hmac.compare_digest()` to prevent timing side-channel attacks.

**404 on failure**: Auth failures return `404 Not Found`, not `401` or `403`. This prevents probers from distinguishing "wrong secret" from "no endpoint here" — a small but meaningful information leak reduction.

### Source IP Allowlist

Optional defense-in-depth. If `WEBHOOK_ALLOWED_SOURCE_IPS` is configured, the request's source IP (direct TCP peer — not `X-Forwarded-For`) is checked against the list of CIDR ranges.

```python
from security import verify_secret, verify_source_ip

verify_secret(request_secret, settings.webhook_shared_secret)  # raises WebhookAuthError on mismatch
verify_source_ip(client_ip, settings.webhook_allowed_source_ips)  # raises WebhookAuthError if not in allowlist
```

> **Reverse proxy note**: Source IP is taken from the direct TCP peer, not `X-Forwarded-For`. If behind a reverse proxy, terminate TLS at the proxy and connect to the gateway directly on an internal network.

---

## Provider Auth Strategies (`provider_auth.py`)

Pluggable per-provider authentication:

| Strategy | Class | Mechanism |
|---|---|---|
| SendGrid | `SendGridAuthStrategy` | URL path secret (see above) |
| Mailgun | `MailgunAuthStrategy` | HMAC-SHA256 signature of `timestamp + token` using `MAILGUN_SIGNING_KEY` |
| AWS SNS | `AWSSNSAuthStrategy` | SNS message signature verification (RSA + SHA256) against SNS certificate |

---

## Rate Limiting (`rate_limit.py`)

Fixed-window rate limiter per source IP. Backed by `storage/` (in-memory or Redis):

```python
from security import RateLimiter

limiter = RateLimiter(store, max_requests=120, window_seconds=60)
# Raises RateLimitExceeded (→ HTTP 429) if limit exceeded
await limiter.check(client_ip)
```

**Cross-instance**: When backed by Redis, rate limits are shared across all gateway instances. An in-memory limiter is per-process — not effective with multiple replicas.

> **Known limitation**: `RedisStore.incr()` is not fully atomic (INCR + separate EXPIRE). Acceptable for rate limiting; revisit with a Lua script if needed for stricter guarantees.

---

## PII / Credential Redaction (`redact.py`)

Strips sensitive data from anything going to logs or the audit trail. Applied automatically at every logging call site:

Patterns redacted:
- API keys / tokens (bearer tokens, `Authorization:` headers)
- Passwords in URLs (`://user:password@host`)
- PEM private key blocks
- AWS access key patterns (`AKIA...`)
- SendGrid / Mailgun API keys

Also redacts credentials that **phishing content itself** might contain — e.g., a credential-harvesting form submission captured in the message body.

```python
from security import redact

safe_text = redact(potentially_sensitive_string)
```

---

## At-Rest Encryption (`encryption.py`)

Fernet symmetric encryption (AES-128-CBC + HMAC-SHA256) for stored `.eml` files and quarantine payloads:

```python
from security import RawMailCipher

cipher = RawMailCipher(key=settings.raw_mail_encryption_key)
encrypted = cipher.encrypt(raw_bytes)
decrypted = cipher.decrypt(encrypted)
```

Generate a key:
```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

If `RAW_MAIL_ENCRYPTION_KEY` is empty, files are stored **unencrypted** and the gateway logs a startup warning. Acceptable for local dev only — `.eml` files routinely contain PII and credentials.

---

## mTLS (`mtls.py`)

Builds TLS client certificate contexts for mutual authentication on internal gRPC/HTTP channels between the public ingress nodes and internal worker pools:

```python
from security import MTLSContextBuilder

ssl_context = MTLSContextBuilder(
    cert_path="/certs/client.crt",
    key_path="/certs/client.key",
    ca_path="/certs/ca.crt",
).build()
```

Enforces TLS 1.3 minimum. Used for internal inter-process communication in production (not for the public webhook endpoints).

---

## Secrets Management (`secrets_manager.py`)

Pluggable secret providers:

| Provider | Class | Notes |
|---|---|---|
| Environment / `.env` | `EnvSecretsProvider` | Default; sufficient for dev |
| HashiCorp Vault | `VaultSecretsProvider` | KV v2 secrets engine |
| AWS Secrets Manager | `AWSSecretsProvider` | Via IRSA; no static AWS credentials |

```python
from security import AWSSecretsProvider

provider = AWSSecretsProvider(secret_name="prod/email-gateway")
secret = provider.get("WEBHOOK_SHARED_SECRET")
```

---

## Bounce / NDR Detection (`bounce_detector.py`)

Detects Delivery Status Notifications and auto-replies to prevent infinite relay loops:

```python
from security import is_bounce_or_ndr

is_bounce, reason = is_bounce_or_ndr(envelope_from, from_header)
```

Detected by:
- Empty envelope-from (`<>` — standard bounce indicator per RFC 5321)
- `Auto-Submitted: auto-generated` header
- `X-Auto-Response-Suppress` header
- DSN content type (`multipart/report; report-type=delivery-status`)
