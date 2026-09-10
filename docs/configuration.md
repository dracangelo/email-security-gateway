# Configuration Reference — email-auth-gateway

All configuration is managed via environment variables (or a `.env` file). The `config/__init__.py` module defines a `Settings` object using `pydantic-settings` — one source of truth for every tunable value and secret in the system.

Generate your `.env` from the provided template:
```bash
cp .env.example .env
```

---

## Webhook Authentication

| Variable | Type | Default | Description |
|---|---|---|---|
| `WEBHOOK_SHARED_SECRET` | `str` | `""` | **Required.** Unguessable URL path segment authenticating the inbound webhook. Generate: `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`. The gateway will warn loudly and run unauthenticated if this is empty — do not expose to the internet without it. |
| `WEBHOOK_ALLOWED_SOURCE_IPS` | `list[str]` (CSV) | `[]` | Optional defense-in-depth: restrict accepted webhook POST source IPs to your provider's published CIDR ranges. Empty = disabled. Keep this list current — provider ranges change. |
| `MAILGUN_SIGNING_KEY` | `str` | `""` | Mailgun webhook HMAC signing key for `POST /webhooks/mailgun/inbound`. |

---

## Admin API Authentication

| Variable | Type | Default | Description |
|---|---|---|---|
| `ADMIN_SHARED_SECRET` | `str` | `""` | **Required for production.** Bearer token for all `/admin/*` endpoints. Independent from `WEBHOOK_SHARED_SECRET` — different trust boundary, rotate separately. |
| `ADMIN_RATE_LIMIT_MAX_REQUESTS` | `int` | `60` | Max admin API requests per 60-second window per source IP. |

---

## Resource Limits (DoS Protection)

| Variable | Type | Default | Description |
|---|---|---|---|
| `MAX_MESSAGE_SIZE_BYTES` | `int` | `26214400` (25 MB) | Reject inbound webhook payloads larger than this. Checked against both `Content-Length` header and actual body. |
| `MAX_URLS_ANALYZED_PER_MESSAGE` | `int` | `25` | Cap on URL reputation / age lookups per message. Prevents single messages with many links from exhausting external API quota. |
| `MAX_ATTACHMENTS_ANALYZED_PER_MESSAGE` | `int` | `10` | Cap on attachments scanned per message. |
| `MAX_ATTACHMENT_SIZE_BYTES` | `int` | `41943040` (40 MB) | Skip hashing / scanning attachments larger than this. |
| `EXTERNAL_CALL_TIMEOUT_SECONDS` | `float` | `8.0` | Per-call timeout for all external HTTP requests (VirusTotal, RDAP, Safe Browsing). |

---

## Rate Limiting

| Variable | Type | Default | Description |
|---|---|---|---|
| `RATE_LIMIT_MAX_REQUESTS` | `int` | `120` | Max inbound webhook requests per window per source IP. |
| `RATE_LIMIT_WINDOW_SECONDS` | `int` | `60` | Fixed window duration for rate limiting. |

---

## Retry & Resilience

| Variable | Type | Default | Description |
|---|---|---|---|
| `EXTERNAL_CALL_MAX_ATTEMPTS` | `int` | `3` | Maximum attempts for external HTTP calls (VirusTotal, RDAP, Safe Browsing). |
| `EXTERNAL_CALL_BACKOFF_BASE_SECONDS` | `float` | `0.25` | Base for exponential backoff between retries. Actual delay: `base * 2^attempt + jitter`. |
| `CIRCUIT_BREAKER_FAILURE_THRESHOLD` | `int` | `5` | Consecutive failures before the circuit breaker opens (stops all calls to that provider). |
| `CIRCUIT_BREAKER_RESET_TIMEOUT_SECONDS` | `float` | `30.0` | Seconds before the circuit breaker attempts recovery (half-open state). |

---

## Caching (TTLs)

| Variable | Type | Default | Description |
|---|---|---|---|
| `DOMAIN_AGE_CACHE_TTL_SECONDS` | `int` | `21600` (6 h) | RDAP domain registration date — changes rarely, cache aggressively. |
| `REPUTATION_CACHE_TTL_SECONDS` | `int` | `1800` (30 min) | URL / domain reputation — can change faster; cache more conservatively. |

---

## Storage & Idempotency

| Variable | Type | Default | Description |
|---|---|---|---|
| `USE_REDIS` | `bool` | `false` | `false` = in-memory store (single process only, dev default). `true` = Redis-backed store, required for multi-instance deployments. |
| `REDIS_URL` | `str` | `redis://localhost:6379/0` | Redis connection URL. Supports `redis://`, `rediss://` (TLS), and `redis+sentinel://`. |
| `DEDUPE_TTL_SECONDS` | `int` | `86400` (24 h) | How long a message's SHA-256 hash is cached for webhook-retry deduplication. |

---

## At-Rest Encryption

| Variable | Type | Default | Description |
|---|---|---|---|
| `RAW_MAIL_LOG_DIR` | `str` | `/tmp/email-gateway-raw` | Directory for encrypted `.eml` files. Swap for S3/GCS in production — local `/tmp` is not durable. |
| `RAW_MAIL_ENCRYPTION_KEY` | `str` | `""` | Fernet key (32 URL-safe base64-encoded bytes). Empty = files stored **unencrypted** — acceptable only for local dev. Generate: `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |

---

## Audit Logging

| Variable | Type | Default | Description |
|---|---|---|---|
| `AUDIT_LOG_PATH` | `str` | `/tmp/email-gateway-audit.jsonl` | Append-only JSONL file. Ship to a log aggregator in production. |
| `ADMIN_AUDIT_LOG_PATH` | `str` | `/tmp/email-gateway-admin-audit.jsonl` | Separate log for all admin actions (release / reject / quarantine). |

---

## Delivery / SMTP Relay

| Variable | Type | Default | Description |
|---|---|---|---|
| `RELAY_HOST` | `str` | `""` | Destination SMTP server hostname. **Empty = dry-run mode**: decisions computed, nothing sent. Safe for initial deployment. |
| `RELAY_PORT` | `int` | `25` | SMTP port. Use `587` with `RELAY_START_TLS=true` for STARTTLS submission. |
| `RELAY_USE_TLS` | `bool` | `false` | Implicit TLS from connect (SMTPS, typically port 465). |
| `RELAY_START_TLS` | `bool` | `true` | STARTTLS upgrade after connecting on a plaintext port. |
| `RELAY_USERNAME` | `str` | `""` | SMTP AUTH username. |
| `RELAY_PASSWORD` | `str` | `""` | SMTP AUTH password. |
| `ENABLE_TAG_ONLY_MODE` | `bool` | `false` | `true` = insert `X-Gateway-Verdict` headers instead of modifying or quarantining. Recommended for staging environments to prevent accidental mail drops. |

---

## Quarantine

| Variable | Type | Default | Description |
|---|---|---|---|
| `QUARANTINE_DIR` | `str` | `/tmp/email-gateway-quarantine` | Directory for quarantined `.eml` payloads (encrypted). Use S3/GCS in production. |
| `QUARANTINE_NOTIFY_WEBHOOK_URL` | `str` | `""` | Slack-compatible incoming webhook URL for quarantine alerts. Empty = logs only. |

---

## Decision Thresholds

| Variable | Type | Default | Description |
|---|---|---|---|
| `WARN_THRESHOLD` | `int` | `30` | Score at or above this → `WARN_AND_STRIP`. Must be lower than `QUARANTINE_THRESHOLD`. |
| `QUARANTINE_THRESHOLD` | `int` | `70` | Score at or above this → `QUARANTINE`. |

---

## Content Analysis

| Variable | Type | Default | Description |
|---|---|---|---|
| `VIP_DISPLAY_NAMES` | `list[str]` (CSV) | `[]` | Protected executive display names. E.g. `"Jane Doe CEO,John Smith CFO"`. Messages impersonating these names receive additional scrutiny and lower quarantine thresholds. |
| `WATCHLIST_DOMAINS` | `list[str]` (CSV) | `[]` | Domain names to flag with extra scrutiny regardless of typosquat distance. |
| `VT_API_KEY` | `str` | `""` | VirusTotal API key. Empty = file/URL reputation lookups return `unknown`. |
| `GSB_API_KEY` | `str` | `""` | Google Safe Browsing API key. Used as a fallback if `VT_API_KEY` is absent. |
| `CLAMD_HOST` | `str` | `""` | ClamAV `clamd` daemon hostname. Empty = ClamAV scanning disabled. |
| `CLAMD_PORT` | `int` | `3310` | ClamAV daemon port. |

---

## Environment Variable Precedence

```
1. Actual environment variables (highest priority)
2. .env file in the working directory
3. Pydantic Field(default=...) values (lowest priority)
```

In Kubernetes, inject secrets via `ExternalSecretsOperator` or the CSI Secret Store Driver — never put real secrets in `ConfigMap` or committed `.env` files.
