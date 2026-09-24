# Configuration Reference — email-auth-gateway

All configuration in `email-auth-gateway` is managed via environment variables (or a local `.env` file). The `config/__init__.py` module defines a centralized `Settings` schema using `pydantic-settings` — providing a single source of truth for every tunable value, policy threshold, and security credential.

Generate your `.env` from the repository template:
```bash
cp .env.example .env
```

---

## Quick Reference: Secret Generation & API Portals

| Credential / Service | Type | Generation Command / Portal Link |
|---|---|---|
| `WEBHOOK_SHARED_SECRET` | Random Secret | `python3 -c "import secrets; print(secrets.token_urlsafe(32))"` or `openssl rand -hex 32` |
| `ADMIN_SHARED_SECRET` | Bearer Token | `python3 -c "import secrets; print(secrets.token_urlsafe(32))"` or `openssl rand -hex 32` |
| `RAW_MAIL_ENCRYPTION_KEY` | Fernet 256-bit Key | `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `VT_API_KEY` / `VIRUSTOTAL_API_KEY` | External API Key | [VirusTotal API Keys Console](https://www.virustotal.com/gui/my-apikey) · [VirusTotal Docs](https://developers.virustotal.com/reference/overview) |
| `GSB_API_KEY` / `SAFE_BROWSING_API_KEY` | External API Key | [Google Cloud Console Credentials](https://console.cloud.google.com/apis/credentials) · [Safe Browsing Setup](https://developers.google.com/safe-browsing/v4/get-started) |
| `MAILGUN_SIGNING_KEY` | Provider HMAC Key | [Mailgun Security Settings](https://app.mailgun.com/settings/api_keys) · [Inbound Routing Docs](https://documentation.mailgun.com/docs/mailgun/user-manual/inbound-routing/) |
| `SENDGRID_API_KEY` | Provider API Key | [SendGrid API Keys](https://app.sendgrid.com/settings/api_keys) · [Inbound Parse Setup](https://app.sendgrid.com/settings/parse) |
| Microsoft 365 / Graph API | OAuth2 Client Credentials | [Microsoft Entra ID App Registrations](https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/RegisteredApps) · `az ad app create` |
| Google Workspace API | Service Account Key | [Google Cloud Service Accounts](https://console.cloud.google.com/iam-admin/serviceaccounts) · `gcloud iam service-accounts create` |
| AWS SES / SNS | IAM Access Key | [AWS IAM Credentials](https://console.aws.amazon.com/iam/home#/security_credentials) · `aws iam create-access-key` |
| `QUARANTINE_NOTIFY_WEBHOOK_URL` | Incoming Webhook | [Slack Apps Console](https://api.slack.com/apps) · [Incoming Webhook Docs](https://api.slack.com/messaging/webhooks) |
| ClamAV Antivirus Daemon | Local/Remote Daemon | `docker run -d --name clamav -p 3310:3310 clamav/clamav:latest` |
| Redis KV Store | Cache / State Backend | `docker run -d --name redis -p 6379:6379 redis:alpine` |
| Mock SMTP Relay (Mailpit) | Local Mail Sink | `docker run -d --name mailpit -p 1025:1025 -p 8025:8025 axllent/mailpit` |

---

## 1. Webhook Authentication & Ingestion

| Variable | Type | Default | Description |
|---|---|---|---|
| `WEBHOOK_SHARED_SECRET` | `str` | `""` | **Required.** Unguessable URL path segment authenticating the inbound webhook (`/webhooks/sendgrid/inbound/{secret}`). The gateway refuses to run unauthenticated if this is empty. Generate: `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`. |
| `WEBHOOK_ALLOWED_SOURCE_IPS` | `list[str]` (CSV) | `[]` | Optional defense-in-depth: restrict accepted webhook POST source IPs to your provider's published CIDR ranges (e.g., `"167.89.0.0/17,198.37.144.0/20"`). Empty = disabled. |
| `MAILGUN_SIGNING_KEY` | `str` | `""` | Mailgun webhook HMAC signing key for `POST /webhooks/mailgun/inbound`. Access key at [Mailgun Control Panel](https://app.mailgun.com/settings/api_keys). |
| `SENDGRID_API_KEY` | `str` | `""` | Twilio SendGrid API key for webhook validation and management. Access key at [SendGrid API Keys Console](https://app.sendgrid.com/settings/api_keys). |

---

## 2. Admin API & SOC Dashboard Authentication

| Variable | Type | Default | Description |
|---|---|---|---|
| `ADMIN_SHARED_SECRET` | `str` | `""` | **Required for production.** Bearer token for all `/admin/*` endpoints and SOC dashboard actions. Independent from `WEBHOOK_SHARED_SECRET` — distinct trust boundary, rotate separately. Generate: `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`. |
| `ADMIN_RATE_LIMIT_MAX_REQUESTS` | `int` | `60` | Max admin API requests per 60-second window per source IP. |

---

## 3. Resource Limits & DoS Protection

| Variable | Type | Default | Description |
|---|---|---|---|
| `MAX_MESSAGE_SIZE_BYTES` | `int` | `26214400` (25 MB) | Reject inbound webhook payloads larger than this. Validated against both the HTTP `Content-Length` header and the actual multipart stream. |
| `MAX_URLS_ANALYZED_PER_MESSAGE` | `int` | `25` | Maximum number of URLs analyzed for reputation, domain age, and typosquatting per message. Prevents quota exhaustion. |
| `MAX_ATTACHMENTS_ANALYZED_PER_MESSAGE` | `int` | `10` | Cap on attachments scanned per message. |
| `MAX_ATTACHMENT_SIZE_BYTES` | `int` | `41943040` (40 MB) | Skip hashing and scanning attachments larger than this. |
| `EXTERNAL_CALL_TIMEOUT_SECONDS` | `float` | `8.0` | Per-call timeout for all external HTTP requests (VirusTotal, Google Safe Browsing, RDAP). |

---

## 4. Rate Limiting & Resilience

| Variable | Type | Default | Description |
|---|---|---|---|
| `RATE_LIMIT_MAX_REQUESTS` | `int` | `120` | Max inbound webhook requests per window per source IP. |
| `RATE_LIMIT_WINDOW_SECONDS` | `int` | `60` | Fixed window duration for rate limiting. |
| `EXTERNAL_CALL_MAX_ATTEMPTS` | `int` | `3` | Maximum attempts for external HTTP calls with exponential backoff. |
| `EXTERNAL_CALL_BACKOFF_BASE_SECONDS` | `float` | `0.25` | Base delay for exponential backoff: `delay = base * 2^attempt + jitter`. |
| `CIRCUIT_BREAKER_FAILURE_THRESHOLD` | `int` | `5` | Consecutive failures before the circuit breaker trips open to prevent cascading failures. |
| `CIRCUIT_BREAKER_RESET_TIMEOUT_SECONDS` | `float` | `30.0` | Seconds before a tripped circuit breaker attempts recovery in half-open state. |

---

## 5. Storage, Deduplication & Encryption at Rest

| Variable | Type | Default | Description |
|---|---|---|---|
| `USE_REDIS` | `bool` | `false` | `false` = in-memory store (single-process dev only). `true` = Redis-backed store (required for production and multi-pod clusters). |
| `REDIS_URL` | `str` | `redis://localhost:6379/0` | Redis connection URL. Supports `redis://`, `rediss://` (TLS), and `redis+sentinel://`. Run locally: `docker run -d --name redis -p 6379:6379 redis:alpine`. |
| `DEDUPE_TTL_SECONDS` | `int` | `86400` (24 h) | Retention duration for message SHA-256 idempotency keys. Duplicate webhook retries within this window are safely acknowledged without re-processing. |
| `RAW_MAIL_LOG_DIR` | `str` | `/tmp/email-gateway-raw` | Directory for raw `.eml` files. Swap for S3/GCS or PVC in production. |
| `RAW_MAIL_ENCRYPTION_KEY` / `ENCRYPTION_KEY` | `str` | `""` | Fernet 256-bit symmetric encryption key (32 URL-safe base64-encoded bytes). If empty, stored raw files remain unencrypted. Generate: `python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. |

---

## 6. Delivery & Outbound SMTP Relay

| Variable | Type | Default | Description |
|---|---|---|---|
| `RELAY_HOST` / `SMTP_HOST` | `str` | `""` | Destination downstream SMTP server hostname. **Empty = dry-run mode** (verdicts computed, nothing relayed). Run test server: `docker run -d --name mailpit -p 1025:1025 -p 8025:8025 axllent/mailpit`. |
| `RELAY_PORT` / `SMTP_PORT` | `int` | `25` | Destination SMTP server port. Use `587` with `RELAY_START_TLS=true` or `465` with `RELAY_USE_TLS=true`. |
| `RELAY_USE_TLS` / `SMTP_USE_TLS` | `bool` | `false` | Direct SMTPS TLS handshake on connection. |
| `RELAY_START_TLS` | `bool` | `true` | Issue STARTTLS upgrade command after connecting on plaintext port. |
| `RELAY_USERNAME` / `SMTP_USER` | `str` | `""` | SMTP AUTH username. |
| `RELAY_PASSWORD` / `SMTP_PASS` | `str` | `""` | SMTP AUTH password. |
| `ENABLE_TAG_ONLY_MODE` | `bool` | `false` | **Observation / Shadow Mode.** When `true`, inserts `X-Gateway-Verdict` headers instead of modifying body or quarantining. Recommended for staging or new-tenant onboarding. |

---

## 7. Content Analysis & External Threat Scanners

### VirusTotal
- **Portal Link**: [https://www.virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey)
- **API Documentation**: [https://developers.virustotal.com/reference/overview](https://developers.virustotal.com/reference/overview)
- **Config Variables**: `VT_API_KEY` (alias: `VIRUSTOTAL_API_KEY`)
- If provided, file hashes and URLs are checked against VirusTotal's intelligence feed. Malicious verdicts immediately trigger quarantine.

### Google Safe Browsing / Web Risk
- **Portal Link**: [https://console.cloud.google.com/apis/credentials](https://console.cloud.google.com/apis/credentials)
- **API Activation**: [Enable Safe Browsing API v4](https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com)
- **Config Variables**: `GSB_API_KEY` (alias: `SAFE_BROWSING_API_KEY`)
- **CLI Generation** (via Google Cloud SDK `gcloud`):
  ```bash
  gcloud services enable safebrowsing.googleapis.com
  gcloud alpha services api-keys create --display-name="SafeBrowsingKey"
  ```
- Serves as primary or secondary reputation provider for embedded URLs.

### ClamAV Antivirus Daemon
- **Config Variables**: `CLAMD_HOST` (alias: `CLAMAV_HOST`), `CLAMD_PORT` (alias: `CLAMAV_PORT`, default: `3310`)
- **Local Docker Setup**:
  ```bash
  docker run -d --name clamav -p 3310:3310 clamav/clamav:latest
  ```
- **Ubuntu/Debian Native Setup**:
  ```bash
  sudo apt-get update && sudo apt-get install -y clamav-daemon
  sudo freshclam
  sudo systemctl start clamav-daemon
  ```

### Microsoft 365 / Microsoft Graph API
- **Portal Link**: [Microsoft Entra ID App Registrations](https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/RegisteredApps)
- **Config Variables**: `M365_TENANT_ID`, `M365_CLIENT_ID`, `M365_CLIENT_SECRET`
- **CLI Generation** (via Azure CLI `az`):
  ```bash
  # Register Application
  az ad app create --display-name "email-auth-gateway"
  # Create Service Principal & Client Secret
  az ad app credential reset --id <APPLICATION_CLIENT_ID> --append
  ```

### Google Workspace / Gmail API Integration
- **Portal Link**: [Google Cloud Service Accounts](https://console.cloud.google.com/iam-admin/serviceaccounts)
- **Domain Delegation**: [Google Workspace Admin Console](https://admin.google.com/ac/owl/domainwidedelegation)
- **Config Variables**: `GOOGLE_WORKSPACE_CREDENTIALS_JSON`
- **CLI Generation** (via `gcloud`):
  ```bash
  gcloud iam service-accounts create email-gateway --display-name="Email Gateway Service Account"
  gcloud iam service-accounts keys create credentials.json --iam-account=email-gateway@<PROJECT_ID>.iam.gserviceaccount.com
  ```

### Amazon Web Services (AWS SES / SNS)
- **Portal Link**: [AWS IAM Security Credentials](https://console.aws.amazon.com/iam/home#/security_credentials)
- **SES Dashboard**: [AWS SES Console](https://console.aws.amazon.com/ses/home)
- **Config Variables**: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`
- **CLI Generation** (via `aws` CLI):
  ```bash
  aws iam create-user --user-name email-gateway-ses-user
  aws iam attach-user-policy --user-name email-gateway-ses-user --policy-arn arn:aws:iam::aws:policy/AmazonSESFullAccess
  aws iam create-access-key --user-name email-gateway-ses-user
  ```

### Slack Alert Notifications
- **Portal Link**: [Slack API App Console](https://api.slack.com/apps)
- **Documentation**: [Slack Incoming Webhooks](https://api.slack.com/messaging/webhooks)
- **Config Variable**: `QUARANTINE_NOTIFY_WEBHOOK_URL`
- When set, all quarantine events dispatch rich JSON notifications to the designated SecOps Slack channel.

---

## 8. Executive Protection, Watchlists & Decision Thresholds

| Variable | Type | Default | Description |
|---|---|---|---|
| `VIP_DISPLAY_NAMES` | `list[str]` (CSV) | `[]` | Executive and high-profile names to guard against display-name impersonation (e.g. `"Jane Doe CEO,John Smith CFO"`). |
| `WATCHLIST_DOMAINS` | `list[str]` (CSV) | `[]` | Internal or critical supplier domains inspected for typosquatting / homoglyphs. |
| `WARN_THRESHOLD` | `int` | `30` | Minimum score to trigger `WARN_AND_STRIP` action. |
| `QUARANTINE_THRESHOLD` | `int` | `70` | Minimum score to trigger `QUARANTINE` action. |

---

## Environment Variable Precedence

The gateway loads configuration in the following order of precedence:

1. **Host Environment Variables** (highest priority — e.g., injected Kubernetes Secrets or container environment)
2. **Local `.env` File** in current working directory
3. **Pydantic Field Defaults** defined in `config/__init__.py` (lowest priority)
