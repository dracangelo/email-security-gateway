# Getting Started — email-auth-gateway

## Prerequisites

| Requirement | Minimum | Notes |
|---|---|---|
| Python | 3.11+ | Uses `match`, walrus operator, `from __future__ import annotations` |
| Redis | 7.x | Optional but required for multi-instance deployments |
| ClamAV (`clamd`) | Latest | Optional; gateway fails open if unreachable |
| Docker / Compose | 24+ | For local full-stack dev |

---

## Quick Start (Local Development)

### 1. Clone & install

```bash
git clone https://github.com/your-org/email-auth-gateway.git
cd email-auth-gateway

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
```

Edit `.env` and at minimum set:

```bash
# Required — generate a strong random secret:
WEBHOOK_SHARED_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")

# Required — generate a Fernet encryption key for stored mail:
RAW_MAIL_ENCRYPTION_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

# Optional — destination SMTP server (empty = dry-run mode, nothing sent)
RELAY_HOST=localhost
RELAY_PORT=1025
```

> **Dry-run mode**: If `RELAY_HOST` is empty, the gateway computes all decisions and stores quarantine items, but `FORWARD` and `WARN_AND_STRIP` messages are only logged — nothing is actually delivered. This is the safe way to observe decisions before trusting the gateway with live mail.

### 3. Start supporting services

```bash
# Start Redis + ClamAV via Docker Compose:
docker compose up -d redis clamav

# Or start a local mail catcher (Mailpit) for SMTP relay testing:
docker compose up -d mailpit
```

### 4. Start the gateway

```bash
uvicorn webhook_receiver.app:app --host 0.0.0.0 --port 8000 --reload
```

### 5. Send a test message

```bash
export WEBHOOK_SHARED_SECRET="<your-secret-from-.env>"

curl -X POST "http://localhost:8000/webhooks/sendgrid/inbound/$WEBHOOK_SHARED_SECRET" \
  -F 'envelope={"from":"attacker@evil.com","to":["you@yourcompany.com"]}' \
  -F 'from=CEO Name <ceo-impersonator@gmail.com>' \
  -F 'text=URGENT: Wire $50,000 immediately. Verify here: https://paypa1.com/login'
```

Expected response:

```json
{
  "message_id": "...",
  "action": "quarantine",
  "score": 95,
  "reasons": ["DMARC fail under p=reject", "BEC urgency keyword match", "typosquat domain paypa1.com"]
}
```

---

## Full Stack with Docker Compose

```bash
docker compose up --build
```

Services started:

| Service | Port | Description |
|---|---|---|
| `email-auth-gateway` | 8000 | FastAPI gateway |
| `redis` | 6379 | State / caching / rate limiting |
| `clamav` | 3310 | Malware scanning daemon |
| `mailpit` | 1025 / 8025 | SMTP trap + web UI for captured mail |

Gateway URL: `http://localhost:8000`  
Mailpit UI (captured delivered mail): `http://localhost:8025`

---

## Running Tests

```bash
python3 -m pytest tests/ -v
```

- **165 tests**, all offline/local.
- DNS and HTTP calls are mocked throughout.
- SMTP relay tests use a real local `aiosmtpd` server.
- Storage tests run identically against `InMemoryStore` and `RedisStore` (via `fakeredis`).

Run only a specific module's tests:

```bash
python3 -m pytest tests/test_auth_checker.py -v
python3 -m pytest tests/test_decision_engine.py -v
```

---

## Configure SendGrid Inbound Parse

1. In SendGrid, go to **Settings → Inbound Parse → Add Host & URL**.
2. Set the URL to:
   ```
   https://your-gateway-host/webhooks/sendgrid/inbound/<WEBHOOK_SHARED_SECRET>
   ```
3. Enable **"Post the raw, full MIME message"** — without this, DKIM verification accuracy degrades (the gateway will warn at startup if only parsed fields arrive).

See: https://www.twilio.com/docs/sendgrid/for-developers/parsing-email/setting-up-the-inbound-parse-webhook

---

## Configure Other Providers

| Provider | Endpoint | Notes |
|---|---|---|
| **Mailgun** | `POST /webhooks/mailgun/inbound` | Uses Mailgun HMAC signature verification |
| **AWS SES + SNS** | `POST /webhooks/ses/inbound` | SNS message signature verified before processing |
| **Postmark** | `POST /webhooks/postmark/inbound` | Standard inbound webhook format |
| **Microsoft 365** | `POST /webhooks/m365/inbound` | Graph API client credentials auth |
| **Google Workspace** | `POST /webhooks/google/inbound` | Gmail API service account auth |

---

## Reviewing Quarantined Mail

```bash
export ADMIN_SHARED_SECRET="<your-admin-secret>"

# List all pending quarantine items
curl http://localhost:8000/admin/quarantine \
  -H "Authorization: Bearer $ADMIN_SHARED_SECRET"

# Release a false positive (relays original, unmodified message)
curl -X POST http://localhost:8000/admin/quarantine/<id>/release \
  -H "Authorization: Bearer $ADMIN_SHARED_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"resolved_by":"analyst@yourcompany.com","note":"false positive - known vendor"}'

# Reject (keeps on disk, marks as reviewed)
curl -X POST http://localhost:8000/admin/quarantine/<id>/reject \
  -H "Authorization: Bearer $ADMIN_SHARED_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"resolved_by":"analyst@yourcompany.com","note":"confirmed phishing"}'
```

---

## Next Steps

- [Architecture](architecture.md) — understand the full data flow and scoring model
- [Configuration Reference](configuration.md) — all environment variables and their defaults
- [API Reference](api_reference.md) — full REST API documentation
- [Deployment: Kubernetes](deployment/kubernetes.md) — production deployment guide
- [Threat Model](security/threat_model.md) — STRIDE analysis and residual risks
