# Deployment: Docker & Docker Compose

## Local Development

### Prerequisites

- Docker Engine 24+
- Docker Compose v2

### Quick Start

```bash
# Clone and enter project
git clone https://github.com/your-org/email-auth-gateway.git
cd email-auth-gateway

# Configure environment
cp .env.example .env
# Edit .env: set WEBHOOK_SHARED_SECRET, RAW_MAIL_ENCRYPTION_KEY at minimum

# Build and start all services
docker compose up --build
```

### Compose Services

| Service | Image | Port(s) | Purpose |
|---|---|---|---|
| `email-auth-gateway` | Local build | `8000` | FastAPI gateway |
| `redis` | `redis:7-alpine` | `6379` | State, caching, rate limiting |
| `clamav` | `clamav/clamav` | `3310` | Malware scanning daemon |
| `mailpit` | `axllent/mailpit` | `1025` (SMTP), `8025` (UI) | SMTP trap for captured mail |

### Service URLs

| URL | Description |
|---|---|
| `http://localhost:8000` | Gateway (health, webhooks, admin API) |
| `http://localhost:8025` | Mailpit web UI — view captured delivered mail |
| `http://localhost:8000/healthz` | Liveness probe |
| `http://localhost:8000/readyz` | Readiness probe |

---

## Dockerfile

The production `Dockerfile` uses a multi-stage Python build:

```dockerfile
FROM python:3.11-slim AS base
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Non-root user for security
RUN useradd -m -u 1000 gateway
USER gateway

# ClamAV signatures directory (volume-mounted in production)
RUN mkdir -p /tmp/email-gateway-raw /tmp/email-gateway-quarantine

EXPOSE 8000
ENTRYPOINT ["uvicorn", "webhook_receiver.app:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Build

```bash
docker build -t email-auth-gateway:latest .
```

### Run Standalone

```bash
docker run -p 8000:8000 \
  -e WEBHOOK_SHARED_SECRET="your-secret" \
  -e RAW_MAIL_ENCRYPTION_KEY="your-fernet-key" \
  -e USE_REDIS=true \
  -e REDIS_URL="redis://redis:6379/0" \
  -e RELAY_HOST="smtp.example.com" \
  -e RELAY_PORT=587 \
  -e RELAY_START_TLS=true \
  email-auth-gateway:latest
```

---

## Testing the Full Stack Locally

### Send a Test Phishing Email

```bash
export SECRET=$(grep WEBHOOK_SHARED_SECRET .env | cut -d= -f2)

curl -X POST "http://localhost:8000/webhooks/sendgrid/inbound/$SECRET" \
  -F 'envelope={"from":"attacker@evil.com","to":["you@yourcompany.com"]}' \
  -F 'from=CEO Name <ceo-fake@gmail.com>' \
  -F 'subject=URGENT: Wire Transfer Required' \
  -F 'text=Please wire $50,000 immediately. Click here: https://paypa1.com/verify'
```

### Verify Quarantine

```bash
export ADMIN=$(grep ADMIN_SHARED_SECRET .env | cut -d= -f2)
curl http://localhost:8000/admin/quarantine -H "Authorization: Bearer $ADMIN"
```

### Test ClamAV EICAR

```bash
# EICAR test string — detected by all AV engines, not actually harmful
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt

curl -X POST "http://localhost:8000/webhooks/sendgrid/inbound/$SECRET" \
  -F 'envelope={"from":"test@test.com","to":["you@yourcompany.com"]}' \
  -F 'from=test@test.com' \
  -F 'text=See attached' \
  -F 'attachment1=@/tmp/eicar.txt;type=text/plain;filename=eicar.txt'
```

Expected: action = `quarantine`, reasons includes `ClamAV: Eicar-Signature FOUND`.

---

## Simulating Failure Modes

```bash
# Test Redis fallback (in-memory mode)
docker compose stop redis
# Gateway should log: "Redis connection failed. Falling back to local in-memory store"

# Test ClamAV circuit breaker
docker compose stop clamav
# Gateway should log: "ClamAV clamd daemon unreachable. Circuit breaker opened."

# Restore services
docker compose start redis clamav
```

---

## Production Docker Considerations

1. **Never use `/tmp` for persistent data**: Set `RAW_MAIL_LOG_DIR`, `QUARANTINE_DIR`, and `AUDIT_LOG_PATH` to mounted persistent volumes.
2. **Secret injection**: Use Docker Secrets or environment variables from a secrets manager — not hardcoded in `docker-compose.yml`.
3. **Resource limits**: Set memory limits on the ClamAV container (requires 1.5–2.5 GB for signature databases).
4. **ClamAV signatures**: Mount a persistent volume for ClamAV signature databases to avoid re-downloading on restart.
5. **Log shipping**: Mount the audit log path and use a log driver or sidecar to ship to your aggregator.
