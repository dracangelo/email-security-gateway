# Environment Parity & Configuration Matrix

This document defines the architectural and configuration differences across **Local Development**, **Staging**, and **Production** environments for the Email Authentication Gateway.

Adhering to the [Twelve-Factor App methodology](https://12factor.net/), the exact same codebase runs in all environments. Differences are injected strictly via environment variables, Kubernetes ConfigMaps/Secrets, or cloud infrastructure providers.

---

## 1. Architectural Parity Matrix

| Subsystem | Local Dev (`docker-compose`) | Staging (`Kubernetes`) | Production (`Kubernetes HA + Cloud`) |
| :--- | :--- | :--- | :--- |
| **Compute / Deployment** | Docker Compose (1 replica) | Kubernetes Deployment (2–6 replicas, HPA) | Kubernetes HA (5–25 replicas, HPA, PDB, Anti-Affinity) |
| **Inbound Webhook** | `localhost:8000/webhook/{secret}` | `gateway.staging.example.com` (TLS) | `gateway.email.example.com` (TLS, CloudFront/WAF, DDoS protection) |
| **State & Caching (Redis)** | Local Redis container (`redis:7-alpine`) | Managed / Internal Redis (`staging-redis.internal`) | Multi-AZ ElastiCache Redis 7 (Transit & Rest Encryption, AUTH) |
| **Antivirus (ClamAV)** | Local ClamAV container | ClamAV Daemon Service (`staging-clamav.internal`) | Dedicated ClamAV Daemon Cluster with Auto-Updating Signatures |
| **SMTP Relay** | Local Mailpit server (`axllent/mailpit:1025`) | Sandbox SMTP Server (`staging-smtp.internal`) | Production Secure MTA / AWS SES (Port 587, STARTTLS + Auth) |
| **Raw Mail & Quarantine Store** | Local Ephemeral Volumes (`/app/quarantine`) | Encrypted Persistent Volumes (EBS gp3 20Gi) | Encrypted S3 Bucket with KMS CMK & Automated Lifecycle Rules |
| **Secret Management** | Local `.env` / Docker Compose env | Kubernetes Secrets / Vault Staging | AWS Secrets Manager / HashiCorp Vault via IRSA |
| **Tag-Only Safe Mode** | `false` (Direct evaluation) | `true` (Inserts headers, prevents accidental drops) | `false` (Active filtering & quarantining) |
| **Observability & Logging** | Stdout + Local JSONL (`/tmp/*.jsonl`) | FluentBit -> CloudWatch / Elasticsearch (Staging) | Prometheus + Grafana + OpenTelemetry + Datadog/Splunk |

---

## 2. Configuration Parameters Comparison

The table below lists all tunable configuration variables in `config/__init__.py` and their target values across environments:

| Environment Variable | Default / Local Dev | Staging | Production | Notes / Security Rationale |
| :--- | :--- | :--- | :--- | :--- |
| `APP_ENV` | `development` | `staging` | `production` | Enables strict mode and error sanitization in prod |
| `LOG_LEVEL` | `DEBUG` | `INFO` | `WARN` / `INFO` | Reduces log noise and prevents sensitive payload leaks |
| `WEBHOOK_SHARED_SECRET` | Static dev token | Staging secret in Vault | KMS-generated unguessable token | Primary gate for inbound parse webhooks |
| `ADMIN_SHARED_SECRET` | Static dev token | Staging admin secret | KMS-generated admin bearer token | Independent auth boundary for `/admin/*` |
| `RAW_MAIL_ENCRYPTION_KEY`| Empty (Plaintext) | Staging Fernet Key | Production 32-byte Fernet Key | Encrypts raw `.eml` files containing PII/credentials |
| `USE_REDIS` | `true` (or `false` for unit) | `true` | `true` | Shared rate limiting, deduplication, and caching |
| `REDIS_URL` | `redis://redis:6379/0` | `redis://staging-redis:6379/0` | `redis://clustercfg.prod-redis:6379/0` | Multi-AZ cluster endpoint with TLS |
| `RELAY_HOST` | `mailpit` | `staging-smtp.internal` | `email-smtp.us-east-1.amazonaws.com` | Destination SMTP server for cleaned mail |
| `RELAY_PORT` | `1025` | `587` | `587` | Standard submission port with STARTTLS |
| `RELAY_START_TLS` | `false` | `true` | `true` | Enforces cryptographic transport security |
| `ENABLE_TAG_ONLY_MODE` | `false` | `true` | `false` | Prevents mail loss during staging test runs |
| `CLAMD_HOST` | `clamav` | `staging-clamav` | `clamav.prod-secops.internal` | Malware attachment scanner host |
| `CLAMD_PORT` | `3310` | `3310` | `3310` | ClamAV clamd daemon port |
| `MAX_MESSAGE_SIZE_BYTES` | 25 MB | 25 MB | 25 MB | Inbound DoS protection limit |
| `RATE_LIMIT_MAX_REQUESTS`| 120 / min | 120 / min | 120 / min | Per-IP token bucket rate limiting |
| `CIRCUIT_BREAKER_RESET_TIMEOUT_SECONDS` | 30.0s | 30.0s | 30.0s | Auto-recovery duration for failing backends |

---

## 3. Secret Injection & Identity Boundaries

1. **Development (`docker-compose.yml` / `.env`)**:
   - Secrets are sourced from local `.env` file (copied from `.env.example`).
   - Mock secrets are acceptable solely in local isolated containers.

2. **Staging & Production (Kubernetes + AWS IAM Roles for Service Accounts - IRSA)**:
   - Pods authenticate with AWS KMS and Secrets Manager using OpenID Connect (OIDC) identity tokens.
   - Long-lived static AWS credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`) are **strictly prohibited**.
   - Secrets are injected at container startup as environment variables via `ExternalSecretsOperator` or CSI Secret Store Driver.

---

## 4. Replicating Production Behavior Locally & in Staging

### Reproducing an Incident in Staging
1. Obtain the anonymized inbound message headers or `.eml` test case.
2. Ensure `ENABLE_TAG_ONLY_MODE=true` in staging so test messages are tagged with `X-Gateway-Verdict` without disrupting destination inboxes.
3. Post the payload directly to the staging webhook URL:
   ```bash
   curl -X POST https://gateway.staging.example.com/webhook/${STAGING_SECRET} \
     -H "Content-Type: multipart/form-data" \
     -F "email=@suspicious_sample.eml" \
     -F "from=ceo@target-domain.com"
   ```

### Reproducing Storage Degradation Locally
To verify fail-open or graceful degradation when Redis or ClamAV goes down:
```bash
# Stop ClamAV container to test antivirus circuit breaker
docker compose stop clamav

# Stop Redis to test in-memory fallback store
docker compose stop redis
```
