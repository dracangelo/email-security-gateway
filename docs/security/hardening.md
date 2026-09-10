# Production Security Hardening Checklist

This document provides a practical checklist for hardening a production deployment of `email-auth-gateway`. Each item includes the specific configuration, rationale, and verification step.

---

## Secrets & Credentials

- [ ] **Generate strong `WEBHOOK_SHARED_SECRET`** (minimum 32 random bytes):
  ```bash
  python3 -c "import secrets; print(secrets.token_urlsafe(32))"
  ```
  Verify: Gateway logs `"WEBHOOK_SHARED_SECRET is set"` at startup, not the warning.

- [ ] **Generate a Fernet `RAW_MAIL_ENCRYPTION_KEY`**:
  ```bash
  python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
  ```
  Verify: `readyz` endpoint does not warn about unencrypted storage.

- [ ] **Generate a separate `ADMIN_SHARED_SECRET`** (do not reuse `WEBHOOK_SHARED_SECRET`):
  Different trust boundaries require different secrets — rotating one should not require rotating the other.

- [ ] **Store all secrets in a secrets manager** (AWS Secrets Manager, HashiCorp Vault) — not in `.env` files, `ConfigMap`, or container image layers.

- [ ] **Rotate secrets on a 90-day schedule** or immediately on suspected compromise. See [Key Rotation Runbook](runbooks/key_rotation.md).

---

## Network

- [ ] **Enable `WEBHOOK_ALLOWED_SOURCE_IPS`** with your mail provider's published CIDR ranges:
  - SendGrid: https://sendgrid.com/en-us/blog/extended-mail-flow-ip-ranges
  - Mailgun: Published in your Mailgun account settings
  - AWS SES: Derived from SNS notification source

- [ ] **Separate public ingress from admin routes** using Kubernetes `NetworkPolicy` (see `k8s/networkpolicy.yaml`). Admin endpoints must not be reachable from the internet.

- [ ] **Terminate TLS at the ingress controller** (not at the gateway pod). Forward plain HTTP internally on a private network. Configure `cert-manager` for automatic certificate renewal.

- [ ] **Place a WAF in front of the ingress** (AWS WAF, Cloudflare) with:
  - Rate limiting at the WAF layer (supplement app-level limiting)
  - Bot detection
  - OWASP Core Rule Set

- [ ] **Enable mTLS for internal inter-service communication** (gateway → Redis, gateway → ClamAV):
  Configure `security/mtls.py` `MTLSContextBuilder` for internal channels.

---

## Authentication

- [ ] **Enable RBAC for admin endpoints** via `identity/manager.py`. Grant `admin` role only to SOC operators; grant `viewer` role for read-only dashboard access.

- [ ] **Set `ADMIN_RATE_LIMIT_MAX_REQUESTS`** to a conservative value (default 60/min). Prevents brute-force against the admin secret.

- [ ] **Configure source IP allowlist for admin API** — admin routes should only be reachable from your internal network or VPN, not the public internet.

---

## Data Protection

- [ ] **Set `QUARANTINE_DIR` to an S3 bucket** with:
  - Server-side encryption (KMS CMK)
  - Versioning enabled
  - Block all public access
  - Lifecycle rules for automated expiration (see Terraform module)

- [ ] **Set `RAW_MAIL_LOG_DIR` to an S3 bucket** (same configuration). Local `/tmp` is not durable and may be shared across containers.

- [ ] **Set `AUDIT_LOG_PATH` to a path shipped to a log aggregator** (Splunk, CloudTrail, Elasticsearch). Local JSONL files are not sufficient for compliance.

- [ ] **Enable per-tenant encryption key isolation** for multi-tenant deployments. Each tenant's quarantined mail must be encrypted with a different key — see [multi_tenancy.md](../modules/multi_tenancy.md).

---

## Delivery

- [ ] **Set `RELAY_START_TLS=true`** and `RELAY_PORT=587`. Enforce STARTTLS for all outbound relaying. Never relay on port 25 without encryption in production.

- [ ] **Do not set `ENABLE_TAG_ONLY_MODE=true` in production** — this mode skips modification and quarantining. It exists for staging observation only.

- [ ] **Configure `QUARANTINE_NOTIFY_WEBHOOK_URL`** with a Slack/Teams webhook so the SecOps team receives immediate alerts on new quarantine items.

---

## External Integrations

- [ ] **Configure `VT_API_KEY`** (VirusTotal) or `GSB_API_KEY` (Google Safe Browsing). Without these, URL and file reputation checks return `unknown` — only heuristic signals apply.

- [ ] **Monitor API quota usage** via the `QuotaTracker` alerts. VT free tier (500 req/day) is easily exhausted at production volume — use a premium key.

- [ ] **Configure DNSSEC validation** on upstream DNS resolvers. SPF/DKIM/DMARC records can be spoofed via DNS cache poisoning if the resolver does not validate DNSSEC.

---

## Kubernetes-Specific

- [ ] **Set resource limits** on all containers (gateway, ClamAV). Without limits, a memory leak in ClamAV during signature loading can OOM the node.

- [ ] **Configure `PodDisruptionBudget`** (`minAvailable: 2`) to prevent rolling updates from taking down the entire gateway.

- [ ] **Use IRSA** (IAM Roles for Service Accounts) for AWS resource access — never mount AWS access keys as environment variables.

- [ ] **Enable Kubernetes secrets encryption at rest** in the etcd encryption configuration.

- [ ] **Scan container images** with Trivy or Snyk in CI before deploying.

---

## Observability & Alerting

Set up alerts for:

- [ ] `email_gateway_circuit_breaker_state{provider="virustotal"} == 1` — VT circuit open
- [ ] `email_gateway_circuit_breaker_state{provider="clamav"} == 1` — ClamAV circuit open
- [ ] `email_gateway_redis_connected == 0` — Redis disconnected, in-memory fallback
- [ ] `email_gateway_quarantine_pending_items > 50` — Quarantine queue growing unreviewed
- [ ] P99 processing latency > 10s — potential memory pressure or external API degradation

See [observability.md](../modules/observability.md) for the full metrics catalog.

---

## Regular Maintenance

- [ ] **Rotate secrets every 90 days** (or immediately on compromise). See [key_rotation.md](runbooks/key_rotation.md).
- [ ] **Update ClamAV signatures** (`freshclam`) daily. Configure the ClamAV container to auto-update.
- [ ] **Review quarantine weekly** — false positive rate is a quality signal. High FP rates indicate threshold tuning is needed.
- [ ] **Run `python3 -m pytest tests/ -v` after every dependency upgrade** — the full test suite runs offline and catches regressions quickly.
