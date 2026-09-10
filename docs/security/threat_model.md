# Threat Model — email-auth-gateway

> This is the canonical threat model document. The original lives at [`THREAT_MODEL.md`](../../THREAT_MODEL.md) in the repo root.

## System Overview & Architecture

`email-auth-gateway` is an enterprise-grade, multi-tenant email security gateway processing hostile inbound mail from public providers (SendGrid, Mailgun, AWS SES, Postmark, M365, Google Workspace, and native SMTP).

### Trust Zones & Boundaries

| Zone | Description |
|---|---|
| **Public Internet (Untrusted)** | Sender MTAs, malicious webhooks, external URL destinations, attacker-controlled email bodies/attachments |
| **Gateway Ingress Boundary** | Inbound webhook receivers (`/webhooks/*`) and SMTP receivers |
| **Internal Microservice Network** | Message queues, worker pools, admin APIs (`/admin/*`), Redis, quarantine stores |
| **Internal Admin Zone** | Authenticated SOC analysts, security admins, automated ticketing systems |

---

## STRIDE Threat Analysis Matrix

| Category | Threat Vector | Impact | Implemented Mitigations |
|---|---|---|---|
| **Spoofing (S)** | Email domain spoofing (From / Envelope-From mismatch) | High | SPF RFC 7208 evaluation, DKIM key validation, DMARC alignment, ARC validation, FCrDNS checks |
| **Spoofing (S)** | Webhook payload forgery by unauthorized HTTP clients | Critical | Provider-specific auth strategies: shared secrets, Mailgun HMAC, AWS SNS signature validation |
| **Tampering (T)** | Modification of raw email content stored at rest | High | Fernet AES-128-CBC payload encryption with per-tenant key isolation (`RawMailCipher`, `TenantIsolatedQuarantine`) |
| **Tampering (T)** | Time-of-Click link tampering mid-transit | Medium | HMAC-SHA256 signature verification on rewritten gateway links (`/toc/redirect`) |
| **Repudiation (R)** | Analyst releasing/rejecting phishing emails without accountability | High | Cryptographically tied JSONL admin audit logging recording operator identity, timestamp, target ID, and reason |
| **Information Disclosure (I)** | PII or credential leakage in system logs or metrics | High | Centralized regex-based PII/credential redactor (`security.redact`) applied at all logging call sites |
| **Information Disclosure (I)** | Multi-tenant data exposure (Tenant A accessing Tenant B's mail) | Critical | `TenantIsolatedQuarantine` with isolated storage paths and per-tenant Fernet keying |
| **Denial of Service (D)** | Inbound webhook flooding / resource exhaustion | High | Dual-layer rate limiting (`RateLimiter`, `TenantRateLimiter`) backed by Redis, payload size caps (25 MB), async queue decoupling |
| **Denial of Service (D)** | MIME parser zip bombs or infinite archive recursion | High | Max attachment depth checks (`max_depth=3`), file count caps (`max_files=10`), decompressed size ratio limits |
| **Elevation of Privilege (E)** | Public ingress caller invoking admin quarantine release APIs | Critical | Network segmentation (`create_inbound_app` / `create_admin_app`), enforced RBAC, rate-limited admin authorization; `/admin/*` returns 401 (not 404) |

---

## Detailed Attack Scenarios

### Scenario 1: Credential Harvesting via Phishing

**Attack**: Attacker sends a spoofed email from `paypa1.com` impersonating PayPal, containing a link to a fake login page.

**Gateway mitigations**:
1. SPF check: `paypa1.com` likely has no SPF record → `+15`
2. DKIM check: No valid signature → `+15`
3. DMARC check: `p=none` or missing → `+10`
4. Typosquat detection: Levenshtein distance 1 from `paypal.com` → `+30`
5. URL reputation: VirusTotal flags `paypa1.com` → `+100`

**Total score**: 170 → **QUARANTINE**

---

### Scenario 2: BEC / CEO Fraud

**Attack**: Attacker sends email with `From: "Jane Doe CEO" <jdoe@gmail.com>` requesting an urgent wire transfer.

**Gateway mitigations**:
1. Display name spoofing: `"Jane Doe CEO"` matches VIP list → `+40`
2. BEC keyword match: "wire transfer", "urgent" → `+25`
3. SPF: `gmail.com` passes (but domain != sender's company) → `0` (auth passes, but alignment check catches it via DMARC)
4. VIP policy engine: lowers quarantine threshold to `50`

**Total score**: 65 > lowered threshold 50 → **QUARANTINE**

---

### Scenario 3: Webhook Forgery Attempt

**Attack**: External attacker discovers the webhook URL pattern and attempts to POST fake payloads.

**Gateway mitigations**:
1. URL contains `WEBHOOK_SHARED_SECRET` as a path segment
2. Constant-time HMAC comparison prevents timing oracle attacks
3. Auth failure returns `404` — attacker cannot determine if the secret is wrong or the endpoint doesn't exist
4. Rate limiting restricts brute-force attempts to 120/minute per IP

---

### Scenario 4: MIME Zip Bomb

**Attack**: Attacker sends an email with a recursive archive containing a massive decompressed payload designed to exhaust memory.

**Gateway mitigations**:
1. `max_depth=3` recursion limit
2. `max_files=10` per archive
3. Decompressed size ratio check (>100:1 flagged immediately)
4. `MAX_ATTACHMENT_SIZE_BYTES=40MB` — oversized attachments are skipped (not scanned, but not memory-exhausted)

---

## Residual Risks & Hardening Guidance

| Risk | Severity | Mitigation Status | Recommendation |
|---|---|---|---|
| **DNSSEC not enforced at resolver** | Medium | Partial | Ensure upstream resolvers explicitly enforce DNSSEC validation for SPF/DKIM/DMARC lookups |
| **PSL walk uses naive heuristic** | Medium | Known limitation | Replace `dmarc._org_domain()` with `publicsuffix2`/`tldextract` |
| **Secrets in environment variables** | High (production) | Acceptable for dev | Deploy `VaultSecretsProvider` or `AWSSecretsProvider` in production |
| **mTLS not default on internal traffic** | Medium | Optional | Enable `MTLSContextBuilder` on inter-process channels between ingress and workers |
| **`RedisStore.incr()` non-atomic** | Low | Documented | Use Lua/`EVAL` if rate limiting becomes a strict security boundary |
| **Link defanging is regex-based** | Low | Documented | Does not catch JavaScript-constructed links; acceptable for the current threat model |
| **ClamAV fails open** | Medium | By design | Monitor `ClamAVUnreachable` alert aggressively; fails open is preferable to service disruption |
| **Quarantine release delivers unmodified message** | Low | By design | Release means "human confirmed false positive"; add re-analysis on release if needed |

---

## Security Controls Summary

| Control Type | Implementation |
|---|---|
| Authentication | Shared secret (webhooks), Bearer token (admin), JWT RBAC (identity) |
| Authorization | RBAC roles (`admin`, `operator`, `viewer`), network segmentation |
| Encryption in transit | TLS on all inbound (Ingress), STARTTLS on relay, mTLS on internal (optional) |
| Encryption at rest | Fernet AES-128-CBC for all stored mail and quarantine payloads |
| Rate limiting | Fixed-window per-IP, Redis-backed (shared across instances), per-tenant |
| Audit logging | Append-only JSONL with SHA-256 chain of custody, operator-tied admin actions |
| Redaction | Centralized regex PII/credential stripper applied at all log/audit call sites |
| Resilience | Retry + circuit breaker on all external dependencies; fail-open on scanning outages |
