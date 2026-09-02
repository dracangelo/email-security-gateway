# Formal Threat Model — email-auth-gateway

This document provides the formal STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) threat model for the `email-auth-gateway` system.

---

## 1. System Overview & Architecture

`email-auth-gateway` is an enterprise-grade, multi-tenant email security gateway designed to process hostile inbound mail flow from public mail providers (SendGrid, Mailgun, AWS SES, Postmark, M365 Graph, Google Workspace Pub/Sub, and native SMTP). 

### Trust Zones & Boundaries
1. **Public Internet / Untrusted Zone**: Sender MTAs, malicious webhooks, external URL destinations, and attacker-controlled email bodies/attachments.
2. **Gateway Ingress Boundary**: Inbound webhook receivers (`/webhooks/*`) and SMTP receivers.
3. **Internal Microservice Network**: Message queues, worker pools, admin APIs (`/admin/*`), database quarantine stores, and Redis cache.
4. **Internal Admin Zone**: Authenticated SOC analysts, security admins, and automated ticketing systems interacting with administrative routes.

---

## 2. STRIDE Threat Analysis Matrix

| Threat Category | Threat Vector | Impact | Implemented Mitigations & Controls |
| :--- | :--- | :--- | :--- |
| **Spoofing (S)** | Email domain spoofing (From / Envelope-From mismatch). | High | SPF RFC 7208 evaluation, DKIM key validation, DMARC alignment via Public Suffix List, ARC validation, and FCrDNS checks. |
| **Spoofing (S)** | Webhook payload forgery by unauthorized HTTP clients. | Critical | Provider-specific webhook authentication strategies (shared secrets, Mailgun HMAC verification, AWS SNS message signature validation). |
| **Tampering (T)** | Modification of raw email content stored at rest in quarantine. | High | Fernet AES-128-CBC payload encryption with per-tenant key isolation (`RawMailCipher`, `TenantIsolatedQuarantine`). |
| **Tampering (T)** | Time-of-Click link tampering mid-transit. | Medium | HMAC-SHA256 signature verification on rewritten gateway links (`/toc/redirect`). |
| **Repudiation (R)** | Analyst releasing or rejecting phishing emails without accountability. | High | Cryptographically tied JSONL admin audit logging (`AuditLogger.record_admin_action`) recording operator identity, timestamp, target ID, and reason. |
| **Information Disclosure (I)** | PII or credential leakage in system logs or metrics. | High | Centralized regex-based PII/credential redactor (`security.redact`) applied at logging and audit submission call sites. |
| **Information Disclosure (I)** | Multi-tenant data exposure (tenant A accessing tenant B's quarantined mail). | Critical | Tenant data isolation model (`TenantIsolatedQuarantine`) with isolated storage paths and per-tenant Fernet keying. |
| **Denial of Service (D)** | Inbound webhook flooding / resource exhaustion. | High | Dual-layer rate limiting (`RateLimiter`, `TenantRateLimiter`) backed by Redis/In-Memory stores, payload size caps (max 10MB), and async message queue decoupling. |
| **Denial of Service (D)** | MIME parser zip bombs or infinite archive recursion. | High | Maximum attachment depth checks (`max_depth=3`), file count caps (`max_files=10`), and corrupted archive exception catching. |
| **Elevation of Privilege (E)** | Public ingress caller invoking administrative quarantine release APIs. | Critical | Network segmentation separating public webhook receivers (`create_inbound_app`) from admin management routes (`create_admin_app`), enforced RBAC, and rate-limited admin authorization. |

---

## 3. Residual Risks & Security Hardening Guidance

1. **DNSSEC Enforcement**: Ensure upstream resolvers explicitly enforce DNSSEC validation for SPF/DKIM/DMARC lookups.
2. **Secrets Manager Integration**: Deploy `VaultSecretsProvider` or `AWSSecretsProvider` in production environments to avoid plaintext secrets in environment variables.
3. **mTLS Internal Traffic**: Enable mutual TLS (`MTLSContextBuilder`) on inter-process gRPC/HTTP channels between public ingress nodes and worker pools.
