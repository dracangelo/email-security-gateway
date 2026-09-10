# Architecture — email-auth-gateway

## Overview

`email-auth-gateway` is an enterprise-grade, multi-tenant email security gateway. It sits between inbound mail providers (SendGrid, Mailgun, AWS SES, M365, Google Workspace) and your internal infrastructure, inspecting every message across three parallel analysis stages before deciding whether to forward, warn-and-strip, or quarantine it.

---

## High-Level Data Flow

```
┌─────────────────────────────────────────────────────┐
│         Public Inbound Providers                    │
│  SendGrid · Mailgun · AWS SES · M365 · GWorkspace  │
└───────────────────┬─────────────────────────────────┘
                    │ HTTPS webhook / SMTP
                    ▼
┌─────────────────────────────────────────────────────┐
│              Security / Ingress Layer               │
│  Webhook Auth · IP Allowlist · Rate Limit · Size   │
│  Bounce Detection · Idempotency (Redis dedup)      │
└───────────────────┬─────────────────────────────────┘
                    │ Raw MIME bytes
                    ▼
        ┌───────────┴───────────┐
        │                       │
        ▼                       ▼
┌───────────────┐   ┌───────────────────────────┐
│ auth_checker/ │   │   content_analysis/       │
│ SPF · DKIM   │   │ Keywords · URLs · Typosquat│
│ DMARC · ARC  │   │ Homoglyphs · Evasion · OCR│
│ BIMI · FCrDNS│   │ Reputation · Domain Age   │
└──────┬────────┘   └────────────┬──────────────┘
       │                         │
       │            ┌────────────┘
       │            │
       ▼            ▼
┌────────────────────────────────┐
│     attachment_analysis/       │
│  Extract · Extensions · Hashes │
│  VirusTotal · ClamAV · Sandbox │
└────────────────┬───────────────┘
                 │  stage scores (score_delta + reasons)
                 ▼
┌─────────────────────────────────────────────────────┐
│              decision_engine/                       │
│  Score Aggregation · Per-Tenant Config              │
│  VIP Policy · Campaign Clustering · Allow/Block    │
│  Feedback Loop · Shadow Mode · Explainability      │
└───────────────────┬─────────────────────────────────┘
                    │  Action: FORWARD / WARN_AND_STRIP / QUARANTINE
                    ▼
┌─────────────────────────────────────────────────────┐
│                  delivery/                          │
│  forward → relay as-is                             │
│  warn_and_strip → modify + relay                   │
│  quarantine → encrypt + store + notify             │
└───────────────────┬─────────────────────────────────┘
                    │
        ┌───────────┴───────────┐
        ▼                       ▼
┌──────────────┐       ┌────────────────┐
│   audit/     │       │  observability/│
│ JSONL trail  │       │ Prometheus     │
│ Admin log    │       │ OpenTelemetry  │
└──────────────┘       └────────────────┘
```

---

## Module Responsibilities

| Module | Role | Key Files |
|---|---|---|
| `webhook_receiver/` | FastAPI application, request parsing, orchestration | `app.py`, `parsers/` |
| `security/` | Auth, rate limiting, encryption, redaction | `webhook_auth.py`, `rate_limit.py`, `encryption.py`, `redact.py` |
| `auth_checker/` | SPF, DKIM, DMARC, ARC, BIMI, FCrDNS, MTA-STS | `pipeline.py`, `spf.py`, `dkim_check.py`, `dmarc.py` |
| `content_analysis/` | URL extraction, typosquatting, keyword matching, reputation | `pipeline.py`, `urls.py`, `keywords.py`, `reputation.py` |
| `attachment_analysis/` | MIME extraction, file scanning, VirusTotal, ClamAV | `pipeline.py`, `extract.py`, `reputation.py` |
| `decision_engine/` | Score aggregation, routing decision, policy layers | `scorer.py`, `allow_block.py`, `vip_policy.py` |
| `delivery/` | SMTP relay, message modification, quarantine, notifications | `pipeline.py`, `relay.py`, `modify.py`, `quarantine.py` |
| `audit/` | Append-only JSONL audit trail | `logger.py` |
| `storage/` | KV abstraction (in-memory or Redis) | `__init__.py` |
| `resilience/` | Retry with backoff, circuit breaker | `retry.py`, `circuit_breaker.py` |
| `config/` | Centralized settings via pydantic-settings | `__init__.py` |
| `multi_tenancy/` | Tenant isolation, MSP view, per-tenant rate limiting | `isolation.py`, `tenant_manager.py` |
| `observability/` | Prometheus metrics, OpenTelemetry tracing, SLOs | `metrics.py`, `tracing.py`, `slo.py` |
| `compliance/` | GDPR, SOC 2, data residency, retention | `gdpr.py`, `retention.py`, `residency.py` |
| `threat_intel/` | IOC feeds, STIX/TAXII, MISP, NRD watchlists | `ioc_feed.py`, `stix_taxii.py`, `misp.py` |
| `identity/` | JWT / bearer RBAC for admin APIs | `manager.py` |
| `admin_ui/` | HTML dashboard, quarantine review, analytics | `ui_app.py`, `dashboard_analytics.py` |
| `time_of_click/` | URL rewriting with HMAC-signed redirect | `service.py` |

---

## Trust Zones

```
Zone 1: Public Internet (UNTRUSTED)
  - Sender MTAs, webhooks, phishing URLs, attacker-controlled content

Zone 2: Gateway Ingress Boundary (SEMI-TRUSTED, verified at entry)
  - /webhooks/* (shared secret + IP allowlist + rate limit)

Zone 3: Internal Microservice Network (TRUSTED)
  - Redis, worker queues, admin APIs (/admin/*)
  - mTLS enforced between internal nodes (production)

Zone 4: Admin Zone (AUTHENTICATED + AUDITED)
  - /admin/* behind separate ADMIN_SHARED_SECRET bearer token
  - All actions recorded in admin audit log with operator identity
```

---

## Scoring Model

Every analysis stage returns a `score_delta` that accumulates into a total risk score:

| Score Range | Action | Description |
|---|---|---|
| 0 – 29 | `FORWARD` | Relay as-is to destination |
| 30 – 69 | `WARN_AND_STRIP` | Prefix subject, defang URLs, strip attachments, then relay |
| 70 – 100+ | `QUARANTINE` | Encrypt, store, notify admin; do not deliver |

> **Single-signal override**: A VirusTotal/ClamAV malware hit contributes `+100` — alone enough to quarantine. Allowlist policy bypasses scoring unless a malware signal is present.

### Score contributions by check

| Check | Pass | Fail | Notes |
|---|---|---|---|
| SPF | 0 | +30 (hard fail), +15 (softfail) | ARC mitigates if valid chain present |
| DKIM | 0 | +30 (invalid), +15 (none) | |
| DMARC | 0 | +50 (p=reject), +35 (p=quarantine), +10 (p=none) | |
| FCrDNS | 0 | +15 | |
| MTA-STS enforce fail | 0 | +20 | |
| BEC / urgency keywords | 0 | +5–+30 | Configurable, per-tenant |
| Typosquat / homoglyph | 0 | +20–+40 | |
| Malicious URL (VirusTotal/GSB) | 0 | +100 | |
| Malware attachment (ClamAV/VT) | 0 | +100 | |
| VIP display name spoof | 0 | +25–+40 | Configurable VIP list |
| IP reputation (Spamhaus/SORBS) | 0 | +15–+30 | |

---

## Deployment Topology

```
                       Internet
                          │
                    [CloudFront/WAF]
                          │
                    [Kubernetes Ingress]
                          │
              ┌───────────┴───────────┐
              │     email-auth-gateway│  <- HPA 5-25 replicas
              │       (FastAPI)       │
              └───┬───────┬───────────┘
                  │       │
          ┌───────┘       └────────┐
          ▼                        ▼
   [Redis ElastiCache]    [ClamAV Daemon]
   Multi-AZ, TLS          Dedicated cluster
          │
          └──── Backing: rate limiting, dedup, caching
```

---

## Resilience Design

| Concern | Mechanism | Behavior on Failure |
|---|---|---|
| Redis unavailable | `InMemoryStore` fallback | Degraded: rate limiting is per-pod |
| ClamAV unreachable | Circuit breaker + fail-open | Attachment scanned only via VT/heuristics |
| VirusTotal timeout | Retry with backoff + circuit breaker | Returns `unknown` verdict; heuristics still apply |
| SMTP relay failure | Retry on connection errors; never retries 5xx | Escalates to quarantine if `warn_and_strip` fails |
| Duplicate webhook delivery | SHA-256 idempotency key in Redis | Silently skipped, response `{"duplicate": true}` |
