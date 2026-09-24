# Architecture & C4 Model — email-auth-gateway

## System Overview

`email-auth-gateway` is an enterprise-grade, multi-tenant email security gateway. Positioned between public inbound mail providers (SendGrid, Mailgun, AWS SES, Microsoft 365, Google Workspace) and internal mail infrastructure, it performs asynchronous, defense-in-depth analysis across three parallel evaluation stages before deciding whether to forward, warn-and-strip, or quarantine incoming messages.

---

## C4 Model Architecture

### Level 1: System Context Diagram

The System Context diagram illustrates how `email-auth-gateway` fits into the broader enterprise email and security ecosystem, identifying external actors, mail delivery systems, and downstream security tools.

```mermaid
graph TB
    subgraph Senders ["External Entities"]
        SenderMTA["Inbound Mail Providers<br/>(SendGrid, Mailgun, SES, M365, GWorkspace)"]
        ThreatActors["Malicious Senders<br/>(Spoofing, Phishing, Malware)"]
    end

    subgraph CoreGateway ["Email Security Perimeter"]
        Gateway["email-auth-gateway<br/>(Ingress Webhook, Parser, Decision Engine)"]
    end

    subgraph InternalSystems ["Internal Enterprise Infrastructure"]
        MTA["Downstream SMTP Relay / Mail Server<br/>(Postfix, Exchange, Zimbra)"]
        Recipients["Enterprise Mailboxes<br/>(Employees / Inboxes)"]
        SOC["Security Operations Center (SOC)<br/>(Incident Responders / Admins)"]
        SIEM["Enterprise SIEM / SOAR<br/>(Splunk, Elastic, Sentinel)"]
    end

    subgraph ExternalFeeds ["External Threat Intelligence"]
        VT["VirusTotal API<br/>(File & URL Reputation)"]
        GSB["Google Safe Browsing API<br/>(Phishing / Malware DB)"]
        RDAP["RDAP / WHOIS Registries<br/>(Domain Age Verification)"]
    end

    SenderMTA -->|HTTPS Webhook / SMTP| Gateway
    ThreatActors -.->|Exploit / Phishing Email| SenderMTA
    Gateway -->|Clean Email (Relay)| MTA
    MTA -->|Deliver| Recipients
    Gateway -->|Security Alerts & Digests| SOC
    SOC -->|Review Quarantine & Release via Admin API| Gateway
    Gateway -->|JSONL Audit & Metrics| SIEM
    Gateway -->|Reputation Lookups| VT
    Gateway -->|URL Scanning| GSB
    Gateway -->|Domain Age Check| RDAP
```

---

### Level 2: Container Diagram

The Container diagram decomposes `email-auth-gateway` into its independently deployable high-level execution components, microservices, and storage layers.

```mermaid
graph TB
    subgraph IngressBoundary ["Ingress Network Boundary"]
        LB["Cloud Load Balancer / Ingress<br/>(TLS Termination, WAF)"]
    end

    subgraph GatewayCluster ["Kubernetes Pod Cluster: email-auth-gateway"]
        FastAPIApp["FastAPI Application<br/>(Port 8000 / ASGI Uvicorn)<br/>- Inbound Webhook Endpoints<br/>- Admin API & Identity RBAC<br/>- SOC Dashboard UI"]
        PipelineWorker["Parallel Analysis Pipeline<br/>- Stage 1: Auth Checker (SPF, DKIM, DMARC, ARC)<br/>- Stage 2: Content Analysis (NLP, Typosquat, URLs)<br/>- Stage 3: Attachment Analysis (Hashes, ClamAV)"]
        DecisionEngine["Decision Engine & Policy Router<br/>- Score Accumulator<br/>- VIP Protection Engine<br/>- Multi-Tenant Rule Evaluator"]
        DeliveryRouter["Delivery & Notification Engine<br/>- Outbound SMTP Relay Client<br/>- DLP Content Stripper<br/>- Quarantine Storage Writer<br/>- Webhook / Slack Notifier"]
    end

    subgraph DataAndBacking ["Storage & Infrastructure Layer"]
        RedisKV[("Redis Cluster / Memory Store<br/>- Idempotency Deduplication<br/>- Distributed Token-Bucket Rate Limiter<br/>- Reputation & RDAP Caches")]
        DiskStorage[("Encrypted Quarantine & Raw Storage<br/>- Fernet AES-128-CBC / HMAC-SHA256<br/>- Tenant-Isolated Directories")]
        ClamAVDaemon["ClamAV Antivirus Daemon<br/>(clamd TCP:3310)<br/>- Local Stream Attachment Scanning"]
        AuditFile[("Append-Only JSONL Audit Store<br/>- Message Lifecycle Records<br/>- Admin Action Trail")]
    end

    LB -->|Route Inbound Traffic| FastAPIApp
    FastAPIApp --> PipelineWorker
    PipelineWorker --> DecisionEngine
    DecisionEngine --> DeliveryRouter
    FastAPIApp <-->|Rate Limit & Dedup| RedisKV
    PipelineWorker <-->|Cache Checks| RedisKV
    PipelineWorker -->|Scan Stream (TCP)| ClamAVDaemon
    DeliveryRouter -->|Store Encrypted .eml| DiskStorage
    DeliveryRouter -->|Append Event| AuditFile
    FastAPIApp -->|Query & Audit Log| AuditFile
```

---

### Level 3: Component Diagram

The Component diagram details the internal modules, pipelines, and class boundaries within `email-auth-gateway`.

```mermaid
graph LR
    subgraph Ingestion ["Ingestion & Security Layer"]
        Parsers["webhook_receiver.parsers<br/>(SendGrid, Mailgun, SES, M365)"]
        SecLayer["security/<br/>- verify_secret<br/>- RateLimiter<br/>- SourceIPAllowlist"]
    end

    subgraph AnalysisStages ["Three Parallel Analysis Stages"]
        AuthCheck["auth_checker/<br/>- check_spf<br/>- check_dkim<br/>- check_dmarc<br/>- check_arc<br/>- check_fcrdns"]
        ContentCheck["content_analysis/<br/>- extract_urls<br/>- check_typosquat<br/>- check_urgency_keywords<br/>- ReputationProvider"]
        AttachCheck["attachment_analysis/<br/>- extract_attachments<br/>- ClamAVScanner<br/>- VirusTotalFileProvider"]
    end

    subgraph DecisionAndDelivery ["Decision & Action Layer"]
        Decision["decision_engine/<br/>- decide()<br/>- VIPPolicyEngine<br/>- TenantConfigStore"]
        Delivery["delivery/<br/>- SMTPRelay<br/>- QuarantineStore<br/>- WebhookNotifier<br/>- DLPScanner"]
    end

    Parsers --> SecLayer
    SecLayer --> AuthCheck
    SecLayer --> ContentCheck
    SecLayer --> AttachCheck
    AuthCheck -->|StageScore| Decision
    ContentCheck -->|StageScore| Decision
    AttachCheck -->|StageScore| Decision
    Decision --> Delivery
```

---

### Level 4: Execution Sequence (Message Lifecycle)

The sequence diagram below traces the end-to-end processing of an inbound message from HTTP POST to delivery or quarantine.

```mermaid
sequenceDiagram
    autonumber
    actor Provider as Mail Provider (SendGrid/Mailgun)
    participant Receiver as Webhook Receiver (FastAPI)
    participant Sec as Security Hardening
    participant Pipe as 3-Stage Pipeline
    participant Dec as Decision Engine
    participant Rel as Delivery / Relay
    participant Quar as Quarantine Store
    participant Aud as Audit Logger

    Provider->>Receiver: POST /webhooks/sendgrid/inbound/{secret}
    Receiver->>Sec: Validate Shared Secret & Source IP
    alt Authentication Failed
        Sec-->>Provider: 404 Not Found (Constant-Time Rejection)
    end
    Receiver->>Sec: Check Rate Limit & Idempotency Hash (Redis)
    alt Duplicate Message
        Sec-->>Provider: 200 OK {"duplicate": true}
    end
    Receiver->>Pipe: Execute Parallel Analysis (Auth + Content + Attachments)
    par Stage 1: Auth Checks
        Pipe->>Pipe: Evaluate SPF, DKIM, DMARC, ARC, FCrDNS
    and Stage 2: Content Analysis
        Pipe->>Pipe: Extract URLs, evaluate domain age & reputation
    and Stage 3: Attachment Analysis
        Pipe->>Pipe: Hash attachments, scan via ClamAV / VT
    end
    Pipe-->>Dec: Aggregate Stage Scores & Flag Reasons
    Dec->>Dec: Calculate Composite Risk Score & Policy Thresholds
    alt Score >= 70 (QUARANTINE)
        Dec->>Quar: Encrypt .eml with Fernet key & persist
        Quar->>Quar: Dispatch Webhook Alert to Slack
        Dec->>Aud: Log Quarantine Record
    else Score between 30 and 69 (WARN_AND_STRIP)
        Dec->>Rel: Defang URLs, tag subject [EXTERNAL], strip attachments
        Rel->>Rel: SMTP Relay to downstream server
        Dec->>Aud: Log Warning & Relay Record
    else Score < 30 (FORWARD)
        Dec->>Rel: SMTP Relay message unmodified
        Dec->>Aud: Log Clean Delivery Record
    end
    Receiver-->>Provider: 200 OK {"message_id": "...", "action": "..."}
```

---

## Security Boundaries & Trust Zones

The gateway establishes four distinct trust boundaries:

| Zone | Level | Components | Access Control |
|---|---|---|---|
| **Zone 1: Public Internet** | Untrusted | Inbound sender MTAs, webhooks, external attachments | Strict rate limiting, payload size caps, constant-time validation |
| **Zone 2: Ingress Boundary** | Semi-Trusted | `/webhooks/*`, `/healthz`, `/readyz` | Shared secrets, IP allowlists, HMAC signature verification |
| **Zone 3: Internal Mesh** | Trusted | Redis KV, ClamAV daemon, worker pipelines | mTLS encryption, network policies, private VPC isolation |
| **Zone 4: Admin & Audit** | Highly Privileged | `/admin/*`, SOC dashboard, raw file decryptor | Bearer token / JWT auth, RBAC roles (`admin`, `analyst`), JSONL audit trail |

---

## Scoring Architecture & Decision Matrix

Scores accumulate from individual stage checks into a composite risk total:

```
Risk Score = Score(Auth Checker) + Score(Content Analysis) + Score(Attachment Analysis) + VIP Penalty
```

- **`0 – 29` Points (`FORWARD`)**: Normal clean delivery.
- **`30 – 69` Points (`WARN_AND_STRIP`)**: Subject prefix `[SUSPICIOUS]`, defanged URLs (`hxxps://...`), attachments quarantined, relayed to user.
- **`70 – 100+` Points (`QUARANTINE`)**: Immediate halt of delivery; message encrypted at rest, admin alert dispatched, reviewable via SOC portal.
- **Malware Override**: Any verified malware hit from ClamAV or VirusTotal assigns `+100` points immediately, triggering unconditional quarantine regardless of allowlist rules.
