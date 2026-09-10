# email-auth-gateway

Pre-delivery email security gateway: SPF/DKIM/DMARC auth checks, content
and URL analysis, attachment scanning, a risk-scoring decision engine, and
a webhook receiver -- hardened with webhook authentication, rate limiting,
resource limits, at-rest encryption, an audit trail, and resilience
(retry/circuit-breaker/caching) against every external dependency.

```
inbound webhook (SendGrid/Mailgun/SES)
        |
        v
  security/  -- shared-secret auth, IP allowlist, rate limit, size limits
        |
        v
  auth_checker/         -- SPF, DKIM, DMARC + alignment
  content_analysis/     -- urgency/BEC keywords, URLs, typosquat, domain age, reputation
  attachment_analysis/  -- hash, extension heuristics, VirusTotal, ClamAV
        |                  (all three stages run per message)
        v
  decision_engine/  -- combine scores -> forward / warn+strip / quarantine
        |
        v
  audit/  -- redacted JSONL audit trail
  security/encryption.py + raw_mail_log_dir  -- encrypted-at-rest message store
```

Supporting infrastructure used throughout:
- **`storage/`** -- KV abstraction (in-memory or Redis) backing caching, rate limiting, and idempotency.
- **`resilience/`** -- retry-with-backoff + circuit breaker, wrapping every external HTTP call (RDAP, VirusTotal, Safe Browsing).
- **`config/`** -- one settings object (pydantic-settings), instead of `os.environ.get()` scattered across the codebase.

## Documentation & HTML Portals

The project includes an enterprise-grade documentation suite with both an **Interactive Single Page Application (SPA) Portal** and standalone **Markdown (`.md`) & Static HTML (`.html`) Guides** for every subsystem:

- 🛡️ **[Interactive Documentation Portal](docs/index.html)** — Comprehensive single-page docs app with instant search, dark mode theme, interactive diagrams, and live syntax highlighting.
- ⚡ **[Getting Started Guide](docs/getting_started.html)** ([Markdown](docs/getting_started.md)) — Prerequisites, installation, and first message verification.
- 🏗️ **[Architecture Deep-Dive](docs/architecture.html)** ([Markdown](docs/architecture.md)) — End-to-end pipeline diagrams, state machine, and data flow.
- ⚙️ **[Configuration Reference](docs/configuration.html)** ([Markdown](docs/configuration.md)) — Full environment variable reference and sensible defaults.
- 📡 **[REST API Reference](docs/api_reference.html)** ([Markdown](docs/api_reference.md)) — Webhook ingestion, admin quarantine management, and health endpoints.
- 🏢 **Gateway Subsystems**:
  - [Authentication Checker (`auth_checker`)](docs/modules/auth_checker.html) ([MD](docs/modules/auth_checker.md))
  - [Content Analysis (`content_analysis`)](docs/modules/content_analysis.html) ([MD](docs/modules/content_analysis.md))
  - [Attachment Scanning (`attachment_analysis`)](docs/modules/attachment_analysis.html) ([MD](docs/modules/attachment_analysis.md))
  - [Decision Engine (`decision_engine`)](docs/modules/decision_engine.html) ([MD](docs/modules/decision_engine.md))
  - [Delivery & Relay (`delivery`)](docs/modules/delivery.html) ([MD](docs/modules/delivery.md))
  - [Security & Webhook Auth (`security`)](docs/modules/security.html) ([MD](docs/modules/security.md))
  - [Resilience & Circuit Breaking (`resilience`)](docs/modules/resilience.html) ([MD](docs/modules/resilience.md))
  - [Key-Value & Redis Storage (`storage`)](docs/modules/storage.html) ([MD](docs/modules/storage.md))
  - [Audit Logging (`audit`)](docs/modules/audit.html) ([MD](docs/modules/audit.md))
  - [Multi-Tenancy (`multi_tenancy`)](docs/modules/multi_tenancy.html) ([MD](docs/modules/multi_tenancy.md))
  - [Observability & Metrics (`observability`)](docs/modules/observability.html) ([MD](docs/modules/observability.md))
  - [Compliance & Retention (`compliance`)](docs/modules/compliance.html) ([MD](docs/modules/compliance.md))
  - [Threat Intelligence (`threat_intel`)](docs/modules/threat_intel.html) ([MD](docs/modules/threat_intel.md))
  - [Time-of-Click URL Protection (`time_of_click`)](docs/modules/time_of_click.html) ([MD](docs/modules/time_of_click.md))
  - [Identity, SSO & RBAC (`identity`)](docs/modules/identity.html) ([MD](docs/modules/identity.md))
  - [SOC Admin UI (`admin_ui`)](docs/modules/admin_ui.html) ([MD](docs/modules/admin_ui.md))
  - [Scalability & Message Queue (`scalability`)](docs/modules/scalability.html) ([MD](docs/modules/scalability.md))
  - [Reliability & DR (`reliability`)](docs/modules/reliability.html) ([MD](docs/modules/reliability.md))
  - [Security Hardening & Fuzzing (`security_hardening`)](docs/modules/security_hardening.html) ([MD](docs/modules/security_hardening.md))
- 🚀 **Deployment Guides**: [Docker Compose](docs/deployment/docker.html) · [Kubernetes](docs/deployment/kubernetes.html) · [Helm](docs/deployment/helm.html) · [Terraform](docs/deployment/terraform.html)
- 🔒 **Security**: [Threat Model & STRIDE](docs/security/threat_model.html) · [Hardening Checklist](docs/security/hardening.html)
- 🚨 **[Incident Runbooks](docs/runbooks/INDEX.html)**: [ClamAV Unreachable](docs/runbooks/clamav_unreachable.html) · [Key Rotation](docs/runbooks/key_rotation.html) · [Quarantine Disk Full](docs/runbooks/quarantine_disk_full.html) · [Redis Down](docs/runbooks/redis_down.html) · [Relay Down](docs/runbooks/relay_down.html)

*(To regenerate all standalone HTML pages after updating Markdown files, run `python3 scripts/generate_docs_html.py`.)*

## Packages

### `auth_checker/` (Step 2A)
SPF (RFC 7208, own evaluation against the client IP), DKIM (`dkimpy`),
DMARC + identifier alignment. See its docstrings for RFC caveats
(org-domain heuristic instead of full PSL walk, `ptr`/`exists` skipped).

### `content_analysis/` (Step 2B)
Keyword/BEC matching, URL extraction + typosquat distance, and pluggable
domain-age (RDAP)/reputation (VirusTotal, Safe Browsing) providers --
each wrapped in retry + a shared circuit breaker (`reputation.py`) and
optionally cached (`caching.py`, TTL-configurable, backed by `storage/`).

### `attachment_analysis/` (Step 2C -- new)
- `extract.py` -- pulls attachments out of the MIME tree.
- `extensions.py` -- dangerous-extension and double-extension ("invoice.pdf.exe") heuristics.
- `reputation.py` -- SHA-256/MD5 hash lookup against VirusTotal (retry + circuit breaker), and live scanning via a `clamd` daemon (runs in a thread, fails open on scan errors so a down ClamAV doesn't turn into "flag everything").
- `pipeline.py` -- orchestrates all of the above into one `AttachmentVerdict`.

### `decision_engine/` (Step 3)
Sums every stage's `score_delta` (auth + content + attachments) and maps
the total onto `forward` / `warn_and_strip` / `quarantine` against
configurable thresholds (default 30/70). A single strong signal -- a
malicious file hash or URL, worth +100 -- already clears the quarantine
bar alone.

### `security/` (new)
- `webhook_auth.py` -- constant-time shared-secret check (SendGrid Inbound Parse doesn't sign payloads the way their Event Webhook product does, so this -- an unguessable URL path segment -- is the real mechanism, not a fabricated signature scheme) + optional CIDR-based source-IP allowlist. Auth failures return 404, not 401/403, so a prober can't distinguish "wrong secret" from "nothing here."
- `rate_limit.py` -- fixed-window limiter per source IP, built on `storage/` so it's correctly shared across instances when backed by Redis.
- `redact.py` -- strips API keys/tokens/passwords/PEM blocks from anything headed to logs or the audit trail, including credentials the *phishing content itself* might contain.
- `encryption.py` -- Fernet at-rest encryption for stored raw mail (`.eml` files routinely contain PII and credentials).

### `resilience/` (new)
- `retry.py` -- exponential backoff + jitter (jitter matters: without it, a burst of messages hitting the same transient failure retry in lockstep and turn a blip into a thundering herd).
- `circuit_breaker.py` -- stops hammering a provider that's already down; fails fast instead of making every message wait out a full retry cycle.

### `storage/` (new)
`KeyValueStore` interface with `InMemoryStore` (single process, zero
setup) and `RedisStore` (shared across instances -- required the moment
you run more than one gateway process, since an in-memory rate
limiter/cache/dedup is per-process and doesn't protect anything as a
whole with more than one).

### `audit/` (new)
Append-only, redacted JSONL audit trail: one line per processed message,
with a SHA-256 content hash for chain-of-custody without storing the
message twice.

### `webhook_receiver/` (glue, hardened)
FastAPI app. `/webhooks/sendgrid/inbound/{secret}` verifies the shared
secret and (optionally) source IP, applies the rate limit, enforces
`max_message_size_bytes` (checked against both `Content-Length` and the
actual body), computes a content hash for idempotency (a webhook retry
with identical bytes is skipped, not reprocessed -- important since
SendGrid *will* retry on timeout), encrypts and stores the raw message,
runs all three analysis stages, **acts on the decision via `delivery/`**,
records the audit entry, and returns the outcome. `/healthz` is liveness;
`/readyz` is readiness (Redis reachable if configured, reports ClamAV and
relay configuration status).

`/admin/quarantine` (list), `/admin/quarantine/{id}` (get),
`/admin/quarantine/{id}/release` (mark reviewed + actually relay the
*original* message), `/admin/quarantine/{id}/reject` (mark reviewed,
message stays on disk per the "don't blind-drop" rule) -- all behind a
separate `ADMIN_SHARED_SECRET` bearer token (401 on failure, unlike the
inbound webhook's deliberate 404 -- these aren't trying to hide their
existence, they're behind a normal auth boundary an operator expects).

### `delivery/` (new -- the gateway now acts, not just decides)
- `modify.py` -- the `warn_and_strip` transform: prefixes the subject,
  **defangs** every link (removes the actual `href`/plain-text URL so
  it's not clickable, replaces it with a bracketed `hxxps[://]evil[.]com`
  form investigators can still read), and strips attachments (replaced
  with a readable "[Attachment removed...]" note, not silently dropped).
- `relay.py` -- async SMTP relay (`aiosmtplib`) with retry-with-backoff
  on connection-level failures only -- never retries a permanent 5xx
  rejection from the destination server.
- `quarantine.py` -- encrypted-at-rest storage (reuses `security.encryption`)
  with `list_pending()` / `release()` / `reject()`. Implements the
  original design doc's explicit rule: *"avoid blind dropping -- quarantine
  suspicious emails rather than outright deleting them so admins can
  review and release legitimate business communications."* Release
  relays the **original, unmodified** message -- the point of release is
  correcting a false positive, not delivering a defanged version of a
  message you've just decided was fine.
- `notify.py` -- pluggable quarantine alerting (`LogNotifier` default,
  `WebhookNotifier` for Slack-compatible incoming webhooks).
- `pipeline.py` -- `deliver()`, the orchestrator: `forward` relays as-is,
  `warn_and_strip` modifies-then-relays (escalating to quarantine if the
  modification itself fails, rather than either relaying unmodified or
  silently dropping), `quarantine` stores + notifies. With `RELAY_HOST`
  unset, forward/warn_and_strip run in **dry-run mode**: fully decided
  and logged, nothing actually sent -- lets you stand this up and watch
  its decisions before trusting it to move mail.

## Run it

```bash
pip install -r requirements.txt
cp .env.example .env   # fill in WEBHOOK_SHARED_SECRET, RAW_MAIL_ENCRYPTION_KEY, RELAY_HOST at minimum
uvicorn webhook_receiver.app:app --host 0.0.0.0 --port 8000
```

```bash
curl -X POST "http://localhost:8000/webhooks/sendgrid/inbound/$WEBHOOK_SHARED_SECRET" \
  -F 'envelope={"from":"bounce@example.com","to":["you@yourcompany.com"]}' \
  -F 'from=Alerts <alerts@example.com>' \
  -F 'text=Your account will be suspended within 24 hours. Verify here: https://paypa1.com/login' \
  -F $'headers=Received: from mail.example.com ([203.0.113.55]) by mx.google.com\r\nFrom: alerts@example.com'
```

Reviewing what's quarantined:

```bash
curl http://localhost:8000/admin/quarantine -H "Authorization: Bearer $ADMIN_SHARED_SECRET"
curl -X POST http://localhost:8000/admin/quarantine/<id>/release \
  -H "Authorization: Bearer $ADMIN_SHARED_SECRET" -H "Content-Type: application/json" \
  -d '{"resolved_by":"you@yourcompany.com","note":"false positive"}'
```

Point SendGrid's Inbound Parse config at
`https://your-host/webhooks/sendgrid/inbound/<secret>` (the secret lives
in the URL you give SendGrid, not in anything they send back). See:
https://www.twilio.com/docs/sendgrid/for-developers/parsing-email/setting-up-the-inbound-parse-webhook

For ClamAV: `docker run -p 3310:3310 clamav/clamav` and set `CLAMD_HOST=localhost`.

Without `RELAY_HOST` set, the gateway runs in dry-run mode: every
decision is fully computed, quarantine still works (it never needed a
relay), but forward/warn_and_strip are logged as "would relay" rather
than actually sent -- a safe way to watch its decisions before pointing
it at your real mail flow.

## Tests

```bash
python3 -m pytest tests/ -v
```

164 tests, all offline/local. DNS/HTTP is mocked throughout (including
purpose-built fake transports for exercising retry/circuit-breaker
behavior); SMTP relay tests run against a real local `aiosmtpd` test
server (not mocked) to exercise actual connection/retry/rejection
behavior; `storage/` tests run identically against `InMemoryStore` and
`RedisStore` (via `fakeredis`). One real DKIM sign/verify round-trip uses
a throwaway keypair with an injected fake DNS answer. One real RDAP call
against `example.com` and one full quarantine→release→real-SMTP-relay
loop were run manually against live infrastructure during development
(not part of the automated suite, which stays fully offline).

## Known simplifications / next steps

- **PSL walk**: `dmarc._org_domain()` and the typosquat organizational-domain
  logic are naive last-two-labels heuristics, wrong for `.co.uk`-style
  domains. Swap in `publicsuffix2`/`tldextract`.
- **RDAP coverage varies by TLD**, and the free `rdap.org` redirector will
  rate-limit under load.
- **Reputation providers need API keys** (`VT_API_KEY`, `GSB_API_KEY`) to
  do anything beyond returning `unknown`. Keyword/typosquat/extension/
  newly-registered-domain signals still work without them.
- **Rate limiting trusts the direct TCP peer**, not `X-Forwarded-For`. If
  you put this behind a reverse proxy, terminate TLS there and connect to
  this app directly on an internal network rather than trusting a
  forwarded header from arbitrary clients.
- **`RedisStore.incr()` isn't fully atomic** (INCR then a separate EXPIRE
  call on creation) -- a documented, deliberate tradeoff for testability
  against `fakeredis` (which doesn't support Lua/`EVAL`). Fine for rate
  limiting; revisit with a Lua script if this ever backs something where
  the small race window actually matters.
- **Audit log and quarantine metadata are local files.** Fine for
  single-instance/dev; ship audit lines to a real log aggregator, and add
  a Redis/Postgres index for `list_pending()` instead of directory
  globbing, before this runs at real volume across multiple processes.
- **`raw_mail_log_dir`/`quarantine_dir` default to `/tmp`.** Swap for
  S3/GCS with server-side encryption in production -- local disk isn't
  durable, and `/tmp` in particular can be shared across more than you'd
  expect depending on your deployment environment.
- **Link defanging is regex-based**, not a full HTML parse/re-serialize.
  It handles the common `<a href="...">` case correctly (tested) but
  won't catch a link constructed via JavaScript or unusual markup --
  same category of limitation as the URL-extraction regex it's paired
  with elsewhere in the codebase.
- **Quarantine release delivers the original message**, not a re-scored
  one. If your review process wants to re-run analysis before releasing
  (e.g. to confirm a fix upstream actually resolved the SPF failure),
  that's a deliberate design choice you'd add on top, not a bug -- release
  currently means "a human confirmed this was a false positive," full stop.
