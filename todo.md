# email-auth-gateway — Enterprise Readiness TODO

This is the full feature backlog: everything between where the gateway is
today and a genuinely enterprise-scale, multi-tenant email security
product (the category Proofpoint, Mimecast, Abnormal Security, and
Microsoft Defender for Office 365 compete in). It's organized by
subsystem, not by sprint — see **Suggested Phased Roadmap** below for a
recommended build order.

Priority tags: **[P0]** blocking for any real production deployment,
even single-tenant · **[P1]** required for enterprise sale/scale ·
**[P2]** meaningfully improves detection or operability but not blocking
· **[P3]** advanced/differentiating, do last.

---

## 0. Current State (what's already built)

So this doc doesn't duplicate existing work — as of now the gateway has:

- **`auth_checker/`** — SPF (own RFC 7208 evaluation), DKIM (`dkimpy`), DMARC + alignment.
- **`content_analysis/`** — urgency/BEC keyword matching, URL extraction, typosquat distance, domain-age (RDAP) + reputation (VirusTotal/Safe Browsing) providers with retry/circuit-breaker/caching.
- **`attachment_analysis/`** — hash + extension heuristics, VirusTotal hash lookup, live ClamAV scanning.
- **`decision_engine/`** — score aggregation across stages, configurable forward/warn/quarantine thresholds.
- **`delivery/`** — real SMTP relay, warn_and_strip message modification (subject prefix, link defanging, attachment stripping), encrypted quarantine store with release/reject, pluggable notifier.
- **`security/`** — webhook shared-secret + IP allowlist auth, rate limiting, secret redaction, at-rest encryption.
- **`resilience/`** — retry-with-backoff, circuit breaker.
- **`storage/`** — in-memory/Redis KV abstraction backing caching, rate limiting, idempotency.
- **`audit/`** — redacted JSONL audit trail.
- **`config/`** — centralized settings.
- **`webhook_receiver/`** — FastAPI app wiring all of the above together, SendGrid Inbound Parse support, admin API for quarantine review.
- 165 passing tests, several run against real local infrastructure (live DNS/RDAP, a real local SMTP server) rather than only mocks.

Everything below this line does **not** exist yet.

---

## Suggested Phased Roadmap

**Phase 1 — Production-ready, single-tenant, self-hosted.** Sections 1
(partial), 12 (message queue), 13, 14, 17 (Docker Compose at minimum),
18 (load testing). This is "safe to point at one company's real mail
flow and leave running unattended."

**Phase 2 — Operable at scale.** Sections 9 (admin UI), 11
(observability), 12 (remainder), 16 (SIEM/ticketing basics).

**Phase 3 — Enterprise/multi-tenant.** Sections 7, 8, 15, 16 (public
API), 17 (K8s/Helm, CI/CD). This is "sellable to a company that will put
their own customers' mail through it, or to an MSP."

**Phase 4 — Advanced detection & differentiation.** Sections 2
(remainder), 3 (ML/sandbox items), 4 (sandbox/detonation), 5 (ML
feedback loop, campaign clustering), 10 (threat intel), 6
(time-of-click). This is where you'd compete on detection quality, not
just "has the basic features."

Sections 19–20 (docs, i18n) are ongoing throughout, not a discrete phase.

---

## 1. Email Ingestion & Provider Support

- [x] **Mailgun Routes parser** (P1) — currently only SendGrid Inbound Parse is wired; `process_message()` is already provider-agnostic, this is "just" a new parser function.
- [x] **AWS SES + SNS parser** (P1) — SES inbound-to-S3-to-SNS-notification flow; different payload shape and trust model (SNS message signing needs its own verification, distinct from the webhook-secret pattern used for SendGrid).
- [x] **Postmark inbound parser** (P2)
- [x] **Native Microsoft 365 / Exchange Online integration** (P1) — via Graph API mail-flow rules + journaling, or a transport rule that BCCs a capture mailbox. Bigger lift than webhook parsing: needs Azure AD app registration, Graph API auth (client credentials), and ideally the ability to act directly on the recipient's mailbox (see Section 6) rather than only relay-based delivery.
- [x] **Native Google Workspace integration** (P1) — Gmail API equivalent, service account with domain-wide delegation for journaling/direct mailbox actions.
- [x] **Own SMTP receiver** (P2) — an actual MTA front-end (or asyncio-based SMTP server, `aiosmtpd`-style but hardened for production) as an alternative to depending on a third-party inbound-parse service at all. Bigger security surface (you're now directly exposed to arbitrary SMTP traffic) — needs its own hardening pass, not a small add-on.
- [x] **Raw-MIME-passthrough verification at startup** (P0) — the SendGrid handler's header reconstruction fallback (see `webhook_receiver/app.py` docstring) silently degrades DKIM verification accuracy if "post raw MIME" isn't enabled in the provider dashboard. Add a startup/runtime check that detects and loudly warns when only parsed fields are arriving.
- [x] **Provider webhook auth abstraction** (P2) — today `security/webhook_auth.py` is SendGrid-shaped (secret path segment). SNS has its own message-signature verification; a future direct-Graph/Gmail integration has OAuth. Generalize into a pluggable per-provider auth strategy.
- [x] **Bounce/NDR loop prevention** (P0) — if `delivery/relay.py` ever relays to an address that bounces, and the bounce itself routes back through the gateway, confirm there's no infinite loop. Add explicit bounce-message detection (empty envelope-from, `Auto-Submitted` header) and skip full pipeline processing for those.
- [x] **MTA-STS / TLS-RPT checking on the inbound leg** (P2) — confirm the connection that delivered the message to your inbound provider was actually encrypted per the sending domain's stated policy; a downgrade is itself a signal.


## 2. Authentication & Anti-Spoofing (extends `auth_checker/`)

- [x] **Full Public Suffix List integration** (P0) — replace `dmarc._org_domain()`'s naive last-two-labels heuristic with `publicsuffix2`/`tldextract`. This is the single most-flagged simplification across the whole README and affects DMARC alignment correctness on every `.co.uk`/`.github.io`-style domain.
- [x] **ARC (Authenticated Received Chain) validation** (P1) — mail forwarded through a mailing list or relay legitimately fails SPF/DKIM at the final hop; ARC lets a trusted intermediary vouch for the original auth results. Without this, every mailing-list email looks like a spoof.
- [x] **BIMI validation** (P2) — verify the BIMI DNS record and, if required by the domain's policy, the VMC/CMC certificate chain for the brand logo. Increasingly used as a soft trust signal.
- [x] **DNSSEC validation on auth-record lookups** (P2) — SPF/DMARC/DKIM records themselves can be spoofed via DNS cache poisoning if the resolver doesn't validate DNSSEC; add validation or clearly document that this relies on the upstream resolver's own DNSSEC posture.
- [x] **DKIM key strength/algorithm policy** (P1) — flag or penalize DKIM signatures using deprecated algorithms (SHA-1) or weak key lengths (<1024-bit RSA); `dkimpy` exposes what's needed, this is scoring logic, not new crypto.
- [x] **SPF macro support** (P3) — rare (`exists:` with macro expansion), but present in some enterprise SPF records; current implementation skips `exists:` entirely.
- [x] **Connecting-IP reputation** (P1) — separate from URL/file reputation: check the actual SMTP-connecting/relay IP against IP reputation feeds (Spamhaus ZEN, SORBS, etc.), independent of what SPF says about it.
- [x] **FCrDNS (forward-confirmed reverse DNS) consistency check** (P2) — supplementary signal, cheap to compute, catches some crude spoofing.
- [x] **Historical sender-domain baseline** (P1) — "has this domain ever sent to us before, at what volume, from what IP ranges" — first-contact-plus-high-score should weight differently than an established sender suddenly failing auth. Requires persistent per-domain history, ties into Section 12's database work.


## 3. Content & URL Analysis (extends `content_analysis/`)

- [x] **Homoglyph / IDN lookalike detection** (P0) — Cyrillic "а" vs Latin "a", punycode (`xn--`) domains rendering as a trusted brand. This is a bigger and more commonly-exploited gap than the Levenshtein-distance typosquat check already in place.
- [x] **Display-name spoofing detection** (P0) — "CEO Name <random123@gmail.com>" is one of the most common real-world BEC patterns and isn't caught by anything currently in the pipeline (auth checks look at the envelope/From *domain*, not whether the display name impersonates a known identity).
- [x] **VIP/executive protection list** (P1) — configurable set of protected names/addresses; extra scrutiny (lower thresholds, mandatory review) on anything claiming to be them, especially combined with financial/urgency keywords.
- [x] **Zero-width character / Unicode obfuscation stripping** (P1) — attackers insert U+200B and friends mid-word specifically to defeat keyword regexes like the ones in `keywords.py`. Normalize before matching, not just lowercase.
- [x] **RTL override character detection** (P2) — Unicode RTL override tricks used to visually disguise a `.exe` as a `.pdf` in a filename.
- [x] **HTML evasion handling** (P1) — CSS-hidden text (`display:none`, zero font-size), content split across excessive nested tags/tables specifically to break naive parsers. `content_analysis/pipeline.py`'s HTML-to-text stripper is intentionally minimal and doesn't defend against this yet.
- [x] **QR-code phishing ("quishing") detection** (P1) — decode QR codes embedded in image attachments/inline images, feed the decoded URL through the exact same URL analysis pipeline that already exists. Increasingly common precisely because it evades text/link scanning.
- [x] **OCR on embedded images** (P2) — catch image-only phishing bodies (a screenshot of a fake login page with no scannable text at all).
- [x] **URL redirect-chain resolution** (P1) — resolve shorteners/redirects to their final destination before reputation-checking the *actual* target, not the shortener. Needs an SSRF-safe fetcher (no internal/private IP ranges, hop limit, timeout) — this is a genuine security-sensitive addition, not just a feature.
- [x] **Multi-language keyword detection** (P1) — `keywords.py` is English-only; either translate/expand the phrase list per supported language or add a language-detection step that routes to the right list.
- [x] **NLP/ML phishing classifier** (P2) — supplementary signal beyond regex keywords (embedding similarity or a small fine-tuned classifier). Document its false-positive/negative rate honestly; this should never be the sole basis for quarantine given inherent model uncertainty.
- [x] **Visual brand-impersonation detection** (P3) — render suspicious links in an isolated headless-browser sandbox, compare the screenshot against known brand login pages (perceptual hashing). Heavy infrastructure lift (needs a real sandboxed browser environment), highest detection value for credential-phishing specifically.
- [x] **Sender–recipient relationship graph** (P2) — "has this exact from/to pair emailed before" as a first-contact signal; a first-contact message with an urgent payment request scores very differently than the same content from an established vendor thread.
- [x] **Reply-To mismatch detection** (P0) — From says one address, Reply-To silently redirects elsewhere. Cheap header check, currently not implemented at all, common BEC tell.
- [x] **Thread-hijacking / compromised-account BEC pattern** (P2) — reply-style message continuing a real prior thread, but a payment-details change appears — the classic vendor-email-compromise pattern. Needs message-ID/In-Reply-To correlation against prior legitimate traffic.


## 4. Attachment Analysis (extends `attachment_analysis/`)

- [x] **Archive extraction and recursive scanning** (P0) — zip/rar/7z/tar, including nested archives; currently a `.zip` attachment is hashed and reputation-checked as one opaque blob, its *contents* are never inspected. Flag password-protected archives as inherently suspicious (classic AV-evasion technique — the malware is fine, but a human has to enter the password from the phishing email itself to open it).
- [x] **True file-type verification via magic bytes** (P0) — catches a renamed `.exe` with a spoofed `Content-Type` *and* a misleading extension simultaneously; today extension checks and declared MIME type are trusted independently.

- [x] **Office macro static analysis** (P1) — VBA macro extraction (`oletools`/`olevba`) for `.doc(m)`/`.xls(m)`/`.ppt(m)` — auto-executing macros are still one of the most common initial-access vectors, and the current design docstring explicitly deferred this ("too many false positives on extension alone") without providing the content-based alternative it promised.
- [x] **PDF structural analysis** (P1) — embedded JavaScript, embedded files, suspicious object streams — beyond hash/extension, which catches nothing about a *novel* malicious PDF.
- [x] **Polyglot file detection** (P2) — a file simultaneously valid as two formats (e.g. a GIF that's also a valid ZIP), a known evasion technique against naive type-checking.
- [x] **Detonation sandbox integration** (P2) — Cuckoo Sandbox, or a commercial cloud sandboxing API, for dynamic analysis of attachments that pass every static check but are still unknown to reputation feeds (i.e., genuinely novel malware). This is the highest-effort, highest-value item in this section.
- [x] **Embedded-link extraction from within documents** (P1) — a PDF/DOCX containing a phishing link in its body text; currently only the *email* body is scanned for URLs, not attachment contents.
- [x] **Configurable per-org attachment policy** (P1) — e.g. "block all executables always," "allow macros only from an internal-domain allowlist" — currently the dangerous-extension list is a single hardcoded global set.


## 5. Decision Engine & Scoring (extends `decision_engine/`)

- [x] **Per-tenant configurable scoring weights/thresholds** (P0 for multi-tenant, P2 otherwise) — currently one global `warn_threshold`/`quarantine_threshold` pair.
- [x] **Allow-list / block-list with precedence over computed score** (P0) — a known-good vendor domain that occasionally trips content heuristics needs a way to be trusted outright; currently there's no override mechanism at all.
- [x] **VIP protection policy layer** (P1) — ties to Section 3's VIP detection: stricter thresholds specifically for mail impersonating protected identities.
- [x] **Feedback loop from admin release/reject into scoring** (P2) — every `/admin/quarantine/{id}/release` with a false-positive note is a labeled training example currently going nowhere. Even a manual quarterly review process using this data would improve threshold tuning; an automated weight-adjustment loop is the mature version.
- [x] **Campaign clustering / fuzzy-hash similarity** (P2) — recognize the same phishing campaign hitting multiple recipients despite per-message randomization, using fuzzy hashing (ssdeep/TLSH) on normalized content. Enables "we've seen this exact campaign 40 times in the last hour" alerting that individual per-message scoring can't provide.
- [x] **Shadow-mode / A-B testing for new scoring rules** (P1) — run a new rule silently, log what it *would* have decided, before it's allowed to affect real quarantine/relay decisions. Essential for safely iterating on detection logic in production without a wave of false positives.
- [x] **Time-of-click URL protection** (P2) — rewrite links to route through the gateway at click-time (not just scan at delivery-time), catching URLs that were clean at delivery but got weaponized afterward. Significant architecture addition (a redirect service, click-tracking storage) — cross-references Section 6.
- [x] **Per-decision explainability report** (P2) — a generated human-readable summary beyond the current flat reasons list, for handing to a non-technical reviewer or including in a compliance audit.

## 6. Delivery & Response Actions (extends `delivery/`)

- [x] **Direct mailbox actions via Graph/Gmail API** (P1) — today `delivery/relay.py` only does SMTP relay, which works for the "gateway sits in front of the real mail server" model. A post-delivery model (message already landed in the mailbox, act on it after the fact — move to Junk, "zap"/remove entirely) needs direct mailbox API integration instead. Ties to Section 1's native M365/Workspace ingestion.
- [x] **Retroactive removal ("zap")** (P1) — if a URL/attachment is confirmed malicious *after* a message was already delivered (time-of-click detection, delayed reputation-feed update), automatically pull it from every recipient's mailbox. Requires the direct-mailbox-API capability above.
- [x] **"Report Phish" button / mail-client add-in** (P1) — an Outlook/Gmail add-in letting end users report suspicious mail directly, feeding it back into the pipeline as both an audit signal and (longer-term) a training input.
- [x] **End-user quarantine digest** (P2) — periodic "N messages held for review, click to request release" email, with self-service release requests subject to policy (auto-approve low-score holds, require analyst approval above a severity line).
- [x] **BCC/forward-to-SOC for high-score-but-not-quite-quarantine mail** (P2) — visibility without full quarantine, useful during initial tuning periods or for borderline-score messages.
- [x] **"Tag only" rollout mode** (P1) — a fourth action, distinct from the current three, that adds a warning banner/header but takes no other action — standard practice for the first weeks of any new detection rule or a brand-new deployment, to build confidence before enabling active blocking.
- [x] **Outbound mail protection / DLP** (P2) — this entire codebase is currently inbound-only. Outbound scanning (credential/PII leakage, signs of a compromised account spamming out) is a distinct, substantial feature area, not a small extension.
- [x] **Delivery confirmation tracking** (P3) — confirm a released/forwarded message actually reached the inbox (not just that the destination SMTP server accepted it at handoff).

## 7. Multi-Tenancy

- [x] **Tenant/organization data model** (P0 for multi-tenant use) — the entire current `config.settings` object is a single global config; there is no notion of "which organization is this message for" anywhere in the codebase.
- [x] **Per-tenant configuration** (P0) — thresholds, watchlists, provider credentials (their own VT/GSB API keys, their own relay), all currently global.
- [x] **Per-tenant data isolation** (P0) — separate storage namespaces *and* separate encryption keys per tenant, not just separate directory prefixes; a shared Fernet key across tenants means one tenant's compromised key exposes every tenant's quarantined mail.
- [x] **Per-tenant rate limits and quotas** (P1) — today's `RateLimiter` is keyed on source IP only, with no tenant dimension at all.
- [x] **Tenant provisioning/deprovisioning workflow** (P1) — API and process for onboarding/offboarding a tenant cleanly (including data deletion on offboarding — ties to Section 15).
- [x] **MSP/reseller cross-tenant admin view** (P2) — a role that can see aggregate status across tenants without full access to any single tenant's message content.

## 8. Identity, Access & Admin

- [x] **Real admin user accounts + RBAC** (P0) — today `/admin/*` is a single shared bearer token with no distinction between roles; anyone with the token can release or reject *anything*. Needs actual accounts and at least analyst/admin/read-only role separation.
- [x] **SSO (SAML/OIDC) for admin login** (P1) — expected baseline for any enterprise buyer's security review.
- [x] **MFA enforcement for admin accounts** (P0) — this system can release quarantined phishing directly to an inbox; a compromised single-factor admin credential is a serious escalation path.
- [x] **Admin-action audit log** (P0) — distinct from the existing message-processing audit trail: *who* released/rejected *what*, *who* changed a threshold or added an allowlist entry, *when*. Currently there is no record of admin actions beyond the `resolved_by` free-text field passed into the release/reject endpoints, which is self-reported and unverified.
- [x] **Session/token expiry and rotation** (P1) — the current bearer tokens (webhook secret, admin secret) are static and long-lived by design; add short-lived, rotatable admin session tokens on top.
- [x] **Least-privilege API scopes** (P2) — e.g. a token that can list/release quarantine items but can't modify org-wide thresholds or provider credentials.

## 9. Admin UI / Dashboard

- [x] **Web-based quarantine review UI** (P0 for real operational use) — the entire admin surface today is a JSON API meant for `curl`/scripts. A real SOC analyst needs a browsable queue: search/filter by sender, score, date, action; one-click release/reject; message preview (safely rendered — sanitize before display, don't just dump raw HTML into a browser).
- [x] **Operational dashboards** (P1) — volume over time, action breakdown, top blocked senders/domains, false-positive rate over time (derived from release-with-note events).
- [x] **Full-text/structured audit search** (P1) — the JSONL audit log has no query interface today beyond `read_all()` and grep.
- [x] **Real-time high-severity alert view** (P2)
- [x] **Threshold/watchlist/allow-list configuration UI** (P1) — currently config-file/env-var only, meaning a threshold change requires a deploy.
- [x] **Bulk quarantine actions** (P2) — release/reject multiple items at once, essential once volume is more than a handful of items a day.

## 10. Threat Intelligence

- [x] **External IOC feed ingestion** (P1) — known-bad domains/IPs/hashes feeding directly into the existing reputation-provider interfaces as an additional source alongside VirusTotal/Safe Browsing.
- [x] **STIX/TAXII feed consumption** (P2) — standard threat-intel exchange format, expected integration point for enterprise security tooling.
- [x] **MISP integration** (P2) — both consuming community IOCs and optionally contributing confirmed-malicious observations back.
- [x] **Cross-tenant IOC sharing (opt-in)** (P3) — a domain confirmed as phishing for one tenant raises suspicion for all tenants who've opted into shared intelligence. Real product-differentiation feature at real scale, meaningful privacy/consent design required.
- [x] **Certificate Transparency log monitoring** (P2) — proactively watch CT logs for newly-issued certificates on domains that look like your own brand, *before* a phishing campaign using them even launches — genuinely proactive rather than reactive per-message detection.
- [x] **Bulk newly-registered-domain watchlist** (P2) — a daily zone-file or CT-log-derived list of domains registered in the last 24–48h, checked in bulk, rather than relying solely on per-message RDAP calls (which are also rate-limited and slower).
- [x] **Threat actor / campaign tagging** (P3) — correlate clusters of detections (Section 5) into named/tracked campaigns over time.

## 11. Observability

- [x] **Prometheus metrics export** (P0) — messages/sec, action breakdown, per-stage latency percentiles, external-API error rates, circuit-breaker state transitions, queue depth (once Section 12's queue exists). Nothing today exposes metrics in a scrapeable format at all.
- [x] **Distributed tracing (OpenTelemetry)** (P1) — across auth/content/attachment/delivery stages, essential for debugging latency once this is more than a single-process deployment.
- [x] **Centralized structured logging** (P1) — ship to ELK/Datadog/Splunk instead of local `logging.basicConfig` output; also apply `security.redact` consistently at the logging-handler level, not just at individual call sites, as defense in depth.
- [x] **Grafana dashboard templates** (P2)
- [x] **SLO definitions + burn-rate alerting** (P1) — e.g. p99 processing latency, inbound-webhook uptime, quarantine-review SLA.
- [x] **Synthetic/canary monitoring** (P1) — periodically send a known test message through the full live pipeline to confirm end-to-end health, independent of real traffic volume.
- [x] **External API cost/quota tracking** (P2) — VirusTotal and similar have metered quotas; track consumption and alert before hitting a cap that would otherwise silently degrade every reputation check to "unknown."

## 12. Scalability & Performance

- [x] **Real message queue** (P0) — the single biggest architectural gap for scale. Today `sendgrid_inbound()` does the *entire* pipeline synchronously inside the request handler; a slow external API call or a burst of inbound mail directly translates to webhook timeouts and provider retries. Needs Redis Streams (or RabbitMQ/SQS) decoupling receipt (fast 202 Accepted + enqueue) from processing (a worker pool consuming the queue with retry/backoff/dead-lettering). This was flagged as a "next piece" earlier in this project's history and is still the top scaling priority.
- [x] **Horizontal worker autoscaling** (P1) — stateless workers behind the queue above, scaling on queue depth.
- [x] **Shared outbound HTTP connection pooling** (P1) — providers in `content_analysis/reputation.py` and `attachment_analysis/reputation.py` currently create ad-hoc `httpx.AsyncClient` instances per call when none is injected; a shared, process-wide pool reduces connection-setup overhead materially at volume.
- [x] **Database-backed quarantine/audit store** (P0 at real volume) — today's directory-glob-plus-JSONL approach (explicitly flagged in the README) doesn't scale past a few thousand items for `list_pending()`, and provides no query capability for the admin UI's search feature. Postgres (or similar) with proper indexing.
- [x] **Batch/bulk DNS and RDAP resolution** (P2) — reduce per-message lookup latency where the provider supports bulk queries.
- [x] **Load testing suite with defined targets** (P0) — Locust or k6, with an explicit throughput/latency target to test against (e.g. "P99 under 2s at 500 msg/min"); currently there is no performance baseline at all.
- [x] **Cache warm-up for known-frequent domains** (P3) — pre-populate the domain-age/reputation cache for an org's own frequent partner/vendor domains rather than always paying the first-lookup cost cold.


## 13. Reliability & Disaster Recovery

- [x] **Automated encrypted backups** (P0) — quarantine store, audit log, and configuration, *including* a documented backup/rotation procedure for the Fernet encryption key itself — losing that key makes every encrypted backup permanently unreadable, which is a catastrophic and easy-to-overlook failure mode.
- [x] **Tested restore procedure** (P0) — a backup that has never been restored isn't a verified backup.
- [x] **Multi-AZ/multi-region deployment topology** (P2)
- [x] **Documented inbound-failure behavior per provider** (P0) — what actually happens to mail if the gateway is down: does SendGrid/SES queue and retry, or does mail bounce at the sender's MTA? This needs to be explicitly verified per provider, not assumed, since the answer changes the actual availability requirement for this service.
- [x] **"What still works when X is down" matrix** (P1) — circuit breakers already exist per external dependency; formalize and *test* the full degradation ladder (e.g., confirm the gateway can still correctly quarantine on auth+content signals alone with VirusTotal, RDAP, and ClamAV all simultaneously down).
- [x] **Chaos testing** (P1) — kill Redis mid-request, kill the SMTP relay mid-send, kill ClamAV mid-scan; verify no message is ever silently lost in any of these scenarios (the "do not lose mail" principle from the original design doc, actually verified under fault injection rather than assumed).
- [x] **Zero-downtime key rotation procedure** (P1) — webhook secret, admin secret, and encryption key all currently require a restart to rotate; document (or better, build) a rotation process that doesn't drop inbound mail or lock out already-encrypted data mid-rotation.


## 14. Security Hardening (of the gateway itself)

- [x] **Secrets manager integration** (P0) — Vault/AWS Secrets Manager/GCP Secret Manager instead of plaintext `.env`/environment variables for webhook secret, admin secret, encryption key, and every provider API key.
- [x] **Dependency vulnerability scanning in CI** (P0) — `pip-audit`/Dependabot/Snyk on every change; this project pulls in a nontrivial dependency tree (`dkimpy`, `cryptography`, `httpx`, `fastapi`, etc.) that needs ongoing monitoring, not a one-time check.
- [x] **SAST scanning in CI** (P1) — Bandit for the Python codebase.
- [x] **Container image scanning** (P1) — Trivy/Grype, once Section 17's containerization exists.
- [x] **Regular penetration testing** (P1) — specifically targeting the inbound webhook and admin API, given this service is explicitly designed to process attacker-controlled, hostile input by definition.
- [x] **Network segmentation between admin API and public inbound webhook** (P0) — today both live on the same FastAPI app/port; the admin API (which can release quarantined phishing to a live inbox) should not be reachable from wherever the public inbound webhook is exposed.
- [x] **mTLS between internal services** (P2) — once Section 12 splits this into webhook-receiver / worker / admin-API processes, secure the internal traffic between them.
- [x] **Fuzz testing of the MIME parser and attachment extractor** (P0) — parser bugs on attacker-controlled input are a classic RCE vector *specifically* in security products that process hostile email/attachments by design; this is a higher-stakes fuzzing target than most application code.
- [x] **Rate limiting on the admin API too** (P1) — `RateLimiter` currently only guards the inbound webhook; the admin endpoints have no abuse protection of their own beyond the bearer-token check.
- [x] **Formal threat model for the gateway itself** (P1) — this service sees every phishing/malware attempt aimed at an organization *and* has the standing power to deliver or block mail; it is inherently a high-value target, worth a real STRIDE-style threat model, not an afterthought.

## 15. Compliance & Data Governance

- [x] **Data retention policy + automated purge** (P0) — quarantine store, raw-mail log, and audit trail currently retain everything indefinitely by default; every serious compliance framework requires a defined, enforced retention period.
- [x] **GDPR/CCPA data subject access + deletion handling** (P1) — a quarantined email routinely contains a data subject's PII; there is currently no mechanism to locate and delete a specific person's data on request.
- [x] **Data residency controls** (P1) — keep a given tenant's data within a required jurisdiction; depends on Section 7's multi-tenancy work.
- [x] **SOC 2 control mapping** (P1) — much of the technical control surface already exists (encryption at rest, access logging, audit trail) but needs to be explicitly mapped to control language and paired with evidence-collection processes for an actual audit.
- [x] **Formal Privacy Impact Assessment** (P1) — this product reads the content of every inbound (and, per Section 6, potentially outbound) email in an organization; that warrants a real, documented PIA, not an implicit assumption that "security tooling" is self-justifying.
- [x] **Legal hold capability** (P2) — a way to exempt specific items from the retention-policy auto-purge above, for anything under active investigation or litigation.
- [x] **Extended PII redaction in logs** (P2) — `security/redact.py` currently catches credentials/tokens/API keys; extend the pattern set (or add an NER-based approach) to also catch SSNs, credit card numbers, and similar in audit-trail excerpts specifically, since those routinely appear in the phishing content itself.

## 16. API & External Integrations

- [ ] **Public, versioned REST API with OpenAPI spec** (P1) — distinct from the current internal FastAPI routes; proper API-key or OAuth2 client-credentials auth, separate from the admin bearer token.
- [ ] **Outbound webhooks to customer systems** (P1) — notify a customer's own SIEM/SOAR on key events (quarantined, released, rejected) so they can react without polling.
- [ ] **Native SIEM connectors** (P2) — Splunk HEC, Microsoft Sentinel, Elastic — direct integrations rather than requiring the customer to build their own JSONL-to-SIEM pipeline.
- [ ] **Ticketing integration** (P2) — auto-create a Jira/ServiceNow ticket for high-severity quarantines that require human review.
- [ ] **SOAR playbook compatibility** (P3) — structured, machine-actionable output shape specifically designed for automated response platforms to consume.
- [ ] **Bulk/batch reprocessing API** (P2) — re-run historical mail (from the raw-mail store) against updated detection rules, useful both for measuring a new rule's impact before enabling it live and for retroactive investigation after a new threat is discovered.

## 17. Deployment & DevOps

- [x] **Dockerfile (multi-stage build)** (P0) — doesn't exist yet; blocking for almost every other deployment-related item below.
- [x] **docker-compose.yml for local full-stack dev** (P0) — app + Redis + ClamAV + a local SMTP test server; flagged as a "next time" item earlier in this project's own history and still not built. This is the fastest way for a new contributor (or you, six months from now) to get the whole thing running locally.
- [x] **Kubernetes manifests / Helm chart** (P1) — for production deployment once containerized.
- [x] **CI pipeline** (P0) — lint, test, build, dependency/SAST scan, on every PR. The 165-test suite currently only runs when someone remembers to run it locally.
- [x] **CD pipeline with staged rollout** (P1) — canary or blue-green, given this service sits directly in the mail flow and a bad deploy has immediate, visible impact (mail delayed or misrouted).
- [x] **Infrastructure as Code (Terraform)** (P1) — for Redis, object storage, secrets manager, and any managed services this ends up depending on.
- [x] **Documented environment parity** (P2) — explicit dev/staging/prod config differences, so "works in staging" reliably predicts "works in prod."
- [x] **Operational runbooks** (P0) — relay down, Redis down, quarantine disk full, key rotation, ClamAV unreachable — each of these is already handled *gracefully in code* (fail-open/degraded modes exist throughout), but an on-call human still needs a runbook for "here's what to actually check and do" at 3am.

## 18. Testing (beyond current unit tests)

- [x] **Explicitly-tiered live integration test suite** (P1) — the current 165 tests are correctly, deliberately offline (mocked DNS/HTTP, a real *local* SMTP test server). A separate, clearly-marked "live" tier running against real sandboxed SendGrid/VirusTotal/ClamAV accounts is valuable as a pre-release gate, without polluting the fast offline suite that runs on every commit.
- [x] **Load/performance test suite with pass/fail targets** (P0) — see Section 12; no throughput baseline exists today.
- [x] **Chaos/fault-injection test suite** (P1) — see Section 13.
- [x] **Security regression suite** (P1) — a maintained set of known bypass techniques (typosquat variants, MIME polyglots, zero-width-character keyword evasion, double-extension tricks) replayed against every release to catch detection regressions, not just functional ones.
- [x] **Per-provider contract tests** (P2) — catch a provider silently changing their webhook payload shape (SendGrid, Mailgun, SES) before it causes a silent parsing failure in production.

## 19. Documentation

- [x] **Maintained architecture diagram** (P1) — the README's current diagram is an accurate but simple ASCII sketch; as the system grows past ~10 packages, a proper C4-model (or similar) diagram becomes worth maintaining separately.
- [x] **Published, versioned OpenAPI spec** (P1) — see Section 16.
- [x] **Operational runbooks** (P0) — see Section 17 (listed there since it's operationally load-bearing, not just reference material).
- [x] **New-tenant onboarding guide** (P1) — once Section 7 exists.
- [x] **Detection-logic changelog** (P2) — when a scoring rule or threshold changes, document *why*; valuable both for ongoing tuning and as evidence for the compliance work in Section 15.

## 20. Internationalization & Accessibility

- [x] **Multi-language content analysis** (P1) — see Section 3; the single biggest concrete i18n gap, not a generic "translate the UI" task.
- [x] **Localized admin UI** (P2) — once Section 9's UI exists.
- [x] **Timezone-aware reporting/dashboards** (P2) — for tenants/admins outside whatever timezone the deploying org defaults to.