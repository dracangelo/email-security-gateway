"""
Inbound webhook receiver -- now with the security and redundancy layer
wired in: shared-secret + optional IP-allowlist auth, per-IP rate
limiting, payload size limits, idempotency dedup (webhook retries don't
get double-processed), at-rest encryption for stored raw mail, redacted
structured logging, an audit trail, and the attachment-scanning stage.

Wired for SendGrid's Inbound Parse format (multipart/form-data POST) --
see the docstring on sendgrid_inbound() for field details. Everything
downstream of parsing (process_message) is provider-agnostic; swap in a
Mailgun/SES parser and call process_message() the same way.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

from attachment_analysis import ClamAVScanner, NullFileReputationProvider, VirusTotalFileProvider, analyze_attachments, extract_attachments
from audit import AuditLogger
from auth_checker import run_auth_checks
from config import settings
from content_analysis import (
    CachedDomainAgeProvider,
    CachedReputationProvider,
    GoogleSafeBrowsingProvider,
    NullReputationProvider,
    RDAPDomainAgeProvider,
    VirusTotalProvider,
    analyze_content,
)
from decision_engine import (
    CampaignClusterEngine,
    FeedbackLoopEngine,
    ShadowModeEngine,
    StageScore,
    TenantConfigStore,
    VIPPolicyEngine,
    decide,
)
from time_of_click import TimeOfClickService, rewrite_urls_in_html, rewrite_urls_in_text
from delivery import (
    DLPScanner,
    DeliveryTracker,
    DirectMailboxService,
    LogNotifier,
    QuarantineDigestGenerator,
    QuarantineStore,
    RelayError,
    RetroactiveZapEngine,
    SMTPRelay,
    UserReportHandler,
    WebhookNotifier,
    deliver,
)
from admin_ui import DashboardAnalyticsEngine, SafeEmailPreviewRenderer, render_admin_dashboard_html
from identity import IdentityAuthManager, InvalidTokenError
from observability import PrometheusMetricsRegistry, QuotaTracker, SLOCalculator, TracingManager
from scalability import AsyncMessageQueue, GlobalHTTPClientPool, IndexedDatabaseQuarantineStore
from threat_intel import CampaignTracker, CrossTenantIOCSharer, CTLogMonitor, IOCFeedManager, MISPIntegrationClient, NRDWatchlistEngine, STIXTAXIIClient
from multi_tenancy import MSPAdminView, TenantIsolatedQuarantine, TenantManager, TenantRateLimiter
from security import AWSSNSAuthStrategy, MailgunAuthStrategy, RateLimitExceeded, RateLimiter, RawMailCipher, SendGridAuthStrategy, WebhookAuthError, is_bounce_or_ndr, verify_secret, verify_source_ip
from storage import InMemoryStore, RedisStore
from webhook_receiver.parsers import (
    parse_aws_ses_payload,
    parse_google_workspace_payload,
    parse_m365_graph_payload,
    parse_mailgun_payload,
    parse_postmark_payload,
    parse_sendgrid_payload,
)

logger = logging.getLogger("email_gateway")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


@asynccontextmanager
async def _lifespan(app: FastAPI):
    await _startup_checks()
    yield


app = FastAPI(title="email-auth-gateway", lifespan=_lifespan)

# --- Shared, process-wide dependencies --------------------------------------
_store = RedisStore(redis_url=settings.redis_url) if settings.use_redis else InMemoryStore()
_rate_limiter = RateLimiter(_store, max_requests=settings.rate_limit_max_requests, window_seconds=settings.rate_limit_window_seconds)
_admin_rate_limiter = RateLimiter(_store, max_requests=settings.admin_rate_limit_max_requests, window_seconds=60)
_cipher = RawMailCipher(key=settings.raw_mail_encryption_key)
_audit_logger = AuditLogger(settings.audit_log_path)

_domain_age_provider = CachedDomainAgeProvider(RDAPDomainAgeProvider(), _store, ttl_seconds=settings.domain_age_cache_ttl_seconds)
_url_reputation_provider = CachedReputationProvider(
    VirusTotalProvider(api_key=settings.vt_api_key) if settings.vt_api_key
    else (GoogleSafeBrowsingProvider(api_key=settings.gsb_api_key) if settings.gsb_api_key else NullReputationProvider()),
    _store,
    ttl_seconds=settings.reputation_cache_ttl_seconds,
)
_file_reputation_provider = VirusTotalFileProvider(api_key=settings.vt_api_key) if settings.vt_api_key else NullFileReputationProvider()
_clamav = ClamAVScanner(host=settings.clamd_host, port=settings.clamd_port)

_relay = (
    SMTPRelay(
        host=settings.relay_host, port=settings.relay_port, use_tls=settings.relay_use_tls,
        start_tls=settings.relay_start_tls, username=settings.relay_username, password=settings.relay_password,
    )
    if settings.relay_host else None
)
_quarantine_store = QuarantineStore(settings.quarantine_dir, cipher=_cipher)
_notifier = (
    WebhookNotifier(webhook_url=settings.quarantine_notify_webhook_url)
    if settings.quarantine_notify_webhook_url else LogNotifier()
)

_tenant_config_store = TenantConfigStore()
_vip_policy_engine = VIPPolicyEngine()
_feedback_loop = FeedbackLoopEngine()
_campaign_cluster_engine = CampaignClusterEngine()
_shadow_mode_engine = ShadowModeEngine()
_mailbox_service = DirectMailboxService()
_zap_engine = RetroactiveZapEngine(mailbox_service=_mailbox_service)
_user_report_handler = UserReportHandler(feedback_loop=_feedback_loop, zap_engine=_zap_engine)
_digest_generator = QuarantineDigestGenerator(quarantine_store=_quarantine_store, secret_key=settings.webhook_shared_secret or "digest_key")
_dlp_scanner = DLPScanner()
_delivery_tracker = DeliveryTracker()
_tenant_manager = TenantManager()
_tenant_quarantine = TenantIsolatedQuarantine(base_quarantine_dir=settings.quarantine_dir, tenant_manager=_tenant_manager)
_tenant_rate_limiter = TenantRateLimiter(fallback_rate_limiter=_rate_limiter)
_msp_view = MSPAdminView(tenant_manager=_tenant_manager, isolated_quarantine=_tenant_quarantine)
_identity_manager = IdentityAuthManager(secret_key=settings.admin_shared_secret or settings.webhook_shared_secret or "identity_secret_key")
_analytics_engine = DashboardAnalyticsEngine(quarantine_store=_quarantine_store, tenant_manager=_tenant_manager)
_ioc_feed_manager = IOCFeedManager()
_stix_taxii_client = STIXTAXIIClient(feed_manager=_ioc_feed_manager)
_misp_client = MISPIntegrationClient(feed_manager=_ioc_feed_manager)
_cross_tenant_sharer = CrossTenantIOCSharer()
_ct_monitor = CTLogMonitor()
_nrd_engine = NRDWatchlistEngine()
_campaign_tracker = CampaignTracker()
_metrics_registry = PrometheusMetricsRegistry()
_tracing_manager = TracingManager()
_slo_calculator = SLOCalculator()
_quota_tracker = QuotaTracker()
_async_queue = AsyncMessageQueue()
_db_quarantine_store = IndexedDatabaseQuarantineStore()


async def _startup_checks() -> None:
    if not settings.webhook_shared_secret:
        logger.warning(
            "=" * 70 + "\n"
            "WEBHOOK_SHARED_SECRET is not set -- the inbound webhook is "
            "running UNAUTHENTICATED. Set WEBHOOK_SHARED_SECRET before exposing "
            "this to the internet.\n" + "=" * 70
        )
    if not settings.raw_mail_encryption_key:
        logger.warning("RAW_MAIL_ENCRYPTION_KEY is not set -- stored raw mail is UNENCRYPTED on disk.")
    if not settings.relay_host:
        logger.warning("RELAY_HOST is not set -- running in DRY-RUN delivery mode: decisions are computed but nothing is actually relayed.")
    if not settings.admin_shared_secret:
        logger.warning("ADMIN_SHARED_SECRET is not set -- /admin/* endpoints are running UNAUTHENTICATED.")
    if settings.enable_tag_only_mode:
        logger.info("TAG-ONLY MODE IS ENABLED -- messages will be tagged with X-Gateway-Verdict headers instead of modified/quarantined.")
    if settings.use_redis:
        ok = await _store.ping()
        logger.info("Redis connectivity check: %s", "ok" if ok else "FAILED")



def _client_ip(request: Request) -> str:
    # The direct TCP peer, not a spoofable header like X-Forwarded-For --
    # if this sits behind a reverse proxy, configure the proxy to connect
    # to this app directly on an internal network and terminate TLS there,
    # rather than trusting a forwarded-for header from arbitrary clients.
    return request.client.host if request.client else "0.0.0.0"


async def process_message(
    message_id: str,
    raw_message: bytes,
    client_ip: str,
    envelope_from: str,
    envelope_to: list[str] | None = None,
    text_body: str = "",
    html_body: str = "",
    from_header: str = "",
    reply_to_header: str = "",
    watchlist: list[str] | None = None,
    vip_display_names: list[str] | None = None,
    tenant_id: str = "default",
) -> dict:
    """The provider-agnostic core: run every analysis stage, combine into
    a routing decision, persist raw mail (encrypted), act on the decision
    (relay / relay-modified / quarantine / tag-only), and record an audit entry."""
    t0 = time.monotonic()
    envelope_to = envelope_to or []
    message_hash = hashlib.sha256(raw_message).hexdigest()

    # Bounce & NDR Loop Prevention
    is_bounce, bounce_reason = is_bounce_or_ndr(envelope_from, from_header)
    if is_bounce:
        logger.info("message_id=%s skipped bounce/NDR processing: %s", message_id, bounce_reason)
        return {"message_id": message_id, "action": "skipped_bounce", "detail": bounce_reason}

    # Idempotency
    dedupe_key = f"dedupe:{message_hash}"
    is_new = await _store.set_if_not_exists(dedupe_key, message_id, ttl_seconds=settings.dedupe_ttl_seconds)
    if not is_new:
        logger.info("message_hash=%s duplicate delivery, skipping reprocessing", message_hash[:16])
        return {"message_id": message_id, "duplicate": True, "action": "skipped_duplicate"}

    _store_raw_message(message_id, raw_message)

    auth_verdict = run_auth_checks(raw_message, client_ip=client_ip, envelope_from=envelope_from)
    content_verdict = await analyze_content(
        text=text_body, html=html_body, from_header=from_header, reply_to_header=reply_to_header,
        watchlist=watchlist or [], vip_display_names=vip_display_names or settings.vip_display_names,
        domain_age_provider=_domain_age_provider, reputation_provider=_url_reputation_provider,
    )
    attachments = extract_attachments(raw_message)
    attachment_verdict = await analyze_attachments(
        attachments,
        max_attachments=settings.max_attachments_analyzed_per_message,
        max_attachment_size_bytes=settings.max_attachment_size_bytes,
        file_reputation_provider=_file_reputation_provider,
        clamav=_clamav,
    )

    # Decision Engine Policy Layers
    tenant_config = _tenant_config_store.get_config(tenant_id)
    vip_result = _vip_policy_engine.evaluate(
        from_header=from_header,
        vip_display_names=vip_display_names or settings.vip_display_names,
        all_reasons=content_verdict.reasons,
    )
    from_domain = envelope_from.split("@")[-1] if "@" in envelope_from else ""
    campaign_result = None
    if text_body.strip() or html_body.strip():
        campaign_result = _campaign_cluster_engine.evaluate_and_register(
            text_body=text_body or html_body,
            subject=from_header,
            from_domain=from_domain,
        )
    feedback_adjustment = _feedback_loop.get_domain_adjustment(from_domain)

    decision = decide(
        [
            StageScore(stage="auth", score_delta=auth_verdict.score_delta, reasons=auth_verdict.reasons),
            StageScore(stage="content", score_delta=content_verdict.score_delta, reasons=content_verdict.reasons),
            StageScore(stage="attachments", score_delta=attachment_verdict.score_delta, reasons=attachment_verdict.reasons),
        ],
        warn_threshold=settings.warn_threshold,
        quarantine_threshold=settings.quarantine_threshold,
        tenant_config=tenant_config,
        vip_result=vip_result,
        campaign_result=campaign_result,
        feedback_adjustment=feedback_adjustment,
        shadow_engine=_shadow_mode_engine if tenant_config.shadow_mode_enabled else None,
        tenant_id=tenant_id,
    )

    delivery_result = await deliver(
        action=decision.action, raw_message=raw_message, message_id=message_id,
        envelope_from=envelope_from, envelope_to=envelope_to,
        total_score=decision.total_score, reasons=decision.all_reasons,
        relay=_relay, quarantine_store=_quarantine_store, notifier=_notifier,
        tag_only=settings.enable_tag_only_mode,
    )

    elapsed_ms = int((time.monotonic() - t0) * 1000)
    logger.info(
        "message_id=%s action=%s outcome=%s score=%d elapsed_ms=%d",
        message_id, decision.action.value, delivery_result.outcome.value, decision.total_score, elapsed_ms,
    )
    await _audit_logger.record(
        message_id=message_id, message_hash=message_hash, envelope_from=envelope_from,
        action=decision.action.value, total_score=decision.total_score,
        reasons=decision.all_reasons + [f"delivery_outcome:{delivery_result.outcome.value}"],
    )

    return {
        "message_id": message_id,
        "message_hash": message_hash,
        "action": decision.action.value,
        "decision": decision.as_dict(),
        "delivery": delivery_result.as_dict(),
        "auth": auth_verdict.as_dict(),
        "content": content_verdict.as_dict(),
        "attachments": attachment_verdict.as_dict(),
    }


def _store_raw_message(message_id: str, raw_bytes: bytes) -> None:
    from pathlib import Path

    log_dir = Path(settings.raw_mail_log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)
    payload = _cipher.encrypt(raw_bytes)
    suffix = ".eml.enc" if _cipher.enabled() else ".eml"
    (log_dir / f"{message_id}{suffix}").write_bytes(payload)


@app.post("/webhooks/sendgrid/inbound/{secret}")
async def sendgrid_inbound(secret: str, request: Request):
    """
    SendGrid Inbound Parse posts multipart/form-data. Key fields used here:
      envelope  - JSON string: {"from": "...", "to": ["..."]}
      from      - visible From: header value
      text/html - body parts
      headers   - raw header block (used to recover client IP if present)
    """
    client_ip = _client_ip(request)

    try:
        verify_secret(secret, settings.webhook_shared_secret)
        verify_source_ip(client_ip, settings.webhook_allowed_source_ips)
        await _rate_limiter.check(client_ip)
    except WebhookAuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc))
    except RateLimitExceeded as exc:
        raise HTTPException(status_code=429, detail=str(exc))

    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > settings.max_message_size_bytes:
        raise HTTPException(status_code=413, detail="payload exceeds max_message_size_bytes")

    form = await request.form()
    parsed = parse_sendgrid_payload(dict(form))

    if not parsed.has_raw_mime:
        logger.warning("SendGrid webhook payload missing raw MIME ('email' field). Using reconstructed header fallback which may affect DKIM signature verification.")

    message_id = str(uuid.uuid4())
    source_ip_from_headers = _extract_client_ip_from_headers(parsed.headers_blob)

    result = await process_message(
        message_id=message_id,
        raw_message=parsed.raw_message,
        client_ip=source_ip_from_headers,
        envelope_from=parsed.envelope_from,
        envelope_to=parsed.envelope_to,
        text_body=parsed.text_body,
        html_body=parsed.html_body,
        from_header=parsed.from_header,
        reply_to_header=parsed.reply_to_header,
        watchlist=settings.watchlist_domains,
        vip_display_names=settings.vip_display_names,
    )
    return JSONResponse(result)


@app.post("/webhooks/mailgun/inbound")
async def mailgun_inbound(request: Request):
    """Mailgun Inbound Routes webhook handler with HMAC signature verification."""
    client_ip = _client_ip(request)

    try:
        verify_source_ip(client_ip, settings.webhook_allowed_source_ips)
        await _rate_limiter.check(client_ip)
    except WebhookAuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc))
    except RateLimitExceeded as exc:
        raise HTTPException(status_code=429, detail=str(exc))

    form = await request.form()
    form_dict = dict(form)

    # Optional Mailgun HMAC signature verification
    timestamp = str(form_dict.get("timestamp", ""))
    token = str(form_dict.get("token", ""))
    signature = str(form_dict.get("signature", ""))
    signing_key = getattr(settings, "mailgun_signing_key", "")

    if signing_key:
        try:
            MailgunAuthStrategy().verify_signature(timestamp, token, signature, signing_key)
        except WebhookAuthError as exc:
            raise HTTPException(status_code=exc.status_code, detail=str(exc))

    parsed = parse_mailgun_payload(form_dict)
    message_id = str(uuid.uuid4())
    source_ip_from_headers = _extract_client_ip_from_headers(parsed.headers_blob)

    result = await process_message(
        message_id=message_id,
        raw_message=parsed.raw_message,
        client_ip=source_ip_from_headers,
        envelope_from=parsed.envelope_from,
        envelope_to=parsed.envelope_to,
        text_body=parsed.text_body,
        html_body=parsed.html_body,
        from_header=parsed.from_header,
        reply_to_header=parsed.reply_to_header,
        watchlist=settings.watchlist_domains,
        vip_display_names=settings.vip_display_names,
    )
    return JSONResponse(result)


@app.post("/webhooks/aws/ses")
async def aws_ses_inbound(request: Request):
    """AWS SES Inbound notification handler via SNS."""
    client_ip = _client_ip(request)

    try:
        verify_source_ip(client_ip, settings.webhook_allowed_source_ips)
        await _rate_limiter.check(client_ip)
    except WebhookAuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc))
    except RateLimitExceeded as exc:
        raise HTTPException(status_code=429, detail=str(exc))

    try:
        body_json = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid SNS JSON payload")

    try:
        AWSSNSAuthStrategy().verify_sns_message(body_json)
    except WebhookAuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc))

    parsed = parse_aws_ses_payload(body_json)
    message_id = str(uuid.uuid4())

    result = await process_message(
        message_id=message_id,
        raw_message=parsed.raw_message,
        client_ip=client_ip,
        envelope_from=parsed.envelope_from,
        envelope_to=parsed.envelope_to,
        text_body=parsed.text_body,
        html_body=parsed.html_body,
        from_header=parsed.from_header,
        reply_to_header=parsed.reply_to_header,
        watchlist=settings.watchlist_domains,
        vip_display_names=settings.vip_display_names,
    )
    return JSONResponse(result)


@app.post("/webhooks/postmark/inbound")
async def postmark_inbound(request: Request):
    """Postmark Inbound Email Webhook handler."""
    client_ip = _client_ip(request)

    try:
        verify_source_ip(client_ip, settings.webhook_allowed_source_ips)
        await _rate_limiter.check(client_ip)
    except WebhookAuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc))
    except RateLimitExceeded as exc:
        raise HTTPException(status_code=429, detail=str(exc))

    try:
        body_json = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid Postmark JSON payload")

    parsed = parse_postmark_payload(body_json)
    message_id = str(uuid.uuid4())
    source_ip_from_headers = _extract_client_ip_from_headers(parsed.headers_blob)

    result = await process_message(
        message_id=message_id,
        raw_message=parsed.raw_message,
        client_ip=source_ip_from_headers,
        envelope_from=parsed.envelope_from,
        envelope_to=parsed.envelope_to,
        text_body=parsed.text_body,
        html_body=parsed.html_body,
        from_header=parsed.from_header,
        reply_to_header=parsed.reply_to_header,
        watchlist=settings.watchlist_domains,
        vip_display_names=settings.vip_display_names,
    )
    return JSONResponse(result)


@app.post("/webhooks/m365/graph")
async def m365_graph_inbound(request: Request):
    """Microsoft 365 Exchange Online Graph API notification handler."""
    client_ip = _client_ip(request)

    try:
        verify_source_ip(client_ip, settings.webhook_allowed_source_ips)
        await _rate_limiter.check(client_ip)
    except WebhookAuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc))
    except RateLimitExceeded as exc:
        raise HTTPException(status_code=429, detail=str(exc))

    # Graph webhooks send validationToken query parameter on subscription setup
    validation_token = request.query_params.get("validationToken")
    if validation_token:
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse(validation_token, status_code=200)

    try:
        body_json = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid M365 Graph JSON payload")

    parsed = parse_m365_graph_payload(body_json)
    message_id = str(uuid.uuid4())

    result = await process_message(
        message_id=message_id,
        raw_message=parsed.raw_message,
        client_ip=client_ip,
        envelope_from=parsed.envelope_from,
        envelope_to=parsed.envelope_to,
        text_body=parsed.text_body,
        html_body=parsed.html_body,
        from_header=parsed.from_header,
        reply_to_header=parsed.reply_to_header,
        watchlist=settings.watchlist_domains,
        vip_display_names=settings.vip_display_names,
    )
    return JSONResponse(result)


@app.post("/webhooks/google/pubsub")
async def google_pubsub_inbound(request: Request):
    """Google Workspace / Gmail Pub/Sub push notification handler."""
    client_ip = _client_ip(request)

    try:
        verify_source_ip(client_ip, settings.webhook_allowed_source_ips)
        await _rate_limiter.check(client_ip)
    except WebhookAuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc))
    except RateLimitExceeded as exc:
        raise HTTPException(status_code=429, detail=str(exc))

    try:
        body_json = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid Google Pub/Sub JSON payload")

    parsed = parse_google_workspace_payload(body_json)
    message_id = str(uuid.uuid4())

    result = await process_message(
        message_id=message_id,
        raw_message=parsed.raw_message,
        client_ip=client_ip,
        envelope_from=parsed.envelope_from,
        envelope_to=parsed.envelope_to,
        text_body=parsed.text_body,
        html_body=parsed.html_body,
        from_header=parsed.from_header,
        reply_to_header=parsed.reply_to_header,
        watchlist=settings.watchlist_domains,
        vip_display_names=settings.vip_display_names,
    )
    return JSONResponse(result)




def _extract_client_ip_from_headers(headers_blob: str) -> str:
    import re

    match = re.search(r"Received:.*?\[(\d{1,3}(?:\.\d{1,3}){3})\]", headers_blob, re.DOTALL)
    return match.group(1) if match else "0.0.0.0"


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.get("/readyz")
async def readyz():
    checks = {"store": True}
    if settings.use_redis:
        checks["redis"] = await _store.ping()
    checks["clamav_configured"] = _clamav.enabled()
    checks["relay_configured"] = _relay is not None
    healthy = all(v is not False for v in checks.values())
    status_code = 200 if healthy else 503
    return JSONResponse({"status": "ready" if healthy else "not_ready", "checks": checks}, status_code=status_code)


async def _verify_admin(request: Request, required_role: Optional[str] = None, required_scope: Optional[str] = None) -> Dict[str, Any]:
    client_ip = _client_ip(request)
    try:
        await _admin_rate_limiter.check(client_ip)
    except RateLimitExceeded as exc:
        raise HTTPException(status_code=429, detail=str(exc))

    auth_header = request.headers.get("authorization", "")
    try:
        payload = _identity_manager.verify_request(
            auth_header=auth_header,
            fallback_secret=settings.admin_shared_secret,
            required_role=required_role,
            required_scope=required_scope,
        )
        return payload
    except InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail=str(exc))
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))


@app.get("/admin/quarantine")
async def list_quarantine(request: Request):
    await _verify_admin(request)
    return {"pending": [r.as_dict() for r in _quarantine_store.list_pending()]}


@app.get("/admin/quarantine/{quarantine_id}")
async def get_quarantine_item(quarantine_id: str, request: Request):
    await _verify_admin(request)
    record = _quarantine_store.get_record(quarantine_id)
    if record is None:
        raise HTTPException(status_code=404, detail="no such quarantine item")
    return record.as_dict()


@app.post("/admin/quarantine/{quarantine_id}/release")
async def release_quarantine_item(quarantine_id: str, request: Request):
    await _verify_admin(request)
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    resolved_by = body.get("resolved_by", "admin")
    note = body.get("note", "")

    record = await _quarantine_store.release(quarantine_id, resolved_by=resolved_by, note=note)
    if record is None:
        raise HTTPException(status_code=404, detail="no such quarantine item")

    _feedback_loop.record_feedback(quarantine_id, record.envelope_from, action="release", note=note)
    await _audit_logger.record_admin_action(operator=resolved_by, action="release", target_id=quarantine_id, note=note)

    raw_message = _quarantine_store.get_raw_message(quarantine_id)
    if raw_message is None:
        raise HTTPException(status_code=500, detail="quarantine metadata found but message content missing")

    if _relay is None:
        return {"status": "released", "relayed": False, "detail": "dry-run mode: RELAY_HOST not configured, message was not actually sent"}
    try:
        await _relay.send(raw_message, mail_from=record.envelope_from, rcpt_to=record.envelope_to)
    except RelayError as exc:
        raise HTTPException(status_code=502, detail=f"released but relay failed: {exc}")
    return {"status": "released", "relayed": True}


@app.post("/admin/quarantine/{quarantine_id}/reject")
async def reject_quarantine_item(quarantine_id: str, request: Request):
    await _verify_admin(request)
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    resolved_by = body.get("resolved_by", "admin")
    note = body.get("note", "")

    record = await _quarantine_store.reject(quarantine_id, resolved_by=resolved_by, note=note)
    if record is None:
        raise HTTPException(status_code=404, detail="no such quarantine item")

    _feedback_loop.record_feedback(quarantine_id, record.envelope_from, action="reject", note=note)
    await _audit_logger.record_admin_action(operator=resolved_by, action="reject", target_id=quarantine_id, note=note)

    return {"status": "rejected"}


@app.get("/toc/redirect")
async def time_of_click_redirect(url: str, sig: str):
    is_valid, target_url = _toc_service.decode_and_verify(url, sig)
    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid or tampered Time-of-Click redirect link")

    is_safe, reason = await _toc_service.evaluate_click(target_url)
    if not is_safe:
        from fastapi.responses import HTMLResponse
        html_warning = f"""
        <html>
            <head><title>Security Warning - Blocked Link</title></head>
            <body style="font-family: sans-serif; text-align: center; padding: 50px; background-color: #f8d7da; color: #721c24;">
                <h1>⚠️ Security Warning: Dangerous Link Blocked</h1>
                <p>The link you clicked has been identified as malicious or unsafe by Email Security Gateway.</p>
                <p><strong>Reason:</strong> {reason}</p>
                <p><strong>Target URL:</strong> <code>{target_url}</code></p>
            </body>
        </html>
        """
        return HTMLResponse(content=html_warning, status_code=403)

    from fastapi.responses import RedirectResponse
    return RedirectResponse(url=target_url, status_code=307)


@app.post("/api/v1/report-phish")
async def report_phish_endpoint(request: Request):
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    reporter = body.get("reporter_email", "")
    message_id = body.get("message_id", "")
    if not reporter or not message_id:
        raise HTTPException(status_code=400, detail="reporter_email and message_id are required")

    res = await _user_report_handler.process_report(
        reporter_email=reporter,
        message_id=message_id,
        sender=body.get("sender", ""),
        subject=body.get("subject", ""),
        body=body.get("body", ""),
        trigger_auto_zap=body.get("trigger_auto_zap", True),
    )
    return res


@app.post("/admin/zap")
async def admin_zap_endpoint(request: Request):
    await _verify_admin(request)
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    url = body.get("url")
    file_hash = body.get("file_hash")
    message_id = body.get("message_id")
    reason = body.get("reason", "Admin retroactive removal request")

    if url:
        zapped = await _zap_engine.trigger_zap_by_url(url, reason=reason)
        return {"status": "success", "mode": "by_url", "zapped_count": len(zapped), "zapped_message_ids": zapped}
    elif file_hash:
        zapped = await _zap_engine.trigger_zap_by_hash(file_hash, reason=reason)
        return {"status": "success", "mode": "by_hash", "zapped_count": len(zapped), "zapped_message_ids": zapped}
    elif message_id:
        ok = await _zap_engine.trigger_zap_by_message_id(message_id, reason=reason)
        return {"status": "success" if ok else "failed", "mode": "by_message_id", "zapped_message_id": message_id}
    else:
        raise HTTPException(status_code=400, detail="Must provide url, file_hash, or message_id to zap")


@app.post("/admin/digest/send")
async def send_quarantine_digest(request: Request):
    await _verify_admin(request)
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    recipient = body.get("recipient_email")
    if not recipient:
        raise HTTPException(status_code=400, detail="recipient_email is required")

    digest = _digest_generator.build_digest_for_recipient(recipient)
    return digest


@app.get("/admin/tenants")
async def list_tenants(request: Request):
    await _verify_admin(request)
    return [t.to_dict() for t in _tenant_manager.list_tenants()]


@app.post("/admin/tenants")
async def create_tenant(request: Request):
    await _verify_admin(request)
    body = await request.json()
    tenant_id = body.get("tenant_id")
    name = body.get("name")
    if not tenant_id or not name:
        raise HTTPException(status_code=400, detail="tenant_id and name are required")

    try:
        tenant = _tenant_manager.create_tenant(
            tenant_id=tenant_id,
            name=name,
            domains=body.get("domains"),
            encryption_key=body.get("encryption_key"),
            warn_threshold=body.get("warn_threshold", 40),
            quarantine_threshold=body.get("quarantine_threshold", 70),
            max_requests_per_minute=body.get("max_requests_per_minute", 500),
            vt_api_key=body.get("vt_api_key"),
            gsb_api_key=body.get("gsb_api_key"),
        )
        return tenant.to_dict()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/admin/tenants/{tenant_id}")
async def get_tenant(tenant_id: str, request: Request):
    await _verify_admin(request)
    tenant = _tenant_manager.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant.to_dict()


@app.put("/admin/tenants/{tenant_id}")
async def update_tenant(tenant_id: str, request: Request):
    await _verify_admin(request)
    body = await request.json()
    try:
        tenant = _tenant_manager.update_tenant(tenant_id, **body)
        return tenant.to_dict()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.delete("/admin/tenants/{tenant_id}")
async def deprovision_tenant(tenant_id: str, request: Request):
    await _verify_admin(request)
    purge = request.query_params.get("purge_data", "true").lower() == "true"
    ok = _tenant_manager.deprovision_tenant(tenant_id, purge_data=purge, storage_base_dir=settings.quarantine_dir)
    if not ok:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return {"status": "deprovisioned", "tenant_id": tenant_id, "data_purged": purge}


@app.get("/admin/msp/dashboard")
async def get_msp_dashboard(request: Request):
    await _verify_admin(request)
    return _msp_view.generate_dashboard_summary()


@app.post("/admin/auth/login")
async def login(request: Request):
    body = await request.json()
    username = body.get("username")
    password = body.get("password")
    totp_code = body.get("totp_code")

    if not username or not password:
        raise HTTPException(status_code=400, detail="username and password are required")

    try:
        return _identity_manager.login(username, password, totp_code=totp_code)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc))


@app.post("/admin/auth/refresh")
async def refresh_token(request: Request):
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=400, detail="Bearer authorization header required")

    token = auth_header.split(" ", 1)[1].strip()
    try:
        new_token = _identity_manager.token_manager.refresh_session_token(token)
        return {"access_token": new_token, "token_type": "Bearer"}
    except Exception as exc:
        raise HTTPException(status_code=401, detail=str(exc))


@app.post("/admin/auth/sso/callback")
async def sso_callback(request: Request):
    body = await request.json()
    claims = body.get("claims")
    if not claims:
        raise HTTPException(status_code=400, detail="OIDC claims payload required")

    try:
        user = _identity_manager.oidc_provider.authenticate_oidc_claims(claims)
        token = _identity_manager.token_manager.create_session_token(
            user_id=user.user_id,
            username=user.username,
            role=user.role,
            tenant_id=user.tenant_id,
            mfa_verified=True,
            scopes=user.scopes,
        )
        return {"status": "authenticated", "access_token": token, "token_type": "Bearer", "user": user.to_dict()}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/admin/users")
async def list_users(request: Request):
    await _verify_admin(request, required_role="admin", required_scope="user:manage")
    return [u.to_dict() for u in _identity_manager.user_manager.list_users()]


@app.post("/admin/users")
async def create_user(request: Request):
    await _verify_admin(request, required_role="admin", required_scope="user:manage")
    body = await request.json()
    username = body.get("username")
    password = body.get("password")
    role = body.get("role", "analyst")
    mfa_enabled = body.get("mfa_enabled", False)

    if not username or not password:
        raise HTTPException(status_code=400, detail="username and password are required")

    try:
        user = _identity_manager.user_manager.create_user(
            username=username,
            password=password,
            role=role,
            tenant_id=body.get("tenant_id"),
            mfa_enabled=mfa_enabled,
            scopes=body.get("scopes"),
        )
        res = user.to_dict()
        if user.mfa_secret:
            res["mfa_secret"] = user.mfa_secret
        return res
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.delete("/admin/users/{username}")
async def delete_user(username: str, request: Request):
    await _verify_admin(request, required_role="admin", required_scope="user:manage")
    ok = _identity_manager.user_manager.delete_user(username)
    if not ok:
        raise HTTPException(status_code=404, detail="User not found")
    return {"status": "deleted", "username": username}


@app.get("/dashboard", response_class=HTMLResponse)
@app.get("/admin/ui", response_class=HTMLResponse)
async def get_admin_dashboard_page():
    return HTMLResponse(content=render_admin_dashboard_html(), status_code=200)


@app.get("/admin/ui/api/analytics")
async def get_ui_analytics(request: Request):
    await _verify_admin(request)
    return _analytics_engine.get_summary_metrics()


@app.get("/admin/ui/api/preview/{quarantine_id}")
async def get_ui_preview(quarantine_id: str, request: Request):
    await _verify_admin(request)
    record = _quarantine_store.get_record(quarantine_id)
    if not record:
        raise HTTPException(status_code=404, detail="Quarantine record not found")

    raw = _quarantine_store.get_raw_message(quarantine_id)
    if not raw:
        return {"html": "<em>[Raw message missing]</em>", "text": ""}

    raw_str = raw.decode("utf-8", errors="replace")
    if "<html" in raw_str.lower() or "<body" in raw_str.lower() or "<div>" in raw_str.lower():
        safe_html = SafeEmailPreviewRenderer.sanitize_html(raw_str)
        return {"html": safe_html, "text": ""}
    else:
        safe_text = SafeEmailPreviewRenderer.render_plain_text(raw_str)
        return {"html": safe_text, "text": raw_str}


@app.post("/admin/ui/api/bulk-action")
async def bulk_quarantine_action(request: Request):
    await _verify_admin(request, required_scope="quarantine:write")
    body = await request.json()
    action = body.get("action")
    ids = body.get("quarantine_ids", [])
    note = body.get("note", "Bulk action via Admin UI")

    if action not in ("release", "reject") or not ids:
        raise HTTPException(status_code=400, detail="Valid action ('release' or 'reject') and quarantine_ids list required")

    processed = []
    for q_id in ids:
        if action == "release":
            res = await _quarantine_store.release(q_id, resolved_by="admin_ui", note=note)
        else:
            res = await _quarantine_store.reject(q_id, resolved_by="admin_ui", note=note)
        if res:
            processed.append(q_id)

    return {"status": "success", "action": action, "processed_count": len(processed), "processed_ids": processed}


@app.get("/metrics", response_class=PlainTextResponse)
async def get_prometheus_metrics():
    """Prometheus scrape endpoint."""
    return PlainTextResponse(content=_metrics_registry.generate_prometheus_text(), media_type="text/plain; version=0.0.4")


@app.get("/admin/slo")
async def get_slo_metrics(request: Request):
    await _verify_admin(request)
    return _slo_calculator.calculate_slo_metrics(window_hours=1.0)


