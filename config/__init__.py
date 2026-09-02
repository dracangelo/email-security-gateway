"""
Centralized configuration. Every module that needs a tunable value or a
secret reads it from here instead of calling os.environ.get() itself --
one source of truth makes it possible to actually see what's configurable,
what the security-relevant defaults are, and where a secret is expected
to come from.

Reads from environment variables and, optionally, a `.env` file (see
`.env.example` in the repo root for the full list with explanations).
"""
from __future__ import annotations

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- Webhook authentication --------------------------------------------
    # SendGrid's Inbound Parse does NOT cryptographically sign its POSTs
    # (unlike their separate Event Webhook product, which does support
    # signing) -- so an unguessable secret as a URL path segment is the
    # primary thing standing between this endpoint and anyone who finds the
    # URL. Generate one with:
    #   python3 -c "import secrets; print(secrets.token_urlsafe(32))"
    # and treat it like any other credential: not in source control, rotated
    # periodically, different per environment.
    webhook_shared_secret: str = Field(default="", description="Required path segment on the inbound webhook URL")

    # Optional defense-in-depth on top of the secret: restrict source IPs to
    # your inbound provider's published ranges. Empty = disabled. Provider
    # ranges change over time, so this is opt-in rather than hardcoded --
    # keep it current from your provider's docs if you turn it on.
    webhook_allowed_source_ips: list[str] = Field(default_factory=list)

    # --- Resource limits (DoS protection) -----------------------------------
    max_message_size_bytes: int = Field(default=25 * 1024 * 1024, description="Reject inbound payloads larger than this")
    max_urls_analyzed_per_message: int = Field(default=25, description="Cap URL reputation/age lookups per message")
    max_attachments_analyzed_per_message: int = Field(default=10)
    max_attachment_size_bytes: int = Field(default=40 * 1024 * 1024, description="Skip hashing/scanning attachments larger than this")
    external_call_timeout_seconds: float = Field(default=8.0)

    # --- Rate limiting (per source IP, fixed window) ------------------------
    rate_limit_max_requests: int = Field(default=120, description="Max webhook requests per window per source IP")
    rate_limit_window_seconds: int = Field(default=60)

    # --- Retry / resilience --------------------------------------------------
    external_call_max_attempts: int = Field(default=3)
    external_call_backoff_base_seconds: float = Field(default=0.25)
    circuit_breaker_failure_threshold: int = Field(default=5)
    circuit_breaker_reset_timeout_seconds: float = Field(default=30.0)

    # --- Caching ---------------------------------------------------------------
    domain_age_cache_ttl_seconds: int = Field(default=6 * 3600, description="RDAP results change slowly; cache generously")
    reputation_cache_ttl_seconds: int = Field(default=1800, description="Reputation can change faster; cache more conservatively")

    # --- Storage / idempotency -------------------------------------------------
    redis_url: str = Field(default="redis://localhost:6379/0")
    use_redis: bool = Field(default=False, description="False = in-memory store (single process only, dev default)")
    dedupe_ttl_seconds: int = Field(default=86400, description="How long a message hash is remembered for webhook-retry dedup")

    # --- Storage / encryption at rest -------------------------------------------
    raw_mail_log_dir: str = Field(default="/tmp/email-gateway-raw")
    # Fernet key (32 url-safe base64-encoded bytes). Generate with:
    #   python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    # Empty = raw .eml files are stored unencrypted -- fine for local dev
    # only. These files routinely contain credentials, PII, and internal
    # infrastructure detail (from the phishing content itself, if nothing
    # else); encrypt at rest for anything real.
    raw_mail_encryption_key: str = Field(default="")

    audit_log_path: str = Field(default="/tmp/email-gateway-audit.jsonl")
    admin_audit_log_path: str = Field(default="/tmp/email-gateway-admin-audit.jsonl")

    # --- Delivery: actually acting on a decision, not just computing it -------
    # Empty relay_host = "dry run" mode: forward/warn_and_strip are decided
    # but never actually sent anywhere. Quarantine works either way (it
    # never needed a relay to begin with).
    relay_host: str = Field(default="", description="Destination SMTP server -- empty disables actual relaying")
    relay_port: int = Field(default=25)
    relay_use_tls: bool = Field(default=False, description="Implicit TLS from connect (SMTPS, typically port 465)")
    relay_start_tls: bool = Field(default=True, description="STARTTLS after connecting on a plaintext port")
    relay_username: str = Field(default="")
    relay_password: str = Field(default="")
    enable_tag_only_mode: bool = Field(default=False, description="True = insert X-Gateway-Verdict headers instead of modifying/quarantining")

    quarantine_dir: str = Field(default="/tmp/email-gateway-quarantine")
    # Slack-compatible incoming webhook URL for quarantine alerts. Empty =
    # falls back to just logging (see delivery/notify.py).
    quarantine_notify_webhook_url: str = Field(default="")

    # Separate from webhook_shared_secret on purpose: that one authenticates
    # your inbound mail PROVIDER (SendGrid); this one authenticates YOUR
    # OWN admin tooling/operators calling the quarantine release/reject
    # endpoints. Different trust boundary, different secret, so rotating
    # or leaking one doesn't affect the other.
    admin_shared_secret: str = Field(default="", description="Required bearer token for /admin/* endpoints")
    admin_rate_limit_max_requests: int = Field(default=60, description="Max admin API requests per window per source IP")

    # --- Decision thresholds -----------------------------------------------------
    warn_threshold: int = Field(default=30)
    quarantine_threshold: int = Field(default=70)

    # --- Content analysis ------------------------------------------------------
    watchlist_domains: list[str] = Field(default_factory=list)
    vip_display_names: list[str] = Field(default_factory=list, description="Protected executive display names to monitor for spoofing")
    vt_api_key: str = Field(default="")
    gsb_api_key: str = Field(default="")
    clamd_host: str = Field(default="", description="Empty disables ClamAV scanning")
    clamd_port: int = Field(default=3310)

    @field_validator("webhook_allowed_source_ips", "watchlist_domains", "vip_display_names", mode="before")

    @classmethod
    def _split_csv(cls, v):
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v

    def require_webhook_secret(self) -> str:
        if not self.webhook_shared_secret:
            raise RuntimeError(
                "WEBHOOK_SHARED_SECRET is not set. Refusing to start with an "
                "unauthenticated inbound webhook -- generate one with "
                "`python3 -c \"import secrets; print(secrets.token_urlsafe(32))\"` "
                "and set it in the environment."
            )
        return self.webhook_shared_secret


settings = Settings()
