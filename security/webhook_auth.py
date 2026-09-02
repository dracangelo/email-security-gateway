"""
SendGrid's Inbound Parse doesn't cryptographically sign its webhook POSTs
the way their separate Event Webhook product does -- so there's no
signature to verify here, and pretending otherwise would be worse than
nothing. The two real defenses available are a shared secret embedded in
the URL path, and (optionally) restricting source IPs to your provider's
published ranges. Both live here.
"""
from __future__ import annotations

import hmac
import ipaddress


class WebhookAuthError(Exception):
    def __init__(self, message: str, status_code: int = 403):
        self.status_code = status_code
        super().__init__(message)


def verify_secret(provided: str, expected: str) -> None:
    """
    Raises WebhookAuthError if `provided` doesn't match `expected`.
    If `expected` is empty, verification is a no-op (unauthenticated mode --
    the caller is responsible for logging a loud warning about that at
    startup, not this function's job).

    Uses hmac.compare_digest for constant-time comparison. A naive
    `provided == expected` short-circuits on the first mismatched
    character, leaking timing information proportional to how much of the
    prefix matched -- a slow but real way to brute-force a secret given
    enough requests and a stable enough network path to measure it over.

    Returns 404 rather than 401/403 on failure so a prober scanning for
    valid paths can't distinguish "wrong secret" from "nothing here" --
    401/403 confirm the endpoint exists, which is exactly the information
    the secret path is trying to keep private in the first place.
    """
    if not expected:
        return
    if not hmac.compare_digest(provided, expected):
        raise WebhookAuthError("invalid webhook secret", status_code=404)


def verify_source_ip(client_ip: str | None, allowed_ranges: list[str]) -> None:
    """
    Raises WebhookAuthError if `client_ip` isn't inside any of
    `allowed_ranges` (CIDR notation, e.g. "192.0.2.0/24"). No-op if
    `allowed_ranges` is empty (allowlist disabled -- the default, since
    provider IP ranges change and hardcoding them here would silently
    break ingestion on rotation without you finding out why).
    """
    if not allowed_ranges:
        return
    if not client_ip:
        raise WebhookAuthError("could not determine client IP", status_code=403)
    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        raise WebhookAuthError(f"invalid client IP: {client_ip!r}", status_code=403)

    for cidr in allowed_ranges:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return
        except ValueError:
            continue  # malformed entry in config -- skip it rather than fail the whole check
    raise WebhookAuthError(f"source IP {client_ip} not in allowlist", status_code=403)
