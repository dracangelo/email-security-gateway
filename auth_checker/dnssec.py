"""
DNSSEC validation for authentication DNS lookups.
Configures EDNS0 DO (DNSSEC OK) flag and inspects AD (Authenticated Data) response flags.
"""
from __future__ import annotations

import logging
import dns.flags
import dns.resolver
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class DNSSECResult:
    is_secure: bool
    explanation: str = ""


def create_dnssec_resolver(nameservers: list[str] | None = None) -> dns.resolver.Resolver:
    """Create a dnspython Resolver configured with EDNS0 and DNSSEC OK (DO) flags."""
    resolver = dns.resolver.Resolver()
    if nameservers:
        resolver.nameservers = nameservers
    resolver.use_edns(0, ednsflags=dns.flags.DO)
    return resolver


def is_dnssec_authenticated(answer: dns.resolver.Answer) -> bool:
    """Check if the DNS response header contains the AD (Authenticated Data) flag."""
    if not answer or not hasattr(answer, "response") or not answer.response:
        return False
    return bool(answer.response.flags & dns.flags.AD)


def resolve_with_dnssec(
    domain: str,
    qtype: str = "TXT",
    resolver: dns.resolver.Resolver | None = None,
) -> tuple[list[str], DNSSECResult]:
    """
    Perform a DNS query with DNSSEC inspection.
    """
    resolver = resolver or create_dnssec_resolver()
    try:
        answers = resolver.resolve(domain, qtype, lifetime=5.0)
        is_secure = is_dnssec_authenticated(answers)
        records = [str(rdata) for rdata in answers]
        explanation = "DNSSEC validated (AD flag set)" if is_secure else "DNSSEC not enforced by resolver (no AD flag)"
        return records, DNSSECResult(is_secure=is_secure, explanation=explanation)
    except Exception as exc:
        return [], DNSSECResult(is_secure=False, explanation=f"DNS query error: {exc}")
