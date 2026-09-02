"""
FCrDNS (Forward-Confirmed Reverse DNS) consistency check.
Verifies connecting IP has a valid PTR record that resolves forward to the same IP.
"""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from enum import Enum
import dns.resolver
import dns.reversename

logger = logging.getLogger(__name__)


class FCrDNSResultCode(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NONE = "none"


@dataclass
class FCrDNSResult:
    code: FCrDNSResultCode
    is_confirmed: bool = False
    ptr_hostname: str = ""
    explanation: str = ""


def check_fcrdns(client_ip: str, resolver: dns.resolver.Resolver | None = None) -> FCrDNSResult:
    """
    Perform Forward-Confirmed Reverse DNS check for connecting IP address.
    """
    if not client_ip or client_ip in ("127.0.0.1", "0.0.0.0", "::1"):
        return FCrDNSResult(
            code=FCrDNSResultCode.PASS,
            is_confirmed=True,
            ptr_hostname="localhost",
            explanation="Loopback/internal IP skipped FCrDNS",
        )

    resolver = resolver or dns.resolver.Resolver()
    try:
        rev_name = dns.reversename.from_address(client_ip)
        ptr_answers = resolver.resolve(rev_name, "PTR", lifetime=5.0)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return FCrDNSResult(code=FCrDNSResultCode.NONE, explanation=f"No PTR record for {client_ip}")
    except Exception as exc:
        return FCrDNSResult(code=FCrDNSResultCode.NONE, explanation=f"PTR lookup error for {client_ip}: {exc}")

    is_ipv6 = ":" in client_ip
    rtype = "AAAA" if is_ipv6 else "A"

    for rdata in ptr_answers:
        hostname = str(rdata.target).rstrip(".")
        try:
            fwd_answers = resolver.resolve(hostname, rtype, lifetime=5.0)
            if any(str(a) == client_ip for a in fwd_answers):
                return FCrDNSResult(
                    code=FCrDNSResultCode.PASS,
                    is_confirmed=True,
                    ptr_hostname=hostname,
                    explanation=f"FCrDNS pass: {client_ip} <-> {hostname}",
                )
        except Exception:
            continue

    first_ptr = str(ptr_answers[0].target).rstrip(".") if ptr_answers else ""
    return FCrDNSResult(
        code=FCrDNSResultCode.FAIL,
        is_confirmed=False,
        ptr_hostname=first_ptr,
        explanation=f"FCrDNS mismatch: PTR {first_ptr} does not resolve forward to {client_ip}",
    )
