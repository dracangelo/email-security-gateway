"""
Connecting IP Reputation & DNSBL Lookup Checker.
Checks connecting SMTP client IP against known IP reputation feeds.
"""
from __future__ import annotations

import socket
from dataclasses import dataclass, field


@dataclass
class IPReputationResult:
    is_listed: bool = False
    reasons: list[str] = field(default_factory=list)
    score_delta: int = 0


def check_connecting_ip_reputation(client_ip: str, dnsbl_zones: list[str] | None = None) -> IPReputationResult:
    result = IPReputationResult()

    if not client_ip or client_ip == "0.0.0.0" or client_ip.startswith("127."):
        return result

    zones = dnsbl_zones or ["zen.spamhaus.org"]
    reversed_ip = ".".join(client_ip.split(".")[::-1])

    for zone in zones:
        lookup_host = f"{reversed_ip}.{zone}"
        try:
            # Short DNS resolution attempt with timeout
            socket.gethostbyname(lookup_host)
            result.is_listed = True
            result.reasons.append(f"connecting IP '{client_ip}' is listed on DNSBL '{zone}'")
            result.score_delta += 40
            break
        except (socket.gaierror, socket.timeout):
            continue

    return result
