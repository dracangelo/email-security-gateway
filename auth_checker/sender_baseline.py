"""
Historical Sender-Domain Baseline tracking.
Tracks domain age/volume history and detects first-contact domains & IP subnet anomalies.
"""
from __future__ import annotations

import ipaddress
import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class SenderBaselineVerdict:
    is_first_contact: bool = False
    is_ip_anomaly: bool = False
    total_messages_seen: int = 0
    score_delta: int = 0
    explanation: str = ""


class SenderBaselineStore:
    """In-memory or persistent store for domain sending history."""

    def __init__(self):
        self._domains: dict[str, dict[str, Any]] = {}

    def get_domain_history(self, domain: str) -> dict[str, Any]:
        return self._domains.get(domain.lower(), {"first_seen": 0, "count": 0, "subnets": set()})

    def record_message(self, domain: str, client_ip: str) -> None:
        domain = domain.lower()
        now = time.time()
        subnet = self._get_subnet(client_ip)

        if domain not in self._domains:
            self._domains[domain] = {
                "first_seen": now,
                "count": 1,
                "subnets": {subnet} if subnet else set(),
            }
        else:
            rec = self._domains[domain]
            rec["count"] += 1
            if subnet:
                rec["subnets"].add(subnet)

    def _get_subnet(self, ip_str: str) -> str:
        try:
            ip = ipaddress.ip_address(ip_str)
            if ip.version == 4:
                network = ipaddress.ip_network(f"{ip_str}/24", strict=False)
            else:
                network = ipaddress.ip_network(f"{ip_str}/48", strict=False)
            return str(network)
        except ValueError:
            return ""


# Shared process baseline store instance
global_baseline_store = SenderBaselineStore()


def evaluate_sender_baseline(
    domain: str,
    client_ip: str,
    store: SenderBaselineStore | None = None,
) -> SenderBaselineVerdict:
    """
    Evaluates domain baseline risk and updates domain history.
    """
    if not domain:
        return SenderBaselineVerdict(explanation="No domain provided for baseline evaluation")

    store = store or global_baseline_store
    domain = domain.lower()
    history = store.get_domain_history(domain)

    is_first_contact = history["count"] == 0
    total_seen = history["count"]
    known_subnets = history.get("subnets", set())
    subnet = store._get_subnet(client_ip)

    is_ip_anomaly = False
    score_delta = 0
    reasons = []

    if is_first_contact:
        score_delta += 10
        reasons.append("First contact domain (no prior sending history)")
    elif total_seen >= 10 and subnet and subnet not in known_subnets:
        is_ip_anomaly = True
        score_delta += 10
        reasons.append(f"Sender IP anomaly: subnet {subnet} not in baseline subnets for {domain}")

    # Record message in history
    store.record_message(domain, client_ip)

    return SenderBaselineVerdict(
        is_first_contact=is_first_contact,
        is_ip_anomaly=is_ip_anomaly,
        total_messages_seen=total_seen + 1,
        score_delta=score_delta,
        explanation="; ".join(reasons) if reasons else "Established sender within baseline parameters",
    )
