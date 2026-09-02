"""
Allow-list and Block-list policy engine.
Provides override precedence over computed heuristic scores.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress


@dataclass
class AllowBlockResult:
    is_allowed: bool = False
    is_blocked: bool = False
    reason: str = ""


class AllowBlockEngine:
    def __init__(
        self,
        allow_domains: list[str] | None = None,
        allow_emails: list[str] | None = None,
        allow_ips: list[str] | None = None,
        block_domains: list[str] | None = None,
        block_emails: list[str] | None = None,
        block_ips: list[str] | None = None,
    ):
        self.allow_domains = {d.lower().strip() for d in (allow_domains or []) if d}
        self.allow_emails = {e.lower().strip() for e in (allow_emails or []) if e}
        self.allow_ips = {ip.strip() for ip in (allow_ips or []) if ip}

        self.block_domains = {d.lower().strip() for d in (block_domains or []) if d}
        self.block_emails = {e.lower().strip() for e in (block_emails or []) if e}
        self.block_ips = {ip.strip() for ip in (block_ips or []) if ip}

    def evaluate(self, envelope_from: str = "", client_ip: str = "", from_header: str = "") -> AllowBlockResult:
        # Extract emails & domains
        envelope_from_clean = envelope_from.lower().strip()
        env_domain = envelope_from_clean.split("@")[-1] if "@" in envelope_from_clean else ""

        header_email = ""
        header_domain = ""
        if from_header:
            import re
            match = re.search(r"[\w\.-]+@[\w\.-]+", from_header)
            if match:
                header_email = match.group(0).lower().strip()
                header_domain = header_email.split("@")[-1]

        # Check Block-list first (Blocklist precedence)
        if envelope_from_clean and envelope_from_clean in self.block_emails:
            return AllowBlockResult(is_blocked=True, reason=f"envelope-from '{envelope_from}' is in blocklist")

        if header_email and header_email in self.block_emails:
            return AllowBlockResult(is_blocked=True, reason=f"From-header email '{header_email}' is in blocklist")

        if env_domain and env_domain in self.block_domains:
            return AllowBlockResult(is_blocked=True, reason=f"domain '{env_domain}' is in blocklist")

        if header_domain and header_domain in self.block_domains:
            return AllowBlockResult(is_blocked=True, reason=f"From-header domain '{header_domain}' is in blocklist")

        if client_ip and self._ip_matches(client_ip, self.block_ips):
            return AllowBlockResult(is_blocked=True, reason=f"client IP '{client_ip}' is in blocklist")

        # Check Allow-list
        if envelope_from_clean and envelope_from_clean in self.allow_emails:
            return AllowBlockResult(is_allowed=True, reason=f"envelope-from '{envelope_from}' is in allowlist")

        if header_email and header_email in self.allow_emails:
            return AllowBlockResult(is_allowed=True, reason=f"From-header email '{header_email}' is in allowlist")

        if env_domain and env_domain in self.allow_domains:
            return AllowBlockResult(is_allowed=True, reason=f"domain '{env_domain}' is in allowlist")

        if header_domain and header_domain in self.allow_domains:
            return AllowBlockResult(is_allowed=True, reason=f"From-header domain '{header_domain}' is in allowlist")

        if client_ip and self._ip_matches(client_ip, self.allow_ips):
            return AllowBlockResult(is_allowed=True, reason=f"client IP '{client_ip}' is in allowlist")

        return AllowBlockResult()

    def _ip_matches(self, client_ip: str, ip_set: set[str]) -> bool:
        if not client_ip or client_ip == "0.0.0.0":
            return False

        try:
            target_ip = ipaddress.ip_address(client_ip)
            for item in ip_set:
                try:
                    if "/" in item:
                        if target_ip in ipaddress.ip_network(item, strict=False):
                            return True
                    else:
                        if target_ip == ipaddress.ip_address(item):
                            return True
                except ValueError:
                    continue
        except ValueError:
            pass

        return False
