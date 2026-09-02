"""
Certificate Transparency (CT) Log Monitoring Engine.
Proactively watches CT logs for newly issued certificates on lookalike/typosquatted brand domains.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Set


class CTLogMonitor:
    def __init__(self, brand_domains: Optional[List[str]] = None):
        self.brand_domains: Set[str] = set(d.lower().strip() for d in (brand_domains or []))
        self.suspicious_certs: List[Dict[str, Any]] = []

    def add_brand_domain(self, domain: str) -> None:
        self.brand_domains.add(domain.lower().strip())

    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        """Compute Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return CTLogMonitor._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    def is_lookalike_domain(self, target_domain: str) -> Optional[Tuple[str, int]]:
        """Check if target_domain is a lookalike/typosquat of any registered brand domain."""
        target_clean = target_domain.lower().strip()
        target_name = target_clean.split(".")[0]

        for brand in self.brand_domains:
            brand_clean = brand.lower().strip()
            brand_name = brand_clean.split(".")[0]

            if target_clean == brand_clean:
                continue  # Exact match on legitimate brand domain is fine

            # Check edit distance on base domain name
            dist = self._levenshtein_distance(target_name, brand_name)
            if 1 <= dist <= 2 and len(brand_name) > 3:
                return (brand_clean, dist)

            # Substring impersonation check (e.g. corp-login.com for corp.com)
            if brand_name in target_name and target_clean != brand_clean:
                return (brand_clean, 0)

        return None

    def process_ct_log_entry(self, cert_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a CT log entry dictionary containing CN / SAN domains."""
        domains = cert_data.get("domains", [])
        if "cn" in cert_data:
            domains.append(cert_data["cn"])

        for domain in domains:
            match_info = self.is_lookalike_domain(domain)
            if match_info:
                brand, dist = match_info
                alert = {
                    "domain": domain,
                    "target_brand": brand,
                    "distance": dist,
                    "issuer": cert_data.get("issuer", "Unknown CA"),
                    "serial_number": cert_data.get("serial_number", ""),
                    "timestamp": cert_data.get("timestamp"),
                    "threat": "proactive_phishing_cert_issuance",
                }
                self.suspicious_certs.append(alert)
                return alert

        return None

    def parse_crtsh_json_response(self, crtsh_json: str) -> List[Dict[str, Any]]:
        """Parse crt.sh JSON API response."""
        alerts = []
        try:
            entries = json.loads(crtsh_json)
            if isinstance(entries, list):
                for entry in entries:
                    cn = entry.get("common_name", "")
                    name_value = entry.get("name_value", "")
                    domains = list(set([cn, name_value] + name_value.split("\n")))
                    alert = self.process_ct_log_entry({
                        "domains": [d for d in domains if d],
                        "issuer": entry.get("issuer_name", ""),
                        "serial_number": entry.get("serial_number", ""),
                    })
                    if alert:
                        alerts.append(alert)
        except json.JSONDecodeError:
            pass
        return alerts
