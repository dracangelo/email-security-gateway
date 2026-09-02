"""
MISP Integration Client.
Ingests threat attributes from MISP REST APIs and exports confirmed email security incidents to MISP.
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from threat_intel.feed_ingestion import IOCFeedManager


class MISPIntegrationClient:
    def __init__(self, misp_url: Optional[str] = None, api_key: Optional[str] = None, feed_manager: Optional[IOCFeedManager] = None):
        self.misp_url = misp_url or "https://misp.local"
        self.api_key = api_key
        self.feed_manager = feed_manager or IOCFeedManager()

    def parse_misp_event_response(self, misp_event_json: str) -> int:
        """Parse MISP REST API event response and populate feed manager with IOC attributes."""
        try:
            data = json.loads(misp_event_json)
        except json.JSONDecodeError:
            return 0

        # MISP returns {"response": [{"Event": {"Attribute": [...]}}]}
        events = data.get("response", [])
        if isinstance(events, dict):
            events = [events]

        count = 0
        for item in events:
            event = item.get("Event", item)
            attributes = event.get("Attribute", [])
            for attr in attributes:
                val = attr.get("value")
                attr_type = attr.get("type", "").lower()
                if not val:
                    continue

                if attr_type in ("domain", "hostname"):
                    if self.feed_manager.add_ioc(val, "domain", source="misp"):
                        count += 1
                elif attr_type in ("ip-src", "ip-dst", "ip"):
                    if self.feed_manager.add_ioc(val, "ip", source="misp"):
                        count += 1
                elif attr_type in ("url", "uri"):
                    if self.feed_manager.add_ioc(val, "url", source="misp"):
                        count += 1
                elif attr_type in ("sha256", "md5", "filename|sha256"):
                    clean_hash = val.split("|")[-1] if "|" in val else val
                    if self.feed_manager.add_ioc(clean_hash, "hash", source="misp"):
                        count += 1

        return count

    def format_export_event(
        self,
        event_info: str,
        sender_ip: Optional[str] = None,
        phishing_domain: Optional[str] = None,
        malicious_url: Optional[str] = None,
        attachment_sha256: Optional[str] = None,
        threat_level_id: int = 1,
    ) -> Dict[str, Any]:
        """Format a confirmed gateway threat detection as an outbound MISP event JSON payload."""
        attributes = []

        if sender_ip:
            attributes.append({"type": "ip-src", "category": "Network activity", "value": sender_ip})
        if phishing_domain:
            attributes.append({"type": "domain", "category": "Network activity", "value": phishing_domain})
        if malicious_url:
            attributes.append({"type": "url", "category": "Payload delivery", "value": malicious_url})
        if attachment_sha256:
            attributes.append({"type": "sha256", "category": "Payload delivery", "value": attachment_sha256})

        return {
            "Event": {
                "info": f"[Email Auth Gateway] {event_info}",
                "threat_level_id": str(threat_level_id),
                "analysis": "2",  # Completed analysis
                "distribution": "0",  # Your organisation only by default
                "date": time.strftime("%Y-%m-%d"),
                "Attribute": attributes,
            }
        }
