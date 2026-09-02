"""
STIX 2.1 & TAXII 2.1 Threat Intelligence Client.
Parses STIX 2.1 JSON bundles and TAXII 2.1 REST collection responses into gateway IOC feeds.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from threat_intel.feed_ingestion import IOCFeedManager


class STIXTAXIIClient:
    # STIX 2.1 pattern extraction regexes
    DOMAIN_PATTERN = re.compile(r"domain-name:value\s*=\s*'([^']+)'", re.IGNORECASE)
    IP_PATTERN = re.compile(r"ipv4-addr:value\s*=\s*'([^']+)'", re.IGNORECASE)
    HASH_PATTERN = re.compile(r"file:hashes\.['\"]?(?:SHA-256|MD5)['\"]?\s*=\s*'([^']+)'", re.IGNORECASE)
    URL_PATTERN = re.compile(r"url:value\s*=\s*'([^']+)'", re.IGNORECASE)

    def __init__(self, feed_manager: Optional[IOCFeedManager] = None):
        self.feed_manager = feed_manager or IOCFeedManager()

    def parse_stix_bundle(self, stix_bundle_json: str) -> List[Tuple[str, str]]:
        """Parse a STIX 2.1 JSON bundle and extract (ioc_value, ioc_type) tuples."""
        extracted: List[Tuple[str, str]] = []
        try:
            bundle = json.loads(stix_bundle_json)
        except json.JSONDecodeError:
            return extracted

        objects = bundle.get("objects", []) if isinstance(bundle, dict) else []

        for obj in objects:
            if obj.get("type") != "indicator":
                continue

            pattern = obj.get("pattern", "")
            if not pattern:
                continue

            # Match domains
            for m in self.DOMAIN_PATTERN.finditer(pattern):
                extracted.append((m.group(1), "domain"))
                self.feed_manager.add_ioc(m.group(1), "domain", source="stix2.1")

            # Match IPs
            for m in self.IP_PATTERN.finditer(pattern):
                extracted.append((m.group(1), "ip"))
                self.feed_manager.add_ioc(m.group(1), "ip", source="stix2.1")

            # Match Hashes
            for m in self.HASH_PATTERN.finditer(pattern):
                extracted.append((m.group(1), "hash"))
                self.feed_manager.add_ioc(m.group(1), "hash", source="stix2.1")

            # Match URLs
            for m in self.URL_PATTERN.finditer(pattern):
                extracted.append((m.group(1), "url"))
                self.feed_manager.add_ioc(m.group(1), "url", source="stix2.1")

        return extracted

    def parse_taxii_collection_response(self, taxii_response_json: str) -> int:
        """Parse a TAXII 2.1 collection envelope containing STIX objects."""
        try:
            data = json.loads(taxii_response_json)
        except json.JSONDecodeError:
            return 0

        # TAXII 2.1 envelope can be wrapped in 'objects' or 'manifest'
        objects = data.get("objects", [])
        if not objects:
            return 0

        bundle_wrapper = json.dumps({"type": "bundle", "id": "bundle--taxii", "objects": objects})
        extracted = self.parse_stix_bundle(bundle_wrapper)
        return len(extracted)
