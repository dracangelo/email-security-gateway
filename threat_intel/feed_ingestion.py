"""
External IOC Feed Ingestion Engine.
Parses, normalizes, and stores domain, IP, URL, and file hash threat intelligence blocklists.
"""
from __future__ import annotations

import json
from typing import Any, Dict, Optional, Set


class IOCFeedManager:
    def __init__(self):
        self.ip_blocklist: Set[str] = set()
        self.domain_blocklist: Set[str] = set()
        self.hash_blocklist: Set[str] = set()
        self.url_blocklist: Set[str] = set()
        self.metadata: Dict[str, Dict[str, Any]] = {}

    def ingest_feed(self, feed_name: str, feed_type: str, content: str) -> int:
        """Parse raw feed content and populate the corresponding IOC set. Returns count of added items."""
        count = 0
        feed_type_clean = feed_type.lower().strip()

        if content.strip().startswith("{") or content.strip().startswith("["):
            try:
                data = json.loads(content)
                items = data if isinstance(data, list) else data.get("items", [])
                for item in items:
                    val = item if isinstance(item, str) else item.get("value")
                    if val and self.add_ioc(val, feed_type_clean, source=feed_name):
                        count += 1
                return count
            except json.JSONDecodeError:
                pass

        lines = content.splitlines()
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue

            # Strip comments at end of line
            val = line.split("#")[0].split(";")[0].strip()
            if val and self.add_ioc(val, feed_type_clean, source=feed_name):
                count += 1

        return count

    def add_ioc(self, value: str, ioc_type: str, source: str = "custom") -> bool:
        """Add a single IOC to the specified store."""
        val_clean = value.lower().strip()
        if not val_clean:
            return False

        if ioc_type in ("ip", "ipv4", "ipv6"):
            self.ip_blocklist.add(val_clean)
        elif ioc_type in ("domain", "hostname"):
            self.domain_blocklist.add(val_clean)
        elif ioc_type in ("hash", "md5", "sha256"):
            self.hash_blocklist.add(val_clean)
        elif ioc_type in ("url", "uri"):
            self.url_blocklist.add(val_clean)
        else:
            return False

        self.metadata[val_clean] = {"type": ioc_type, "source": source}
        return True

    def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        ip_clean = ip.lower().strip()
        if ip_clean in self.ip_blocklist:
            return self.metadata.get(ip_clean, {"type": "ip", "source": "known_bad"})
        return None

    def check_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        dom_clean = domain.lower().strip()
        if dom_clean in self.domain_blocklist:
            return self.metadata.get(dom_clean, {"type": "domain", "source": "known_bad"})
        return None

    def check_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        hash_clean = file_hash.lower().strip()
        if hash_clean in self.hash_blocklist:
            return self.metadata.get(hash_clean, {"type": "hash", "source": "known_bad"})
        return None

    def check_url(self, url: str) -> Optional[Dict[str, Any]]:
        url_clean = url.lower().strip()
        if url_clean in self.url_blocklist:
            return self.metadata.get(url_clean, {"type": "url", "source": "known_bad"})
        return None
