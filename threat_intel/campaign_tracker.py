"""
Threat Actor & Campaign Clustering Engine.
Correlates related threat events across time, IP addresses, domains, and attachment hashes into named campaigns.
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


class CampaignTracker:
    def __init__(self):
        self.campaigns: Dict[str, Dict[str, Any]] = {}  # campaign_id -> campaign_data
        self.ioc_to_campaign: Dict[str, str] = {}  # ioc_value -> campaign_id

    def record_incident(
        self,
        sender_ip: Optional[str] = None,
        domain: Optional[str] = None,
        attachment_hash: Optional[str] = None,
        subject: Optional[str] = None,
        threat_type: str = "phishing",
    ) -> Dict[str, Any]:
        """Record a threat incident and correlate with existing or new campaign."""
        iocs = [i for i in [sender_ip, domain, attachment_hash] if i]
        matched_campaign_id = None

        # 1. Search for matching existing campaign
        for ioc in iocs:
            clean_ioc = ioc.lower().strip()
            if clean_ioc in self.ioc_to_campaign:
                matched_campaign_id = self.ioc_to_campaign[clean_ioc]
                break

        # 2. Create new campaign if no match found
        if not matched_campaign_id:
            matched_campaign_id = f"Campaign-{threat_type.upper()}-{uuid.uuid4().hex[:6]}"
            self.campaigns[matched_campaign_id] = {
                "campaign_id": matched_campaign_id,
                "threat_type": threat_type,
                "created_timestamp": time.time(),
                "last_seen_timestamp": time.time(),
                "incident_count": 0,
                "associated_iocs": set(),
                "sample_subjects": [],
            }

        campaign = self.campaigns[matched_campaign_id]
        campaign["incident_count"] += 1
        campaign["last_seen_timestamp"] = time.time()

        for ioc in iocs:
            clean_ioc = ioc.lower().strip()
            campaign["associated_iocs"].add(clean_ioc)
            self.ioc_to_campaign[clean_ioc] = matched_campaign_id

        if subject and subject not in campaign["sample_subjects"]:
            campaign["sample_subjects"].append(subject[:100])

        res = dict(campaign)
        res["associated_iocs"] = list(campaign["associated_iocs"])
        return res

    def get_campaign(self, campaign_id: str) -> Optional[Dict[str, Any]]:
        c = self.campaigns.get(campaign_id)
        if not c:
            return None
        res = dict(c)
        res["associated_iocs"] = list(c["associated_iocs"])
        return res

    def list_campaigns(self) -> List[Dict[str, Any]]:
        results = []
        for c in self.campaigns.values():
            res = dict(c)
            res["associated_iocs"] = list(c["associated_iocs"])
            results.append(res)
        return results
