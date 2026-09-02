"""
Tests for Threat Intelligence Module (Task 10):
- External IOC Feed Ingestion
- STIX 2.1 & TAXII 2.1 Feed Client
- MISP Ingestion & Event Export
- Cross-Tenant Opt-In IOC Sharing
- Certificate Transparency (CT) Log Monitoring
- Newly Registered Domain (NRD) Watchlist Engine
- Threat Actor Campaign Clustering
"""
from __future__ import annotations

import json
import pytest

from threat_intel import (
    CampaignTracker,
    CrossTenantIOCSharer,
    CTLogMonitor,
    IOCFeedManager,
    MISPIntegrationClient,
    NRDWatchlistEngine,
    STIXTAXIIClient,
)


def test_ioc_feed_manager():
    mgr = IOCFeedManager()

    raw_feed = """
    # Bad IP list
    192.0.2.50
    203.0.113.100 ; C2 Server
    """
    added_ips = mgr.ingest_feed("abuse_ip_list", "ip", raw_feed)
    assert added_ips == 2

    assert mgr.check_ip("192.0.2.50") is not None
    assert mgr.check_ip("10.0.0.1") is None

    mgr.add_ioc("phish-domain.com", "domain", source="manual")
    assert mgr.check_domain("phish-domain.com") is not None


def test_stix_taxii_client():
    mgr = IOCFeedManager()
    stix_client = STIXTAXIIClient(feed_manager=mgr)

    stix_bundle = {
        "type": "bundle",
        "id": "bundle--123",
        "objects": [
            {
                "type": "indicator",
                "pattern": "[domain-name:value = 'stix-malware.com'] AND [ipv4-addr:value = '198.51.100.44']",
            }
        ],
    }

    extracted = stix_client.parse_stix_bundle(json.dumps(stix_bundle))
    assert len(extracted) == 2
    assert mgr.check_domain("stix-malware.com") is not None
    assert mgr.check_ip("198.51.100.44") is not None

    taxii_env = {"objects": stix_bundle["objects"]}
    count = stix_client.parse_taxii_collection_response(json.dumps(taxii_env))
    assert count == 2


def test_misp_integration_client():
    mgr = IOCFeedManager()
    misp_client = MISPIntegrationClient(feed_manager=mgr)

    misp_response = {
        "response": [
            {
                "Event": {
                    "Attribute": [
                        {"type": "domain", "value": "misp-phish.com"},
                        {"type": "ip-src", "value": "198.51.100.99"},
                    ]
                }
            }
        ]
    }

    count = misp_client.parse_misp_event_response(json.dumps(misp_response))
    assert count == 2
    assert mgr.check_domain("misp-phish.com") is not None

    export_payload = misp_client.format_export_event(
        event_info="Credential Phishing Attempt",
        sender_ip="198.51.100.99",
        phishing_domain="misp-phish.com",
    )
    assert export_payload["Event"]["info"].startswith("[Email Auth Gateway]")
    assert len(export_payload["Event"]["Attribute"]) == 2


def test_cross_tenant_ioc_sharing():
    sharer = CrossTenantIOCSharer()

    sharer.opt_in_tenant("tenant_alpha")
    sharer.opt_in_tenant("tenant_beta")

    # Non-opted tenant trying to share
    assert not sharer.share_confirmed_ioc("tenant_gamma", "evil-net.com", "domain")

    # Opted-in tenant sharing anonymously
    assert sharer.share_confirmed_ioc("tenant_alpha", "evil-net.com", "domain")

    # Opted-in tenant querying shared pool
    match = sharer.check_shared_ioc("tenant_beta", "evil-net.com")
    assert match is not None
    assert match["value"] == "evil-net.com"

    # Non-opted tenant querying shared pool receives None
    assert sharer.check_shared_ioc("tenant_gamma", "evil-net.com") is None


def test_ct_log_monitor():
    monitor = CTLogMonitor(brand_domains=["mycompany.com"])

    # Typosquat / Lookalike check
    match = monitor.is_lookalike_domain("mycompnay.com")
    assert match is not None
    assert match[0] == "mycompany.com"

    # Process CT cert entry
    cert_entry = {
        "cn": "mycompnay.com",
        "domains": ["mycompnay.com", "login-mycompany.com"],
        "issuer": "Let's Encrypt",
    }
    alert = monitor.process_ct_log_entry(cert_entry)
    assert alert is not None
    assert alert["target_brand"] == "mycompany.com"


def test_nrd_watchlist_engine():
    nrd = NRDWatchlistEngine(max_age_days=7)

    raw_nrd_feed = "fresh-domain-1.com\nfresh-domain-2.com"
    count = nrd.ingest_nrd_feed(raw_nrd_feed)
    assert count == 2

    res = nrd.is_newly_registered("fresh-domain-1.com")
    assert res is not None
    assert res["is_nrd"] is True
    assert nrd.is_newly_registered("old-established-domain.com") is None


def test_campaign_tracker():
    tracker = CampaignTracker()

    inc1 = tracker.record_incident(
        sender_ip="192.0.2.10",
        domain="campaign-phish.com",
        subject="Important Account Security Alert",
        threat_type="phishing",
    )
    c_id = inc1["campaign_id"]
    assert c_id.startswith("Campaign-PHISHING-")

    # Second incident matching same IP -> should cluster into same campaign
    inc2 = tracker.record_incident(
        sender_ip="192.0.2.10",
        domain="new-domain-phish.com",
        subject="Urgent Verification Needed",
        threat_type="phishing",
    )
    assert inc2["campaign_id"] == c_id
    assert inc2["incident_count"] == 2
    assert "new-domain-phish.com" in inc2["associated_iocs"]
